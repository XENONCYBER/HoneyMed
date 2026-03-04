"""
HoneyMed - Phase 11: SIEM REST API Connector
===============================================
Provides a REST API that reads ML-classified, blockchain-verified
threat data and exposes it in formats consumable by enterprise SIEM
platforms (Splunk, IBM QRadar, Elastic Security).

Endpoints:
  GET  /api/siem/threats          — Paginated threat feed (JSON)
  GET  /api/siem/threats/feed     — STIX-like IOC feed
  GET  /api/siem/threats/<hash>   — Single threat detail
  POST /api/siem/threats/receive  — Receive from distributed peers
  GET  /api/siem/stats            — Dashboard statistics
  POST /api/siem/block-ip         — Trigger automated IP block

The connector reads from:
  1. classified_events.db  (pipeline/ML layer)
  2. blockchain_ledger.db  (blockchain layer)
  3. chaincode_state.db    (smart contract IOCs)
  4. peer_network.db       (distributed consensus)
"""

import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

from flask import Flask, jsonify, request
from flask_cors import CORS

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.loader import get_config, get_base_dir
from utils.logger import get_logger

logger = get_logger("siem.api_connector", layer="SIEM", log_file="siem_api.jsonl")

# Database paths
DATA_DIR = os.path.join(get_base_dir(), "data")
EVENTS_DB = os.path.join(DATA_DIR, "classified_events.db")
LEDGER_DB = os.path.join(DATA_DIR, "blockchain_ledger.db")
CHAINCODE_DB = os.path.join(DATA_DIR, "chaincode_state.db")
PEER_DB = os.path.join(DATA_DIR, "peer_network.db")


def _query_db(db_path: str, query: str, params: tuple = ()) -> list[dict]:
    """Safely query a SQLite database and return list of dicts."""
    if not os.path.exists(db_path):
        return []
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError as e:
        logger.warning(f"DB query error ({db_path}): {e}")
        return []
    finally:
        conn.close()


class SIEMAPIConnector:
    """
    Flask-based REST API that aggregates threat data from all HoneyMed
    layers and serves it to SIEM platforms.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 5002):
        cfg = get_config()
        siem_cfg = cfg.get("siem", {})

        self.host = siem_cfg.get("api_host", host)
        self.port = siem_cfg.get("api_port", port)

        self.app = Flask("HoneyMed-SIEM-API")
        CORS(self.app)
        self._register_routes()

        logger.info(f"SIEM API Connector ready on {self.host}:{self.port}")

    def _register_routes(self):
        """Register all SIEM API endpoints."""

        @self.app.route("/api/siem/threats", methods=["GET"])
        def get_threats():
            """Paginated threat events from the ML pipeline."""
            page = request.args.get("page", 1, type=int)
            per_page = min(request.args.get("per_page", 50, type=int), 500)
            label_filter = request.args.get("label")
            attacks_only = request.args.get("attacks_only", "false").lower() == "true"

            offset = (page - 1) * per_page

            conditions = []
            params: list = []

            if attacks_only:
                conditions.append("is_attack = 1")
            if label_filter:
                conditions.append("label = ?")
                params.append(label_filter)

            where = ""
            if conditions:
                where = "WHERE " + " AND ".join(conditions)

            query = f"""
                SELECT timestamp, attacker_ip, service, event_type, protocol,
                       label, confidence, is_attack, sha256_hash, payload_size,
                       payload_entropy, created_at
                FROM classified_events {where}
                ORDER BY timestamp DESC LIMIT ? OFFSET ?
            """
            params.extend([per_page, offset])

            results = _query_db(EVENTS_DB, query, tuple(params))

            # Total count
            count_query = f"SELECT COUNT(*) as cnt FROM classified_events {where}"
            count_params = tuple(params[:-2])  # exclude LIMIT/OFFSET
            total_rows = _query_db(EVENTS_DB, count_query, count_params)
            total = total_rows[0]["cnt"] if total_rows else 0

            return jsonify({
                "page": page,
                "per_page": per_page,
                "total": total,
                "threats": results,
            })

        @self.app.route("/api/siem/threats/feed", methods=["GET"])
        def get_threat_feed():
            """IOC feed in a STIX-like format for SIEM ingestion."""
            limit = min(request.args.get("limit", 100, type=int), 1000)
            since = request.args.get("since")

            conditions = ["is_attack = 1"]
            params: list = []

            if since:
                conditions.append("timestamp >= ?")
                params.append(since)

            where = "WHERE " + " AND ".join(conditions)
            query = f"""
                SELECT sha256_hash, label, confidence, attacker_ip, timestamp,
                       service, protocol
                FROM classified_events {where}
                ORDER BY timestamp DESC LIMIT ?
            """
            params.append(limit)
            events = _query_db(EVENTS_DB, query, tuple(params))

            # Format as IOC indicators
            indicators = []
            for e in events:
                indicators.append({
                    "type": "indicator",
                    "id": f"indicator--{e['sha256_hash'][:36]}",
                    "created": e["timestamp"],
                    "labels": [e["label"]],
                    "pattern": f"[ipv4-addr:value = '{e.get('attacker_ip', '')}']",
                    "confidence": int(e.get("confidence", 0) * 100),
                    "extensions": {
                        "honeymed": {
                            "service": e.get("service"),
                            "protocol": e.get("protocol"),
                            "sha256": e["sha256_hash"],
                        }
                    },
                })

            return jsonify({
                "type": "bundle",
                "id": f"bundle--honeymed-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                "objects": indicators,
            })

        @self.app.route("/api/siem/threats/<sha256_hash>", methods=["GET"])
        def get_threat_detail(sha256_hash):
            """Get details for a specific threat by its SHA-256 hash."""
            events = _query_db(
                EVENTS_DB,
                "SELECT * FROM classified_events WHERE sha256_hash = ? LIMIT 1",
                (sha256_hash,),
            )
            if not events:
                return jsonify({"error": "Threat not found"}), 404

            # Also check blockchain verification
            blockchain_info = _query_db(
                LEDGER_DB,
                "SELECT * FROM threat_records WHERE threat_hash = ? LIMIT 1",
                (sha256_hash,),
            )

            # Check consensus status
            consensus_info = _query_db(
                PEER_DB,
                "SELECT * FROM shared_threats WHERE sha256_hash = ? LIMIT 1",
                (sha256_hash,),
            )

            result = events[0]
            result["blockchain_verified"] = len(blockchain_info) > 0
            result["blockchain_record"] = blockchain_info[0] if blockchain_info else None
            result["consensus_verified"] = (
                consensus_info[0].get("verified", 0) == 1 if consensus_info else False
            )
            result["consensus_record"] = consensus_info[0] if consensus_info else None

            return jsonify(result)

        @self.app.route("/api/siem/threats/receive", methods=["POST"])
        def receive_threat():
            """Receive a threat from a distributed peer node."""
            data = request.get_json(force=True)
            required = ["sha256_hash", "threat_label", "source_node"]
            for field in required:
                if field not in data:
                    return jsonify({"error": f"Missing field: {field}"}), 400

            try:
                from distributed.node_manager import get_node_manager
                nm = get_node_manager()
                result = nm.receive_threat(
                    data["sha256_hash"],
                    data["threat_label"],
                    data.get("confidence", 0.0),
                    data["source_node"],
                )
                return jsonify(result)
            except Exception as e:
                logger.error(f"Error receiving threat: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/siem/stats", methods=["GET"])
        def get_stats():
            """Aggregate statistics for SIEM dashboard."""
            # Event stats
            event_stats = _query_db(EVENTS_DB, """
                SELECT
                    COUNT(*) as total_events,
                    SUM(CASE WHEN is_attack = 1 THEN 1 ELSE 0 END) as total_attacks,
                    COUNT(DISTINCT attacker_ip) as unique_attackers,
                    AVG(confidence) as avg_confidence
                FROM classified_events
            """)

            # Label breakdown
            label_stats = _query_db(EVENTS_DB, """
                SELECT label, COUNT(*) as count
                FROM classified_events
                GROUP BY label ORDER BY count DESC
            """)

            # Blockchain stats
            blockchain_stats = _query_db(LEDGER_DB, """
                SELECT COUNT(*) as total_blocks FROM ledger_blocks
            """)

            # Peer stats
            peer_stats = _query_db(PEER_DB, """
                SELECT COUNT(*) as total_peers FROM peers WHERE status = 'active'
            """)

            return jsonify({
                "events": event_stats[0] if event_stats else {},
                "labels": label_stats,
                "blockchain": blockchain_stats[0] if blockchain_stats else {},
                "peers": peer_stats[0] if peer_stats else {},
                "generated_at": datetime.now(timezone.utc).isoformat(),
            })

        @self.app.route("/api/siem/block-ip", methods=["POST"])
        def block_ip():
            """Trigger automated IP blocking via auto-response module."""
            data = request.get_json(force=True)
            ip = data.get("ip")
            reason = data.get("reason", "SIEM automated block")

            if not ip:
                return jsonify({"error": "Missing 'ip' field"}), 400

            try:
                from siem.auto_response import AutoResponse
                responder = AutoResponse()
                result = responder.block_ip(ip, reason)
                return jsonify(result)
            except Exception as e:
                logger.error(f"Auto-response error: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/siem/health", methods=["GET"])
        def health():
            return jsonify({"status": "ok", "service": "HoneyMed SIEM API"})

    def run(self):
        """Start the SIEM API server."""
        logger.info(f"Starting SIEM API at http://{self.host}:{self.port}")
        self.app.run(host=self.host, port=self.port, debug=False)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
_siem_connector = None


def get_siem_connector() -> SIEMAPIConnector:
    """Get or create the singleton SIEM API connector."""
    global _siem_connector
    if _siem_connector is None:
        _siem_connector = SIEMAPIConnector()
    return _siem_connector


if __name__ == "__main__":
    connector = SIEMAPIConnector()
    connector.run()
