"""
HoneyMed - Layer 4: REST API Backend
=====================================
Provides a REST API for the dashboard and external consumers.
This API serves classified event data from the SQLite database.

Future Compatibility: This API allows other hospitals in a
distributed network to pull threat intelligence securely.
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

logger = get_logger("dashboard.api", layer="DASHBOARD", log_file="dashboard_api.jsonl")
cfg = get_config()

app = Flask(__name__)
CORS(app)

DB_PATH = os.path.join(get_base_dir(), "data", "classified_events.db")


def _get_db():
    """Get a database connection."""
    # Ensure data directory exists
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.route("/api/status")
def api_status():
    """Health check and system status."""
    try:
        conn = _get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as total FROM classified_events")
        total = cursor.fetchone()["total"]
        cursor.execute("SELECT COUNT(*) as attacks FROM classified_events WHERE is_attack = 1")
        attacks = cursor.fetchone()["attacks"]
        conn.close()
        db_ok = True
    except Exception:
        total, attacks, db_ok = 0, 0, False

    return jsonify({
        "status": "running",
        "project": "HoneyMed IoMT Honeypot",
        "version": cfg.get("VERSION", "1.0.0"),
        "database": "connected" if db_ok else "disconnected",
        "total_events": total,
        "total_attacks": attacks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/events/recent")
def api_recent_events():
    """Get the most recent classified events."""
    limit = request.args.get("limit", 50, type=int)
    attack_only = request.args.get("attacks_only", "false").lower() == "true"

    conn = _get_db()
    cursor = conn.cursor()

    query = "SELECT * FROM classified_events"
    if attack_only:
        query += " WHERE is_attack = 1"
    query += " ORDER BY id DESC LIMIT ?"

    cursor.execute(query, (limit,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return jsonify(rows)


@app.route("/api/events/stats")
def api_event_stats():
    """Get aggregated statistics."""
    conn = _get_db()
    cursor = conn.cursor()

    # Total counts by label
    cursor.execute("""
        SELECT label, COUNT(*) as count
        FROM classified_events
        GROUP BY label
        ORDER BY count DESC
    """)
    label_dist = {row["label"]: row["count"] for row in cursor.fetchall()}

    # Top attackers
    cursor.execute("""
        SELECT attacker_ip, COUNT(*) as count,
               SUM(CASE WHEN is_attack = 1 THEN 1 ELSE 0 END) as attack_count
        FROM classified_events
        WHERE attacker_ip != ''
        GROUP BY attacker_ip
        ORDER BY count DESC
        LIMIT 20
    """)
    top_attackers = [dict(r) for r in cursor.fetchall()]

    # Events over time (last 100 windows)
    cursor.execute("""
        SELECT * FROM attack_summary
        ORDER BY id DESC LIMIT 100
    """)
    timeline = [dict(r) for r in cursor.fetchall()]

    # Service distribution
    cursor.execute("""
        SELECT service, COUNT(*) as count
        FROM classified_events
        WHERE service != ''
        GROUP BY service
    """)
    services = {row["service"]: row["count"] for row in cursor.fetchall()}

    # Average confidence
    cursor.execute("""
        SELECT AVG(confidence) as avg_confidence
        FROM classified_events
        WHERE is_attack = 1
    """)
    avg_conf = cursor.fetchone()["avg_confidence"] or 0

    conn.close()

    return jsonify({
        "label_distribution": label_dist,
        "top_attackers": top_attackers,
        "timeline": timeline[::-1],  # Chronological order
        "service_distribution": services,
        "average_attack_confidence": round(avg_conf, 4),
    })


@app.route("/api/events/search")
def api_search():
    """Search events by attacker IP or event type."""
    ip = request.args.get("ip", "")
    event_type = request.args.get("type", "")
    label = request.args.get("label", "")
    limit = request.args.get("limit", 100, type=int)

    conn = _get_db()
    cursor = conn.cursor()

    conditions = []
    params = []
    if ip:
        conditions.append("attacker_ip LIKE ?")
        params.append(f"%{ip}%")
    if event_type:
        conditions.append("event_type LIKE ?")
        params.append(f"%{event_type}%")
    if label:
        conditions.append("label = ?")
        params.append(label)

    query = "SELECT * FROM classified_events"
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return jsonify(rows)


@app.route("/api/hashes/recent")
def api_recent_hashes():
    """
    Get recent SHA-256 hashes.
    These are the hashes that would be pushed to a blockchain ledger.
    """
    limit = request.args.get("limit", 50, type=int)

    conn = _get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, attacker_ip, event_type, label, sha256_hash
        FROM classified_events
        ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return jsonify({
        "description": "SHA-256 hashes for blockchain verification",
        "count": len(rows),
        "hashes": rows,
    })


@app.route("/api/threat-intelligence")
def api_threat_intel():
    """
    Threat intelligence feed (future: shared across hospitals).
    Returns IOCs (Indicators of Compromise) detected by the system.
    """
    conn = _get_db()
    cursor = conn.cursor()

    # Get unique attacker IPs with their attack patterns
    cursor.execute("""
        SELECT attacker_ip,
               GROUP_CONCAT(DISTINCT label) as attack_types,
               COUNT(*) as total_events,
               MIN(timestamp) as first_seen,
               MAX(timestamp) as last_seen,
               AVG(confidence) as avg_confidence
        FROM classified_events
        WHERE is_attack = 1 AND attacker_ip != ''
        GROUP BY attacker_ip
        ORDER BY total_events DESC
        LIMIT 50
    """)
    iocs = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return jsonify({
        "feed_name": "HoneyMed Threat Intelligence",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ioc_count": len(iocs),
        "indicators": iocs,
    })


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
def run_api():
    """Start the REST API server."""
    port = cfg["dashboard"]["api_port"]
    logger.info(f"Starting Dashboard API on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)


if __name__ == "__main__":
    run_api()
