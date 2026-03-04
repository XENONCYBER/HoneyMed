"""
HoneyMed - Phase 8: Hyperledger Fabric Client
===============================================
Interfaces with a Hyperledger Fabric peer node to commit
SHA-256 hashes and threat classifications to an immutable ledger.

In a full deployment, this connects to a real Fabric peer via gRPC.
For development / standalone mode, it maintains a local JSON-based
ledger that mirrors the blockchain's structure and can be swapped
for the real Fabric SDK when infrastructure is available.

Architecture:
    Honeypot → Pipeline → ML Engine → Hash Protocol → Fabric Client → Ledger
"""

import hashlib
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.loader import get_config, get_base_dir
from utils.logger import get_logger

logger = get_logger("blockchain.fabric", layer="BLOCKCHAIN", log_file="blockchain.jsonl")


# ---------------------------------------------------------------------------
# Local Ledger (dev-mode — mirrors Hyperledger Fabric structure)
# ---------------------------------------------------------------------------

LEDGER_DB = os.path.join(get_base_dir(), "data", "blockchain_ledger.db")


def _init_ledger_db():
    """Initialize the local blockchain ledger database."""
    os.makedirs(os.path.dirname(LEDGER_DB), exist_ok=True)
    conn = sqlite3.connect(LEDGER_DB)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS ledger_blocks (
            block_number INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            data_hash TEXT NOT NULL,
            tx_id TEXT NOT NULL UNIQUE,
            channel TEXT DEFAULT 'honeymed-channel',
            block_hash TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS ledger_transactions (
            tx_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            function_name TEXT NOT NULL,
            args TEXT NOT NULL,
            submitter TEXT DEFAULT 'HoneyMedEdge',
            status TEXT DEFAULT 'VALID',
            block_number INTEGER,
            FOREIGN KEY (block_number) REFERENCES ledger_blocks(block_number)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS threat_records (
            record_id TEXT PRIMARY KEY,
            sha256_hash TEXT NOT NULL,
            threat_label TEXT NOT NULL,
            confidence REAL,
            attacker_ip TEXT,
            timestamp TEXT NOT NULL,
            encrypted INTEGER DEFAULT 0,
            disclosed INTEGER DEFAULT 0,
            disclosure_date TEXT,
            tx_id TEXT,
            FOREIGN KEY (tx_id) REFERENCES ledger_transactions(tx_id)
        )
    """)

    conn.commit()
    conn.close()
    logger.info(f"Ledger database initialized: {LEDGER_DB}")


def _get_last_block(conn: sqlite3.Connection) -> dict:
    """Get the latest block from the local ledger."""
    c = conn.cursor()
    c.execute("SELECT block_number, block_hash FROM ledger_blocks ORDER BY block_number DESC LIMIT 1")
    row = c.fetchone()
    if row:
        return {"block_number": row[0], "block_hash": row[1]}
    # Genesis reference
    return {"block_number": -1, "block_hash": "0" * 64}


# ---------------------------------------------------------------------------
# Fabric Client
# ---------------------------------------------------------------------------

class FabricClient:
    """
    Client that commits threat intelligence hashes to the blockchain ledger.

    Modes:
      - 'local':  Uses a local SQLite-based ledger (dev/standalone).
      - 'fabric': Connects to a real Hyperledger Fabric peer (requires
                   fabric-sdk-py / fabric-gateway and peer endpoint config).
    """

    def __init__(self, mode: str | None = None):
        cfg = get_config()
        bc_cfg = cfg.get("blockchain", {})
        self.mode = mode or bc_cfg.get("mode", "local")
        self.channel = bc_cfg.get("channel", "honeymed-channel")
        self.chaincode = bc_cfg.get("chaincode", "threat_intel")
        self.org = bc_cfg.get("org_name", "HospitalOrg1")
        self.peer_endpoint = bc_cfg.get("peer_endpoint", "localhost:7051")

        if self.mode == "local":
            _init_ledger_db()
            logger.info(f"FabricClient running in LOCAL ledger mode")
        else:
            logger.info(f"FabricClient connecting to Fabric peer: {self.peer_endpoint}")

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def submit_threat_hash(
        self,
        sha256_hash: str,
        threat_label: str,
        confidence: float,
        attacker_ip: str = "",
        event_timestamp: str = "",
        encrypted: bool = False,
    ) -> dict:
        """
        Submit a threat intelligence hash to the blockchain.

        Only the hash + classification go on-chain; raw data stays local.
        Returns the transaction receipt.
        """
        record_id = hashlib.sha256(
            f"{sha256_hash}:{event_timestamp}:{attacker_ip}".encode()
        ).hexdigest()[:24]

        tx_args = {
            "record_id": record_id,
            "sha256_hash": sha256_hash,
            "threat_label": threat_label,
            "confidence": round(confidence, 4),
            "attacker_ip": attacker_ip,
            "timestamp": event_timestamp or datetime.now(timezone.utc).isoformat(),
            "encrypted": encrypted,
        }

        if self.mode == "local":
            return self._submit_local(tx_args)
        else:
            return self._submit_fabric(tx_args)

    def query_threat(self, record_id: str) -> dict | None:
        """Query a single threat record by ID."""
        if self.mode == "local":
            return self._query_local(record_id)
        return self._query_fabric(record_id)

    def query_recent_threats(self, limit: int = 50) -> list[dict]:
        """Get the most recent threat records from the ledger."""
        if self.mode == "local":
            return self._query_recent_local(limit)
        return self._query_recent_fabric(limit)

    def get_chain_info(self) -> dict:
        """Get current blockchain info (height, latest hash)."""
        if self.mode == "local":
            conn = sqlite3.connect(LEDGER_DB)
            last = _get_last_block(conn)
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM ledger_transactions")
            tx_count = c.fetchone()[0]
            conn.close()
            return {
                "mode": "local",
                "channel": self.channel,
                "height": last["block_number"] + 1,
                "latest_hash": last["block_hash"],
                "total_transactions": tx_count,
            }
        return {"mode": "fabric", "peer": self.peer_endpoint}

    # ------------------------------------------------------------------
    # Local ledger implementation
    # ------------------------------------------------------------------

    def _submit_local(self, tx_args: dict) -> dict:
        """Commit a transaction to the local ledger (simulates Fabric)."""
        conn = sqlite3.connect(LEDGER_DB)
        now = datetime.now(timezone.utc).isoformat()

        # Generate tx ID
        tx_id = hashlib.sha256(
            f"{tx_args['record_id']}:{now}:{os.urandom(8).hex()}".encode()
        ).hexdigest()[:48]

        # Get previous block
        last = _get_last_block(conn)
        new_block_num = last["block_number"] + 1
        prev_hash = last["block_hash"]

        # Compute block hash (chain integrity)
        block_data = json.dumps({
            "block_number": new_block_num,
            "prev_hash": prev_hash,
            "tx_id": tx_id,
            "data": tx_args,
        }, sort_keys=True)
        block_hash = hashlib.sha256(block_data.encode()).hexdigest()

        c = conn.cursor()

        # Insert block
        c.execute("""
            INSERT INTO ledger_blocks (block_number, timestamp, prev_hash, data_hash, tx_id, channel, block_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (new_block_num, now, prev_hash, tx_args["sha256_hash"], tx_id, self.channel, block_hash))

        # Insert transaction
        c.execute("""
            INSERT INTO ledger_transactions (tx_id, timestamp, function_name, args, submitter, status, block_number)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (tx_id, now, "SubmitThreatHash", json.dumps(tx_args), self.org, "VALID", new_block_num))

        # Insert threat record
        c.execute("""
            INSERT OR REPLACE INTO threat_records
            (record_id, sha256_hash, threat_label, confidence, attacker_ip, timestamp, encrypted, tx_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            tx_args["record_id"], tx_args["sha256_hash"], tx_args["threat_label"],
            tx_args["confidence"], tx_args["attacker_ip"], tx_args["timestamp"],
            int(tx_args.get("encrypted", False)), tx_id,
        ))

        conn.commit()
        conn.close()

        receipt = {
            "tx_id": tx_id,
            "block_number": new_block_num,
            "block_hash": block_hash,
            "record_id": tx_args["record_id"],
            "status": "VALID",
            "timestamp": now,
        }
        logger.info(
            f"Ledger TX committed: block={new_block_num} tx={tx_id[:16]}... "
            f"label={tx_args['threat_label']} hash={tx_args['sha256_hash'][:16]}..."
        )
        return receipt

    def _query_local(self, record_id: str) -> dict | None:
        conn = sqlite3.connect(LEDGER_DB)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM threat_records WHERE record_id = ?", (record_id,))
        row = c.fetchone()
        conn.close()
        return dict(row) if row else None

    def _query_recent_local(self, limit: int) -> list[dict]:
        conn = sqlite3.connect(LEDGER_DB)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM threat_records ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows

    # ------------------------------------------------------------------
    # Fabric SDK stubs (for real deployment)
    # ------------------------------------------------------------------

    def _submit_fabric(self, tx_args: dict) -> dict:
        """
        Submit to real Hyperledger Fabric network.
        Requires: hfc (fabric-sdk-py) or fabric-gateway-java/go bridge.
        """
        logger.warning("Fabric mode: real peer submission not yet connected.")
        # Placeholder — in production, use:
        #   from hfc.fabric import Client
        #   cli = Client(net_profile="network.json")
        #   response = cli.chaincode_invoke(...)
        return {"status": "STUB", "message": "Fabric peer not connected"}

    def _query_fabric(self, record_id: str) -> dict | None:
        logger.warning("Fabric mode: real peer query not yet connected.")
        return None

    def _query_recent_fabric(self, limit: int) -> list[dict]:
        logger.warning("Fabric mode: real peer query not yet connected.")
        return []

    def verify_chain_integrity(self) -> dict:
        """Verify the integrity of the local ledger chain."""
        if self.mode != "local":
            return {"status": "skip", "reason": "Only available in local mode"}

        conn = sqlite3.connect(LEDGER_DB)
        c = conn.cursor()
        c.execute("SELECT block_number, prev_hash, block_hash FROM ledger_blocks ORDER BY block_number")
        blocks = c.fetchall()
        conn.close()

        if not blocks:
            return {"status": "ok", "blocks_verified": 0}

        errors = []
        for i in range(1, len(blocks)):
            if blocks[i][1] != blocks[i - 1][2]:
                errors.append({
                    "block": blocks[i][0],
                    "expected_prev": blocks[i - 1][2],
                    "actual_prev": blocks[i][1],
                })

        return {
            "status": "ok" if not errors else "INTEGRITY_VIOLATION",
            "blocks_verified": len(blocks),
            "errors": errors,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_client: FabricClient | None = None


def get_fabric_client() -> FabricClient:
    global _client
    if _client is None:
        _client = FabricClient()
    return _client


if __name__ == "__main__":
    client = FabricClient(mode="local")

    # Submit a test threat
    receipt = client.submit_threat_hash(
        sha256_hash="abc123" * 10 + "ab",
        threat_label="DoS",
        confidence=0.92,
        attacker_ip="10.0.0.5",
    )
    print(f"TX Receipt: {json.dumps(receipt, indent=2)}")

    # Verify chain
    integrity = client.verify_chain_integrity()
    print(f"Chain integrity: {integrity}")

    # Query
    info = client.get_chain_info()
    print(f"Chain info: {json.dumps(info, indent=2)}")
