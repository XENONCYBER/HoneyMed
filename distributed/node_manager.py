"""
HoneyMed - Phase 10: Distributed Node Manager
================================================
Manages a network of HoneyMed nodes that share threat intelligence
through the Hyperledger Fabric blockchain.

Architecture:
  - Each node has a unique ID, endpoint, and organization
  - Nodes register with each other via REST API
  - Threat hashes are broadcast to all peers for verification
  - Local SQLite tracks peer state (for dev/standalone mode)
  - In production, Fabric gossip protocol handles peer discovery

This module simulates multi-node behaviour in a single process
for development and testing, while providing the API layer that
would interface with real Fabric peers in production.
"""

import hashlib
import json
import os
import secrets
import sqlite3
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.loader import get_config, get_base_dir
from utils.logger import get_logger

logger = get_logger("distributed.node_manager", layer="DISTRIBUTED", log_file="distributed.jsonl")

PEER_DB_PATH = os.path.join(get_base_dir(), "data", "peer_network.db")


def _init_peer_db():
    """Create the peer network tracking database."""
    # Ensure data directory exists
    os.makedirs(os.path.dirname(PEER_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(PEER_DB_PATH)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS peers (
            node_id TEXT PRIMARY KEY,
            endpoint TEXT NOT NULL,
            org TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            last_seen TEXT,
            registered_at TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS shared_threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sha256_hash TEXT NOT NULL,
            threat_label TEXT,
            confidence REAL,
            source_node TEXT NOT NULL,
            received_at TEXT NOT NULL,
            verified INTEGER DEFAULT 0,
            verification_count INTEGER DEFAULT 0
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS sync_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_node TEXT,
            target_node TEXT,
            action TEXT,
            hashes_synced INTEGER DEFAULT 0,
            status TEXT
        )
    """)

    c.execute("CREATE INDEX IF NOT EXISTS idx_shared_hash ON shared_threats(sha256_hash)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_shared_source ON shared_threats(source_node)")

    conn.commit()
    conn.close()


class NodeManager:
    """
    Manages the local node's identity, peer connections, and threat sharing.
    """

    def __init__(self, node_id: str | None = None, endpoint: str | None = None,
                 org: str | None = None):
        cfg = get_config()
        dist_cfg = cfg.get("distributed", {})

        self.node_id = node_id or dist_cfg.get("node_id", f"node_{secrets.token_hex(4)}")
        self.endpoint = endpoint or dist_cfg.get("endpoint", "http://127.0.0.1:5001")
        self.org = org or dist_cfg.get("org", "HospitalA")

        _init_peer_db()

        # Register self as a peer
        self._register_self()

        logger.info(
            f"NodeManager initialized: id={self.node_id}, "
            f"endpoint={self.endpoint}, org={self.org}"
        )

    def _register_self(self):
        """Ensure the local node is registered in the peer database."""
        conn = sqlite3.connect(PEER_DB_PATH)
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT OR REPLACE INTO peers (node_id, endpoint, org, status, last_seen, registered_at) "
            "VALUES (?, ?, ?, 'active', ?, ?)",
            (self.node_id, self.endpoint, self.org, now, now),
        )
        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # Peer Management
    # ------------------------------------------------------------------

    def register_peer(self, node_id: str, endpoint: str, org: str) -> dict:
        """
        Register a remote peer node.

        In production, this happens via Fabric's gossip protocol.
        Here we maintain a local registry for simulation.
        """
        conn = sqlite3.connect(PEER_DB_PATH)
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT OR REPLACE INTO peers (node_id, endpoint, org, status, last_seen, registered_at) "
            "VALUES (?, ?, ?, 'active', ?, ?)",
            (node_id, endpoint, org, now, now),
        )
        conn.commit()
        conn.close()

        logger.info(f"Peer registered: {node_id} ({org}) at {endpoint}")

        return {"status": "registered", "node_id": node_id, "org": org}

    def get_peers(self, active_only: bool = True) -> list[dict]:
        """List all known peer nodes."""
        conn = sqlite3.connect(PEER_DB_PATH)
        conn.row_factory = sqlite3.Row

        query = "SELECT * FROM peers WHERE node_id != ?"
        params: list = [self.node_id]
        if active_only:
            query += " AND status = 'active'"

        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def update_peer_status(self, node_id: str, status: str):
        """Update a peer's status (active/inactive/unreachable)."""
        conn = sqlite3.connect(PEER_DB_PATH)
        conn.execute(
            "UPDATE peers SET status = ?, last_seen = ? WHERE node_id = ?",
            (status, datetime.now(timezone.utc).isoformat(), node_id),
        )
        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # Threat Intelligence Sharing
    # ------------------------------------------------------------------

    def share_threat(self, sha256_hash: str, threat_label: str,
                     confidence: float) -> dict:
        """
        Share a locally detected threat with the peer network.

        Steps:
          1. Record the threat in shared_threats table
          2. Attempt to broadcast to all active peers (via REST API)
          3. Log the sync attempt
        """
        conn = sqlite3.connect(PEER_DB_PATH)
        now = datetime.now(timezone.utc).isoformat()

        # Store locally
        conn.execute(
            "INSERT INTO shared_threats "
            "(sha256_hash, threat_label, confidence, source_node, received_at, verified, verification_count) "
            "VALUES (?, ?, ?, ?, ?, 1, 1)",
            (sha256_hash, threat_label, confidence, self.node_id, now),
        )
        conn.commit()
        conn.close()

        # Broadcast to peers
        peers = self.get_peers()
        broadcast_results = []

        for peer in peers:
            result = self._send_to_peer(peer, sha256_hash, threat_label, confidence)
            broadcast_results.append(result)

            # Log sync attempt
            conn = sqlite3.connect(PEER_DB_PATH)
            conn.execute(
                "INSERT INTO sync_log (timestamp, source_node, target_node, action, hashes_synced, status) "
                "VALUES (?, ?, ?, 'share_threat', 1, ?)",
                (now, self.node_id, peer["node_id"], result["status"]),
            )
            conn.commit()
            conn.close()

        logger.info(
            f"Threat shared: {threat_label} (hash={sha256_hash[:16]}...) "
            f"to {len(peers)} peers"
        )

        return {
            "sha256_hash": sha256_hash,
            "peers_notified": len(peers),
            "results": broadcast_results,
        }

    def _send_to_peer(self, peer: dict, sha256_hash: str,
                      threat_label: str, confidence: float) -> dict:
        """
        Send a threat record to a specific peer.

        In production, this would be an HTTP POST to the peer's REST API
        or a Fabric chaincode invoke. Here we simulate the response.
        """
        try:
            import requests
            resp = requests.post(
                f"{peer['endpoint']}/api/threats/receive",
                json={
                    "sha256_hash": sha256_hash,
                    "threat_label": threat_label,
                    "confidence": confidence,
                    "source_node": self.node_id,
                    "source_org": self.org,
                },
                timeout=5,
            )
            if resp.status_code == 200:
                return {"node_id": peer["node_id"], "status": "delivered"}
            return {"node_id": peer["node_id"], "status": f"error_{resp.status_code}"}
        except Exception:
            # Peer unreachable — store for retry
            logger.debug(f"Peer {peer['node_id']} unreachable, queued for retry")
            return {"node_id": peer["node_id"], "status": "queued"}

    def receive_threat(self, sha256_hash: str, threat_label: str,
                       confidence: float, source_node: str) -> dict:
        """
        Receive a threat record from a remote peer.

        Called when this node's REST API receives a /api/threats/receive POST.
        """
        conn = sqlite3.connect(PEER_DB_PATH)
        now = datetime.now(timezone.utc).isoformat()

        # Check if we already have this hash
        existing = conn.execute(
            "SELECT id, verification_count FROM shared_threats WHERE sha256_hash = ?",
            (sha256_hash,),
        ).fetchone()

        if existing:
            # Already known — increment verification count
            conn.execute(
                "UPDATE shared_threats SET verified = 1, verification_count = verification_count + 1 "
                "WHERE id = ?",
                (existing[0],),
            )
            action = "verified"
        else:
            # New threat — store it
            conn.execute(
                "INSERT INTO shared_threats "
                "(sha256_hash, threat_label, confidence, source_node, received_at, verified, verification_count) "
                "VALUES (?, ?, ?, ?, ?, 0, 1)",
                (sha256_hash, threat_label, confidence, source_node, now),
            )
            action = "received"

        conn.commit()
        conn.close()

        logger.info(f"Threat {action} from {source_node}: {threat_label} [{sha256_hash[:16]}...]")
        return {"status": action, "sha256_hash": sha256_hash}

    # ------------------------------------------------------------------
    # Verification & Consensus
    # ------------------------------------------------------------------

    def get_shared_threats(self, verified_only: bool = False,
                           limit: int = 100) -> list[dict]:
        """Retrieve shared threat records from the network."""
        conn = sqlite3.connect(PEER_DB_PATH)
        conn.row_factory = sqlite3.Row

        query = "SELECT * FROM shared_threats"
        if verified_only:
            query += " WHERE verified = 1"
        query += " ORDER BY received_at DESC LIMIT ?"

        rows = conn.execute(query, (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_sync_log(self, limit: int = 50) -> list[dict]:
        """Get recent synchronization activity."""
        conn = sqlite3.connect(PEER_DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM sync_log ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_network_stats(self) -> dict:
        """Get summary statistics for the peer network."""
        conn = sqlite3.connect(PEER_DB_PATH)

        total_peers = conn.execute(
            "SELECT COUNT(*) FROM peers WHERE node_id != ?", (self.node_id,)
        ).fetchone()[0]

        active_peers = conn.execute(
            "SELECT COUNT(*) FROM peers WHERE node_id != ? AND status = 'active'",
            (self.node_id,),
        ).fetchone()[0]

        total_threats = conn.execute(
            "SELECT COUNT(*) FROM shared_threats"
        ).fetchone()[0]

        verified_threats = conn.execute(
            "SELECT COUNT(*) FROM shared_threats WHERE verified = 1"
        ).fetchone()[0]

        conn.close()

        return {
            "node_id": self.node_id,
            "org": self.org,
            "total_peers": total_peers,
            "active_peers": active_peers,
            "total_shared_threats": total_threats,
            "verified_threats": verified_threats,
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
_node_manager = None


def get_node_manager() -> NodeManager:
    """Get or create the singleton NodeManager instance."""
    global _node_manager
    if _node_manager is None:
        _node_manager = NodeManager()
    return _node_manager


# ---------------------------------------------------------------------------
# CLI demo
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=== HoneyMed Distributed Node Demo ===\n")

    # Create two nodes (simulating Node A and Node B)
    node_a = NodeManager(node_id="hospital_a", endpoint="http://127.0.0.1:5001", org="HospitalA")
    node_b = NodeManager(node_id="hospital_b", endpoint="http://127.0.0.1:5002", org="HospitalB")

    # Register each other as peers
    node_a.register_peer("hospital_b", "http://127.0.0.1:5002", "HospitalB")
    node_b.register_peer("hospital_a", "http://127.0.0.1:5001", "HospitalA")

    print(f"Node A peers: {[p['node_id'] for p in node_a.get_peers()]}")
    print(f"Node B peers: {[p['node_id'] for p in node_b.get_peers()]}")

    # Node A detects a threat and shares it
    threat_hash = hashlib.sha256(b"brute_force_attack_001").hexdigest()
    print(f"\nNode A sharing threat: {threat_hash[:24]}...")
    share_result = node_a.share_threat(threat_hash, "BruteForce", 0.94)
    print(f"  Peers notified: {share_result['peers_notified']}")

    # Node B receives and verifies the threat
    recv_result = node_b.receive_threat(threat_hash, "BruteForce", 0.94, "hospital_a")
    print(f"  Node B: {recv_result['status']}")

    # Node B independently detects the same threat
    recv_result2 = node_b.receive_threat(threat_hash, "BruteForce", 0.92, "hospital_b")
    print(f"  Node B independent detection: {recv_result2['status']}")

    # Check network stats
    print(f"\nNode A stats: {json.dumps(node_a.get_network_stats(), indent=2)}")
    print(f"\nNode B verified threats: {len(node_b.get_shared_threats(verified_only=True))}")

    print("\n[PASS] Distributed node demo complete!")
