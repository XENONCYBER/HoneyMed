"""
HoneyMed - Phase 10: Distributed Consensus Engine
====================================================
Implements cross-node verification of threat intelligence.

When multiple nodes independently detect the same threat hash,
the consensus engine:
  1. Tallies verification counts across the network
  2. Computes a consensus score (% of nodes that verified)
  3. Elevates high-consensus threats to "confirmed" status
  4. Maintains verification proofs for blockchain audit

In a real Hyperledger Fabric deployment, this logic would be part
of the ordering service and endorsement policy. Here we implement
the equivalent logic in Python for dev/test.
"""

import hashlib
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.loader import get_config, get_base_dir
from utils.logger import get_logger

logger = get_logger("distributed.consensus", layer="DISTRIBUTED", log_file="distributed_consensus.jsonl")

PEER_DB_PATH = os.path.join(get_base_dir(), "data", "peer_network.db")


class ConsensusEngine:
    """
    Verifies threat intelligence across multiple nodes using a
    simple majority-based consensus mechanism.
    """

    def __init__(self, min_verifications: int = 2, consensus_threshold: float = 0.5):
        """
        Args:
            min_verifications:   Minimum number of independent verifications needed.
            consensus_threshold: Fraction of active peers that must verify (0..1).
        """
        cfg = get_config()
        cons_cfg = cfg.get("distributed", {}).get("consensus", {})

        self.min_verifications = cons_cfg.get("min_verifications", min_verifications)
        self.consensus_threshold = cons_cfg.get("threshold", consensus_threshold)

        logger.info(
            f"ConsensusEngine: min_verifications={self.min_verifications}, "
            f"threshold={self.consensus_threshold}"
        )

    def check_consensus(self, sha256_hash: str) -> dict:
        """
        Check whether a specific threat has reached consensus.

        Returns:
            dict with consensus status, verification count, and score.
        """
        conn = sqlite3.connect(PEER_DB_PATH)

        # Count verifications for this hash
        row = conn.execute(
            "SELECT verification_count, verified, threat_label, confidence "
            "FROM shared_threats WHERE sha256_hash = ?",
            (sha256_hash,),
        ).fetchone()

        if not row:
            conn.close()
            return {
                "sha256_hash": sha256_hash,
                "status": "unknown",
                "verification_count": 0,
                "consensus_score": 0.0,
                "reached_consensus": False,
            }

        verification_count = row[0]
        threat_label = row[2]
        confidence = row[3]

        # Count active peers (including self)
        total_nodes = conn.execute(
            "SELECT COUNT(*) FROM peers WHERE status = 'active'"
        ).fetchone()[0]
        conn.close()

        # Compute consensus score
        consensus_score = verification_count / max(total_nodes, 1)
        reached = (
            verification_count >= self.min_verifications
            and consensus_score >= self.consensus_threshold
        )

        return {
            "sha256_hash": sha256_hash,
            "threat_label": threat_label,
            "confidence": confidence,
            "status": "confirmed" if reached else "pending",
            "verification_count": verification_count,
            "total_nodes": total_nodes,
            "consensus_score": round(consensus_score, 3),
            "reached_consensus": reached,
        }

    def get_confirmed_threats(self, limit: int = 100) -> list[dict]:
        """
        Return all threats that have reached distributed consensus.
        """
        conn = sqlite3.connect(PEER_DB_PATH)
        conn.row_factory = sqlite3.Row

        rows = conn.execute(
            "SELECT sha256_hash, threat_label, confidence, verification_count, source_node, received_at "
            "FROM shared_threats WHERE verified = 1 AND verification_count >= ? "
            "ORDER BY received_at DESC LIMIT ?",
            (self.min_verifications, limit),
        ).fetchall()
        conn.close()

        results = []
        for row in rows:
            record = dict(row)
            # Re-check actual consensus score
            status = self.check_consensus(record["sha256_hash"])
            if status["reached_consensus"]:
                record["consensus_score"] = status["consensus_score"]
                record["status"] = "confirmed"
                results.append(record)

        return results

    def submit_verification(self, sha256_hash: str, verifying_node: str,
                            computed_hash: str) -> dict:
        """
        A remote node submits its independent verification of a threat.

        The verifying node re-computed the hash from its own observations
        and submits it here. If it matches, the verification count increments.

        Args:
            sha256_hash:   The original hash from the source node.
            verifying_node: ID of the node that is verifying.
            computed_hash:  Hash as computed by the verifying node.

        Returns:
            Verification result dict.
        """
        if sha256_hash != computed_hash:
            logger.warning(
                f"Hash mismatch from {verifying_node}: "
                f"expected {sha256_hash[:16]}... got {computed_hash[:16]}..."
            )
            return {
                "status": "mismatch",
                "sha256_hash": sha256_hash,
                "verifying_node": verifying_node,
            }

        conn = sqlite3.connect(PEER_DB_PATH)
        existing = conn.execute(
            "SELECT id, verification_count FROM shared_threats WHERE sha256_hash = ?",
            (sha256_hash,),
        ).fetchone()

        if existing:
            conn.execute(
                "UPDATE shared_threats SET verified = 1, verification_count = verification_count + 1 "
                "WHERE id = ?",
                (existing[0],),
            )
            conn.commit()
            new_count = existing[1] + 1
        else:
            conn.close()
            return {"status": "not_found", "sha256_hash": sha256_hash}

        conn.close()

        # Check if consensus just reached
        consensus = self.check_consensus(sha256_hash)

        logger.info(
            f"Verification from {verifying_node}: hash={sha256_hash[:16]}... "
            f"count={new_count}, consensus={consensus['reached_consensus']}"
        )

        return {
            "status": "verified",
            "sha256_hash": sha256_hash,
            "verifying_node": verifying_node,
            "verification_count": new_count,
            "reached_consensus": consensus["reached_consensus"],
            "consensus_score": consensus["consensus_score"],
        }

    def get_consensus_summary(self) -> dict:
        """
        Get an overall summary of consensus status across all shared threats.
        """
        conn = sqlite3.connect(PEER_DB_PATH)

        total = conn.execute("SELECT COUNT(*) FROM shared_threats").fetchone()[0]
        verified = conn.execute(
            "SELECT COUNT(*) FROM shared_threats WHERE verified = 1"
        ).fetchone()[0]
        high_consensus = conn.execute(
            "SELECT COUNT(*) FROM shared_threats WHERE verification_count >= ?",
            (self.min_verifications,),
        ).fetchone()[0]

        active_nodes = conn.execute(
            "SELECT COUNT(*) FROM peers WHERE status = 'active'"
        ).fetchone()[0]

        conn.close()

        return {
            "total_shared_threats": total,
            "verified_threats": verified,
            "high_consensus_threats": high_consensus,
            "active_nodes": active_nodes,
            "min_verifications": self.min_verifications,
            "consensus_threshold": self.consensus_threshold,
        }


# ---------------------------------------------------------------------------
# CLI demo
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=== HoneyMed Consensus Engine Demo ===\n")

    engine = ConsensusEngine(min_verifications=2, consensus_threshold=0.5)

    # Create a test hash
    test_hash = hashlib.sha256(b"test_threat_event").hexdigest()

    # Simulate: threat not yet known
    status = engine.check_consensus(test_hash)
    print(f"Before share: {status['status']} (count={status['verification_count']})")

    # Simulate: Node A shares threat
    conn = sqlite3.connect(PEER_DB_PATH)
    conn.execute(
        "INSERT OR IGNORE INTO shared_threats "
        "(sha256_hash, threat_label, confidence, source_node, received_at, verified, verification_count) "
        "VALUES (?, ?, ?, ?, ?, 0, 1)",
        (test_hash, "DoS", 0.88, "hospital_a", datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()

    status = engine.check_consensus(test_hash)
    print(f"After 1 node: {status['status']} (count={status['verification_count']}, score={status['consensus_score']})")

    # Simulate: Node B verifies
    result = engine.submit_verification(test_hash, "hospital_b", test_hash)
    print(f"After verification: {result['status']} (count={result['verification_count']}, consensus={result['reached_consensus']})")

    # Summary
    print(f"\nSummary: {json.dumps(engine.get_consensus_summary(), indent=2)}")

    print("\n[PASS] Consensus engine demo complete!")
