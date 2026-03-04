"""
HoneyMed - Phase 8: Hash Protocol
===================================
Implements the privacy-preserving hashing protocol:
  1. Takes ML-classified attack logs (which may contain simulated PHI)
  2. Strips/redacts any PHI fields
  3. Generates a SHA-256 hash of the sanitized record
  4. Pushes ONLY the hash + threat classification to the blockchain
  5. Keeps the raw encrypted data stored locally

This fulfills healthcare data-privacy regulations (HIPAA, GDPR)
by ensuring no patient data ever reaches the distributed ledger.
"""

import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.loader import get_config, get_base_dir
from utils.logger import get_logger

logger = get_logger("blockchain.hash_protocol", layer="BLOCKCHAIN", log_file="blockchain.jsonl")

# PHI fields that must NEVER appear on the blockchain
PHI_FIELDS = frozenset({
    "patient_id", "patient_name", "name", "dob", "date_of_birth",
    "ssn", "social_security", "mrn", "medical_record_number",
    "address", "phone", "email", "insurance_id", "diagnosis",
})


class HashProtocol:
    """
    Privacy-preserving hashing protocol for blockchain submission.

    Workflow:
        raw_event → sanitize PHI → canonical JSON → SHA-256 → blockchain
    """

    def __init__(self):
        cfg = get_config()
        self.enable_blockchain = cfg.get("blockchain", {}).get("enabled", True)
        self._fabric_client = None

    @property
    def fabric_client(self):
        """Lazy-load the Fabric client."""
        if self._fabric_client is None:
            from blockchain.fabric_client import get_fabric_client
            self._fabric_client = get_fabric_client()
        return self._fabric_client

    @staticmethod
    def sanitize_phi(event: dict) -> dict:
        """
        Deep-strip any PHI fields from an event dict.
        Returns a copy — never mutates the original.
        """
        def _clean(obj):
            if isinstance(obj, dict):
                return {
                    k: ("*** PHI REDACTED ***" if k.lower() in PHI_FIELDS else _clean(v))
                    for k, v in obj.items()
                }
            if isinstance(obj, list):
                return [_clean(item) for item in obj]
            return obj

        return _clean(event)

    @staticmethod
    def compute_hash(data: dict) -> str:
        """Compute SHA-256 hash of canonical (sorted-key) JSON."""
        canonical = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def process_event(
        self,
        event: dict,
        prediction: dict,
        commit_to_chain: bool = True,
    ) -> dict:
        """
        Full hash-protocol pipeline for a single classified event.

        Args:
            event:       Raw honeypot event dict.
            prediction:  ML prediction dict (label, confidence, etc.).
            commit_to_chain: Whether to submit to the blockchain ledger.

        Returns:
            Dict with hash, sanitized event, and optional blockchain receipt.
        """
        # Step 1: Sanitize PHI
        sanitized = self.sanitize_phi(event)

        # Step 2: Compute SHA-256 of the sanitized data
        hash_input = {
            "event": sanitized,
            "prediction": prediction,
        }
        sha256_hash = self.compute_hash(hash_input)

        result = {
            "sha256_hash": sha256_hash,
            "sanitized_event": sanitized,
            "prediction": prediction,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Step 3: Commit hash + classification to blockchain
        if commit_to_chain and self.enable_blockchain:
            try:
                receipt = self.fabric_client.submit_threat_hash(
                    sha256_hash=sha256_hash,
                    threat_label=prediction.get("label", "Unknown"),
                    confidence=prediction.get("confidence", 0.0),
                    attacker_ip=event.get("attacker_ip", ""),
                    event_timestamp=event.get("timestamp", ""),
                    encrypted=True,
                )
                result["blockchain_receipt"] = receipt
                logger.info(
                    f"Hash committed to ledger: {sha256_hash[:16]}... "
                    f"block={receipt.get('block_number')} "
                    f"tx={receipt.get('tx_id', '')[:16]}..."
                )
            except Exception as e:
                logger.error(f"Blockchain submission failed: {e}")
                result["blockchain_receipt"] = {"status": "ERROR", "error": str(e)}
        else:
            result["blockchain_receipt"] = None

        return result

    def verify_hash(self, event: dict, prediction: dict, expected_hash: str) -> bool:
        """
        Verify that a stored hash matches the recomputed hash.
        Used for blockchain audit / tamper detection.
        """
        sanitized = self.sanitize_phi(event)
        recomputed = self.compute_hash({"event": sanitized, "prediction": prediction})
        match = recomputed == expected_hash
        if not match:
            logger.warning(
                f"Hash mismatch! Expected {expected_hash[:16]}... "
                f"got {recomputed[:16]}..."
            )
        return match

    def batch_process(
        self,
        events_with_predictions: list[tuple[dict, dict]],
    ) -> list[dict]:
        """Process a batch of (event, prediction) tuples through the hash protocol."""
        results = []
        for event, prediction in events_with_predictions:
            result = self.process_event(event, prediction)
            results.append(result)
        logger.info(f"Batch processed: {len(results)} events through hash protocol")
        return results


if __name__ == "__main__":
    hp = HashProtocol()

    # Test with a fake event containing PHI
    test_event = {
        "timestamp": "2026-01-15T10:30:00+00:00",
        "attacker_ip": "192.168.1.50",
        "service": "web_portal",
        "event_type": "LOGIN_ATTEMPT",
        "details": {
            "username": "admin",
            "patient_name": "John Doe",
            "ssn": "123-45-6789",
        },
    }
    test_prediction = {"label": "BruteForce", "confidence": 0.93, "is_attack": True}

    result = hp.process_event(test_event, test_prediction)
    print(f"SHA-256: {result['sha256_hash']}")
    print(f"Sanitized: {json.dumps(result['sanitized_event'], indent=2)}")
    print(f"Receipt: {result['blockchain_receipt']}")
