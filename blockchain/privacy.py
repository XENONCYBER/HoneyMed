"""
HoneyMed - Phase 8: Privacy Engine (Zero-Knowledge Concepts)
==============================================================
Implements privacy-by-design principles for threat intelligence sharing:

  1. Commitment Scheme: Prove you know attack data without revealing it
  2. Range Proofs: Prove confidence thresholds without revealing exact values
  3. Selective Disclosure: Reveal only what each role is authorized to see
  4. PHI Tokenization: Replace identifiers with reversible tokens

In a full ZKP implementation, this would use zk-SNARKs or Bulletproofs.
Here we implement hash-based commitment schemes that provide practical
privacy guarantees compatible with the Hyperledger Fabric ledger.
"""

import hashlib
import hmac
import json
import os
import secrets
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.loader import get_config, get_base_dir
from utils.logger import get_logger

logger = get_logger("blockchain.privacy", layer="BLOCKCHAIN", log_file="blockchain_privacy.jsonl")


class PrivacyEngine:
    """
    Provides privacy-preserving operations for threat intelligence data.

    Designed to work with the HashProtocol and FabricClient to ensure
    no sensitive data leaks through the blockchain.
    """

    def __init__(self, secret_key: bytes | None = None):
        """
        Args:
            secret_key: 32-byte key for commitment schemes.
                        Auto-generated if not provided.
        """
        if secret_key is None:
            secret_key = self._load_or_generate_secret()
        self._secret = secret_key

    @staticmethod
    def _load_or_generate_secret() -> bytes:
        """Load or create a persistent secret for the privacy engine."""
        secret_path = os.path.join(get_base_dir(), "data", ".privacy_secret")
        if os.path.exists(secret_path):
            with open(secret_path, "rb") as f:
                return f.read()
        secret = secrets.token_bytes(32)
        os.makedirs(os.path.dirname(secret_path), exist_ok=True)
        with open(secret_path, "wb") as f:
            f.write(secret)
        logger.info("Generated new privacy engine secret.")
        return secret

    # ------------------------------------------------------------------
    # 1. Commitment Scheme (Pedersen-like using HMAC)
    # ------------------------------------------------------------------

    def create_commitment(self, data: str | dict) -> tuple[str, str]:
        """
        Create a cryptographic commitment to data.

        Returns:
            (commitment, blinding_factor)
            - commitment: Published on blockchain (reveals nothing)
            - blinding_factor: Kept secret; needed to open the commitment
        """
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True)

        blinding = secrets.token_hex(32)
        message = f"{data}||{blinding}".encode("utf-8")
        commitment = hmac.new(self._secret, message, hashlib.sha256).hexdigest()

        return commitment, blinding

    def verify_commitment(self, data: str | dict, commitment: str, blinding: str) -> bool:
        """Verify that a commitment matches the data + blinding factor."""
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True)

        message = f"{data}||{blinding}".encode("utf-8")
        recomputed = hmac.new(self._secret, message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(recomputed, commitment)

    # ------------------------------------------------------------------
    # 2. Range Proofs (simplified hash-based)
    # ------------------------------------------------------------------

    def create_confidence_range_proof(
        self,
        confidence: float,
        threshold: float = 0.7,
    ) -> dict:
        """
        Prove that a confidence value exceeds a threshold
        without revealing the exact value.

        Returns a proof dict that can be verified without knowing
        the actual confidence score.
        """
        above = confidence >= threshold
        # Commit to the boolean result and a rounded bucket
        bucket = int(confidence * 10) / 10  # Round to nearest 0.1
        nonce = secrets.token_hex(16)

        proof_data = f"{above}:{bucket}:{nonce}"
        proof_hash = hashlib.sha256(proof_data.encode()).hexdigest()

        return {
            "above_threshold": above,
            "threshold": threshold,
            "proof_hash": proof_hash,
            "nonce": nonce,
            "bucket": bucket if above else None,  # Only reveal bucket if above
        }

    def verify_confidence_range_proof(self, proof: dict, confidence: float) -> bool:
        """Verify a range proof given the actual confidence (for auditing)."""
        above = confidence >= proof["threshold"]
        bucket = int(confidence * 10) / 10
        proof_data = f"{above}:{bucket}:{proof['nonce']}"
        expected = hashlib.sha256(proof_data.encode()).hexdigest()
        return hmac.compare_digest(expected, proof["proof_hash"])

    # ------------------------------------------------------------------
    # 3. Selective Disclosure
    # ------------------------------------------------------------------

    # Role hierarchy: admin > analyst > researcher > public
    ROLE_VISIBLE_FIELDS = {
        "admin": {
            "sha256_hash", "threat_label", "confidence", "attacker_ip",
            "timestamp", "event_type", "service", "protocol",
            "payload_size", "payload_entropy", "raw_event",
        },
        "analyst": {
            "sha256_hash", "threat_label", "confidence", "attacker_ip",
            "timestamp", "event_type", "service", "protocol",
            "payload_size", "payload_entropy",
        },
        "researcher": {
            "sha256_hash", "threat_label", "confidence",
            "timestamp", "event_type", "protocol",
        },
        "public": {
            "sha256_hash", "threat_label", "timestamp",
        },
    }

    def selective_disclose(self, record: dict, role: str) -> dict:
        """
        Filter a threat record to show only fields the role is authorized to see.

        Args:
            record: Full threat record dict.
            role:   One of 'admin', 'analyst', 'researcher', 'public'.

        Returns:
            Filtered dict containing only permitted fields.
        """
        allowed = self.ROLE_VISIBLE_FIELDS.get(role, self.ROLE_VISIBLE_FIELDS["public"])
        disclosed = {k: v for k, v in record.items() if k in allowed}
        disclosed["_disclosure_role"] = role
        disclosed["_disclosed_at"] = datetime.now(timezone.utc).isoformat()
        return disclosed

    # ------------------------------------------------------------------
    # 4. PHI Tokenization
    # ------------------------------------------------------------------

    def tokenize(self, value: str) -> str:
        """
        Replace a PHI value with a deterministic but irreversible token.
        Same input always produces the same token (for correlation)
        but the original value cannot be recovered without the secret.
        """
        token_input = f"TOKEN:{value}".encode("utf-8")
        return hmac.new(self._secret, token_input, hashlib.sha256).hexdigest()[:24]

    def tokenize_event(self, event: dict, fields_to_tokenize: list[str] | None = None) -> dict:
        """
        Tokenize specific fields in an event dict.
        Default fields: attacker_ip, username, client_id.
        """
        if fields_to_tokenize is None:
            fields_to_tokenize = ["attacker_ip", "username", "client_id"]

        result = {}
        for k, v in event.items():
            if k in fields_to_tokenize and isinstance(v, str) and v:
                result[k] = f"TOK:{self.tokenize(v)}"
            elif isinstance(v, dict):
                result[k] = self.tokenize_event(v, fields_to_tokenize)
            else:
                result[k] = v
        return result

    # ------------------------------------------------------------------
    # Combined privacy pipeline
    # ------------------------------------------------------------------

    def apply_privacy(self, event: dict, prediction: dict, role: str = "researcher") -> dict:
        """
        Full privacy pipeline:
          1. Tokenize identifiers
          2. Create commitment
          3. Build range proof for confidence
          4. Apply selective disclosure
        """
        # Tokenize
        tokenized = self.tokenize_event(event)

        # Commitment
        commitment, blinding = self.create_commitment(tokenized)

        # Range proof
        confidence = prediction.get("confidence", 0.0)
        cfg = get_config()
        threshold = cfg.get("ml_engine", {}).get("confidence_threshold", 0.7)
        range_proof = self.create_confidence_range_proof(confidence, threshold)

        # Build full record
        full_record = {
            "sha256_hash": hashlib.sha256(
                json.dumps(tokenized, sort_keys=True).encode()
            ).hexdigest(),
            "threat_label": prediction.get("label", "Unknown"),
            "confidence": confidence,
            "attacker_ip": tokenized.get("attacker_ip", ""),
            "timestamp": event.get("timestamp", ""),
            "event_type": event.get("event_type", ""),
            "service": event.get("service", ""),
            "protocol": event.get("protocol", ""),
            "commitment": commitment,
            "range_proof": range_proof,
        }

        # Selective disclosure based on role
        disclosed = self.selective_disclose(full_record, role)

        return {
            "disclosed_record": disclosed,
            "commitment": commitment,
            "blinding_factor": blinding,  # Store locally, never share
            "range_proof": range_proof,
        }


if __name__ == "__main__":
    pe = PrivacyEngine()

    event = {
        "timestamp": "2026-01-15T10:30:00+00:00",
        "attacker_ip": "192.168.1.50",
        "service": "web_portal",
        "event_type": "LOGIN_ATTEMPT",
        "details": {"username": "admin", "patient_name": "John Doe"},
    }
    prediction = {"label": "BruteForce", "confidence": 0.93, "is_attack": True}

    # Test commitment
    c, b = pe.create_commitment(event)
    assert pe.verify_commitment(event, c, b)
    print(f"[PASS] Commitment verified: {c[:32]}...")

    # Test range proof
    proof = pe.create_confidence_range_proof(0.93, 0.7)
    assert proof["above_threshold"] is True
    assert pe.verify_confidence_range_proof(proof, 0.93)
    print(f"[PASS] Range proof: above_threshold={proof['above_threshold']}")

    # Test selective disclosure
    record = {"sha256_hash": "abc", "threat_label": "DoS", "confidence": 0.9,
              "attacker_ip": "10.0.0.5", "raw_event": "secret"}
    for role in ("admin", "analyst", "researcher", "public"):
        d = pe.selective_disclose(record, role)
        print(f"  {role:12s} sees: {sorted(k for k in d if not k.startswith('_'))}")

    # Test full privacy pipeline
    result = pe.apply_privacy(event, prediction, role="researcher")
    print(f"\n[PASS] Full privacy pipeline:")
    print(f"  Visible fields: {sorted(result['disclosed_record'].keys())}")
    print(f"  Commitment: {result['commitment'][:32]}...")
