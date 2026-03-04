"""
HoneyMed - Phase 7: Secure Communication Layer (AES-256-GCM)
==============================================================
Provides authenticated encryption-at-rest and encryption-in-transit
for all classified attack logs flowing between components.

AES-256-GCM guarantees:
  - Confidentiality (256-bit key)
  - Integrity (GCM authentication tag)
  - Healthcare compliance (HIPAA, HITECH data-in-transit requirements)

Usage:
    from security.encryption import EncryptionManager
    mgr = EncryptionManager()
    ct  = mgr.encrypt(b"attack log payload")
    pt  = mgr.decrypt(ct)
"""

import base64
import hashlib
import json
import os
import secrets
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.loader import get_config, get_base_dir
from utils.logger import get_logger

logger = get_logger("security.encryption", layer="SECURITY", log_file="security.jsonl")

# We use the cryptography library's low-level AESGCM primitive
# rather than Fernet (which is AES-CBC + HMAC) for spec compliance.
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# Key Management
# ---------------------------------------------------------------------------

_KEY_FILE = os.path.join(get_base_dir(), "data", ".honeymed_key")


def _derive_key_from_passphrase(passphrase: str) -> bytes:
    """Derive a 256-bit key from a passphrase using SHA-256 (simple KDF)."""
    return hashlib.sha256(passphrase.encode("utf-8")).digest()


def _load_or_generate_key() -> bytes:
    """
    Load the 256-bit AES key from disk, or generate & persist a new one.
    In production, this should come from a hardware HSM or vault.
    """
    cfg = get_config()
    sec_cfg = cfg.get("security", {})

    # Option 1: key in config (base64-encoded)
    if sec_cfg.get("aes_key_b64"):
        return base64.b64decode(sec_cfg["aes_key_b64"])

    # Option 2: passphrase in config
    if sec_cfg.get("passphrase"):
        return _derive_key_from_passphrase(sec_cfg["passphrase"])

    # Option 3: key file on disk
    if os.path.exists(_KEY_FILE):
        with open(_KEY_FILE, "rb") as f:
            key = f.read()
        if len(key) == 32:
            return key

    # Option 4: generate new 256-bit random key
    key = AESGCM.generate_key(bit_length=256)
    os.makedirs(os.path.dirname(_KEY_FILE), exist_ok=True)
    with open(_KEY_FILE, "wb") as f:
        f.write(key)
    logger.info("Generated new AES-256 key and stored in key file.")
    return key


# ---------------------------------------------------------------------------
# Encryption Manager
# ---------------------------------------------------------------------------

class EncryptionManager:
    """
    Provides AES-256-GCM encrypt / decrypt for the HoneyMed pipeline.

    Wire format (for each ciphertext blob):
        [12-byte nonce][ciphertext + 16-byte GCM tag]
    All returned as base64 strings for safe JSON / DB storage.
    """

    NONCE_SIZE = 12  # 96 bits — recommended for GCM

    def __init__(self, key: bytes | None = None):
        if key is None:
            key = _load_or_generate_key()
        if len(key) != 32:
            raise ValueError(f"AES-256 requires a 32-byte key, got {len(key)}")
        self._aesgcm = AESGCM(key)
        self._key_fingerprint = hashlib.sha256(key).hexdigest()[:16]
        logger.info(f"EncryptionManager initialized (key fingerprint: {self._key_fingerprint})")

    # ------ Low-level ------

    def encrypt_bytes(self, plaintext: bytes, aad: bytes | None = None) -> bytes:
        """
        Encrypt raw bytes.  Returns  nonce || ciphertext || tag  (all raw bytes).
        Optional AAD provides additional authenticated data.
        """
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        ct = self._aesgcm.encrypt(nonce, plaintext, aad)
        return nonce + ct  # ct already includes the 16-byte tag

    def decrypt_bytes(self, blob: bytes, aad: bytes | None = None) -> bytes:
        """Decrypt raw bytes produced by encrypt_bytes."""
        nonce = blob[:self.NONCE_SIZE]
        ct = blob[self.NONCE_SIZE:]
        return self._aesgcm.decrypt(nonce, ct, aad)

    # ------ String / JSON helpers ------

    def encrypt(self, data: str | bytes | dict) -> str:
        """
        Encrypt data and return a base64 string suitable for JSON/DB storage.

        Accepts str, bytes, or dict (auto-serialized to JSON).
        """
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True).encode("utf-8")
        elif isinstance(data, str):
            data = data.encode("utf-8")
        raw = self.encrypt_bytes(data)
        return base64.b64encode(raw).decode("ascii")

    def decrypt(self, b64_ciphertext: str) -> bytes:
        """Decrypt a base64-encoded ciphertext back to plaintext bytes."""
        raw = base64.b64decode(b64_ciphertext)
        return self.decrypt_bytes(raw)

    def decrypt_to_str(self, b64_ciphertext: str) -> str:
        """Decrypt and decode as UTF-8 string."""
        return self.decrypt(b64_ciphertext).decode("utf-8")

    def decrypt_to_dict(self, b64_ciphertext: str) -> dict:
        """Decrypt and parse as JSON dict."""
        return json.loads(self.decrypt_to_str(b64_ciphertext))

    # ------ Event-level helpers (pipeline integration) ------

    def encrypt_event(self, event: dict) -> dict:
        """
        Encrypt a classified attack event for secure storage/transmission.

        Returns a wrapper dict with:
          - encrypted_payload (base64 ciphertext)
          - sha256_hash (of plaintext, for blockchain verification)
          - metadata (unencrypted — needed for indexing)
        """
        plaintext = json.dumps(event, sort_keys=True)
        sha256 = hashlib.sha256(plaintext.encode()).hexdigest()
        ciphertext = self.encrypt(plaintext)

        return {
            "encrypted_payload": ciphertext,
            "sha256_hash": sha256,
            "key_fingerprint": self._key_fingerprint,
            "encryption_algo": "AES-256-GCM",
            "encrypted_at": datetime.now(timezone.utc).isoformat(),
            # Unencrypted metadata for DB indexing / search
            "meta_timestamp": event.get("timestamp", ""),
            "meta_attacker_ip": event.get("attacker_ip", ""),
            "meta_label": event.get("prediction", {}).get("label", "")
                          if isinstance(event.get("prediction"), dict)
                          else event.get("label", ""),
        }

    def decrypt_event(self, encrypted_event: dict) -> dict:
        """Decrypt an event previously encrypted with encrypt_event."""
        return self.decrypt_to_dict(encrypted_event["encrypted_payload"])

    @property
    def key_fingerprint(self) -> str:
        return self._key_fingerprint


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------
_instance: EncryptionManager | None = None


def get_encryption_manager() -> EncryptionManager:
    """Return a module-level singleton EncryptionManager."""
    global _instance
    if _instance is None:
        _instance = EncryptionManager()
    return _instance


# ---------------------------------------------------------------------------
# CLI self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=== AES-256-GCM Self-Test ===")
    mgr = EncryptionManager()

    # Test 1: round-trip string
    original = "Sensitive attack log: brute-force from 10.0.0.5"
    ct = mgr.encrypt(original)
    pt = mgr.decrypt_to_str(ct)
    assert pt == original, "String round-trip failed!"
    print(f"[PASS] String encryption  (ciphertext length: {len(ct)} chars)")

    # Test 2: round-trip dict
    event = {"attacker_ip": "10.0.0.5", "label": "BruteForce", "confidence": 0.93}
    ct2 = mgr.encrypt(event)
    pt2 = mgr.decrypt_to_dict(ct2)
    assert pt2 == event, "Dict round-trip failed!"
    print(f"[PASS] Dict encryption    (ciphertext length: {len(ct2)} chars)")

    # Test 3: encrypt_event wrapper
    full_event = {
        "timestamp": "2026-01-15T10:30:00+00:00",
        "attacker_ip": "192.168.1.50",
        "service": "web_portal",
        "event_type": "LOGIN_ATTEMPT",
        "prediction": {"label": "BruteForce", "confidence": 0.95},
    }
    enc = mgr.encrypt_event(full_event)
    dec = mgr.decrypt_event(enc)
    assert dec == full_event, "Event round-trip failed!"
    print(f"[PASS] Event encryption   (algo: {enc['encryption_algo']})")

    print(f"\nKey fingerprint: {mgr.key_fingerprint}")
    print("All tests passed!")
