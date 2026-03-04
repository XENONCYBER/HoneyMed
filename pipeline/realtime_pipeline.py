"""
HoneyMed - Layer 2: Real-Time Pipeline
========================================
The "glue" script that continuously:
  1. Captures live events from honeypot services
  2. Extracts features every N seconds
  3. Passes features to the ML model for classification
  4. Generates SHA-256 hashes for blockchain readiness
  5. Stores classified events in a local database (SQLite)

This is the central nervous system of the entire framework.
"""

import hashlib
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.loader import get_config, get_base_dir
from utils.logger import get_logger
from pipeline.feature_extractor import extract_features_from_event
from ml_engine.predictor import AttackPredictor

logger = get_logger("pipeline.realtime", layer="PIPELINE", log_file="pipeline_realtime.jsonl")

# Phase 7: Optional encryption for classified events
_encryption_mgr = None

def _get_encryption_manager():
    """Lazy-load the encryption manager (only if security is enabled in config)."""
    global _encryption_mgr
    if _encryption_mgr is not None:
        return _encryption_mgr
    cfg = get_config()
    if cfg.get("security", {}).get("enable_encryption", False):
        try:
            from security.encryption import get_encryption_manager
            _encryption_mgr = get_encryption_manager()
            logger.info("AES-256-GCM encryption enabled for pipeline events.")
        except ImportError:
            logger.warning("cryptography package not installed — encryption disabled.")
            _encryption_mgr = False  # sentinel: tried and failed
    else:
        _encryption_mgr = False
    return _encryption_mgr if _encryption_mgr else None

# ---------------------------------------------------------------------------
# SQLite Database for classified events
# ---------------------------------------------------------------------------
DB_PATH = os.path.join(get_base_dir(), "data", "classified_events.db")


def init_database():
    """Initialize the SQLite database for storing classified events."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS classified_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            attacker_ip TEXT,
            attacker_port INTEGER,
            service TEXT,
            event_type TEXT,
            protocol TEXT,
            prediction INTEGER,
            label TEXT,
            confidence REAL,
            is_attack INTEGER,
            payload_size INTEGER,
            payload_entropy REAL,
            sha256_hash TEXT,
            encrypted_payload TEXT,
            raw_event TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_summary (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            window_start TEXT,
            window_end TEXT,
            total_events INTEGER,
            benign_count INTEGER,
            dos_count INTEGER,
            portscan_count INTEGER,
            bruteforce_count INTEGER,
            recon_count INTEGER,
            unique_attackers INTEGER,
            sha256_hash TEXT
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_timestamp ON classified_events(timestamp)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_attacker_ip ON classified_events(attacker_ip)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_prediction ON classified_events(prediction)
    """)

    conn.commit()
    conn.close()
    logger.info(f"Database initialized: {DB_PATH}")


def store_classified_event(event: dict, prediction: dict, features: dict, sha256: str):
    """Store a single classified event in the database (optionally encrypted)."""
    enc_mgr = _get_encryption_manager()
    encrypted_payload = ""
    raw_event_json = json.dumps(event)

    if enc_mgr:
        try:
            encrypted_payload = enc_mgr.encrypt(raw_event_json)
        except Exception as e:
            logger.warning(f"Encryption failed, storing plaintext: {e}")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO classified_events
        (timestamp, attacker_ip, attacker_port, service, event_type, protocol,
         prediction, label, confidence, is_attack, payload_size, payload_entropy,
         sha256_hash, encrypted_payload, raw_event)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.get("timestamp", ""),
        event.get("attacker_ip", ""),
        event.get("attacker_port", 0),
        event.get("service", ""),
        event.get("event_type", ""),
        event.get("protocol", ""),
        prediction["prediction"],
        prediction["label"],
        prediction["confidence"],
        int(prediction["is_attack"]),
        features.get("payload_size", 0),
        features.get("payload_entropy", 0.0),
        sha256,
        encrypted_payload,
        raw_event_json,
    ))

    conn.commit()
    conn.close()


def store_window_summary(window_start: str, window_end: str, events: list[dict]):
    """Store a summary of a processing window."""
    label_counts = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
    unique_ips = set()

    for evt in events:
        pred = evt.get("prediction", {}).get("prediction", 0)
        label_counts[pred] = label_counts.get(pred, 0) + 1
        unique_ips.add(evt.get("attacker_ip", ""))

    # Hash the summary
    summary_data = json.dumps({
        "window_start": window_start,
        "window_end": window_end,
        "counts": label_counts,
    }, sort_keys=True)
    sha256 = hashlib.sha256(summary_data.encode()).hexdigest()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO attack_summary
        (window_start, window_end, total_events, benign_count, dos_count,
         portscan_count, bruteforce_count, recon_count, unique_attackers, sha256_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        window_start, window_end, len(events),
        label_counts[0], label_counts[1], label_counts[2],
        label_counts[3], label_counts[4],
        len(unique_ips), sha256,
    ))
    conn.commit()
    conn.close()

    return sha256


# ---------------------------------------------------------------------------
# Real-Time Processing Loop
# ---------------------------------------------------------------------------

class RealTimePipeline:
    """
    Continuously polls honeypot events, extracts features,
    classifies them, and stores results.
    """

    def __init__(self, honeypot_url: str | None = None):
        if honeypot_url is None:
            honeypot_url = os.environ.get("HONEYPOT_URL", "http://127.0.0.1:80")
        self.honeypot_url = honeypot_url
        self.predictor = AttackPredictor()
        self.cfg = get_config()
        self.interval = self.cfg["pipeline"]["flow_interval_seconds"]
        self.last_event_count = 0
        self.total_processed = 0
        self.total_attacks = 0

        # Lazy-loaded integration modules (Phase 8 / Phase 11)
        self._hash_protocol = None
        self._auto_responder = None

        init_database()

    def _get_hash_protocol(self):
        """Lazy-load the blockchain hash protocol (Phase 8)."""
        if self._hash_protocol is not None:
            return self._hash_protocol if self._hash_protocol else None
        if self.cfg.get("blockchain", {}).get("mode"):
            try:
                from blockchain.hash_protocol import HashProtocol
                self._hash_protocol = HashProtocol()
                logger.info("Blockchain hash protocol enabled.")
            except ImportError:
                self._hash_protocol = False
        else:
            self._hash_protocol = False
        return self._hash_protocol if self._hash_protocol else None

    def _get_auto_responder(self):
        """Lazy-load the auto-response engine (Phase 11)."""
        if self._auto_responder is not None:
            return self._auto_responder if self._auto_responder else None
        if self.cfg.get("siem", {}).get("auto_response", {}).get("mode"):
            try:
                from siem.auto_response import AutoResponse
                self._auto_responder = AutoResponse()
                logger.info("Auto-response engine enabled.")
            except ImportError:
                self._auto_responder = False
        else:
            self._auto_responder = False
        return self._auto_responder if self._auto_responder else None

    def _submit_to_blockchain(self, event: dict, prediction: dict, sha256: str):
        """Submit classified event hash to blockchain (Phase 8)."""
        hp = self._get_hash_protocol()
        if hp and prediction.get("is_attack"):
            try:
                hp.process_event(event, prediction["label"], prediction["confidence"])
            except Exception as e:
                logger.warning(f"Blockchain submission failed: {e}")

    def _evaluate_auto_response(self, event: dict, prediction: dict):
        """Evaluate threat for automated IP blocking (Phase 11)."""
        ar = self._get_auto_responder()
        if ar:
            try:
                result = ar.evaluate_threat(event, prediction)
                if result and result.get("status") == "blocked":
                    logger.warning(f"Auto-blocked IP: {event.get('attacker_ip')}")
            except Exception as e:
                logger.warning(f"Auto-response evaluation failed: {e}")

    def _fetch_new_events(self) -> list[dict]:
        """Fetch new events from the honeypot's internal API."""
        try:
            resp = requests.get(f"{self.honeypot_url}/internal/events", timeout=3)
            if resp.status_code == 200:
                all_events = resp.json()
                new_events = all_events[self.last_event_count:]
                self.last_event_count = len(all_events)
                return new_events
        except requests.exceptions.ConnectionError:
            pass  # Honeypot not running
        except Exception as e:
            logger.error(f"Error fetching events: {e}")
        return []

    def _process_event(self, event: dict) -> dict:
        """Process a single event through the full pipeline."""
        # Step 1: Extract features
        features = extract_features_from_event(event)

        # Step 2: ML Classification
        prediction = self.predictor.predict(features)

        # Step 3: Generate SHA-256 hash (blockchain readiness)
        event_json = json.dumps(event, sort_keys=True)
        sha256 = hashlib.sha256(event_json.encode()).hexdigest()

        # Step 4: Sanitize PHI (strip any mock patient data)
        sanitized_event = {k: v for k, v in event.items()}
        details = sanitized_event.get("details", {})
        for phi_field in ["patient_id", "patient_name", "dob", "ssn"]:
            if phi_field in details:
                details[phi_field] = "*** PHI REDACTED ***"

        # Step 5: Store in database
        store_classified_event(event, prediction, features, sha256)

        # Step 6 (Phase 8): Submit hash to blockchain if enabled
        self._submit_to_blockchain(event, prediction, sha256)

        # Step 7 (Phase 11): Evaluate for auto-response (IP blocking)
        self._evaluate_auto_response(event, prediction)

        return {
            "event": sanitized_event,
            "features": features,
            "prediction": prediction,
            "sha256": sha256,
        }

    def process_window(self) -> list[dict]:
        """Process all new events in the current time window."""
        new_events = self._fetch_new_events()
        if not new_events:
            return []

        processed = []
        window_start = datetime.now(timezone.utc).isoformat()

        for event in new_events:
            result = self._process_event(event)
            processed.append(result)

            self.total_processed += 1
            if result["prediction"]["is_attack"]:
                self.total_attacks += 1

                # Alert for high-confidence attacks
                if result["prediction"]["above_threshold"]:
                    logger.warning(
                        f"⚠ ATTACK: {result['prediction']['label']} "
                        f"from {event.get('attacker_ip', '?')} "
                        f"(confidence: {result['prediction']['confidence']:.2f}) "
                        f"[SHA256: {result['sha256'][:16]}...]"
                    )

        window_end = datetime.now(timezone.utc).isoformat()

        # Store window summary with hash
        if processed:
            summary_hash = store_window_summary(
                window_start, window_end,
                [{"attacker_ip": p["event"].get("attacker_ip"), "prediction": p["prediction"]}
                 for p in processed],
            )
            logger.info(
                f"Window processed: {len(processed)} events | "
                f"Attacks: {sum(1 for p in processed if p['prediction']['is_attack'])} | "
                f"Hash: {summary_hash[:16]}..."
            )

        return processed

    def run(self):
        """Start the continuous real-time processing loop."""
        logger.info("=" * 60)
        logger.info("  HoneyMed Real-Time Pipeline Started")
        logger.info(f"  Polling interval: {self.interval}s")
        logger.info(f"  Model loaded: {self.predictor.is_loaded}")
        logger.info(f"  Database: {DB_PATH}")
        logger.info("=" * 60)

        try:
            while True:
                self.process_window()
                time.sleep(self.interval)
        except KeyboardInterrupt:
            logger.info(
                f"\nPipeline stopped. Processed {self.total_processed} events, "
                f"detected {self.total_attacks} attacks."
            )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="HoneyMed Real-Time Pipeline")
    parser.add_argument("--honeypot-url", default="http://127.0.0.1:80",
                        help="URL of the running honeypot web portal")
    parser.add_argument("--interval", type=int, default=None,
                        help="Override polling interval (seconds)")
    args = parser.parse_args()

    pipeline = RealTimePipeline(honeypot_url=args.honeypot_url)
    if args.interval:
        pipeline.interval = args.interval

    pipeline.run()
