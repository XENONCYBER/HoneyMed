"""
HoneyMed - Layer 2: Feature Extractor
======================================
Converts raw honeypot JSON logs into structured feature vectors
suitable for ML model training and inference.

Extracts network-level and application-level features from each event,
labels them based on the attack type, and outputs a clean CSV dataset.
"""

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.loader import get_config, get_base_dir
from utils.logger import get_logger

logger = get_logger("pipeline.feature_extractor", layer="PIPELINE", log_file="pipeline.jsonl")

# ---------------------------------------------------------------------------
# Label Mapping
# ---------------------------------------------------------------------------
ATTACK_LABEL_MAP = {
    # Benign traffic
    "BENIGN_WEB":     0,
    "BENIGN_HL7":     0,
    "BENIGN_MQTT":    0,
    "BENIGN_DICOM":   0,

    # DoS Attacks
    "DOS_HTTP_FLOOD": 1,
    "DOS_TCP_SYN":    1,

    # Port Scanning / Reconnaissance
    "PORTSCAN":       2,
    "API_ENUMERATION": 2,

    # Brute-Force
    "BRUTEFORCE_WEB": 3,
    "LOGIN_ATTEMPT":  3,

    # Protocol-specific attacks
    "HL7_INJECTION":       4,
    "MQTT_PROBE":          4,
    "MQTT_SUBSCRIBE_PROBE": 4,
    "MQTT_PUBLISH_PROBE":  4,
    "DICOM_PROBE":         4,
}

LABEL_NAMES = {
    0: "Benign",
    1: "DoS",
    2: "PortScan",
    3: "BruteForce",
    4: "Reconnaissance",
}


# ---------------------------------------------------------------------------
# Feature Extraction Functions
# ---------------------------------------------------------------------------

def extract_features_from_event(event: dict) -> dict:
    """
    Extract ML features from a single honeypot event.

    Features include:
      - Temporal: hour, minute, day_of_week
      - Network: port targeted, payload size
      - Protocol: one-hot encoding of protocol type
      - Behavioral: request rate indicators
      - Content: payload entropy, credential presence
    """
    features = {}

    # --- Temporal Features ---
    ts_str = event.get("timestamp", "")
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        features["hour_of_day"] = ts.hour
        features["minute"] = ts.minute
        features["day_of_week"] = ts.weekday()
        features["is_business_hours"] = 1 if 8 <= ts.hour <= 18 else 0
    except (ValueError, TypeError):
        features["hour_of_day"] = 0
        features["minute"] = 0
        features["day_of_week"] = 0
        features["is_business_hours"] = 0

    # --- Network Features ---
    features["attacker_port"] = event.get("attacker_port", 0) or 0

    # Determine target port from the service/event
    service = event.get("service", "")
    event_type = event.get("event_type", event.get("attack_type", event.get("traffic_type", "")))
    details = event.get("details", {})

    port_map = {
        "web_portal": 80,
        "hl7_listener": 2575,
        "dicom_listener": 11112,
        "mqtt_listener": 1883,
        "ssh_listener": 22,
    }
    features["target_port"] = port_map.get(service, details.get("port", 0))

    # --- Payload Features ---
    raw_len = details.get("raw_length", 0) or 0
    response_len = details.get("response_length", 0) or 0
    content_len = details.get("content_length", 0) or 0
    features["payload_size"] = max(raw_len, response_len, content_len)

    # Payload entropy (measure of randomness — high entropy = potentially encrypted/obfuscated)
    raw_data = str(details.get("raw_payload", details.get("raw_hex", "")))
    if raw_data:
        byte_counts = np.zeros(256)
        for ch in raw_data.encode():
            byte_counts[ch] += 1
        byte_counts = byte_counts[byte_counts > 0]
        probs = byte_counts / byte_counts.sum()
        features["payload_entropy"] = float(-np.sum(probs * np.log2(probs)))
    else:
        features["payload_entropy"] = 0.0

    # --- Protocol One-Hot Encoding ---
    protocol = event.get("protocol", "").upper()
    for proto in ["HTTP", "HL7", "DICOM", "MQTT", "SSH", "TCP"]:
        features[f"proto_{proto.lower()}"] = 1 if proto in protocol or proto.lower() in service else 0

    # Special case: web portal is HTTP
    if service == "web_portal" or "WEB" in event_type.upper():
        features["proto_http"] = 1

    # --- Behavioral Features ---
    # Credential attempt indicator
    has_creds = 1 if (
        details.get("username") or details.get("password") or
        details.get("client_id") or "LOGIN" in event_type.upper() or
        "BRUTEFORCE" in event_type.upper()
    ) else 0
    features["has_credentials"] = has_creds

    # Scanning indicator
    features["is_scan_like"] = 1 if (
        "SCAN" in event_type.upper() or
        "ENUMERATION" in event_type.upper() or
        "PROBE" in event_type.upper()
    ) else 0

    # High volume indicator (for DoS)
    total_requests = details.get("total_requests", 0) or 0
    features["high_volume"] = 1 if total_requests > 100 else 0
    features["request_count"] = total_requests

    # --- Status Code (HTTP-specific) ---
    features["status_code"] = details.get("status_code", 0) or 0

    # --- Label ---
    attack_type = event.get("attack_type", event.get("traffic_type", event_type))
    features["label"] = ATTACK_LABEL_MAP.get(attack_type, -1)
    features["label_name"] = LABEL_NAMES.get(features["label"], "Unknown")
    features["event_type"] = event_type

    return features


def process_log_files(raw_dir: str | None = None) -> pd.DataFrame:
    """
    Process all JSON log files in the raw data directory into a feature DataFrame.
    """
    if raw_dir is None:
        raw_dir = os.path.join(get_base_dir(), "data", "raw")

    all_features = []
    log_files = list(Path(raw_dir).glob("*.json"))

    if not log_files:
        logger.warning(f"No JSON log files found in {raw_dir}")
        return pd.DataFrame()

    logger.info(f"Processing {len(log_files)} log files from {raw_dir}")

    for log_file in log_files:
        with open(log_file, "r") as f:
            events = json.load(f)

        logger.info(f"  {log_file.name}: {len(events)} events")

        for event in events:
            features = extract_features_from_event(event)
            if features["label"] != -1:  # Skip unlabeled events
                all_features.append(features)

    df = pd.DataFrame(all_features)

    if len(df) > 0:
        logger.info(f"Total features extracted: {len(df)}")
        logger.info(f"Label distribution:\n{df['label_name'].value_counts().to_string()}")

    return df


def save_dataset(df: pd.DataFrame, output_dir: str | None = None) -> str:
    """Save the processed dataset as CSV."""
    if output_dir is None:
        output_dir = os.path.join(get_base_dir(), "data", "processed")

    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"dataset_{timestamp}.csv")

    df.to_csv(filepath, index=False)
    logger.info(f"Dataset saved to {filepath}")

    # Generate SHA-256 hash for blockchain readiness
    with open(filepath, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    logger.info(f"Dataset SHA-256: {file_hash}")

    # Save hash to a sidecar file
    hash_path = filepath + ".sha256"
    with open(hash_path, "w") as f:
        f.write(file_hash)

    return filepath


def generate_synthetic_dataset(n_samples: int = 5000) -> pd.DataFrame:
    """
    Generate a synthetic dataset for initial ML training.
    Uses realistic statistical distributions for each attack type.
    This is useful when you haven't collected enough real traffic yet.
    """
    logger.info(f"Generating synthetic dataset with {n_samples} samples...")
    np.random.seed(42)

    records = []

    # Define profiles per attack type
    profiles = {
        0: {  # Benign
            "weight": 0.40,
            "target_ports": [80, 2575, 1883, 11112],
            "payload_range": (50, 500),
            "entropy_range": (2.0, 4.5),
            "has_creds_prob": 0.05,
            "high_volume_prob": 0.0,
            "scan_prob": 0.0,
        },
        1: {  # DoS
            "weight": 0.15,
            "target_ports": [80],
            "payload_range": (0, 100),
            "entropy_range": (0.5, 2.0),
            "has_creds_prob": 0.0,
            "high_volume_prob": 0.95,
            "scan_prob": 0.0,
        },
        2: {  # PortScan
            "weight": 0.15,
            "target_ports": [21, 22, 23, 80, 443, 1883, 2575, 3306, 8080, 11112],
            "payload_range": (0, 60),
            "entropy_range": (0.0, 1.5),
            "has_creds_prob": 0.0,
            "high_volume_prob": 0.1,
            "scan_prob": 0.95,
        },
        3: {  # BruteForce
            "weight": 0.15,
            "target_ports": [22, 80],
            "payload_range": (80, 300),
            "entropy_range": (3.0, 5.0),
            "has_creds_prob": 0.95,
            "high_volume_prob": 0.3,
            "scan_prob": 0.0,
        },
        4: {  # Reconnaissance
            "weight": 0.15,
            "target_ports": [2575, 11112, 1883],
            "payload_range": (100, 2000),
            "entropy_range": (3.5, 6.0),
            "has_creds_prob": 0.3,
            "high_volume_prob": 0.0,
            "scan_prob": 0.4,
        },
    }

    for label, profile in profiles.items():
        n = int(n_samples * profile["weight"])
        for _ in range(n):
            hour = np.random.randint(0, 24)
            record = {
                "hour_of_day": hour,
                "minute": np.random.randint(0, 60),
                "day_of_week": np.random.randint(0, 7),
                "is_business_hours": 1 if 8 <= hour <= 18 else 0,
                "attacker_port": np.random.randint(1024, 65535),
                "target_port": np.random.choice(profile["target_ports"]),
                "payload_size": np.random.randint(*profile["payload_range"]),
                "payload_entropy": np.random.uniform(*profile["entropy_range"]),
                "proto_http": 1 if np.random.choice(profile["target_ports"]) == 80 else 0,
                "proto_hl7": 1 if 2575 in profile["target_ports"] and np.random.random() > 0.5 else 0,
                "proto_dicom": 1 if 11112 in profile["target_ports"] and np.random.random() > 0.5 else 0,
                "proto_mqtt": 1 if 1883 in profile["target_ports"] and np.random.random() > 0.5 else 0,
                "proto_ssh": 1 if 22 in profile["target_ports"] and np.random.random() > 0.5 else 0,
                "proto_tcp": np.random.choice([0, 1]),
                "has_credentials": 1 if np.random.random() < profile["has_creds_prob"] else 0,
                "is_scan_like": 1 if np.random.random() < profile["scan_prob"] else 0,
                "high_volume": 1 if np.random.random() < profile["high_volume_prob"] else 0,
                "request_count": np.random.randint(100, 10000) if np.random.random() < profile["high_volume_prob"] else np.random.randint(1, 10),
                "status_code": np.random.choice([200, 401, 403, 404]) if label != 1 else 0,
                "label": label,
                "label_name": LABEL_NAMES[label],
            }
            records.append(record)

    df = pd.DataFrame(records)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # Shuffle

    logger.info(f"Synthetic dataset generated: {len(df)} samples")
    logger.info(f"Label distribution:\n{df['label_name'].value_counts().to_string()}")

    return df


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="HoneyMed Feature Extractor")
    parser.add_argument("--synthetic", action="store_true", help="Generate synthetic dataset")
    parser.add_argument("--samples", type=int, default=5000, help="Number of synthetic samples")
    parser.add_argument("--process", action="store_true", help="Process raw log files")
    args = parser.parse_args()

    if args.synthetic:
        df = generate_synthetic_dataset(args.samples)
        save_dataset(df)
    elif args.process:
        df = process_log_files()
        if len(df) > 0:
            save_dataset(df)
    else:
        print("Use --synthetic to generate training data, or --process to process raw logs.")
