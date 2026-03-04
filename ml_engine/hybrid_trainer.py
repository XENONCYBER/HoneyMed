"""
HoneyMed - Phase 6: Hybrid Dataset Trainer
============================================
Creates a hyper-accurate ML model by merging:
  1. Public IoMT/IoT datasets (WUSTL-EHLL, Edge-IIoTset, CIC-IDS)
  2. Custom honeypot attack logs from HoneyMed's own capture

The hybrid approach ensures the model is globally smart (broad attack
patterns from public data) yet specialized to IoMT edge environments.

Usage:
    python ml_engine/hybrid_trainer.py --public-dir data/public_datasets
    python ml_engine/hybrid_trainer.py --synthetic --custom-dir data/raw
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.loader import get_config, get_base_dir
from utils.logger import get_logger
from pipeline.feature_extractor import (
    FEATURE_COLUMNS,
    LABEL_NAMES,
    ATTACK_LABEL_MAP,
    extract_features_from_event,
    generate_synthetic_dataset,
    save_dataset,
)

logger = get_logger("ml_engine.hybrid_trainer", layer="ML_ENGINE", log_file="ml_hybrid.jsonl")


# ---------------------------------------------------------------------------
# Public Dataset Loaders
# ---------------------------------------------------------------------------

def _map_public_label(raw_label: str) -> int:
    """
    Map labels from public IoT/IDS datasets to HoneyMed's 5-class schema.

    Handles common naming conventions from:
    - WUSTL-EHLL (HL7 attack dataset)
    - Edge-IIoTset
    - CIC-IDS2017/2018
    - TON_IoT
    """
    label = str(raw_label).strip().upper()

    # Benign
    if label in ("BENIGN", "NORMAL", "LEGITIMATE", "0"):
        return 0

    # DoS / DDoS
    if any(k in label for k in ("DOS", "DDOS", "FLOOD", "SLOWLORIS", "HULK",
                                 "GOLDENEYE", "SLOWHTTP", "RUDY")):
        return 1

    # PortScan / Reconnaissance
    if any(k in label for k in ("PORTSCAN", "PORT_SCAN", "SCAN", "RECON",
                                 "FINGERPRINT", "OS_FINGERPRINT")):
        return 2

    # Brute-Force
    if any(k in label for k in ("BRUTEFORCE", "BRUTE_FORCE", "BRUTE-FORCE",
                                 "FTP-PATATOR", "SSH-PATATOR", "CREDENTIAL")):
        return 3

    # Protocol-level / Injection / Other (map to Reconnaissance class)
    if any(k in label for k in ("INJECTION", "XSS", "SQL", "HEARTBLEED",
                                 "INFILTRATION", "BOTNET", "WEBATTACK",
                                 "EXPLOIT", "BACKDOOR", "RANSOMWARE",
                                 "MITM", "MQTT", "HL7", "DICOM")):
        return 4

    # Unknown — default to Reconnaissance
    logger.warning(f"Unknown public label '{raw_label}', mapping to Reconnaissance (4)")
    return 4


def load_public_dataset(csv_path: str) -> pd.DataFrame:
    """
    Load a public IoT/IDS dataset CSV and normalize it to HoneyMed features.

    Expects at minimum columns for: label/Label/attack_type + some numeric features.
    Missing HoneyMed features will be synthesized from available data.
    """
    logger.info(f"Loading public dataset: {csv_path}")
    df = pd.read_csv(csv_path, low_memory=False)
    logger.info(f"  Raw shape: {df.shape}")

    # --- Identify the label column ---
    label_col = None
    for candidate in ("label", "Label", "attack_type", "Attack_type", "class",
                      "Class", "category", "Attack", "attack_cat"):
        if candidate in df.columns:
            label_col = candidate
            break

    if label_col is None:
        raise ValueError(f"Cannot find label column in {csv_path}. "
                         f"Available: {list(df.columns[:20])}")

    # Map labels to HoneyMed 5-class schema
    df["label"] = df[label_col].apply(_map_public_label)
    df["label_name"] = df["label"].map(LABEL_NAMES)

    # --- Map available numeric columns to HoneyMed features ---
    mapped = pd.DataFrame()

    # Direct mapping attempts (common column names in public datasets)
    column_mappings = {
        "hour_of_day":      ["hour", "Hour", "timestamp_hour"],
        "minute":           ["minute", "Minute"],
        "day_of_week":      ["day_of_week", "DayOfWeek", "weekday"],
        "attacker_port":    ["src_port", "Src Port", "Source Port", "Sport"],
        "target_port":      ["dst_port", "Dst Port", "Destination Port", "Dport"],
        "payload_size":     ["total_len", "Tot Fwd Pkts", "Flow Bytes/s",
                             "Fwd Pkt Len Max", "pkt_size", "TotalLenofFwdPkts"],
        "payload_entropy":  ["entropy", "Fwd Header Len", "pkt_entropy"],
        "request_count":    ["flow_pkts_toclient", "Total Fwd Packets",
                             "Tot Fwd Pkts", "packets"],
        "status_code":      ["status_code", "http_status"],
    }

    for honeymed_col, candidates in column_mappings.items():
        for c in candidates:
            if c in df.columns:
                mapped[honeymed_col] = pd.to_numeric(df[c], errors="coerce").fillna(0)
                break

    # Fill any still-missing feature columns with reasonable defaults
    for col in FEATURE_COLUMNS:
        if col not in mapped.columns:
            if col == "is_business_hours":
                if "hour_of_day" in mapped.columns:
                    mapped[col] = mapped["hour_of_day"].apply(
                        lambda h: 1 if 8 <= h <= 18 else 0
                    )
                else:
                    mapped[col] = np.random.choice([0, 1], size=len(df))
            elif col.startswith("proto_"):
                # Infer protocol from port if possible
                proto_port_map = {
                    "proto_http": [80, 443, 8080, 8443],
                    "proto_hl7": [2575],
                    "proto_dicom": [11112, 104],
                    "proto_mqtt": [1883],
                    "proto_ssh": [22],
                    "proto_tcp": [],
                }
                if "target_port" in mapped.columns and col in proto_port_map:
                    ports = proto_port_map[col]
                    if ports:
                        mapped[col] = mapped["target_port"].isin(ports).astype(int)
                    else:
                        mapped[col] = np.random.choice([0, 1], size=len(df))
                else:
                    mapped[col] = 0
            elif col in ("has_credentials", "is_scan_like", "high_volume"):
                # Infer from label
                if col == "has_credentials":
                    mapped[col] = (df["label"] == 3).astype(int)
                elif col == "is_scan_like":
                    mapped[col] = (df["label"] == 2).astype(int)
                elif col == "high_volume":
                    mapped[col] = (df["label"] == 1).astype(int)
            else:
                mapped[col] = 0

    mapped["label"] = df["label"]
    mapped["label_name"] = df["label_name"]

    logger.info(f"  Mapped shape: {mapped.shape}")
    logger.info(f"  Label distribution:\n{mapped['label_name'].value_counts().to_string()}")

    return mapped


def load_custom_honeypot_logs(raw_dir: str | None = None) -> pd.DataFrame:
    """
    Load attack/benign logs generated by HoneyMed's own honeypot
    (from data/raw/*.json produced by attack_simulator and benign_traffic).
    """
    if raw_dir is None:
        raw_dir = os.path.join(get_base_dir(), "data", "raw")

    all_features = []
    json_files = list(Path(raw_dir).glob("*.json"))

    if not json_files:
        logger.warning(f"No custom JSON logs found in {raw_dir}")
        return pd.DataFrame()

    logger.info(f"Loading {len(json_files)} custom honeypot log files from {raw_dir}")

    for jf in json_files:
        try:
            with open(jf, "r") as f:
                events = json.load(f)
            logger.info(f"  {jf.name}: {len(events)} events")
            for event in events:
                features = extract_features_from_event(event)
                if features["label"] != -1:
                    all_features.append(features)
        except (json.JSONDecodeError, Exception) as e:
            logger.warning(f"  Skipping {jf.name}: {e}")

    df = pd.DataFrame(all_features)
    if len(df) > 0:
        logger.info(f"Custom dataset: {len(df)} labeled events")
        logger.info(f"  Label distribution:\n{df['label_name'].value_counts().to_string()}")
    return df


# ---------------------------------------------------------------------------
# Hybrid Merging & Training
# ---------------------------------------------------------------------------

def merge_datasets(
    public_dfs: list[pd.DataFrame],
    custom_df: pd.DataFrame | None,
    synthetic_df: pd.DataFrame | None = None,
    custom_weight: float = 2.0,
) -> pd.DataFrame:
    """
    Merge public + custom + synthetic datasets with optional oversampling
    of the custom data so the model is specialized to our environment.

    Args:
        public_dfs:    List of DataFrames from public datasets.
        custom_df:     DataFrame from HoneyMed's own honeypot logs.
        synthetic_df:  Optional synthetic baseline data.
        custom_weight: How many times to oversample the custom data (default 2x).
    """
    frames = []

    for i, pdf in enumerate(public_dfs):
        pdf = pdf[FEATURE_COLUMNS + ["label", "label_name"]].copy()
        pdf["source"] = f"public_{i}"
        frames.append(pdf)

    if synthetic_df is not None and len(synthetic_df) > 0:
        sdf = synthetic_df[FEATURE_COLUMNS + ["label", "label_name"]].copy()
        sdf["source"] = "synthetic"
        frames.append(sdf)

    if custom_df is not None and len(custom_df) > 0:
        cdf = custom_df[FEATURE_COLUMNS + ["label", "label_name"]].copy()
        cdf["source"] = "custom_honeypot"
        # Oversample custom data to boost its influence
        repeat = max(1, int(custom_weight))
        for _ in range(repeat):
            frames.append(cdf.copy())
        logger.info(f"Custom data oversampled {repeat}x ({len(cdf)} -> {len(cdf) * repeat})")

    if not frames:
        raise ValueError("No data available for merging. Provide at least one data source.")

    merged = pd.concat(frames, ignore_index=True)
    merged = merged.sample(frac=1, random_state=42).reset_index(drop=True)

    logger.info(f"Merged dataset: {len(merged)} total samples")
    logger.info(f"Source distribution:\n{merged['source'].value_counts().to_string()}")
    logger.info(f"Label distribution:\n{merged['label_name'].value_counts().to_string()}")

    return merged


def train_hybrid_model(df: pd.DataFrame, test_size: float = 0.2):
    """
    Train an enhanced model suite on the hybrid dataset.
    Includes RandomForest + GradientBoosting (+ XGBoost if available).
    """
    logger.info("=" * 60)
    logger.info("  Phase 6: Hybrid Model Training")
    logger.info("=" * 60)

    X = df[FEATURE_COLUMNS].fillna(0)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y,
    )
    logger.info(f"Train: {len(X_train)} | Test: {len(X_test)}")

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    models = {
        "RandomForest": RandomForestClassifier(
            n_estimators=200, max_depth=25, min_samples_split=4,
            min_samples_leaf=2, random_state=42, n_jobs=-1,
        ),
        "GradientBoosting": GradientBoostingClassifier(
            n_estimators=150, max_depth=8, learning_rate=0.1,
            random_state=42,
        ),
    }

    try:
        from xgboost import XGBClassifier
        models["XGBoost"] = XGBClassifier(
            n_estimators=200, max_depth=12, learning_rate=0.08,
            random_state=42, eval_metric="mlogloss",
        )
    except ImportError:
        logger.warning("XGBoost not installed — skipping.")

    results = {}
    best_model, best_f1, best_name = None, 0, ""

    for name, model in models.items():
        logger.info(f"\n--- Training: {name} ---")
        import time as _time
        t0 = _time.time()

        model.fit(X_train_scaled, y_train)
        train_time = _time.time() - t0

        y_pred = model.predict(X_test_scaled)
        acc = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)

        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_f1 = cross_val_score(model, X_train_scaled, y_train, cv=cv, scoring="f1_weighted")

        target_names = [LABEL_NAMES[i] for i in sorted(y.unique())]
        report = classification_report(y_test, y_pred, target_names=target_names, zero_division=0)

        results[name] = {
            "accuracy": round(acc, 4),
            "f1_score": round(f1, 4),
            "cv_f1_mean": round(cv_f1.mean(), 4),
            "cv_f1_std": round(cv_f1.std(), 4),
            "train_time": round(train_time, 2),
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
            "classification_report": report,
        }

        logger.info(f"  Accuracy: {acc:.4f}  F1: {f1:.4f}  CV-F1: {cv_f1.mean():.4f}")

        if f1 > best_f1:
            best_f1 = f1
            best_model = model
            best_name = name

    logger.info(f"\nBest Hybrid Model: {best_name} (F1: {best_f1:.4f})")
    return best_model, scaler, best_name, results


def save_hybrid_model(model, scaler, model_name: str, results: dict):
    """Export the hybrid-trained model, overwriting the previous model."""
    model_dir = os.path.join(get_base_dir(), "data", "models")
    os.makedirs(model_dir, exist_ok=True)

    model_path = os.path.join(model_dir, "attack_classifier.pkl")
    scaler_path = os.path.join(model_dir, "feature_scaler.pkl")
    results_path = os.path.join(model_dir, "hybrid_training_results.json")

    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    logger.info(f"Hybrid model saved: {model_path}")

    save_results = {
        "best_model": model_name,
        "training_mode": "hybrid",
        "feature_columns": FEATURE_COLUMNS,
        "label_names": {str(k): v for k, v in LABEL_NAMES.items()},
        "trained_at": datetime.now().isoformat(),
        "results": {k: {kk: vv for kk, vv in v.items() if kk != "classification_report"}
                    for k, v in results.items()},
    }
    with open(results_path, "w") as f:
        json.dump(save_results, f, indent=2)
    logger.info(f"Results saved: {results_path}")

    return model_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    import argparse

    parser = argparse.ArgumentParser(description="HoneyMed Phase 6 — Hybrid ML Trainer")
    parser.add_argument("--public-dir", type=str, default=None,
                        help="Directory containing public dataset CSV files")
    parser.add_argument("--custom-dir", type=str, default=None,
                        help="Directory containing custom honeypot JSON logs")
    parser.add_argument("--synthetic", action="store_true",
                        help="Include synthetic baseline data")
    parser.add_argument("--samples", type=int, default=5000,
                        help="Number of synthetic samples")
    parser.add_argument("--custom-weight", type=float, default=2.0,
                        help="Oversampling factor for custom data")
    args = parser.parse_args()

    public_dfs = []
    if args.public_dir:
        for csv_file in sorted(Path(args.public_dir).glob("*.csv")):
            try:
                pdf = load_public_dataset(str(csv_file))
                public_dfs.append(pdf)
            except Exception as e:
                logger.error(f"Failed to load {csv_file}: {e}")

    custom_df = load_custom_honeypot_logs(args.custom_dir) if args.custom_dir else None

    synthetic_df = None
    if args.synthetic or (not public_dfs and custom_df is None):
        logger.info("Generating synthetic baseline data...")
        synthetic_df = generate_synthetic_dataset(args.samples)

    merged = merge_datasets(public_dfs, custom_df, synthetic_df,
                            custom_weight=args.custom_weight)

    csv_path = save_dataset(merged)
    best_model, scaler, best_name, results = train_hybrid_model(merged)
    save_hybrid_model(best_model, scaler, best_name, results)

    print(f"\nHybrid training complete! Best model: {best_name}")
    print(f"Model exported to data/models/attack_classifier.pkl")


if __name__ == "__main__":
    main()
