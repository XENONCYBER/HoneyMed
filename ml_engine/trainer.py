"""
HoneyMed - Layer 3: ML Model Trainer
=====================================
Trains multiple ML classifiers on the extracted feature dataset,
evaluates their performance, and exports the best model.

Models trained:
  - Random Forest (primary — best for tabular cybersecurity data)
  - Decision Tree (interpretable baseline)
  - XGBoost (gradient boosting for higher accuracy)

Evaluation metrics:
  - Accuracy, Precision, Recall, F1-Score
  - Confusion Matrix
  - Classification Report per attack type
"""

import json
import os
import sys
import time
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
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

logger = get_logger("ml_engine.trainer", layer="ML_ENGINE", log_file="ml_training.jsonl")

# Feature columns used for training (must match feature_extractor output)
FEATURE_COLUMNS = [
    "hour_of_day",
    "minute",
    "day_of_week",
    "is_business_hours",
    "attacker_port",
    "target_port",
    "payload_size",
    "payload_entropy",
    "proto_http",
    "proto_hl7",
    "proto_dicom",
    "proto_mqtt",
    "proto_ssh",
    "proto_tcp",
    "has_credentials",
    "is_scan_like",
    "high_volume",
    "request_count",
    "status_code",
]

LABEL_NAMES = {
    0: "Benign",
    1: "DoS",
    2: "PortScan",
    3: "BruteForce",
    4: "Reconnaissance",
}


def load_dataset(csv_path: str) -> tuple[pd.DataFrame, pd.Series]:
    """Load and validate the training dataset."""
    logger.info(f"Loading dataset from {csv_path}")
    df = pd.read_csv(csv_path)

    # Validate required columns
    missing = set(FEATURE_COLUMNS) - set(df.columns)
    if missing:
        raise ValueError(f"Missing feature columns: {missing}")

    if "label" not in df.columns:
        raise ValueError("Missing 'label' column in dataset")

    X = df[FEATURE_COLUMNS].fillna(0)
    y = df["label"]

    logger.info(f"Dataset shape: {X.shape}")
    logger.info(f"Classes: {dict(y.value_counts().sort_index())}")

    return X, y


def train_models(X: pd.DataFrame, y: pd.Series, test_size: float = 0.2):
    """
    Train multiple classifiers and return evaluation results.
    """
    logger.info("=" * 50)
    logger.info("Starting ML Training Pipeline")
    logger.info("=" * 50)

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y
    )
    logger.info(f"Train: {len(X_train)} samples | Test: {len(X_test)} samples")

    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Define models
    models = {
        "RandomForest": RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
        ),
        "DecisionTree": DecisionTreeClassifier(
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
        ),
    }

    # Try importing XGBoost
    try:
        from xgboost import XGBClassifier
        models["XGBoost"] = XGBClassifier(
            n_estimators=100,
            max_depth=10,
            learning_rate=0.1,
            random_state=42,
            eval_metric="mlogloss",
        )
    except ImportError:
        logger.warning("XGBoost not installed. Skipping XGBoost model.")

    results = {}
    best_model = None
    best_f1 = 0
    best_name = ""

    for name, model in models.items():
        logger.info(f"\n--- Training: {name} ---")
        start_time = time.time()

        # Train
        model.fit(X_train_scaled, y_train)
        train_time = time.time() - start_time

        # Predict
        y_pred = model.predict(X_test_scaled)

        # Metrics
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, average="weighted", zero_division=0)
        rec = recall_score(y_test, y_pred, average="weighted", zero_division=0)
        f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)
        cm = confusion_matrix(y_test, y_pred)

        # Cross validation
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=cv, scoring="f1_weighted")

        target_names = [LABEL_NAMES[i] for i in sorted(y.unique())]
        report = classification_report(y_test, y_pred, target_names=target_names, zero_division=0)

        results[name] = {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "cv_f1_mean": round(cv_scores.mean(), 4),
            "cv_f1_std": round(cv_scores.std(), 4),
            "train_time_seconds": round(train_time, 2),
            "confusion_matrix": cm.tolist(),
            "classification_report": report,
        }

        logger.info(f"  Accuracy:  {acc:.4f}")
        logger.info(f"  Precision: {prec:.4f}")
        logger.info(f"  Recall:    {rec:.4f}")
        logger.info(f"  F1-Score:  {f1:.4f}")
        logger.info(f"  CV F1:     {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        logger.info(f"  Train Time: {train_time:.2f}s")
        logger.info(f"\n{report}")

        if f1 > best_f1:
            best_f1 = f1
            best_model = model
            best_name = name

    logger.info(f"\n{'=' * 50}")
    logger.info(f"Best Model: {best_name} (F1: {best_f1:.4f})")
    logger.info(f"{'=' * 50}")

    # Feature importance (for tree-based models)
    if hasattr(best_model, "feature_importances_"):
        importances = pd.Series(
            best_model.feature_importances_,
            index=FEATURE_COLUMNS,
        ).sort_values(ascending=False)
        logger.info(f"\nTop Feature Importances:\n{importances.head(10).to_string()}")

    return best_model, scaler, best_name, results


def save_model(model, scaler, model_name: str, results: dict):
    """Export the trained model, scaler, and evaluation results."""
    cfg = get_config()
    model_dir = os.path.join(get_base_dir(), "data", "models")
    os.makedirs(model_dir, exist_ok=True)

    # Save model
    model_path = os.path.join(model_dir, "attack_classifier.pkl")
    joblib.dump(model, model_path)
    logger.info(f"Model saved: {model_path}")

    # Save scaler
    scaler_path = os.path.join(model_dir, "feature_scaler.pkl")
    joblib.dump(scaler, scaler_path)
    logger.info(f"Scaler saved: {scaler_path}")

    # Save evaluation results
    results_path = os.path.join(model_dir, "training_results.json")
    save_results = {
        "best_model": model_name,
        "feature_columns": FEATURE_COLUMNS,
        "label_names": LABEL_NAMES,
        "trained_at": datetime.now().isoformat(),
        "results": {k: {kk: vv for kk, vv in v.items() if kk != "classification_report"}
                    for k, v in results.items()},
    }
    with open(results_path, "w") as f:
        json.dump(save_results, f, indent=2)
    logger.info(f"Results saved: {results_path}")

    # Save classification reports as text
    for name, result in results.items():
        report_path = os.path.join(model_dir, f"report_{name}.txt")
        with open(report_path, "w") as f:
            f.write(f"Classification Report - {name}\n")
            f.write("=" * 50 + "\n")
            f.write(result["classification_report"])
        logger.info(f"Report saved: {report_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description="HoneyMed ML Model Trainer")
    parser.add_argument("--dataset", type=str, help="Path to CSV dataset")
    parser.add_argument("--synthetic", action="store_true", help="Generate and use synthetic data")
    parser.add_argument("--samples", type=int, default=5000, help="Synthetic sample count")
    args = parser.parse_args()

    if args.synthetic:
        # Import and generate synthetic dataset
        from pipeline.feature_extractor import generate_synthetic_dataset, save_dataset
        df = generate_synthetic_dataset(args.samples)
        csv_path = save_dataset(df)
        X, y = load_dataset(csv_path)
    elif args.dataset:
        X, y = load_dataset(args.dataset)
    else:
        # Find the latest dataset
        processed_dir = os.path.join(get_base_dir(), "data", "processed")
        csv_files = sorted(Path(processed_dir).glob("dataset_*.csv"))
        if not csv_files:
            print("No dataset found. Use --synthetic to generate one, or --dataset to specify a path.")
            sys.exit(1)
        csv_path = str(csv_files[-1])
        print(f"Using latest dataset: {csv_path}")
        X, y = load_dataset(csv_path)

    best_model, scaler, best_name, results = train_models(X, y)
    save_model(best_model, scaler, best_name, results)

    print("\nTraining complete! Model exported to data/models/")


if __name__ == "__main__":
    main()
