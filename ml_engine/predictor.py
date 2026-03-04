"""
HoneyMed - Layer 3: ML Inference Engine (Predictor)
====================================================
Loads the trained model and provides real-time attack classification.
This module is used by both the real-time pipeline (Layer 2) and
the dashboard API (Layer 4).
"""

import os
import sys

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.loader import get_config, get_base_dir
from utils.logger import get_logger

logger = get_logger("ml_engine.predictor", layer="ML_ENGINE", log_file="ml_predictions.jsonl")

FEATURE_COLUMNS = [
    "hour_of_day", "minute", "day_of_week", "is_business_hours",
    "attacker_port", "target_port", "payload_size", "payload_entropy",
    "proto_http", "proto_hl7", "proto_dicom", "proto_mqtt", "proto_ssh", "proto_tcp",
    "has_credentials", "is_scan_like", "high_volume", "request_count", "status_code",
]

LABEL_NAMES = {
    0: "Benign",
    1: "DoS",
    2: "PortScan",
    3: "BruteForce",
    4: "Reconnaissance",
}


class AttackPredictor:
    """
    Real-time attack classifier.
    Loads the trained model and scaler, and provides predict() for incoming events.
    """

    def __init__(self, model_path: str | None = None, scaler_path: str | None = None):
        base = get_base_dir()
        cfg = get_config()

        if model_path is None:
            model_path = os.path.join(base, cfg["ml_engine"]["model_path"])
        if scaler_path is None:
            scaler_path = os.path.join(base, cfg["ml_engine"]["scaler_path"])

        self.model = None
        self.scaler = None
        self.confidence_threshold = cfg["ml_engine"]["confidence_threshold"]

        self._load_model(model_path, scaler_path)

    def _load_model(self, model_path: str, scaler_path: str):
        """Load the trained model and scaler from disk."""
        if os.path.exists(model_path) and os.path.exists(scaler_path):
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            logger.info(f"Model loaded: {model_path}")
            logger.info(f"Scaler loaded: {scaler_path}")
        else:
            logger.warning("Model or scaler not found. Run trainer.py first.")

    def predict(self, features: dict) -> dict:
        """
        Classify a single event.

        Args:
            features: Dictionary of extracted features (from feature_extractor).

        Returns:
            Dictionary with prediction, confidence, and label name.
        """
        if self.model is None:
            return {
                "prediction": -1,
                "label": "MODEL_NOT_LOADED",
                "confidence": 0.0,
            }

        # Build feature vector
        feature_vector = [features.get(col, 0) for col in FEATURE_COLUMNS]
        X = np.array([feature_vector])

        # Scale
        X_scaled = self.scaler.transform(X)

        # Predict
        prediction = int(self.model.predict(X_scaled)[0])

        # Confidence (probability of the predicted class)
        confidence = 0.0
        if hasattr(self.model, "predict_proba"):
            probas = self.model.predict_proba(X_scaled)[0]
            confidence = float(probas[prediction])

        label = LABEL_NAMES.get(prediction, "Unknown")

        # Log high-confidence attacks
        if prediction != 0 and confidence >= self.confidence_threshold:
            logger.warning(
                f"ATTACK DETECTED: {label} (confidence: {confidence:.2f})",
                extra={
                    "prediction": prediction,
                    "confidence": confidence,
                    "action": "ATTACK_CLASSIFIED",
                },
            )

        return {
            "prediction": prediction,
            "label": label,
            "confidence": round(confidence, 4),
            "is_attack": prediction != 0,
            "above_threshold": confidence >= self.confidence_threshold,
        }

    def predict_batch(self, features_list: list[dict]) -> list[dict]:
        """Classify multiple events at once."""
        return [self.predict(f) for f in features_list]

    @property
    def is_loaded(self) -> bool:
        return self.model is not None and self.scaler is not None
