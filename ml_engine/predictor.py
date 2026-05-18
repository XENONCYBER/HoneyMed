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

SERVICE_HINT_LABELS = {
    "mqtt_listener": 4,
    "hl7_listener": 4,
    "dicom_listener": 4,
    "ssh_listener": 3,
}

EVENT_TYPE_HINT_LABELS = {
    "LOGIN_ATTEMPT": 3,
    "BRUTEFORCE_WEB": 3,
    "API_DEVICE_INFO": 2,
    "API_VITALS_ACCESS": 2,
    "FIRMWARE_PAGE_ACCESS": 2,
    "FIRMWARE_UPLOAD_ATTEMPT": 2,
    "CONFIG_ACCESS": 2,
    "CONFIG_CHANGE_ATTEMPT": 2,
    "DASHBOARD_ACCESS": 2,
    "PATH_PROBE": 2,
    "HL7_PAGE_ACCESS": 4,
    "MQTT_CONNECTION": 4,
    "MQTT_CONNECT": 4,
    "MQTT_SUBSCRIBE": 4,
    "MQTT_PUBLISH": 4,
    "MQTT_PING": 4,
    "MQTT_DISCONNECTED": 4,
    "MQTT_TIMEOUT": 4,
    "MQTT_CONN_RESET": 4,
    "MQTT_ERROR": 4,
    "MQTT_UNKNOWN_PACKET": 4,
    "HL7_CONNECTION": 4,
    "HL7_MESSAGE_RECEIVED": 4,
    "HL7_TIMEOUT": 4,
    "HL7_CONN_RESET": 4,
    "HL7_DISCONNECTED": 4,
    "DICOM_CONNECTION": 4,
    "DICOM_PDU_RECEIVED": 4,
    "DICOM_ASSOCIATE_REQUEST": 4,
    "DICOM_COMMAND": 4,
    "DICOM_TIMEOUT": 4,
    "DICOM_CONN_RESET": 4,
    "DICOM_DISCONNECTED": 4,
    "SSH_CONNECTION": 3,
    "SSH_CLIENT_BANNER": 3,
    "SSH_DATA_RECEIVED": 3,
    "SSH_TIMEOUT": 3,
    "SSH_CONN_RESET": 3,
    "SSH_DISCONNECTED": 3,
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

    def _rule_based_prediction(self, features: dict) -> tuple[int, str] | None:
        """Apply lightweight rules for protocol- and path-specific demo traffic."""
        service = str(features.get("service", "")).lower()
        event_type = str(features.get("event_type", "")).upper()
        request_path = str(features.get("request_path", "")).lower()

        if service == "web_portal":
            if event_type == "LOGIN_ATTEMPT" or request_path == "/login":
                prediction = 3
                return prediction, LABEL_NAMES[prediction]
            if request_path.startswith("/api/v1/") or request_path in {"/dashboard", "/hl7"}:
                prediction = 2
                return prediction, LABEL_NAMES[prediction]

        if service in SERVICE_HINT_LABELS:
            prediction = SERVICE_HINT_LABELS[service]
            return prediction, LABEL_NAMES[prediction]

        if event_type in EVENT_TYPE_HINT_LABELS:
            prediction = EVENT_TYPE_HINT_LABELS[event_type]
            return prediction, LABEL_NAMES[prediction]

        return None

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

        override = self._rule_based_prediction(features)
        if override is not None:
            prediction, label = override
            return {
                "prediction": prediction,
                "label": label,
                "confidence": 0.99,
                "is_attack": prediction != 0,
                "above_threshold": True,
            }

        # Build feature vector
        feature_vector = [features.get(col, 0) for col in FEATURE_COLUMNS]
        X = pd.DataFrame([feature_vector], columns=FEATURE_COLUMNS)

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
