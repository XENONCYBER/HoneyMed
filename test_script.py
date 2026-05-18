import os
import sys

# Ensure current directory is in path
sys.path.append(os.getcwd())

from monitoring.intrusion_detection import extract_features_from_event, AttackPredictor, RealTimePipeline

def test_mock_events():
    predictor = AttackPredictor(model_path="models/rf_model.pkl", scaler_path="models/scaler.pkl")
    
    mock_events = [
        {
            "service": "web_portal",
            "event_type": "/login",
            "timestamp": "2026-05-18T14:00:00",
            "attacker_ip": "192.168.1.50",
            "attacker_port": 44332,
            "target_ip": "127.0.0.1",
            "payload_size": 150,
            "payload_entropy": 4.5
        },
        {
            "service": "web_portal",
            "event_type": "/api/v1/device/info",
            "timestamp": "2026-05-18T14:00:01",
            "attacker_ip": "192.168.1.50",
            "attacker_port": 44333,
            "target_ip": "127.0.0.1",
            "payload_size": 200,
            "payload_entropy": 3.8
        },
        {
            "service": "mqtt_listener",
            "event_type": "MQTT_CONNECT",
            "timestamp": "2026-05-18T14:00:02",
            "attacker_ip": "192.168.1.51",
            "attacker_port": 1883,
            "target_ip": "127.0.0.1",
            "payload_size": 50,
            "payload_entropy": 2.1
        }
    ]

    print("--- 1, 2, 3: Prediction Results ---")
    for event in mock_events:
        features = extract_features_from_event(event)
        label, confidence = predictor.predict(features)
        print(f"Service: {event['service']}, Event: {event['event_type']} -> Label: {label}")

    print("\n--- 4: Pipeline Check ---")
    pipeline = RealTimePipeline()
    print(f"last_event_count: {pipeline.last_event_count}")

if __name__ == "__main__":
    test_mock_events()
