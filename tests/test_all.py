"""
HoneyMed - Unit Tests
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestConfigLoader(unittest.TestCase):
    """Test the configuration loader."""

    def test_load_config(self):
        from config.loader import load_config, get_base_dir
        config = load_config()
        self.assertIn("honeypot", config)
        self.assertIn("pipeline", config)
        self.assertIn("ml_engine", config)
        self.assertIn("dashboard", config)

    def test_honeypot_config(self):
        from config.loader import get_config
        cfg = get_config()
        hp = cfg["honeypot"]
        self.assertEqual(hp["web_portal"]["port"], 80)
        self.assertEqual(hp["hl7_listener"]["port"], 2575)
        self.assertEqual(hp["dicom_listener"]["port"], 11112)
        self.assertEqual(hp["mqtt_listener"]["port"], 1883)
        self.assertEqual(hp["ssh_listener"]["port"], 22)


class TestFeatureExtractor(unittest.TestCase):
    """Test feature extraction from events."""

    def test_extract_bruteforce_event(self):
        from pipeline.feature_extractor import extract_features_from_event

        event = {
            "timestamp": "2026-01-15T10:30:00+00:00",
            "service": "web_portal",
            "event_type": "LOGIN_ATTEMPT",
            "attacker_ip": "192.168.1.50",
            "attacker_port": 54321,
            "details": {
                "username": "admin",
                "password": "password123",
            },
        }

        features = extract_features_from_event(event)

        self.assertEqual(features["hour_of_day"], 10)
        self.assertEqual(features["target_port"], 80)
        self.assertEqual(features["has_credentials"], 1)
        self.assertEqual(features["proto_http"], 1)
        self.assertEqual(features["label"], 3)  # BruteForce
        self.assertEqual(features["label_name"], "BruteForce")

    def test_extract_benign_event(self):
        from pipeline.feature_extractor import extract_features_from_event

        event = {
            "timestamp": "2026-01-15T14:00:00+00:00",
            "traffic_type": "BENIGN_WEB",
            "details": {"path": "/api/v1/device/info", "status_code": 200},
        }

        features = extract_features_from_event(event)
        self.assertEqual(features["label"], 0)  # Benign
        self.assertEqual(features["is_business_hours"], 1)

    def test_extract_dos_event(self):
        from pipeline.feature_extractor import extract_features_from_event

        event = {
            "timestamp": "2026-01-15T03:00:00+00:00",
            "attack_type": "DOS_HTTP_FLOOD",
            "details": {"total_requests": 5000, "duration_seconds": 15},
        }

        features = extract_features_from_event(event)
        self.assertEqual(features["label"], 1)  # DoS
        self.assertEqual(features["high_volume"], 1)
        self.assertEqual(features["is_business_hours"], 0)

    def test_generate_synthetic_dataset(self):
        from pipeline.feature_extractor import generate_synthetic_dataset

        df = generate_synthetic_dataset(500)
        self.assertGreater(len(df), 400)
        self.assertEqual(set(df["label"].unique()), {0, 1, 2, 3, 4})


class TestMLTrainer(unittest.TestCase):
    """Test ML training pipeline."""

    def test_train_and_predict(self):
        from pipeline.feature_extractor import generate_synthetic_dataset, save_dataset
        from ml_engine.trainer import load_dataset, train_models, save_model
        from ml_engine.predictor import AttackPredictor

        # Generate small dataset
        df = generate_synthetic_dataset(500)
        csv_path = save_dataset(df)

        # Train
        X, y = load_dataset(csv_path)
        model, scaler, name, results = train_models(X, y)

        # Verify results
        self.assertIn(name, ["RandomForest", "DecisionTree", "XGBoost"])
        self.assertGreater(results[name]["accuracy"], 0.5)

        # Save
        save_model(model, scaler, name, results)

        # Load predictor and test
        predictor = AttackPredictor()
        self.assertTrue(predictor.is_loaded)

        # Predict a DoS event
        prediction = predictor.predict({
            "hour_of_day": 3,
            "minute": 30,
            "day_of_week": 2,
            "is_business_hours": 0,
            "attacker_port": 45678,
            "target_port": 80,
            "payload_size": 50,
            "payload_entropy": 1.2,
            "proto_http": 1,
            "proto_hl7": 0,
            "proto_dicom": 0,
            "proto_mqtt": 0,
            "proto_ssh": 0,
            "proto_tcp": 1,
            "has_credentials": 0,
            "is_scan_like": 0,
            "high_volume": 1,
            "request_count": 5000,
            "status_code": 0,
        })

        self.assertIn("prediction", prediction)
        self.assertIn("label", prediction)
        self.assertIn("confidence", prediction)
        self.assertIsInstance(prediction["confidence"], float)


class TestDatabasePipeline(unittest.TestCase):
    """Test the database initialization and storage."""

    def test_init_database(self):
        from pipeline.realtime_pipeline import init_database, DB_PATH
        init_database()
        self.assertTrue(os.path.exists(DB_PATH))


class TestEncryption(unittest.TestCase):
    """Test Phase 7: AES-256-GCM encryption."""

    def test_encrypt_decrypt_string(self):
        from security.encryption import EncryptionManager
        mgr = EncryptionManager(key=os.urandom(32))
        plaintext = "Hello, HoneyMed!"
        ciphertext = mgr.encrypt(plaintext)
        self.assertNotEqual(ciphertext, plaintext)
        result = mgr.decrypt_to_str(ciphertext)
        self.assertEqual(result, plaintext)

    def test_encrypt_decrypt_dict(self):
        from security.encryption import EncryptionManager
        mgr = EncryptionManager(key=os.urandom(32))
        data = {"attacker_ip": "10.0.0.1", "label": "DoS"}
        ciphertext = mgr.encrypt(json.dumps(data))
        result = mgr.decrypt_to_dict(ciphertext)
        self.assertEqual(result["attacker_ip"], "10.0.0.1")


class TestBlockchainPrivacy(unittest.TestCase):
    """Test Phase 8: Blockchain + Privacy."""

    def test_hash_protocol_sanitize(self):
        from blockchain.hash_protocol import HashProtocol
        hp = HashProtocol()
        event = {
            "attacker_ip": "10.0.0.1",
            "details": {"patient_name": "John Doe", "ssn": "123-45-6789"},
        }
        sanitized = hp.sanitize_phi(event)
        self.assertEqual(sanitized["details"]["patient_name"], "*** REDACTED ***")
        self.assertEqual(sanitized["details"]["ssn"], "*** REDACTED ***")

    def test_privacy_commitment(self):
        from blockchain.privacy import PrivacyEngine
        pe = PrivacyEngine(secret_key=os.urandom(32))
        data = {"test": "value"}
        commitment, blinding = pe.create_commitment(data)
        self.assertTrue(pe.verify_commitment(data, commitment, blinding))
        self.assertFalse(pe.verify_commitment({"test": "other"}, commitment, blinding))

    def test_selective_disclosure(self):
        from blockchain.privacy import PrivacyEngine
        pe = PrivacyEngine(secret_key=os.urandom(32))
        record = {
            "sha256_hash": "abc",
            "threat_label": "DoS",
            "confidence": 0.9,
            "attacker_ip": "10.0.0.5",
            "raw_event": "secret",
        }
        pub = pe.selective_disclose(record, "public")
        self.assertNotIn("attacker_ip", pub)
        self.assertNotIn("raw_event", pub)
        self.assertIn("sha256_hash", pub)

        admin = pe.selective_disclose(record, "admin")
        self.assertIn("attacker_ip", admin)
        self.assertIn("raw_event", admin)


class TestChaincode(unittest.TestCase):
    """Test Phase 9: Smart Contracts."""

    def test_rbac_permissions(self):
        from blockchain.chaincode.access_control import AccessControl, Role
        ac = AccessControl()
        ac.register_user("test_researcher", Role.RESEARCHER, org="TestOrg")
        self.assertTrue(ac.check_permission("test_researcher", "read_anonymized_event"))
        self.assertFalse(ac.check_permission("test_researcher", "write_event"))

    def test_ioc_submission(self):
        import hashlib
        from blockchain.chaincode.access_control import AccessControl, Role
        from blockchain.chaincode.threat_contract import ThreatContract
        ac = AccessControl()
        contract = ThreatContract(ac)
        h = hashlib.sha256(b"test_event_unit").hexdigest()
        result = contract.submit_ioc("system_admin", h, "DoS", 0.88, "10.0.0.1")
        self.assertEqual(result["status"], "submitted")


class TestDistributed(unittest.TestCase):
    """Test Phase 10: Distributed Nodes."""

    def test_node_registration(self):
        from distributed.node_manager import NodeManager
        nm = NodeManager(node_id="test_node_a", endpoint="http://127.0.0.1:9999", org="TestOrg")
        result = nm.register_peer("test_node_b", "http://127.0.0.1:9998", "TestOrgB")
        self.assertEqual(result["status"], "registered")
        peers = nm.get_peers()
        self.assertTrue(any(p["node_id"] == "test_node_b" for p in peers))

    def test_threat_sharing(self):
        import hashlib
        from distributed.node_manager import NodeManager
        nm = NodeManager(node_id="test_share_node", endpoint="http://127.0.0.1:9997", org="TestOrg")
        h = hashlib.sha256(b"shared_threat_test").hexdigest()
        result = nm.share_threat(h, "PortScan", 0.77)
        self.assertIn("sha256_hash", result)


class TestAutoResponse(unittest.TestCase):
    """Test Phase 11: Auto-response."""

    def test_block_and_check(self):
        from siem.auto_response import AutoResponse
        ar = AutoResponse(mode="simulate")
        result = ar.block_ip("10.99.99.99", reason="unit test")
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(ar.is_blocked("10.99.99.99"))
        ar.unblock_ip("10.99.99.99")
        self.assertFalse(ar.is_blocked("10.99.99.99"))

    def test_whitelist(self):
        from siem.auto_response import AutoResponse
        ar = AutoResponse(mode="simulate")
        result = ar.block_ip("127.0.0.1", reason="should be whitelisted")
        self.assertEqual(result["status"], "whitelisted")

    def test_evaluate_threat(self):
        from siem.auto_response import AutoResponse
        ar = AutoResponse(mode="simulate")
        ar.unblock_ip("10.88.88.88")  # Ensure clean state
        ar.confidence_threshold = 0.8
        ar.auto_block_labels = ["DoS"]
        event = {"attacker_ip": "10.88.88.88"}
        pred = {"label": "DoS", "confidence": 0.95, "is_attack": True}
        result = ar.evaluate_threat(event, pred)
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
