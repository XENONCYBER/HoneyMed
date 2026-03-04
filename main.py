"""
HoneyMed - Master Entry Point
===============================
One-command launcher for the entire framework.

Usage:
    python main.py --mode full          # Run everything (honeypot + pipeline + dashboard)
    python main.py --mode honeypot      # Run only the honeypot layer
    python main.py --mode pipeline      # Run only the real-time pipeline
    python main.py --mode train         # Train/retrain the ML model
    python main.py --mode hybrid-train  # Phase 6: Train on hybrid public+custom dataset
    python main.py --mode blockchain    # Phase 8-9: Blockchain + chaincode demo
    python main.py --mode dashboard     # Run only the dashboard
    python main.py --mode siem-api      # Phase 11: Start SIEM REST API server
    python main.py --mode siem-push     # Phase 11: Push threats to configured SIEMs
    python main.py --mode simulate      # Run attack simulation against the honeypot
"""

import argparse
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.loader import get_config
from utils.logger import get_logger

logger = get_logger("main", layer="SYSTEM", log_file="system.jsonl")


def run_honeypot():
    """Start all honeypot services."""
    from honeypot.run_honeypot import start_all_services
    start_all_services()


def run_pipeline():
    """Start the real-time classification pipeline."""
    from pipeline.realtime_pipeline import RealTimePipeline
    pipeline = RealTimePipeline()
    pipeline.run()


def run_dashboard_api():
    """Start the REST API backend."""
    from dashboard.api import run_api
    run_api()


def run_dashboard_ui():
    """Launch the Streamlit dashboard."""
    import subprocess
    dashboard_path = os.path.join(os.path.dirname(__file__), "dashboard", "streamlit_app.py")
    subprocess.run([
        sys.executable, "-m", "streamlit", "run", dashboard_path,
        "--server.port", "8501",
        "--server.headless", "true",
    ])


def run_train():
    """Train or retrain the ML model."""
    from pipeline.feature_extractor import generate_synthetic_dataset, save_dataset
    from ml_engine.trainer import load_dataset, train_models, save_model

    logger.info("Generating synthetic training dataset...")
    df = generate_synthetic_dataset(5000)
    csv_path = save_dataset(df)

    logger.info("Training ML models...")
    X, y = load_dataset(csv_path)
    best_model, scaler, best_name, results = train_models(X, y)
    save_model(best_model, scaler, best_name, results)
    logger.info("Training complete!")


def run_hybrid_train():
    """Phase 6: Train ML model on hybrid (public + custom) dataset."""
    from ml_engine.hybrid_trainer import HybridTrainer

    logger.info("Starting Hybrid ML Training (Phase 6)...")
    trainer = HybridTrainer()
    df = trainer.merge_datasets()
    results = trainer.train_hybrid_model(df)

    for name, metrics in results.items():
        logger.info(f"  {name}: accuracy={metrics['accuracy']:.4f}")
    logger.info("Hybrid training complete!")


def run_blockchain_demo():
    """Phase 8-9: Demonstrate blockchain + chaincode functionality."""
    import hashlib
    from blockchain.fabric_client import get_fabric_client
    from blockchain.hash_protocol import HashProtocol
    from blockchain.privacy import PrivacyEngine
    from blockchain.chaincode.threat_contract import ThreatContract
    from blockchain.chaincode.access_control import AccessControl, Role

    logger.info("Running Blockchain + Chaincode Demo...")

    # Hash protocol demo
    hp = HashProtocol()
    sample_event = {
        "timestamp": "2026-01-15T10:30:00+00:00",
        "attacker_ip": "192.168.1.50",
        "service": "web_portal",
        "event_type": "LOGIN_ATTEMPT",
        "details": {"username": "admin", "patient_name": "John Doe"},
    }
    prediction = {"label": "BruteForce", "confidence": 0.95, "is_attack": True}
    result = hp.process_event(sample_event, prediction)
    logger.info(f"Hash: {result['sha256_hash'][:32]}... committed to ledger")

    # Privacy engine demo
    pe = PrivacyEngine()
    prediction = {"label": "BruteForce", "confidence": 0.93, "is_attack": True}
    privacy_result = pe.apply_privacy(sample_event, prediction, role="researcher")
    logger.info(f"Privacy: {len(privacy_result['disclosed_record'])} fields disclosed")

    # Chaincode demo
    ac = AccessControl()
    contract = ThreatContract(ac)
    event_hash = hashlib.sha256(b"demo_event").hexdigest()
    ioc = contract.submit_ioc("system_admin", event_hash, "BruteForce", 0.95, "192.168.1.50")
    logger.info(f"IOC submitted: disclosure_at={ioc['disclosure_at']}")

    logger.info("Blockchain demo complete!")


def run_siem_api():
    """Phase 11: Start the SIEM REST API server."""
    from siem.api_connector import SIEMAPIConnector
    connector = SIEMAPIConnector()
    connector.run()


def run_siem_push():
    """Phase 11: Push current threats to configured SIEM platforms."""
    from siem.siem_integration import SIEMIntegration

    logger.info("Pushing threats to SIEM platforms...")
    integration = SIEMIntegration()
    results = integration.push_all()

    for platform, result in results.items():
        logger.info(f"  {platform}: {result.get('status')} ({result.get('count', 0)} events)")

    if not results:
        logger.info("  No SIEM platforms configured. Edit siem.enabled_platforms in settings.yaml")
    logger.info("SIEM push complete!")


def run_full():
    """Run the complete framework: Honeypot + Pipeline + Dashboard API."""
    logger.info("=" * 60)
    logger.info("  HoneyMed — Full System Launch")
    logger.info("=" * 60)

    # Step 1: Start honeypot services (in background threads)
    logger.info("[1/3] Starting Honeypot Services...")
    honeypot_thread = threading.Thread(target=run_honeypot, daemon=True)
    honeypot_thread.start()
    time.sleep(2)  # Let honeypot bind ports

    # Step 2: Start pipeline (in background thread)
    logger.info("[2/3] Starting Real-Time Pipeline...")
    pipeline_thread = threading.Thread(target=run_pipeline, daemon=True)
    pipeline_thread.start()

    # Step 3: Start Dashboard API (in background thread)
    logger.info("[3/3] Starting Dashboard API...")
    api_thread = threading.Thread(target=run_dashboard_api, daemon=True)
    api_thread.start()

    logger.info("\n" + "=" * 60)
    logger.info("  All systems running!")
    logger.info("  Honeypot:  Ports 22, 80, 1883, 2575, 11112")
    logger.info("  Pipeline:  Processing events every 5s")
    logger.info("  API:       http://localhost:5001")
    logger.info("  Dashboard: Run 'streamlit run dashboard/streamlit_app.py'")
    logger.info("=" * 60)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("\nShutting down all systems...")


def main():
    parser = argparse.ArgumentParser(
        description="HoneyMed — Intelligent Honeypot Framework for IoMT Networks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --mode train       # First: train the ML model
  python main.py --mode full        # Then: launch everything
  python main.py --mode simulate    # From another terminal: run attacks
        """,
    )
    parser.add_argument(
        "--mode",
        choices=["full", "honeypot", "pipeline", "train", "hybrid-train",
                 "blockchain", "dashboard", "api", "siem-api", "siem-push",
                 "simulate"],
        default="full",
        help="Which components to run",
    )
    parser.add_argument("--target", default="127.0.0.1", help="Target IP for simulate mode")

    args = parser.parse_args()

    mode_map = {
        "full": run_full,
        "honeypot": lambda: (run_honeypot(), threading.Event().wait()),
        "pipeline": run_pipeline,
        "train": run_train,
        "hybrid-train": run_hybrid_train,
        "blockchain": run_blockchain_demo,
        "dashboard": run_dashboard_ui,
        "api": run_dashboard_api,
        "siem-api": run_siem_api,
        "siem-push": run_siem_push,
    }

    if args.mode == "simulate":
        from attacks.attack_simulator import AttackSimulator
        sim = AttackSimulator(args.target)
        sim.attack_portscan()
        sim.attack_bruteforce_web()
        sim.attack_api_enumeration()
        sim.attack_dos_http(duration_seconds=10)
        sim.attack_hl7_injection()
        sim.attack_mqtt_probe()
        sim.attack_dicom_probe()
        sim.save_results()
    else:
        mode_map[args.mode]()


if __name__ == "__main__":
    main()
