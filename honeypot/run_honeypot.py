"""
HoneyMed - Layer 1: Honeypot Orchestrator
==========================================
Launches all honeypot services as threads from a single entry point.
This is the main entry point for the entire honeypot layer.
"""

import os
import sys
import threading
import signal

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.loader import get_config
from utils.logger import get_logger
from honeypot.services.web_portal import run_web_portal
from honeypot.services.hl7_listener import run_hl7_listener
from honeypot.services.dicom_listener import run_dicom_listener
from honeypot.services.mqtt_listener import run_mqtt_listener
from honeypot.services.ssh_listener import run_ssh_listener

logger = get_logger("honeypot.orchestrator", layer="HONEYPOT", log_file="honeypot_main.jsonl")


SERVICES = {
    "Web Portal (Medical Device UI)":  run_web_portal,
    "HL7 MLLP Listener":              run_hl7_listener,
    "DICOM PACS Listener":            run_dicom_listener,
    "MQTT IoT Broker":                run_mqtt_listener,
    "SSH Embedded Device":            run_ssh_listener,
}


def start_all_services():
    """Launch all honeypot services in separate daemon threads."""
    cfg = get_config()

    logger.info("=" * 60)
    logger.info("  HoneyMed IoMT Honeypot Framework")
    logger.info("  An Intelligent Honeypot for IoMT Networks")
    logger.info("=" * 60)

    threads = []
    for name, func in SERVICES.items():
        logger.info(f"Starting service: {name}")
        t = threading.Thread(target=func, name=name, daemon=True)
        t.start()
        threads.append(t)

    logger.info(f"All {len(threads)} honeypot services are running.")
    logger.info("Press Ctrl+C to stop all services.")

    ports = [
        cfg["honeypot"]["web_portal"]["port"],
        cfg["honeypot"]["hl7_listener"]["port"],
        cfg["honeypot"]["dicom_listener"]["port"],
        cfg["honeypot"]["mqtt_listener"]["port"],
        cfg["honeypot"]["ssh_listener"]["port"],
    ]
    logger.info(f"Active ports: {ports}")

    return threads


def main():
    """Main entry point."""
    threads = start_all_services()

    # Keep the main thread alive
    try:
        for t in threads:
            while t.is_alive():
                t.join(timeout=1.0)
    except KeyboardInterrupt:
        logger.info("\nShutting down all honeypot services...")
        logger.info("Goodbye.")


if __name__ == "__main__":
    main()
    main()
