"""
HoneyMed - Phase 2: Benign Traffic Generator
=============================================
Generates realistic "normal" medical device traffic to create
the benign class in our training dataset.

This simulates:
  - Regular device status checks
  - Normal HL7 patient admission messages
  - Standard MQTT vital sign telemetry
  - Routine DICOM C-ECHO (connectivity test)
"""

import argparse
import json
import os
import random
import socket
import struct
import sys
import time
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class BenignTrafficGenerator:
    """Generates normal/expected traffic patterns for an IoMT network."""

    def __init__(self, target_ip: str, verbose: bool = True):
        self.target = target_ip
        self.verbose = verbose
        self.results: list[dict] = []

    def _log(self, msg: str):
        if self.verbose:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"  [{ts}] {msg}")

    def _record(self, traffic_type: str, details: dict):
        self.results.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "traffic_type": traffic_type,
            "label": "BENIGN",
            "target": self.target,
            **details,
        })

    def generate_web_traffic(self, port: int = 80, count: int = 30):
        """Simulate normal browsing of device status pages."""
        self._log(f"Generating {count} normal web requests...")

        normal_paths = [
            "/api/v1/device/info",
            "/api/v1/vitals/current",
            "/hl7",
            "/login",
        ]

        for i in range(count):
            path = random.choice(normal_paths)
            try:
                url = f"http://{self.target}:{port}{path}"
                resp = requests.get(url, timeout=5, headers={
                    "User-Agent": "MedDeviceManager/3.2 (Windows NT 10.0; Clinical Workstation)",
                })
                self._record("BENIGN_WEB", {
                    "path": path,
                    "status_code": resp.status_code,
                })
            except Exception:
                pass

            # Realistic inter-request delay (normal user behavior)
            time.sleep(random.uniform(2.0, 8.0))

        self._log(f"Web traffic generation complete ({count} requests).")

    def generate_hl7_traffic(self, port: int = 2575, count: int = 10):
        """Send normal HL7 ADT/ORU messages like a real HIS would."""
        self._log(f"Generating {count} normal HL7 messages...")

        for i in range(count):
            ts = datetime.now().strftime("%Y%m%d%H%M%S")
            patient_id = f"PAT{random.randint(1000, 9999)}"

            # Normal ADT^A01 (Patient Admit)
            msg = (
                f"MSH|^~\\&|HIS_APP|MAIN_HOSPITAL|MONITOR|ICU|{ts}||ADT^A01|MSG{i:04d}|P|2.5.1\r"
                f"PID|1||{patient_id}^^^HOSP||*** PHI REDACTED ***||19700101|U\r"
                f"PV1|1|I|ICU^BED{random.randint(1,20)}|||ATTENDING^DR\r"
            )

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.target, port))

                mllp_msg = b"\x0b" + msg.encode() + b"\x1c\x0d"
                sock.sendall(mllp_msg)

                resp = sock.recv(4096)
                self._record("BENIGN_HL7", {
                    "message_type": "ADT^A01",
                    "patient_id": patient_id,
                    "response_received": len(resp) > 0,
                })
                sock.close()
            except Exception as e:
                self._log(f"  HL7 Error: {e}")

            time.sleep(random.uniform(5.0, 15.0))  # Realistic interval

        self._log(f"HL7 traffic generation complete ({count} messages).")

    def generate_mqtt_traffic(self, port: int = 1883, count: int = 20):
        """Simulate normal MQTT vital sign telemetry."""
        self._log(f"Generating {count} MQTT vital sign publications...")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port))

            # CONNECT
            client_id = "ICU_MONITOR_01"
            connect_payload = bytearray()
            connect_payload += b"\x00\x04MQTT"
            connect_payload += b"\x04"
            connect_payload += b"\x02"  # Clean session only (no user/pass — normal device)
            connect_payload += b"\x00\x3C"
            connect_payload += struct.pack(">H", len(client_id)) + client_id.encode()

            pkt = bytes([0x10]) + bytes([len(connect_payload)]) + connect_payload
            sock.sendall(pkt)
            sock.recv(4)

            topic = "hospital/icu/vitals"
            for i in range(count):
                vitals = {
                    "device_id": "ICU_MON_04",
                    "heart_rate": random.randint(60, 100),
                    "spo2": random.randint(94, 100),
                    "bp_systolic": random.randint(110, 140),
                    "bp_diastolic": random.randint(60, 90),
                    "temperature": round(random.uniform(36.0, 37.5), 1),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                payload = json.dumps(vitals).encode()

                pub_payload = bytearray()
                pub_payload += struct.pack(">H", len(topic)) + topic.encode()
                pub_payload += payload

                pub_pkt = bytes([0x30]) + bytes([len(pub_payload)]) + pub_payload
                sock.sendall(pub_pkt)

                self._record("BENIGN_MQTT", {
                    "topic": topic,
                    "heart_rate": vitals["heart_rate"],
                })

                time.sleep(random.uniform(3.0, 10.0))

            sock.close()
        except Exception as e:
            self._log(f"  MQTT Error: {e}")

        self._log(f"MQTT traffic generation complete ({count} publications).")

    def save_results(self, output_dir: str = "data/raw"):
        """Save benign traffic log."""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(output_dir, f"benign_log_{timestamp}.json")

        with open(filepath, "w") as f:
            json.dump(self.results, f, indent=2)

        print(f"\n  Benign traffic saved to {filepath} ({len(self.results)} events)")
        return filepath


def main():
    parser = argparse.ArgumentParser(description="HoneyMed Benign Traffic Generator")
    parser.add_argument("--target", required=True, help="Target IP (honeypot)")
    parser.add_argument("--quick", action="store_true", help="Quick mode (fewer events)")
    args = parser.parse_args()

    print("=" * 60)
    print("  HoneyMed Benign Traffic Generator")
    print(f"  Target: {args.target}")
    print("=" * 60)

    gen = BenignTrafficGenerator(args.target)

    count = 5 if args.quick else 30
    gen.generate_web_traffic(count=count)
    gen.generate_hl7_traffic(count=max(3, count // 3))
    gen.generate_mqtt_traffic(count=max(5, count // 2))
    gen.save_results()

    print("\nBenign traffic generation complete.")


if __name__ == "__main__":
    main()
