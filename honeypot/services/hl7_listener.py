"""
HoneyMed - Layer 1: HL7 Listener Honeypot
==========================================
Simulates an HL7 v2.x MLLP (Minimum Lower Layer Protocol) endpoint.
Health Level 7 is the dominant protocol for exchanging clinical data
between hospital systems (ADT, ORM, ORU messages).

Listens on port 2575 and captures any HL7 messages or connection attempts.
"""

import json
import os
import socket
import threading
from datetime import datetime, timezone

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from config.loader import get_config
from utils.logger import get_logger

cfg = get_config()
hl7_cfg = cfg["honeypot"]["hl7_listener"]
logger = get_logger("honeypot.hl7", layer="HONEYPOT", log_file="honeypot_hl7.jsonl")

# HL7 MLLP framing characters
MLLP_START = b"\x0b"  # VT (vertical tab)
MLLP_END = b"\x1c\x0d"  # FS + CR

# Captured events shared with pipeline
HL7_EVENTS: list[dict] = []


def _build_hl7_ack(message_id: str = "0001") -> bytes:
    """
    Build a fake HL7 ACK response.
    This makes the honeypot appear as a real HL7 endpoint.
    """
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    ack = (
        f"MSH|^~\\&|HONEYPOT_HIS|ICU_WARD|SENDER_APP|SENDER_FAC|{timestamp}||ACK^A01|{message_id}|P|2.5.1\r"
        f"MSA|AA|{message_id}|Message received successfully\r"
    )
    return MLLP_START + ack.encode() + MLLP_END


def _capture_event(client_addr: tuple, event_type: str, details: dict):
    """Record an HL7 interaction."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "hl7_listener",
        "event_type": event_type,
        "attacker_ip": client_addr[0],
        "attacker_port": client_addr[1],
        "protocol": "HL7/MLLP",
        "details": details,
    }
    HL7_EVENTS.append(event)
    logger.info(
        f"{event_type} from {client_addr[0]}:{client_addr[1]}",
        extra={
            "attacker_ip": client_addr[0],
            "attacker_port": client_addr[1],
            "service": "hl7_listener",
            "action": event_type,
            "protocol": "HL7",
        },
    )


def _handle_client(conn: socket.socket, addr: tuple):
    """Handle a single HL7 MLLP connection."""
    _capture_event(addr, "HL7_CONNECTION", {"stage": "connected"})
    conn.settimeout(30)

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break

            raw_text = data.decode("utf-8", errors="replace")

            # Try to parse HL7 message type
            msg_type = "UNKNOWN"
            if "MSH|" in raw_text:
                parts = raw_text.split("|")
                if len(parts) > 8:
                    msg_type = parts[8]  # e.g., ADT^A01

            _capture_event(addr, "HL7_MESSAGE_RECEIVED", {
                "raw_length": len(data),
                "message_type": msg_type,
                "raw_payload": raw_text[:500],  # First 500 chars
            })

            # Send ACK to keep the attacker engaged
            ack_response = _build_hl7_ack()
            conn.sendall(ack_response)

    except socket.timeout:
        _capture_event(addr, "HL7_TIMEOUT", {"reason": "client idle"})
    except ConnectionResetError:
        _capture_event(addr, "HL7_CONN_RESET", {})
    except Exception as e:
        _capture_event(addr, "HL7_ERROR", {"error": str(e)})
    finally:
        conn.close()
        _capture_event(addr, "HL7_DISCONNECTED", {})


def run_hl7_listener():
    """Start the HL7 MLLP honeypot listener."""
    host = hl7_cfg["host"]
    port = hl7_cfg["port"]

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(10)

    logger.info(f"HL7 MLLP Honeypot listening on {host}:{port}")

    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=_handle_client, args=(conn, addr), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        logger.info("HL7 Listener shutting down.")
    finally:
        server.close()


if __name__ == "__main__":
    run_hl7_listener()
