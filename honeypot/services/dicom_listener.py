"""
HoneyMed - Layer 1: DICOM Listener Honeypot
============================================
Simulates a DICOM (Digital Imaging and Communications in Medicine) service.
DICOM is the standard protocol for medical imaging systems (CT, MRI, X-Ray).

Listens on port 11112 (standard DICOM port) and captures connection attempts
and any C-ECHO, C-FIND, C-STORE, or C-MOVE commands.
"""

import json
import os
import socket
import struct
import threading
from datetime import datetime, timezone

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from config.loader import get_config
from utils.logger import get_logger

cfg = get_config()
dcm_cfg = cfg["honeypot"]["dicom_listener"]
logger = get_logger("honeypot.dicom", layer="HONEYPOT", log_file="honeypot_dicom.jsonl")

DICOM_EVENTS: list[dict] = []


def _build_associate_accept(called_ae: str = "HONEYPOT_PACS") -> bytes:
    """
    Build a minimal DICOM A-ASSOCIATE-AC (Accept) PDU.
    This tricks DICOM clients into thinking they have connected to a real PACS.
    """
    # Simplified A-ASSOCIATE-AC PDU
    # PDU Type: 0x02 (A-ASSOCIATE-AC)
    pdu_type = b"\x02"
    reserved = b"\x00"

    # Called AE Title (16 bytes, space-padded)
    called_ae_bytes = called_ae.encode().ljust(16)[:16]
    calling_ae_bytes = b"ANY_SCU         "

    # Reserved bytes (32 bytes)
    reserved_32 = b"\x00" * 32

    # Application Context
    app_context_name = b"1.2.840.10008.3.1.1.1"  # DICOM Application Context
    app_context_item = b"\x10\x00" + struct.pack(">H", len(app_context_name)) + app_context_name

    # Build variable items
    variable_items = app_context_item

    # PDU length (everything after the 6-byte header)
    pdu_body = (
        b"\x00\x01"  # Protocol Version
        + b"\x00\x00"  # Reserved
        + called_ae_bytes
        + calling_ae_bytes
        + reserved_32
        + variable_items
    )

    pdu_length = struct.pack(">I", len(pdu_body))

    return pdu_type + reserved + pdu_length + pdu_body


def _capture_event(client_addr: tuple, event_type: str, details: dict):
    """Record a DICOM interaction."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "dicom_listener",
        "event_type": event_type,
        "attacker_ip": client_addr[0],
        "attacker_port": client_addr[1],
        "protocol": "DICOM",
        "details": details,
    }
    DICOM_EVENTS.append(event)
    logger.info(
        f"{event_type} from {client_addr[0]}:{client_addr[1]}",
        extra={
            "attacker_ip": client_addr[0],
            "attacker_port": client_addr[1],
            "service": "dicom_listener",
            "action": event_type,
            "protocol": "DICOM",
        },
    )


def _parse_pdu_type(data: bytes) -> str:
    """Identify the DICOM PDU type from the first byte."""
    if not data:
        return "EMPTY"
    pdu_types = {
        0x01: "A-ASSOCIATE-RQ",
        0x02: "A-ASSOCIATE-AC",
        0x03: "A-ASSOCIATE-RJ",
        0x04: "P-DATA-TF",
        0x05: "A-RELEASE-RQ",
        0x06: "A-RELEASE-RP",
        0x07: "A-ABORT",
    }
    return pdu_types.get(data[0], f"UNKNOWN(0x{data[0]:02x})")


def _handle_client(conn: socket.socket, addr: tuple):
    """Handle a single DICOM connection."""
    _capture_event(addr, "DICOM_CONNECTION", {"stage": "connected"})
    conn.settimeout(30)

    try:
        while True:
            data = conn.recv(8192)
            if not data:
                break

            pdu_type = _parse_pdu_type(data)

            _capture_event(addr, "DICOM_PDU_RECEIVED", {
                "pdu_type": pdu_type,
                "raw_length": len(data),
                "raw_hex": data[:100].hex(),
            })

            # If it's an Association Request, send an Accept
            if data[0] == 0x01:
                # Extract Called AE Title (bytes 10-26 in A-ASSOCIATE-RQ)
                called_ae = ""
                if len(data) > 26:
                    called_ae = data[10:26].decode("ascii", errors="replace").strip()

                _capture_event(addr, "DICOM_ASSOCIATE_REQUEST", {
                    "called_ae_title": called_ae,
                })

                accept_pdu = _build_associate_accept(dcm_cfg["ae_title"])
                conn.sendall(accept_pdu)

            # If it's a P-DATA (actual DICOM command), log it
            elif data[0] == 0x04:
                _capture_event(addr, "DICOM_COMMAND", {
                    "pdu_type": "P-DATA-TF",
                    "payload_size": len(data),
                })

            # Release request
            elif data[0] == 0x05:
                release_rp = b"\x06\x00\x00\x00\x00\x04\x00\x00\x00\x00"
                conn.sendall(release_rp)
                break

    except socket.timeout:
        _capture_event(addr, "DICOM_TIMEOUT", {"reason": "client idle"})
    except ConnectionResetError:
        _capture_event(addr, "DICOM_CONN_RESET", {})
    except Exception as e:
        _capture_event(addr, "DICOM_ERROR", {"error": str(e)})
    finally:
        conn.close()
        _capture_event(addr, "DICOM_DISCONNECTED", {})


def run_dicom_listener():
    """Start the DICOM honeypot listener."""
    host = dcm_cfg["host"]
    port = dcm_cfg["port"]

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(10)

    logger.info(f"DICOM Honeypot (AE Title: {dcm_cfg['ae_title']}) listening on {host}:{port}")

    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=_handle_client, args=(conn, addr), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        logger.info("DICOM Listener shutting down.")
    finally:
        server.close()


if __name__ == "__main__":
    run_dicom_listener()
