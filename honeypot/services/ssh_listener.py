"""
HoneyMed - Layer 1: SSH Honeypot
=================================
Simulates an SSH server that appears as a medical device's embedded SSH.
Captures brute-force login attempts, commands executed, etc.

Uses a raw socket-based approach (no paramiko dependency).
"""

import json
import os
import socket
import threading
import time
from datetime import datetime, timezone

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from config.loader import get_config
from utils.logger import get_logger

cfg = get_config()
ssh_cfg = cfg["honeypot"]["ssh_listener"]
logger = get_logger("honeypot.ssh", layer="HONEYPOT", log_file="honeypot_ssh.jsonl")

SSH_EVENTS: list[dict] = []


def _capture_event(client_addr: tuple, event_type: str, details: dict):
    """Record an SSH interaction."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "ssh_listener",
        "event_type": event_type,
        "attacker_ip": client_addr[0],
        "attacker_port": client_addr[1],
        "protocol": "SSH",
        "details": details,
    }
    SSH_EVENTS.append(event)
    logger.info(
        f"{event_type} from {client_addr[0]}:{client_addr[1]}",
        extra={
            "attacker_ip": client_addr[0],
            "attacker_port": client_addr[1],
            "service": "ssh_listener",
            "action": event_type,
            "protocol": "SSH",
        },
    )


def _handle_client(conn: socket.socket, addr: tuple):
    """
    Handle SSH connection at banner level.
    We send a realistic banner and capture whatever the client sends.
    """
    _capture_event(addr, "SSH_CONNECTION", {"stage": "connected"})
    conn.settimeout(30)
    attempts = 0

    try:
        # Send SSH banner
        banner = ssh_cfg["banner"] + "\r\n"
        conn.sendall(banner.encode())

        # Receive client's SSH version string
        client_banner = conn.recv(256)
        if client_banner:
            client_version = client_banner.decode("utf-8", errors="replace").strip()
            _capture_event(addr, "SSH_CLIENT_BANNER", {
                "client_version": client_version,
            })
        while attempts < 10:
            data = conn.recv(4096)
            if not data:
                break

            _capture_event(addr, "SSH_DATA_RECEIVED", {
                "raw_length": len(data),
                "raw_hex": data[:200].hex(),
                "attempt_number": attempts + 1,
            })

            # Simulate slow response to waste attacker's time
            time.sleep(0.5)
            attempts += 1

    except socket.timeout:
        _capture_event(addr, "SSH_TIMEOUT", {"reason": "client idle"})
    except ConnectionResetError:
        _capture_event(addr, "SSH_CONN_RESET", {})
    except Exception as e:
        _capture_event(addr, "SSH_ERROR", {"error": str(e)})
    finally:
        conn.close()
        _capture_event(addr, "SSH_DISCONNECTED", {"total_data_exchanges": attempts})


def run_ssh_listener():
    """Start the SSH honeypot listener."""
    host = ssh_cfg["host"]
    port = ssh_cfg["port"]

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(10)

    logger.info(f"SSH Honeypot listening on {host}:{port}")
    logger.info(f"Banner: {ssh_cfg['banner']}")

    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=_handle_client, args=(conn, addr), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        logger.info("SSH Listener shutting down.")
    finally:
        server.close()


if __name__ == "__main__":
    run_ssh_listener()
