"""
HoneyMed - Layer 1: MQTT Listener Honeypot
===========================================
Simulates an MQTT broker that IoMT devices connect to.
MQTT is the lightweight messaging protocol used by many IoT/medical
devices for telemetry (vitals, device status, alerts).

Listens on port 1883 and captures CONNECT, SUBSCRIBE, PUBLISH commands.
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
mqtt_cfg = cfg["honeypot"]["mqtt_listener"]
logger = get_logger("honeypot.mqtt", layer="HONEYPOT", log_file="honeypot_mqtt.jsonl")

MQTT_EVENTS: list[dict] = []

# MQTT packet types
MQTT_CONNECT = 1
MQTT_CONNACK = 2
MQTT_PUBLISH = 3
MQTT_PUBACK = 4
MQTT_SUBSCRIBE = 8
MQTT_SUBACK = 9
MQTT_PINGREQ = 12
MQTT_PINGRESP = 13
MQTT_DISCONNECT = 14


def _capture_event(client_addr: tuple, event_type: str, details: dict):
    """Record an MQTT interaction."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "mqtt_listener",
        "event_type": event_type,
        "attacker_ip": client_addr[0],
        "attacker_port": client_addr[1],
        "protocol": "MQTT",
        "details": details,
    }
    MQTT_EVENTS.append(event)
    logger.info(
        f"{event_type} from {client_addr[0]}:{client_addr[1]}",
        extra={
            "attacker_ip": client_addr[0],
            "attacker_port": client_addr[1],
            "service": "mqtt_listener",
            "action": event_type,
            "protocol": "MQTT",
        },
    )


def _decode_remaining_length(conn: socket.socket) -> int:
    """Decode MQTT variable-length encoding."""
    multiplier = 1
    value = 0
    for _ in range(4):
        byte = conn.recv(1)
        if not byte:
            return 0
        encoded = byte[0]
        value += (encoded & 0x7F) * multiplier
        if (encoded & 0x80) == 0:
            break
        multiplier *= 128
    return value


def _decode_utf8_string(data: bytes, offset: int) -> tuple[str, int]:
    """Decode MQTT UTF-8 prefixed string."""
    if offset + 2 > len(data):
        return "", offset
    str_len = struct.unpack(">H", data[offset:offset + 2])[0]
    offset += 2
    string = data[offset:offset + str_len].decode("utf-8", errors="replace")
    return string, offset + str_len


def _handle_client(conn: socket.socket, addr: tuple):
    """Handle a single MQTT connection."""
    _capture_event(addr, "MQTT_CONNECTION", {"stage": "connected"})
    conn.settimeout(60)

    try:
        while True:
            # Read fixed header (first byte)
            header_byte = conn.recv(1)
            if not header_byte:
                break

            pkt_type = (header_byte[0] & 0xF0) >> 4
            remaining_len = _decode_remaining_length(conn)

            # Read the rest of the packet
            payload = b""
            if remaining_len > 0:
                payload = conn.recv(remaining_len)

            if pkt_type == MQTT_CONNECT:
                # Parse CONNECT packet
                client_id = ""
                username = ""
                password = ""
                if len(payload) > 10:
                    offset = 10  # Skip variable header
                    client_id, offset = _decode_utf8_string(payload, offset)

                    # Check connect flags for username/password
                    if len(payload) > 7:
                        connect_flags = payload[7]
                        has_username = (connect_flags & 0x80) != 0
                        has_password = (connect_flags & 0x40) != 0

                        if has_username and offset < len(payload):
                            username, offset = _decode_utf8_string(payload, offset)
                        if has_password and offset < len(payload):
                            password, offset = _decode_utf8_string(payload, offset)

                _capture_event(addr, "MQTT_CONNECT", {
                    "client_id": client_id,
                    "username": username,
                    "password": password,
                })

                # Send CONNACK (connection accepted)
                connack = bytes([0x20, 0x02, 0x00, 0x00])  # Return code 0 = accepted
                conn.sendall(connack)

            elif pkt_type == MQTT_PUBLISH:
                # Parse PUBLISH packet
                topic = ""
                message = ""
                if len(payload) > 2:
                    topic, offset = _decode_utf8_string(payload, 0)
                    message = payload[offset:].decode("utf-8", errors="replace")

                _capture_event(addr, "MQTT_PUBLISH", {
                    "topic": topic,
                    "message": message[:500],
                    "message_length": len(payload),
                })

            elif pkt_type == MQTT_SUBSCRIBE:
                # Parse SUBSCRIBE
                topics = []
                if len(payload) > 2:
                    offset = 2  # Skip packet ID
                    while offset < len(payload):
                        topic, offset = _decode_utf8_string(payload, offset)
                        if offset < len(payload):
                            qos = payload[offset]
                            offset += 1
                            topics.append({"topic": topic, "qos": qos})

                _capture_event(addr, "MQTT_SUBSCRIBE", {
                    "topics": topics,
                })

                # Send SUBACK
                if len(payload) >= 2:
                    pkt_id = payload[0:2]
                    granted_qos = bytes([0x00] * len(topics))
                    suback = bytes([0x90, 2 + len(topics)]) + pkt_id + granted_qos
                    conn.sendall(suback)

            elif pkt_type == MQTT_PINGREQ:
                _capture_event(addr, "MQTT_PING", {})
                # Send PINGRESP
                conn.sendall(bytes([0xD0, 0x00]))

            elif pkt_type == MQTT_DISCONNECT:
                _capture_event(addr, "MQTT_DISCONNECT", {})
                break

            else:
                _capture_event(addr, "MQTT_UNKNOWN_PACKET", {
                    "packet_type": pkt_type,
                    "payload_hex": payload[:100].hex() if payload else "",
                })

    except socket.timeout:
        _capture_event(addr, "MQTT_TIMEOUT", {"reason": "client idle"})
    except ConnectionResetError:
        _capture_event(addr, "MQTT_CONN_RESET", {})
    except Exception as e:
        _capture_event(addr, "MQTT_ERROR", {"error": str(e)})
    finally:
        conn.close()
        _capture_event(addr, "MQTT_DISCONNECTED", {})


def run_mqtt_listener():
    """Start the MQTT honeypot listener."""
    host = mqtt_cfg["host"]
    port = mqtt_cfg["port"]

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(10)

    logger.info(f"MQTT Honeypot listening on {host}:{port}")
    logger.info(f"Monitoring topics: {mqtt_cfg['topics']}")

    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=_handle_client, args=(conn, addr), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        logger.info("MQTT Listener shutting down.")
    finally:
        server.close()


if __name__ == "__main__":
    run_mqtt_listener()
