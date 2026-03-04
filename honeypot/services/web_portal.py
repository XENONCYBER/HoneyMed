"""
HoneyMed - Layer 1: Web Portal Honeypot
========================================
Simulates a medical device web management interface (patient monitor).
Captures login attempts, page accesses, and injection attacks.

Emulates: VitalSync Pro 3000 — a fictitious patient-monitoring device
with a realistic login portal, device status API, and firmware page.
"""

import json
import os
import time
from datetime import datetime, timezone

from flask import Flask, request, render_template, jsonify, redirect, url_for
from flask_cors import CORS

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from config.loader import get_config
from utils.logger import get_logger

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
cfg = get_config()
hp_cfg = cfg["honeypot"]["web_portal"]

logger = get_logger("honeypot.web_portal", layer="HONEYPOT", log_file="honeypot_web.jsonl")

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates"),
    static_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "static"),
)
app.secret_key = os.urandom(32)
CORS(app)

# In-memory store for captured interactions
CAPTURED_EVENTS: list[dict] = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _capture_event(event_type: str, details: dict | None = None):
    """Record every interaction as a structured JSON event."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "web_portal",
        "event_type": event_type,
        "attacker_ip": request.remote_addr,
        "attacker_port": request.environ.get("REMOTE_PORT", 0),
        "method": request.method,
        "path": request.path,
        "user_agent": request.headers.get("User-Agent", ""),
        "details": details or {},
    }
    CAPTURED_EVENTS.append(event)
    logger.info(
        f"{event_type} from {request.remote_addr} -> {request.path}",
        extra={
            "attacker_ip": request.remote_addr,
            "service": "web_portal",
            "action": event_type,
        },
    )
    return event


# ---------------------------------------------------------------------------
# Fake device data (realistic IoMT patient-monitor responses)
# ---------------------------------------------------------------------------
DEVICE_INFO = {
    "device_name": hp_cfg["device_name"],
    "manufacturer": hp_cfg["manufacturer"],
    "model": hp_cfg["model"],
    "firmware_version": hp_cfg["firmware"],
    "serial_number": "SN-2024-MED-88412",
    "ip_address": "192.168.1.100",
    "mac_address": "00:1A:2B:3C:4D:5E",
    "uptime_hours": 1247,
    "last_calibration": "2025-12-15T08:00:00Z",
    "connected_sensors": [
        {"id": "ECG-01", "type": "ECG", "status": "active"},
        {"id": "SPO2-03", "type": "SpO2", "status": "active"},
        {"id": "NIBP-02", "type": "Blood Pressure", "status": "active"},
        {"id": "TEMP-01", "type": "Temperature", "status": "standby"},
    ],
}

FAKE_VITALS = {
    "patient_id": "*** PHI REDACTED ***",
    "heart_rate": 72,
    "spo2": 98,
    "blood_pressure": {"systolic": 120, "diastolic": 80},
    "temperature_c": 36.7,
    "respiratory_rate": 16,
    "timestamp": datetime.now(timezone.utc).isoformat(),
}


# ---------------------------------------------------------------------------
# Routes - Realistic Medical Device Web Interface
# ---------------------------------------------------------------------------
@app.before_request
def log_every_request():
    """Capture every single request hitting the honeypot."""
    _capture_event("HTTP_REQUEST", {
        "headers": dict(request.headers),
        "query_params": dict(request.args),
    })


@app.route("/")
def index():
    """Device landing page — redirects to login."""
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Fake login page mimicking a medical device web UI.
    Captures all credential attempts.
    """
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        _capture_event("LOGIN_ATTEMPT", {
            "username": username,
            "password": password,
        })

        # Always fail — but with a realistic delay
        time.sleep(1.2)
        return render_template(
            "login.html",
            device=DEVICE_INFO,
            error="Authentication failed. Contact your system administrator.",
        )

    return render_template("login.html", device=DEVICE_INFO, error=None)


@app.route("/dashboard")
def device_dashboard():
    """Fake device dashboard — appears if attacker guesses a session."""
    _capture_event("DASHBOARD_ACCESS")
    return render_template("device_dashboard.html", device=DEVICE_INFO, vitals=FAKE_VITALS)


@app.route("/api/v1/device/info")
def api_device_info():
    """REST API endpoint returning device metadata (realistic bait)."""
    _capture_event("API_DEVICE_INFO")
    return jsonify(DEVICE_INFO)


@app.route("/api/v1/vitals/current")
def api_vitals():
    """REST API returning current patient vitals (PHI-redacted bait)."""
    _capture_event("API_VITALS_ACCESS")
    return jsonify(FAKE_VITALS)


@app.route("/api/v1/firmware/update", methods=["GET", "POST"])
def firmware_update():
    """
    Fake firmware update endpoint.
    Attackers often probe for this to upload malicious firmware.
    """
    if request.method == "POST":
        _capture_event("FIRMWARE_UPLOAD_ATTEMPT", {
            "content_type": request.content_type,
            "content_length": request.content_length,
            "filename": request.files.get("firmware", {}).filename
            if request.files.get("firmware")
            else None,
        })
        return jsonify({"status": "error", "message": "Firmware signature verification failed."}), 403

    _capture_event("FIRMWARE_PAGE_ACCESS")
    return jsonify({
        "current_version": hp_cfg["firmware"],
        "update_available": True,
        "latest_version": "v2.5.0",
        "release_notes": "Security patches and performance improvements.",
    })


@app.route("/api/v1/config", methods=["GET", "POST"])
def device_config():
    """
    Device configuration endpoint.
    GET:  returns current config (bait).
    POST: captures any config change attempts.
    """
    if request.method == "POST":
        _capture_event("CONFIG_CHANGE_ATTEMPT", {
            "body": request.get_json(silent=True) or request.form.to_dict(),
        })
        return jsonify({"status": "error", "message": "Insufficient privileges."}), 403

    _capture_event("CONFIG_ACCESS")
    return jsonify({
        "network": {"dhcp": True, "ip": "192.168.1.100", "gateway": "192.168.1.1"},
        "display": {"brightness": 80, "auto_dim": True},
        "alarms": {"high_hr": 120, "low_hr": 50, "low_spo2": 90},
    })


@app.route("/hl7")
def hl7_info():
    """Fake HL7 integration status page."""
    _capture_event("HL7_PAGE_ACCESS")
    return jsonify({
        "hl7_version": "2.5.1",
        "sending_facility": "ICU_MONITOR_01",
        "receiving_facility": "HIS_MAIN",
        "connection_status": "active",
        "last_message_sent": datetime.now(timezone.utc).isoformat(),
    })


# Catch-all for any other path probing
@app.errorhandler(404)
def catch_all(e):
    _capture_event("PATH_PROBE", {"attempted_path": request.path})
    return jsonify({"error": "Resource not found"}), 404


# ---------------------------------------------------------------------------
# Internal API: Retrieve captured events (used by Layer 2 pipeline)
# ---------------------------------------------------------------------------
@app.route("/internal/events")
def get_events():
    """Return all captured events from ALL honeypot services (consumed by the data pipeline)."""
    all_events = list(CAPTURED_EVENTS)

    # Aggregate events from other honeypot services (running as co-located threads)
    try:
        from honeypot.services.hl7_listener import HL7_EVENTS
        all_events.extend(HL7_EVENTS)
    except (ImportError, Exception):
        pass
    try:
        from honeypot.services.dicom_listener import DICOM_EVENTS
        all_events.extend(DICOM_EVENTS)
    except (ImportError, Exception):
        pass
    try:
        from honeypot.services.mqtt_listener import MQTT_EVENTS
        all_events.extend(MQTT_EVENTS)
    except (ImportError, Exception):
        pass
    try:
        from honeypot.services.ssh_listener import SSH_EVENTS
        all_events.extend(SSH_EVENTS)
    except (ImportError, Exception):
        pass

    # Sort chronologically
    all_events.sort(key=lambda e: e.get("timestamp", ""))
    return jsonify(all_events)


@app.route("/internal/events/count")
def get_event_count():
    return jsonify({"count": len(CAPTURED_EVENTS)})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def run_web_portal():
    """Start the Web Portal honeypot."""
    logger.info(f"Starting Web Portal Honeypot on port {hp_cfg['port']}")
    logger.info(f"Emulating: {hp_cfg['device_name']} ({hp_cfg['manufacturer']})")
    app.run(host=hp_cfg["host"], port=hp_cfg["port"], debug=False, threaded=True)


if __name__ == "__main__":
    run_web_portal()
