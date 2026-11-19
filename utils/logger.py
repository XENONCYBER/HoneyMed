"""
HoneyMed - Shared Logging Utility
Provides structured JSON logging for all layers.
All logs are JSON-formatted for blockchain compatibility.
"""

import json
import logging
import os
import sys
import hashlib
from datetime import datetime, timezone

from config.loader import get_base_dir


class LayerFilter(logging.Filter):
    """Injects the 'layer' attribute into every log record for this logger."""

    def __init__(self, layer: str):
        super().__init__()
        self.layer = layer

    def filter(self, record: logging.LogRecord) -> bool:
        record.layer = self.layer
        return True


class JSONFormatter(logging.Formatter):
    """Custom formatter that outputs log records as JSON lines."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "layer": getattr(record, "layer", "GENERAL"),
            "source": record.name,
            "message": record.getMessage(),
        }

        # Attach extra fields if present
        for key in ("attacker_ip", "attacker_port", "service", "action",
                     "protocol", "payload", "prediction", "confidence"):
            val = getattr(record, key, None)
            if val is not None:
                log_entry[key] = val

        # Generate SHA-256 hash for blockchain readiness
        raw = json.dumps(log_entry, sort_keys=True)
        log_entry["sha256"] = hashlib.sha256(raw.encode()).hexdigest()

        return json.dumps(log_entry)


def _open_file_handler(log_dir: str, log_file: str) -> logging.FileHandler | None:
    """
    Open a JSON log file for appending, recovering from permission problems.

    Log files created by an earlier `sudo`/root run are owned by root and make
    every later unprivileged run fail with PermissionError. When that happens we
    move the old file aside (keeping its contents) and start a fresh one.
    """
    try:
        os.makedirs(log_dir, exist_ok=True)
    except OSError as exc:
        print(f"[logging] cannot create {log_dir} ({exc}); file logging disabled",
              file=sys.stderr)
        return None

    path = os.path.join(log_dir, log_file)

    if os.path.exists(path) and not os.access(path, os.W_OK):
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = f"{path}.{stamp}.unwritable"
        try:
            os.replace(path, backup)
            print(f"[logging] {path} was not writable; moved it to {backup}",
                  file=sys.stderr)
        except OSError as exc:
            print(f"[logging] {path} is not writable ({exc}); file logging disabled",
                  file=sys.stderr)
            return None

    try:
        return logging.FileHandler(path, encoding="utf-8")
    except OSError as exc:
        print(f"[logging] cannot open {path} ({exc}); file logging disabled",
              file=sys.stderr)
        return None


def get_logger(name: str, layer: str = "GENERAL", log_file: str | None = None) -> logging.Logger:
    """
    Create a logger that writes JSON-structured logs.

    Args:
        name:     Logger name (e.g., 'honeypot.web_portal').
        layer:    Which architectural layer (HONEYPOT, PIPELINE, ML, DASHBOARD).
        log_file: Optional filename inside the logs/ directory.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # already configured

    logger.setLevel(logging.DEBUG)

    # Per-logger filter to inject layer attribute (avoids global state)
    logger.addFilter(LayerFilter(layer))

    # Console handler (colored summary)
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(
        f"[%(asctime)s] [{layer}] %(name)s :: %(message)s",
        datefmt="%H:%M:%S",
    ))
    logger.addHandler(console)

    # File handler (full JSON)
    if log_file:
        log_dir = os.path.join(get_base_dir(), "logs")
        fh = _open_file_handler(log_dir, log_file)
        if fh is not None:
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(JSONFormatter())
            logger.addHandler(fh)

    return logger
