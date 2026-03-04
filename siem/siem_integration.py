"""
HoneyMed - Phase 11: SIEM Platform Integration
=================================================
Adapters for pushing HoneyMed threat intelligence into enterprise
SIEM platforms:

  1. Splunk  — HTTP Event Collector (HEC)
  2. IBM QRadar — Syslog LEEF format
  3. Elastic Security — Elasticsearch bulk index API

Each adapter reads classified events from the pipeline database
and formats them according to the target SIEM's ingestion protocol.
"""

import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.loader import get_config, get_base_dir
from utils.logger import get_logger

logger = get_logger("siem.integration", layer="SIEM", log_file="siem_integration.jsonl")

DATA_DIR = os.path.join(get_base_dir(), "data")
EVENTS_DB = os.path.join(DATA_DIR, "classified_events.db")


def _get_recent_attacks(limit: int = 100, since: str | None = None) -> list[dict]:
    """Fetch recent attack events from the pipeline DB."""
    if not os.path.exists(EVENTS_DB):
        return []

    conn = sqlite3.connect(EVENTS_DB)
    conn.row_factory = sqlite3.Row

    query = "SELECT * FROM classified_events WHERE is_attack = 1"
    params: list = []
    if since:
        query += " AND timestamp >= ?"
        params.append(since)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, tuple(params)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


class SplunkAdapter:
    """
    Push events to Splunk via the HTTP Event Collector (HEC).

    Config (settings.yaml -> siem.splunk):
      hec_url:  "https://splunk-server:8088/services/collector/event"
      hec_token: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
      index:     "honeymed"
      sourcetype: "honeymed:threat"
    """

    def __init__(self):
        cfg = get_config().get("siem", {}).get("splunk", {})
        self.hec_url = cfg.get("hec_url", "https://localhost:8088/services/collector/event")
        self.hec_token = cfg.get("hec_token", "")
        self.index = cfg.get("index", "honeymed")
        self.sourcetype = cfg.get("sourcetype", "honeymed:threat")

    def format_event(self, event: dict) -> dict:
        """Format a classified event as a Splunk HEC JSON payload."""
        return {
            "time": event.get("timestamp", ""),
            "host": "honeymed",
            "source": "honeymed_pipeline",
            "sourcetype": self.sourcetype,
            "index": self.index,
            "event": {
                "sha256": event.get("sha256_hash", ""),
                "threat_label": event.get("label", ""),
                "confidence": event.get("confidence", 0),
                "attacker_ip": event.get("attacker_ip", ""),
                "service": event.get("service", ""),
                "protocol": event.get("protocol", ""),
                "payload_size": event.get("payload_size", 0),
                "is_attack": event.get("is_attack", 0),
            },
        }

    def push_events(self, events: list[dict] | None = None) -> dict:
        """
        Push events to Splunk HEC.

        If no events provided, fetches recent attacks from DB.
        Returns a summary of the push operation.
        """
        if events is None:
            events = _get_recent_attacks()

        if not events:
            return {"status": "no_events", "count": 0}

        formatted = [self.format_event(e) for e in events]

        if not self.hec_token:
            logger.warning("Splunk HEC token not configured — simulating push")
            return {
                "status": "simulated",
                "count": len(formatted),
                "sample": formatted[0] if formatted else None,
            }

        # Real push via requests
        try:
            import requests
            headers = {"Authorization": f"Splunk {self.hec_token}"}
            payload = "\n".join(json.dumps(e) for e in formatted)
            resp = requests.post(
                self.hec_url, data=payload, headers=headers,
                verify=False, timeout=10,
            )
            return {
                "status": "sent",
                "count": len(formatted),
                "response_code": resp.status_code,
            }
        except Exception as e:
            logger.error(f"Splunk push failed: {e}")
            return {"status": "error", "error": str(e), "count": len(formatted)}


class QRadarAdapter:
    """
    Push events to IBM QRadar via syslog (LEEF format).

    Config (settings.yaml -> siem.qradar):
      host: "qradar-server"
      port: 514
      protocol: "udp"  # or "tcp"
    """

    def __init__(self):
        cfg = get_config().get("siem", {}).get("qradar", {})
        self.host = cfg.get("host", "localhost")
        self.port = cfg.get("port", 514)
        self.protocol = cfg.get("protocol", "udp")

    def format_leef(self, event: dict) -> str:
        """
        Format a classified event as a LEEF (Log Event Extended Format) line
        for QRadar ingestion.
        """
        leef_header = (
            f"LEEF:2.0|HoneyMed|IoMT-Honeypot|1.0|{event.get('label', 'Unknown')}|"
        )
        attributes = {
            "devTime": event.get("timestamp", ""),
            "src": event.get("attacker_ip", ""),
            "proto": event.get("protocol", ""),
            "sev": self._severity(event.get("confidence", 0)),
            "cat": event.get("service", ""),
            "sha256": event.get("sha256_hash", ""),
            "payloadSize": str(event.get("payload_size", 0)),
            "isAttack": str(event.get("is_attack", 0)),
        }
        attr_str = "\t".join(f"{k}={v}" for k, v in attributes.items())
        return leef_header + attr_str

    @staticmethod
    def _severity(confidence: float) -> str:
        """Map confidence to QRadar severity (1-10)."""
        if confidence >= 0.9:
            return "9"
        elif confidence >= 0.7:
            return "7"
        elif confidence >= 0.5:
            return "5"
        return "3"

    def push_events(self, events: list[dict] | None = None) -> dict:
        """Send events to QRadar via syslog."""
        if events is None:
            events = _get_recent_attacks()

        if not events:
            return {"status": "no_events", "count": 0}

        leef_lines = [self.format_leef(e) for e in events]

        if self.host == "localhost" and self.port == 514:
            logger.warning("QRadar syslog not configured — simulating push")
            return {
                "status": "simulated",
                "count": len(leef_lines),
                "sample": leef_lines[0] if leef_lines else None,
            }

        try:
            import socket
            if self.protocol == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.host, self.port))

            for line in leef_lines:
                msg = (line + "\n").encode("utf-8")
                if self.protocol == "udp":
                    sock.sendto(msg, (self.host, self.port))
                else:
                    sock.sendall(msg)

            sock.close()
            return {"status": "sent", "count": len(leef_lines)}
        except Exception as e:
            logger.error(f"QRadar push failed: {e}")
            return {"status": "error", "error": str(e), "count": len(leef_lines)}


class ElasticAdapter:
    """
    Push events to Elastic Security / Elasticsearch.

    Config (settings.yaml -> siem.elastic):
      url: "http://elasticsearch:9200"
      index: "honeymed-threats"
      api_key: ""
    """

    def __init__(self):
        cfg = get_config().get("siem", {}).get("elastic", {})
        self.url = cfg.get("url", "http://localhost:9200")
        self.index = cfg.get("index", "honeymed-threats")
        self.api_key = cfg.get("api_key", "")

    def format_event(self, event: dict) -> dict:
        """Format a classified event for Elasticsearch indexing."""
        return {
            "@timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "event": {
                "kind": "alert",
                "category": "intrusion_detection",
                "module": "honeymed",
            },
            "threat": {
                "indicator": {
                    "type": "ipv4-addr",
                    "ip": event.get("attacker_ip", ""),
                },
                "technique": {
                    "name": event.get("label", "Unknown"),
                },
            },
            "source": {"ip": event.get("attacker_ip", "")},
            "honeymed": {
                "sha256": event.get("sha256_hash", ""),
                "label": event.get("label", ""),
                "confidence": event.get("confidence", 0),
                "service": event.get("service", ""),
                "protocol": event.get("protocol", ""),
                "payload_size": event.get("payload_size", 0),
                "is_attack": event.get("is_attack", 0),
            },
        }

    def push_events(self, events: list[dict] | None = None) -> dict:
        """Bulk-index events into Elasticsearch."""
        if events is None:
            events = _get_recent_attacks()

        if not events:
            return {"status": "no_events", "count": 0}

        formatted = [self.format_event(e) for e in events]

        if self.url == "http://localhost:9200" and not self.api_key:
            logger.warning("Elasticsearch not configured — simulating push")
            return {
                "status": "simulated",
                "count": len(formatted),
                "sample": formatted[0] if formatted else None,
            }

        try:
            import requests

            # Elasticsearch bulk API format
            bulk_body = ""
            for doc in formatted:
                bulk_body += json.dumps({"index": {"_index": self.index}}) + "\n"
                bulk_body += json.dumps(doc) + "\n"

            headers = {"Content-Type": "application/x-ndjson"}
            if self.api_key:
                headers["Authorization"] = f"ApiKey {self.api_key}"

            resp = requests.post(
                f"{self.url}/_bulk",
                data=bulk_body,
                headers=headers,
                timeout=15,
            )
            return {
                "status": "sent",
                "count": len(formatted),
                "response_code": resp.status_code,
            }
        except Exception as e:
            logger.error(f"Elasticsearch push failed: {e}")
            return {"status": "error", "error": str(e), "count": len(formatted)}


class SIEMIntegration:
    """
    Unified interface for pushing threat data to any configured SIEM.
    Reads the siem.enabled_platforms list from config to determine
    which adapters to activate.
    """

    def __init__(self):
        cfg = get_config().get("siem", {})
        self.enabled = cfg.get("enabled_platforms", [])

        self.adapters: dict = {}
        adapter_map = {
            "splunk": SplunkAdapter,
            "qradar": QRadarAdapter,
            "elastic": ElasticAdapter,
        }

        for platform in self.enabled:
            platform = platform.lower()
            if platform in adapter_map:
                self.adapters[platform] = adapter_map[platform]()
                logger.info(f"SIEM adapter loaded: {platform}")

        if not self.adapters:
            logger.info("No SIEM platforms configured — running in standalone mode")

    def push_all(self, events: list[dict] | None = None) -> dict:
        """Push events to all enabled SIEM platforms."""
        results = {}
        for name, adapter in self.adapters.items():
            try:
                results[name] = adapter.push_events(events)
            except Exception as e:
                results[name] = {"status": "error", "error": str(e)}
                logger.error(f"SIEM push to {name} failed: {e}")
        return results

    def get_status(self) -> dict:
        """Return which SIEM platforms are configured."""
        return {
            "enabled_platforms": list(self.adapters.keys()),
            "total_adapters": len(self.adapters),
        }


# ---------------------------------------------------------------------------
# CLI demo
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=== HoneyMed SIEM Integration Demo ===\n")

    # Test formatting
    sample_event = {
        "timestamp": "2026-01-15T10:30:00+00:00",
        "attacker_ip": "192.168.1.50",
        "service": "web_portal",
        "label": "BruteForce",
        "confidence": 0.95,
        "protocol": "HTTP",
        "sha256_hash": "abc123def456",
        "payload_size": 1024,
        "is_attack": 1,
    }

    print("--- Splunk HEC Format ---")
    splunk = SplunkAdapter()
    print(json.dumps(splunk.format_event(sample_event), indent=2))

    print("\n--- QRadar LEEF Format ---")
    qradar = QRadarAdapter()
    print(qradar.format_leef(sample_event))

    print("\n--- Elastic ECS Format ---")
    elastic = ElasticAdapter()
    print(json.dumps(elastic.format_event(sample_event), indent=2))

    # Test unified push (simulated)
    print("\n--- Unified SIEM Push (simulated) ---")
    integration = SIEMIntegration()
    results = integration.push_all([sample_event])
    print(f"  Status: {integration.get_status()}")

    print("\n[PASS] SIEM integration demo complete!")
