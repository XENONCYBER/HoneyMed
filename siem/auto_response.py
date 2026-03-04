"""
HoneyMed - Phase 11: Automated Response Engine
=================================================
Demonstrates how a threat caught by the honeypot + ML pipeline can
trigger automated actions in the enterprise security stack:

  1. Firewall IP blocking (iptables / Windows Firewall simulation)
  2. Auto-block based on ML confidence thresholds
  3. Block list management (add/remove/list/export)
  4. Integration hook for SIEM-triggered workflows

In production, this module would interface with:
  - pf/iptables/nftables on Linux
  - Windows Firewall / Defender APIs
  - Cloud WAF APIs (AWS WAF, Azure NSG, Cloudflare)
  - Network equipment APIs (Palo Alto, Fortinet, Cisco)

For safety, the default mode is "simulate" — it logs actions
without actually modifying any firewall rules.
"""

import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.loader import get_config, get_base_dir
from utils.logger import get_logger

logger = get_logger("siem.auto_response", layer="SIEM", log_file="siem_autoresponse.jsonl")

RESPONSE_DB = os.path.join(get_base_dir(), "data", "auto_response.db")


def _init_response_db():
    """Create the auto-response tracking database."""
    # Ensure data directory exists
    os.makedirs(os.path.dirname(RESPONSE_DB), exist_ok=True)
    conn = sqlite3.connect(RESPONSE_DB)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            reason TEXT,
            threat_label TEXT,
            confidence REAL,
            sha256_hash TEXT,
            blocked_at TEXT NOT NULL,
            expires_at TEXT,
            active INTEGER DEFAULT 1,
            source TEXT DEFAULT 'auto'
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS response_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT,
            target_ip TEXT,
            details TEXT,
            result TEXT
        )
    """)

    c.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ip ON blocked_ips(ip)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_blocked_active ON blocked_ips(active)")

    conn.commit()
    conn.close()


class AutoResponse:
    """
    Automated response engine that blocks attacker IPs based on
    ML-classified threats from the pipeline.
    """

    def __init__(self, mode: str = "simulate"):
        """
        Args:
            mode: 'simulate' (log only) or 'enforce' (actually modify firewall).
                  Default is 'simulate' for safety.
        """
        cfg = get_config()
        response_cfg = cfg.get("siem", {}).get("auto_response", {})

        self.mode = response_cfg.get("mode", mode)
        self.confidence_threshold = response_cfg.get("confidence_threshold", 0.85)
        self.auto_block_labels = response_cfg.get(
            "auto_block_labels",
            ["DoS", "BruteForce"],
        )
        self.block_duration_hours = response_cfg.get("block_duration_hours", 24)

        # Whitelisted IPs that should never be blocked
        self.whitelist = set(response_cfg.get("whitelist", [
            "127.0.0.1", "::1", "0.0.0.0",
        ]))

        _init_response_db()
        logger.info(
            f"AutoResponse initialized: mode={self.mode}, "
            f"threshold={self.confidence_threshold}, "
            f"auto_labels={self.auto_block_labels}"
        )

    # ------------------------------------------------------------------
    # IP Blocking
    # ------------------------------------------------------------------

    def block_ip(self, ip: str, reason: str = "", threat_label: str = "",
                 confidence: float = 0.0, sha256_hash: str = "") -> dict:
        """
        Block an IP address.

        In 'simulate' mode, only logs and records the action.
        In 'enforce' mode, would also add a firewall rule.
        """
        if ip in self.whitelist:
            logger.info(f"IP {ip} is whitelisted — skipping block")
            return {"status": "whitelisted", "ip": ip}

        # Check if already blocked
        if self.is_blocked(ip):
            return {"status": "already_blocked", "ip": ip}

        now = datetime.now(timezone.utc)
        from datetime import timedelta
        expires_at = now + timedelta(hours=self.block_duration_hours)

        # Record in database
        conn = sqlite3.connect(RESPONSE_DB)
        conn.execute(
            "INSERT INTO blocked_ips "
            "(ip, reason, threat_label, confidence, sha256_hash, blocked_at, expires_at, active, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
            (ip, reason, threat_label, confidence, sha256_hash,
             now.isoformat(), expires_at.isoformat(), "auto" if not reason else "manual"),
        )
        conn.execute(
            "INSERT INTO response_log (timestamp, action, target_ip, details, result) "
            "VALUES (?, 'block', ?, ?, ?)",
            (now.isoformat(), ip, f"label={threat_label}, conf={confidence:.2f}",
             self.mode),
        )
        conn.commit()
        conn.close()

        # In enforce mode, actually add firewall rule
        if self.mode == "enforce":
            self._apply_firewall_block(ip)

        logger.warning(
            f"IP BLOCKED [{self.mode}]: {ip} | {threat_label} | "
            f"conf={confidence:.2f} | expires={expires_at.isoformat()}"
        )

        return {
            "status": "blocked",
            "mode": self.mode,
            "ip": ip,
            "threat_label": threat_label,
            "confidence": confidence,
            "expires_at": expires_at.isoformat(),
        }

    def unblock_ip(self, ip: str) -> dict:
        """Remove an IP from the block list."""
        conn = sqlite3.connect(RESPONSE_DB)
        conn.execute("UPDATE blocked_ips SET active = 0 WHERE ip = ? AND active = 1", (ip,))
        conn.execute(
            "INSERT INTO response_log (timestamp, action, target_ip, details, result) "
            "VALUES (?, 'unblock', ?, '', ?)",
            (datetime.now(timezone.utc).isoformat(), ip, self.mode),
        )
        conn.commit()
        conn.close()

        if self.mode == "enforce":
            self._remove_firewall_block(ip)

        logger.info(f"IP UNBLOCKED [{self.mode}]: {ip}")
        return {"status": "unblocked", "ip": ip}

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        conn = sqlite3.connect(RESPONSE_DB)
        row = conn.execute(
            "SELECT COUNT(*) FROM blocked_ips WHERE ip = ? AND active = 1",
            (ip,),
        ).fetchone()
        conn.close()
        return row[0] > 0

    def get_blocked_ips(self, active_only: bool = True) -> list[dict]:
        """List all blocked IPs."""
        conn = sqlite3.connect(RESPONSE_DB)
        conn.row_factory = sqlite3.Row

        query = "SELECT * FROM blocked_ips"
        if active_only:
            query += " WHERE active = 1"
        query += " ORDER BY blocked_at DESC"

        rows = conn.execute(query).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Automated Blocking (ML-triggered)
    # ------------------------------------------------------------------

    def evaluate_threat(self, event: dict, prediction: dict) -> dict | None:
        """
        Evaluate whether a classified event warrants automatic blocking.

        Args:
            event:      Raw event dict (must include 'attacker_ip').
            prediction: ML prediction dict with 'label', 'confidence', 'is_attack'.

        Returns:
            Block result dict if blocked, None if no action taken.
        """
        if not prediction.get("is_attack"):
            return None

        label = prediction.get("label", "")
        confidence = prediction.get("confidence", 0)
        ip = event.get("attacker_ip", "")

        if not ip:
            return None

        # Auto-block criteria: label in auto-block list AND confidence above threshold
        if label in self.auto_block_labels and confidence >= self.confidence_threshold:
            return self.block_ip(
                ip=ip,
                reason=f"Auto-blocked: {label} detected with {confidence:.0%} confidence",
                threat_label=label,
                confidence=confidence,
                sha256_hash=prediction.get("sha256", ""),
            )

        return None

    # ------------------------------------------------------------------
    # Expiry Management
    # ------------------------------------------------------------------

    def cleanup_expired(self) -> int:
        """Remove expired blocks. Returns number of blocks expired."""
        now = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect(RESPONSE_DB)

        expired = conn.execute(
            "SELECT ip FROM blocked_ips WHERE active = 1 AND expires_at <= ?",
            (now,),
        ).fetchall()

        conn.execute(
            "UPDATE blocked_ips SET active = 0 WHERE active = 1 AND expires_at <= ?",
            (now,),
        )
        conn.commit()
        conn.close()

        for row in expired:
            if self.mode == "enforce":
                self._remove_firewall_block(row[0])
            logger.info(f"Block expired: {row[0]}")

        return len(expired)

    # ------------------------------------------------------------------
    # Firewall Integration (platform-specific)
    # ------------------------------------------------------------------

    def _apply_firewall_block(self, ip: str):
        """
        Apply an actual firewall rule to block an IP.

        WARNING: Only runs in 'enforce' mode. Requires admin/root privileges.
        """
        import platform as _platform

        if _platform.system() == "Windows":
            cmd = (
                f'netsh advfirewall firewall add rule name="HoneyMed_Block_{ip}" '
                f'dir=in action=block remoteip={ip}'
            )
        else:
            cmd = f"iptables -A INPUT -s {ip} -j DROP"

        logger.warning(f"ENFORCE: Would execute: {cmd}")
        # NOT actually executing for safety. In production, uncomment:
        # import subprocess
        # subprocess.run(cmd, shell=True, check=True)

    def _remove_firewall_block(self, ip: str):
        """Remove a firewall rule for an IP."""
        import platform as _platform

        if _platform.system() == "Windows":
            cmd = f'netsh advfirewall firewall delete rule name="HoneyMed_Block_{ip}"'
        else:
            cmd = f"iptables -D INPUT -s {ip} -j DROP"

        logger.info(f"ENFORCE: Would execute: {cmd}")

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_blocklist(self, format: str = "json") -> str:
        """
        Export the current block list.

        Formats: 'json', 'csv', 'plain' (one IP per line)
        """
        blocked = self.get_blocked_ips(active_only=True)

        if format == "csv":
            lines = ["ip,threat_label,confidence,blocked_at,expires_at"]
            for b in blocked:
                lines.append(
                    f"{b['ip']},{b.get('threat_label','')},{b.get('confidence',0)},"
                    f"{b.get('blocked_at','')},{b.get('expires_at','')}"
                )
            return "\n".join(lines)

        elif format == "plain":
            return "\n".join(b["ip"] for b in blocked)

        else:
            return json.dumps(blocked, indent=2)

    def get_response_log(self, limit: int = 100) -> list[dict]:
        """Get recent auto-response actions."""
        conn = sqlite3.connect(RESPONSE_DB)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM response_log ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# CLI demo
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=== HoneyMed Auto-Response Demo ===\n")

    responder = AutoResponse(mode="simulate")

    # Simulate blocking
    print("--- Manual block ---")
    result = responder.block_ip("10.0.0.50", reason="Testing", threat_label="DoS", confidence=0.92)
    print(f"  {result['status']}: {result['ip']} (mode={result['mode']})")

    # Auto-evaluate
    print("\n--- Auto-evaluate threats ---")
    events = [
        ({"attacker_ip": "192.168.1.100"}, {"label": "BruteForce", "confidence": 0.95, "is_attack": True}),
        ({"attacker_ip": "192.168.1.200"}, {"label": "PortScan", "confidence": 0.60, "is_attack": True}),
        ({"attacker_ip": "10.0.0.1"}, {"label": "DoS", "confidence": 0.92, "is_attack": True}),
        ({"attacker_ip": "172.16.0.5"}, {"label": "Benign", "confidence": 0.99, "is_attack": False}),
    ]
    for event, pred in events:
        r = responder.evaluate_threat(event, pred)
        action = r["status"] if r else "no action"
        print(f"  {event['attacker_ip']:16s} | {pred['label']:12s} | conf={pred['confidence']:.2f} | {action}")

    # List blocked
    print(f"\n--- Blocked IPs ({len(responder.get_blocked_ips())}) ---")
    for b in responder.get_blocked_ips():
        print(f"  {b['ip']:16s} | {b.get('threat_label','?'):12s} | expires={b.get('expires_at','')}")

    # Export
    print(f"\n--- Block list (plain) ---")
    print(responder.export_blocklist("plain"))

    print("\n[PASS] Auto-response demo complete!")
