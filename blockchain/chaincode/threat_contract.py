"""
HoneyMed - Phase 9: Smart Contract / Chaincode
=================================================
Simulates Hyperledger Fabric chaincode logic in Python.

Key features:
  1. RBAC-gated event submission and query  
  2. Automated 7-day disclosure timer for IOCs  
  3. IOC masking (partial IP, hashed payloads) for public feeds  
  4. Audit trail for every chaincode invocation  

In a real Hyperledger deployment these functions would be compiled
as Go/Java chaincode and installed on the peer nodes. Here we
implement identical logic in Python for local/dev testing.
"""

import hashlib
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from config.loader import get_config, get_base_dir
from utils.logger import get_logger
from blockchain.chaincode.access_control import AccessControl, Role, PERMISSIONS

logger = get_logger("blockchain.chaincode", layer="BLOCKCHAIN", log_file="blockchain_chaincode.jsonl")

# Default IOC grace period before public disclosure (seconds)
DEFAULT_DISCLOSURE_DAYS = 7
DISCLOSURE_SECONDS = DEFAULT_DISCLOSURE_DAYS * 86400

# ---------------------------------------------------------------------------
# Chaincode Database (extends the ledger DB)
# ---------------------------------------------------------------------------
CC_DB_PATH = os.path.join(get_base_dir(), "data", "chaincode_state.db")


def _init_chaincode_db():
    """Create the chaincode state tables if they don't exist."""
    # Ensure data directory exists
    os.makedirs(os.path.dirname(CC_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(CC_DB_PATH)
    c = conn.cursor()

    # IOC records awaiting or past disclosure
    c.execute("""
        CREATE TABLE IF NOT EXISTS ioc_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sha256_hash TEXT UNIQUE NOT NULL,
            threat_label TEXT,
            confidence REAL,
            attacker_ip TEXT,
            masked_ip TEXT,
            submitted_by TEXT,
            org TEXT,
            submitted_at TEXT NOT NULL,
            disclosure_at TEXT NOT NULL,
            disclosed INTEGER DEFAULT 0,
            metadata TEXT
        )
    """)

    # Audit trail for chaincode invocations
    c.execute("""
        CREATE TABLE IF NOT EXISTS chaincode_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user_id TEXT,
            operation TEXT,
            target_hash TEXT,
            result TEXT,
            details TEXT
        )
    """)

    c.execute("CREATE INDEX IF NOT EXISTS idx_ioc_hash ON ioc_records(sha256_hash)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_ioc_disclosure ON ioc_records(disclosed, disclosure_at)")

    conn.commit()
    conn.close()


class ThreatContract:
    """
    Chaincode-equivalent smart contract for threat intelligence management.

    All state-changing methods require an authenticated user_id and are
    gated by the AccessControl RBAC system.
    """

    def __init__(self, access_control: AccessControl | None = None):
        self.ac = access_control or AccessControl()
        self.cfg = get_config()
        disclosure_days = (
            self.cfg.get("blockchain", {})
                .get("chaincode", {})
                .get("disclosure_days", DEFAULT_DISCLOSURE_DAYS)
        )
        self.disclosure_seconds = disclosure_days * 86400
        _init_chaincode_db()
        logger.info(
            f"ThreatContract initialized (disclosure={disclosure_days}d, "
            f"db={CC_DB_PATH})"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _mask_ip(ip: str) -> str:
        """Mask an IPv4 address for public disclosure (e.g., 192.168.1.50 -> 192.168.1.xxx)."""
        parts = ip.split(".")
        if len(parts) == 4:
            parts[-1] = "xxx"
            return ".".join(parts)
        return "masked"

    def _audit(self, user_id: str, operation: str, target_hash: str,
               result: str, details: str = ""):
        """Write an audit log entry."""
        conn = sqlite3.connect(CC_DB_PATH)
        conn.execute(
            "INSERT INTO chaincode_audit (timestamp, user_id, operation, target_hash, result, details) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), user_id, operation, target_hash, result, details),
        )
        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # 1. Submit Threat IOC (write_event)
    # ------------------------------------------------------------------

    def submit_ioc(self, user_id: str, event_hash: str, threat_label: str,
                   confidence: float, attacker_ip: str,
                   metadata: dict | None = None) -> dict:
        """
        Submit a new IOC to the chaincode ledger.

        Requires: write_event permission (ADMIN or HOSPITAL roles).
        
        The IOC enters a grace period before public disclosure.
        """
        self.ac.require_permission(user_id, "write_event")

        org = self.ac.get_user_org(user_id) or "unknown"
        now = datetime.now(timezone.utc)
        disclosure_at = now + timedelta(seconds=self.disclosure_seconds)

        conn = sqlite3.connect(CC_DB_PATH)
        try:
            conn.execute("""
                INSERT OR IGNORE INTO ioc_records
                (sha256_hash, threat_label, confidence, attacker_ip, masked_ip,
                 submitted_by, org, submitted_at, disclosure_at, disclosed, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
            """, (
                event_hash,
                threat_label,
                confidence,
                attacker_ip,
                self._mask_ip(attacker_ip),
                user_id,
                org,
                now.isoformat(),
                disclosure_at.isoformat(),
                json.dumps(metadata or {}),
            ))
            conn.commit()
        finally:
            conn.close()

        self._audit(user_id, "submit_ioc", event_hash, "success")

        logger.info(
            f"IOC submitted by {user_id}: {threat_label} "
            f"(conf={confidence:.2f}, disclosure={disclosure_at.isoformat()})"
        )

        return {
            "status": "submitted",
            "sha256_hash": event_hash,
            "disclosure_at": disclosure_at.isoformat(),
        }

    # ------------------------------------------------------------------
    # 2. Query IOCs (role-gated)
    # ------------------------------------------------------------------

    def query_iocs(self, user_id: str, limit: int = 100,
                   threat_label: str | None = None) -> list[dict]:
        """
        Query IOC records with role-appropriate field visibility.

        - ADMIN / HOSPITAL: see full records including real IP
        - RESEARCHER: see anonymized (masked IP, no raw metadata)
        - PUBLIC: see only disclosed IOCs with masked IP
        """
        role = self.ac.get_user_role(user_id)
        if role is None:
            raise PermissionError(f"Unknown user: {user_id}")

        conn = sqlite3.connect(CC_DB_PATH)
        conn.row_factory = sqlite3.Row

        query = "SELECT * FROM ioc_records"
        params: list = []
        conditions = []

        # Public can only see disclosed IOCs
        if role == Role.PUBLIC:
            self.ac.require_permission(user_id, "read_published_ioc")
            conditions.append("disclosed = 1")
        elif role == Role.RESEARCHER:
            self.ac.require_permission(user_id, "read_anonymized_event")
        else:
            self.ac.require_permission(user_id, "read_full_event")

        if threat_label:
            conditions.append("threat_label = ?")
            params.append(threat_label)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY submitted_at DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        conn.close()

        results = []
        for row in rows:
            record = dict(row)
            if role in (Role.RESEARCHER, Role.PUBLIC):
                # Strip sensitive fields
                record.pop("attacker_ip", None)
                record.pop("submitted_by", None)
                record.pop("metadata", None)
                record["ip"] = record.pop("masked_ip", "masked")
            elif role == Role.HOSPITAL:
                org = self.ac.get_user_org(user_id)
                if record.get("org") != org:
                    # Can't see full details of other orgs
                    record.pop("attacker_ip", None)
                    record["ip"] = record.pop("masked_ip", "masked")
            results.append(record)

        self._audit(user_id, "query_iocs", "", "success", f"returned {len(results)} records")
        return results

    # ------------------------------------------------------------------
    # 3. Automated Disclosure Timer
    # ------------------------------------------------------------------

    def process_disclosures(self, user_id: str = "system_admin") -> list[dict]:
        """
        Check for IOCs past their grace period and mark them as disclosed.

        This would be triggered by a cron job or a Fabric scheduled event.
        Requires manage_disclosure permission (ADMIN only).
        """
        self.ac.require_permission(user_id, "manage_disclosure")

        now = datetime.now(timezone.utc).isoformat()

        conn = sqlite3.connect(CC_DB_PATH)
        conn.row_factory = sqlite3.Row

        # Find IOCs past their grace period
        pending = conn.execute(
            "SELECT id, sha256_hash, threat_label, masked_ip, disclosure_at "
            "FROM ioc_records WHERE disclosed = 0 AND disclosure_at <= ?",
            (now,),
        ).fetchall()

        disclosed = []
        for row in pending:
            conn.execute(
                "UPDATE ioc_records SET disclosed = 1 WHERE id = ?",
                (row["id"],),
            )
            disclosed.append({
                "sha256_hash": row["sha256_hash"],
                "threat_label": row["threat_label"],
                "masked_ip": row["masked_ip"],
                "disclosure_at": row["disclosure_at"],
            })
            logger.info(
                f"IOC disclosed: {row['threat_label']} [{row['masked_ip']}] "
                f"hash={row['sha256_hash'][:16]}..."
            )

        conn.commit()
        conn.close()

        if disclosed:
            self._audit(user_id, "process_disclosures", "", "success",
                        f"disclosed {len(disclosed)} IOCs")
        return disclosed

    # ------------------------------------------------------------------
    # 4. Get Public Threat Feed
    # ------------------------------------------------------------------

    def get_public_feed(self, limit: int = 50) -> list[dict]:
        """
        Return disclosed IOCs in a format suitable for public threat feeds.
        No authentication required (read_published_ioc for PUBLIC role).
        """
        conn = sqlite3.connect(CC_DB_PATH)
        conn.row_factory = sqlite3.Row

        rows = conn.execute(
            "SELECT sha256_hash, threat_label, confidence, masked_ip, "
            "submitted_at, disclosure_at FROM ioc_records "
            "WHERE disclosed = 1 ORDER BY disclosure_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()

        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # 5. Audit Trail
    # ------------------------------------------------------------------

    def get_audit_trail(self, user_id: str, limit: int = 200) -> list[dict]:
        """Retrieve chaincode audit trail. Requires ADMIN role."""
        self.ac.require_permission(user_id, "manage_users")

        conn = sqlite3.connect(CC_DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM chaincode_audit ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()

        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# CLI demo
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=== HoneyMed Chaincode Demo ===\n")

    ac = AccessControl()
    contract = ThreatContract(ac)

    # Register users
    admin_key = ac.register_user("hosp_admin_1", Role.HOSPITAL, org="HospitalA")
    researcher_key = ac.register_user("researcher_1", Role.RESEARCHER, org="University")
    public_key = ac.register_user("public_user", Role.PUBLIC, org="Public")

    # Submit IOCs as hospital admin
    print("\n--- Submit IOCs ---")
    for i, (label, conf, ip) in enumerate([
        ("BruteForce", 0.95, "10.0.0.50"),
        ("DoS", 0.88, "172.16.1.100"),
        ("PortScan", 0.76, "192.168.5.22"),
    ]):
        h = hashlib.sha256(f"event_{i}".encode()).hexdigest()
        result = contract.submit_ioc("hosp_admin_1", h, label, conf, ip)
        print(f"  {result['status']}: {label} -> disclosure at {result['disclosure_at']}")

    # Query as different roles
    print("\n--- Query as hospital admin (full access) ---")
    for rec in contract.query_iocs("hosp_admin_1"):
        print(f"  {rec.get('threat_label')} | IP={rec.get('attacker_ip', rec.get('ip', '?'))}")

    print("\n--- Query as researcher (anonymized) ---")
    for rec in contract.query_iocs("researcher_1"):
        print(f"  {rec.get('threat_label')} | IP={rec.get('ip', '?')}")

    print("\n--- Query as public (should be empty - grace period not elapsed) ---")
    public_iocs = contract.query_iocs("public_user")
    print(f"  Records visible: {len(public_iocs)}")

    # Force disclosure for demo
    print("\n--- Force disclosure (set disclosure_at to past) ---")
    conn = sqlite3.connect(CC_DB_PATH)
    conn.execute("UPDATE ioc_records SET disclosure_at = '2020-01-01T00:00:00+00:00'")
    conn.commit()
    conn.close()

    disclosed = contract.process_disclosures("system_admin")
    print(f"  Disclosed {len(disclosed)} IOCs")

    print("\n--- Public feed after disclosure ---")
    for rec in contract.get_public_feed():
        print(f"  {rec['threat_label']} | {rec['masked_ip']} | conf={rec['confidence']}")

    print("\n--- Audit trail ---")
    for entry in contract.get_audit_trail("system_admin", limit=5):
        print(f"  [{entry['timestamp']}] {entry['user_id']}:{entry['operation']} -> {entry['result']}")

    print("\n[PASS] Chaincode demo complete!")
