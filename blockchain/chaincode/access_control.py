"""
HoneyMed - Phase 9: Role-Based Access Control (RBAC)
======================================================
Governs who can read/write what on the threat intelligence ledger.

Roles:
  - ADMIN:       Full access (read/write all data, manage users)
  - HOSPITAL:    Read own full logs, write events, query anonymized from others
  - RESEARCHER:  Query anonymized / masked threat data only
  - PUBLIC:      View published IOCs after disclosure period ends
"""

import hashlib
import hmac
import os
import secrets
import sys
from enum import Enum

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from utils.logger import get_logger

logger = get_logger("blockchain.access_control", layer="BLOCKCHAIN", log_file="blockchain_access.jsonl")


class Role(Enum):
    ADMIN = "admin"
    HOSPITAL = "hospital_admin"
    RESEARCHER = "researcher"
    PUBLIC = "public"


# Permission matrix: operation -> set of roles that can perform it
PERMISSIONS = {
    "write_event":            {Role.ADMIN, Role.HOSPITAL},
    "read_full_event":        {Role.ADMIN, Role.HOSPITAL},
    "read_anonymized_event":  {Role.ADMIN, Role.HOSPITAL, Role.RESEARCHER},
    "read_published_ioc":     {Role.ADMIN, Role.HOSPITAL, Role.RESEARCHER, Role.PUBLIC},
    "manage_disclosure":      {Role.ADMIN},
    "manage_users":           {Role.ADMIN},
    "query_chain":            {Role.ADMIN, Role.HOSPITAL, Role.RESEARCHER},
    "verify_hash":            {Role.ADMIN, Role.HOSPITAL, Role.RESEARCHER, Role.PUBLIC},
}


class AccessControl:
    """
    Simple in-memory RBAC system for the chaincode layer.

    In production this would be backed by Hyperledger Fabric's MSP
    (Membership Service Provider) and X.509 certificates.
    """

    def __init__(self):
        # user_id -> {role, org, api_key_hash}
        self._users: dict[str, dict] = {}
        self._api_keys: dict[str, str] = {}  # api_key_hash -> user_id

        # Bootstrap a default admin
        self._bootstrap_admin()

    def _bootstrap_admin(self):
        """Create a default admin user if none exists."""
        if not self._users:
            admin_key = self.register_user("system_admin", Role.ADMIN, org="HoneyMed")
            logger.info(f"Bootstrapped default admin user 'system_admin'.")

    # ------------------------------------------------------------------
    # User Management
    # ------------------------------------------------------------------

    def register_user(self, user_id: str, role: Role, org: str = "default") -> str:
        """
        Register a new user and return their API key.

        Args:
            user_id: Unique user identifier.
            role:    Role enum value.
            org:     Organization name (for multi-hospital scenarios).

        Returns:
            API key string (only shown once).
        """
        api_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        self._users[user_id] = {
            "role": role,
            "org": org,
            "api_key_hash": key_hash,
            "active": True,
        }
        self._api_keys[key_hash] = user_id

        logger.info(f"User registered: {user_id} [{role.value}] org={org}")
        return api_key

    def authenticate(self, api_key: str) -> str | None:
        """
        Validate an API key and return the user_id, or None if invalid.
        """
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        user_id = self._api_keys.get(key_hash)
        if user_id and self._users.get(user_id, {}).get("active", False):
            return user_id
        return None

    def get_user_role(self, user_id: str) -> Role | None:
        """Get the role of a registered user."""
        user = self._users.get(user_id)
        if user:
            return user["role"]
        return None

    def get_user_org(self, user_id: str) -> str | None:
        """Get the organization of a registered user."""
        user = self._users.get(user_id)
        if user:
            return user["org"]
        return None

    def deactivate_user(self, user_id: str) -> bool:
        """Deactivate a user account."""
        if user_id in self._users:
            self._users[user_id]["active"] = False
            logger.info(f"User deactivated: {user_id}")
            return True
        return False

    # ------------------------------------------------------------------
    # Authorization
    # ------------------------------------------------------------------

    def check_permission(self, user_id: str, operation: str) -> bool:
        """
        Check if a user is authorized for the given operation.

        Args:
            user_id:   The authenticated user identifier.
            operation: One of the keys in PERMISSIONS dict.

        Returns:
            True if authorized, False otherwise.
        """
        user = self._users.get(user_id)
        if not user or not user.get("active", False):
            logger.warning(f"Permission denied: unknown or inactive user '{user_id}'")
            return False

        role = user["role"]
        allowed_roles = PERMISSIONS.get(operation, set())

        if role in allowed_roles:
            return True

        logger.warning(
            f"Permission denied: user '{user_id}' (role={role.value}) "
            f"not allowed for '{operation}'"
        )
        return False

    def require_permission(self, user_id: str, operation: str):
        """Same as check_permission but raises PermissionError on denial."""
        if not self.check_permission(user_id, operation):
            raise PermissionError(
                f"User '{user_id}' is not authorized for operation '{operation}'"
            )

    def list_users(self) -> list[dict]:
        """Return a summary of all registered users (no secrets)."""
        return [
            {"user_id": uid, "role": info["role"].value, "org": info["org"], "active": info["active"]}
            for uid, info in self._users.items()
        ]
