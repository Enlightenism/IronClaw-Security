from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import hmac
import logging
import secrets
from threading import RLock
from typing import Any, Final, Literal

from app.core.logging import get_logger
from app.core.supabase import get_supabase_service_client
from app.supabaseclient import SupabaseAPIError, SupabaseClientError

_logger: logging.Logger = get_logger("ironclaw.install_keys")

# ---------------------------------------------------------------------------
# Constants — distinct from apikeys.py ic_ and ic_org_ prefixes
# ---------------------------------------------------------------------------

_INSTALL_KEY_PREFIX_OPENCLAW: Final[str] = "ic_install_openclaw_"
_INSTALL_KEY_PREFIX_CLAUDE: Final[str] = "ic_install_claude_code_"
_INSTALL_KEY_SECRET_BYTES: Final[int] = 32
_T_INSTALL_KEYS: Final[str] = "install_keys"

ProgramCode = Literal["openclaw", "claude_code"]
_VALID_PROGRAMS: frozenset[str] = frozenset({"openclaw", "claude_code"})

# Ordered longest-first so the greedy prefix match is always correct.
_KNOWN_PREFIXES: Final[tuple[str, ...]] = (
    _INSTALL_KEY_PREFIX_CLAUDE,  # "ic_install_claude_code_" (longer)
    _INSTALL_KEY_PREFIX_OPENCLAW,  # "ic_install_openclaw_"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _mask_key(raw_key: str) -> str:
    """
    Preserve the full program prefix intact, append '...', then show the
    last 4 characters of the secret token.

    Examples:
      ic_install_openclaw_<secret>     → ic_install_openclaw_...Xy9z
      ic_install_claude_code_<secret>  → ic_install_claude_code_...Xy9z

    For any key shorter than (prefix + 5) characters the entire value is
    masked with '*' so the secret body is never exposed under any input.
    """
    for prefix in _KNOWN_PREFIXES:
        if raw_key.startswith(prefix):
            secret_part = raw_key[len(prefix) :]
            if len(secret_part) < 5:
                return "*" * len(raw_key)
            return f"{prefix}...{secret_part[-4:]}"
    # Fallback for keys that somehow lack a recognised prefix
    if len(raw_key) <= 12:
        return "*" * len(raw_key)
    return f"{raw_key[:10]}...{raw_key[-4:]}"


def _generate_raw_key(program: ProgramCode) -> str:
    prefix = _INSTALL_KEY_PREFIX_OPENCLAW if program == "openclaw" else _INSTALL_KEY_PREFIX_CLAUDE
    return f"{prefix}{secrets.token_urlsafe(_INSTALL_KEY_SECRET_BYTES)}"


def _new_key_id() -> str:
    return f"ik_{secrets.token_hex(10)}"


def _constant_time_match(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass
class InstallKeyRecord:
    key_id: str
    owner_key: str
    subscription_id: str
    program: ProgramCode
    raw_key: str
    raw_key_hash: str
    masked_key: str
    label: str = ""
    active: bool = True
    units_consumed: int = 0
    created_at: datetime = field(default_factory=_utc_now)
    last_used_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.program not in _VALID_PROGRAMS:
            raise ValueError(f"Invalid program: {self.program!r}. Must be one of {sorted(_VALID_PROGRAMS)}")
        if self.units_consumed < 0:
            raise ValueError("units_consumed cannot be negative")

    def to_db_row(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "owner_key": self.owner_key,
            "subscription_id": self.subscription_id,
            "program": self.program,
            "raw_key_hash": self.raw_key_hash,
            "masked_key": self.masked_key,
            "label": self.label,
            "active": self.active,
            "units_consumed": self.units_consumed,
            "created_at": self.created_at.isoformat(),
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "metadata": self.metadata,
        }

    def public_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "owner_key": self.owner_key,
            "subscription_id": self.subscription_id,
            "program": self.program,
            "masked_key": self.masked_key,
            "label": self.label,
            "active": self.active,
            "units_consumed": self.units_consumed,
            "created_at": self.created_at.isoformat(),
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Row deserializer
# ---------------------------------------------------------------------------


def _record_from_row(row: dict[str, Any], *, raw_key: str = "") -> InstallKeyRecord:
    def _parse_dt(val: Any) -> datetime | None:
        if val is None:
            return None
        if isinstance(val, datetime):
            return val
        if isinstance(val, str):
            return datetime.fromisoformat(val)
        return None

    created_raw = _parse_dt(row.get("created_at"))
    created_at = created_raw if created_raw is not None else _utc_now()

    return InstallKeyRecord(
        key_id=row["key_id"],
        owner_key=row["owner_key"],
        subscription_id=row["subscription_id"],
        program=row["program"],
        raw_key=raw_key,
        raw_key_hash=row["raw_key_hash"],
        masked_key=row["masked_key"],
        label=row.get("label") or "",
        active=bool(row.get("active", True)),
        units_consumed=int(row.get("units_consumed", 0)),
        created_at=created_at,
        last_used_at=_parse_dt(row.get("last_used_at")),
        metadata=row.get("metadata") or {},
    )


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class InstallKeyError(Exception):
    """Base error for install key operations."""


class InstallKeyNotFoundError(InstallKeyError):
    def __init__(self, key_id: str) -> None:
        super().__init__(f"Install key not found: {key_id!r}")
        self.key_id = key_id


class InstallKeyAlreadyExistsError(InstallKeyError):
    def __init__(self, owner_key: str, program: ProgramCode) -> None:
        super().__init__(f"An active install key for program {program!r} already exists for owner {owner_key!r}")
        self.owner_key = owner_key
        self.program = program


class InstallKeyUsageError(InstallKeyError):
    def __init__(self, key_id: str, message: str) -> None:
        super().__init__(f"Usage error for key {key_id!r}: {message}")
        self.key_id = key_id


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class InstallKeyRegistry:
    """
    Manages install keys for openclaw and claude_code programs.

    Distinct from APIKeyRegistry (app/core/apikeys.py):
    - Scoped to post-purchase install keys only
    - Keys are program-typed (openclaw | claude_code)
    - One active key per program per owner enforced at DB and in-memory
    - units_consumed tracked per key and persisted to Supabase
    - raw_key is returned once at generation and never stored in plaintext
    """

    def __init__(self) -> None:
        self._lock = RLock()
        # key_id → record (raw_key is empty string after load from DB)
        self._records_by_id: dict[str, InstallKeyRecord] = {}
        # raw_key_hash → key_id (for authenticate_install_key lookups)
        self._key_id_by_hash: dict[str, str] = {}
        self._loaded = False

    # ------------------------------------------------------------------
    # Internal load
    # ------------------------------------------------------------------

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        try:
            client = get_supabase_service_client()
            resp = client.table(_T_INSTALL_KEYS).select("*").execute()
            rows = resp.data or []
            if isinstance(rows, dict):
                rows = [rows]
            for row in rows:
                record = _record_from_row(row)
                self._records_by_id[record.key_id] = record
                self._key_id_by_hash[record.raw_key_hash] = record.key_id
        except (SupabaseAPIError, SupabaseClientError, Exception):
            _logger.exception("install_keys: failed to load from Supabase; continuing with empty state")
        self._loaded = True

    # ------------------------------------------------------------------
    # generate_install_key
    # ------------------------------------------------------------------

    def generate_install_key(
        self,
        owner_key: str,
        subscription_id: str,
        program: ProgramCode,
        *,
        label: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> InstallKeyRecord:
        """
        Generate a new install key for owner_key + program.
        Enforces one active key per program per owner.
        Returns the record with raw_key populated (only time it is available).
        """
        if program not in _VALID_PROGRAMS:
            raise ValueError(f"Invalid program: {program!r}")

        with self._lock:
            self._ensure_loaded()

            # Enforce unique active key per program per owner
            for rec in self._records_by_id.values():
                if rec.owner_key == owner_key and rec.program == program and rec.active:
                    raise InstallKeyAlreadyExistsError(owner_key, program)

            raw_key = _generate_raw_key(program)
            raw_key_hash = _hash_key(raw_key)
            key_id = _new_key_id()
            now = _utc_now()

            record = InstallKeyRecord(
                key_id=key_id,
                owner_key=owner_key,
                subscription_id=subscription_id,
                program=program,
                raw_key=raw_key,
                raw_key_hash=raw_key_hash,
                masked_key=_mask_key(raw_key),
                label=label.strip(),
                active=True,
                units_consumed=0,
                created_at=now,
                last_used_at=None,
                metadata=metadata or {},
            )

            # Persist to Supabase
            try:
                client = get_supabase_service_client()
                client.table(_T_INSTALL_KEYS).insert(record.to_db_row()).execute()
            except (SupabaseAPIError, SupabaseClientError, Exception):
                _logger.exception("install_keys: failed to persist new key %s", key_id)

            self._records_by_id[key_id] = record
            self._key_id_by_hash[raw_key_hash] = key_id

            _logger.info(
                "install_key_generated",
                extra={"key_id": key_id, "owner_key": owner_key, "program": program},
            )
            return record

    # ------------------------------------------------------------------
    # get_keys_for_owner
    # ------------------------------------------------------------------

    def get_keys_for_owner(self, owner_key: str) -> list[InstallKeyRecord]:
        """Return all install key records (active and revoked) for owner_key."""
        with self._lock:
            self._ensure_loaded()
            return [r for r in self._records_by_id.values() if r.owner_key == owner_key]

    # ------------------------------------------------------------------
    # get_key_by_id
    # ------------------------------------------------------------------

    def get_key_by_id(self, key_id: str) -> InstallKeyRecord | None:
        with self._lock:
            self._ensure_loaded()
            return self._records_by_id.get(key_id)

    # ------------------------------------------------------------------
    # authenticate_install_key
    # ------------------------------------------------------------------

    def authenticate_install_key(self, raw_key: str) -> InstallKeyRecord | None:
        """
        Constant-time authenticate an install key.
        Returns the record if the key is active, None otherwise.
        Updates last_used_at on success.
        """
        candidate_hash = _hash_key(raw_key)

        with self._lock:
            self._ensure_loaded()
            key_id = self._key_id_by_hash.get(candidate_hash)
            if not key_id:
                return None
            record = self._records_by_id.get(key_id)
            if record is None or not record.active:
                return None
            # Constant-time comparison on the hash to prevent timing attacks
            if not _constant_time_match(candidate_hash, record.raw_key_hash):
                return None

            # Touch last_used_at
            now = _utc_now()
            updated = InstallKeyRecord(
                key_id=record.key_id,
                owner_key=record.owner_key,
                subscription_id=record.subscription_id,
                program=record.program,
                raw_key="",  # never retained after generation
                raw_key_hash=record.raw_key_hash,
                masked_key=record.masked_key,
                label=record.label,
                active=record.active,
                units_consumed=record.units_consumed,
                created_at=record.created_at,
                last_used_at=now,
                metadata=record.metadata,
            )
            self._records_by_id[key_id] = updated

            try:
                client = get_supabase_service_client()
                client.table(_T_INSTALL_KEYS).update({"last_used_at": now.isoformat()}).eq("key_id", key_id).execute()
            except (SupabaseAPIError, SupabaseClientError, Exception):
                _logger.warning("install_keys: failed to persist last_used_at for %s", key_id)

            return updated

    # ------------------------------------------------------------------
    # revoke_key
    # ------------------------------------------------------------------

    def revoke_key(self, key_id: str) -> InstallKeyRecord:
        """Deactivate an install key. Returns the updated record."""
        with self._lock:
            self._ensure_loaded()
            record = self._records_by_id.get(key_id)
            if record is None:
                raise InstallKeyNotFoundError(key_id)

            if not record.active:
                return record

            updated = InstallKeyRecord(
                key_id=record.key_id,
                owner_key=record.owner_key,
                subscription_id=record.subscription_id,
                program=record.program,
                raw_key="",
                raw_key_hash=record.raw_key_hash,
                masked_key=record.masked_key,
                label=record.label,
                active=False,
                units_consumed=record.units_consumed,
                created_at=record.created_at,
                last_used_at=record.last_used_at,
                metadata=record.metadata,
            )
            self._records_by_id[key_id] = updated

            try:
                client = get_supabase_service_client()
                client.table(_T_INSTALL_KEYS).update({"active": False}).eq("key_id", key_id).execute()
            except (SupabaseAPIError, SupabaseClientError, Exception):
                _logger.exception("install_keys: failed to persist revocation for %s", key_id)

            _logger.info("install_key_revoked", extra={"key_id": key_id})
            return updated

    # ------------------------------------------------------------------
    # record_key_usage
    # ------------------------------------------------------------------

    def record_key_usage(self, key_id: str, *, units: int) -> InstallKeyRecord:
        """
        Increment units_consumed for the given key_id and persist to Supabase.
        Raises InstallKeyNotFoundError if key_id is unknown.
        Raises InstallKeyUsageError if key is inactive or units <= 0.

        ``units`` is keyword-only to match the contract relied on by
        dashboard.py and the billing provisioning call.
        """
        if units <= 0:
            raise InstallKeyUsageError(key_id, "units must be a positive integer")

        with self._lock:
            self._ensure_loaded()
            record = self._records_by_id.get(key_id)
            if record is None:
                raise InstallKeyNotFoundError(key_id)
            if not record.active:
                raise InstallKeyUsageError(key_id, "key is inactive and cannot record usage")

            new_consumed = record.units_consumed + units
            now = _utc_now()

            updated = InstallKeyRecord(
                key_id=record.key_id,
                owner_key=record.owner_key,
                subscription_id=record.subscription_id,
                program=record.program,
                raw_key="",
                raw_key_hash=record.raw_key_hash,
                masked_key=record.masked_key,
                label=record.label,
                active=record.active,
                units_consumed=new_consumed,
                created_at=record.created_at,
                last_used_at=now,
                metadata=record.metadata,
            )
            self._records_by_id[key_id] = updated

            try:
                client = get_supabase_service_client()
                client.table(_T_INSTALL_KEYS).update({"units_consumed": new_consumed, "last_used_at": now.isoformat()}).eq("key_id", key_id).execute()
            except (SupabaseAPIError, SupabaseClientError, Exception):
                _logger.exception("install_keys: failed to persist usage for %s", key_id)

            _logger.info(
                "install_key_usage_recorded",
                extra={"key_id": key_id, "units": units, "total_consumed": new_consumed},
            )
            return updated

    # ------------------------------------------------------------------
    # summary
    # ------------------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        with self._lock:
            self._ensure_loaded()
            records = list(self._records_by_id.values())
        total = len(records)
        active = sum(1 for r in records if r.active)
        openclaw = sum(1 for r in records if r.program == "openclaw")
        claude = sum(1 for r in records if r.program == "claude_code")
        return {
            "total": total,
            "active": active,
            "revoked": total - active,
            "openclaw_keys": openclaw,
            "claude_code_keys": claude,
        }


# ---------------------------------------------------------------------------
# Module-level singleton — isolated from get_api_key_registry()
# ---------------------------------------------------------------------------

_install_key_registry: InstallKeyRegistry | None = None
_install_key_registry_lock = RLock()


def get_install_key_registry() -> InstallKeyRegistry:
    global _install_key_registry
    if _install_key_registry is None:
        with _install_key_registry_lock:
            if _install_key_registry is None:
                _install_key_registry = InstallKeyRegistry()
    return _install_key_registry


def _reset_install_key_registry_for_testing() -> None:
    """Reset the module-level singleton. For use in pytest fixtures only."""
    global _install_key_registry
    with _install_key_registry_lock:
        _install_key_registry = None


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------

__all__ = [
    "InstallKeyRecord",
    "InstallKeyError",
    "InstallKeyNotFoundError",
    "InstallKeyAlreadyExistsError",
    "InstallKeyUsageError",
    "InstallKeyRegistry",
    "ProgramCode",
    "get_install_key_registry",
    "_reset_install_key_registry_for_testing",
]
