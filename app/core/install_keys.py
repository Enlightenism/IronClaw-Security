from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import hmac
import json
import logging
import os
import secrets
from threading import RLock
from typing import Any, Final, Literal

from app.core.install_key_formats import (
    CONNECTOR_INSTALL_KEY_PROGRAMS,
    RUNTIME_INSTALL_KEY_PROGRAMS,
    SUPPORTED_INSTALL_KEY_PROGRAMS,
    InstallKeyFormatRegistry,
    InstallKeyProgram,
    RuntimeInstallKeyProgram,
)
from app.core.logging import get_logger
from app.core.supabase import get_supabase_service_client, is_supabase_configured
from app.core.unit_wallet import get_unit_wallet_registry
from app.supabaseclient import SupabaseAPIError, SupabaseClientError

_logger: logging.Logger = get_logger("ironclaw.install_keys")

# ---------------------------------------------------------------------------
# Constants — distinct from apikeys.py ic_ and ic_org_ prefixes
# ---------------------------------------------------------------------------

_INSTALL_KEY_SECRET_BYTES: Final[int] = 32
_T_INSTALL_KEYS: Final[str] = "install_key_records"
_T_INSTALL_KEY_STATE: Final[str] = "ironclaw_install_key_state"
_T_INSTALL_KEY_HISTORY: Final[str] = "ironclaw_install_key_history"
_T_EVENT_IDEMPOTENCY: Final[str] = "ironclaw_event_idempotency"

# Security Guardian is a shared connector/install-key family that links the
# runtime platforms to IronClaw security. It is not a standalone runtime
# platform and must never be treated as one in platform enumeration or UI lists.
RuntimeProgramCode = RuntimeInstallKeyProgram
ConnectorProgramCode = Literal["security_guardian"]
ProgramCode = InstallKeyProgram

_RUNTIME_PROGRAMS: Final[frozenset[str]] = frozenset(RUNTIME_INSTALL_KEY_PROGRAMS)
_CONNECTOR_PROGRAMS: Final[frozenset[str]] = frozenset(CONNECTOR_INSTALL_KEY_PROGRAMS)
_VALID_PROGRAMS: Final[frozenset[str]] = frozenset(SUPPORTED_INSTALL_KEY_PROGRAMS)
_PREFIX_BY_PROGRAM: Final[dict[ProgramCode, str]] = {spec.program: spec.prefix for spec in InstallKeyFormatRegistry.list_specs()}

# Ordered longest-first so the greedy prefix match is always correct.
_KNOWN_PREFIXES: Final[tuple[str, ...]] = tuple(sorted(_PREFIX_BY_PROGRAM.values(), key=len, reverse=True))

_PAID_PAYMENT_STATUSES: Final[frozenset[str]] = frozenset({"paid", "success", "succeeded", "complete", "completed", "active", "authorized"})
_ACTIVE_ENTITLEMENT_STATUSES: Final[frozenset[str]] = frozenset({"active", "paid", "enabled", "granted"})
_PUBLIC_METADATA_BLOCKLIST: Final[frozenset[str]] = frozenset(
    {
        "raw_key",
        "rawvalue",
        "secret",
        "secret_key",
        "api_key",
        "apikey",
        "token",
        "access_token",
        "refresh_token",
        "private_key",
        "key_material",
        "key_value",
        "install_key",
        "installkey",
        "password",
    }
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


def _canonical_owner_key(owner_key: str | Any) -> str:
    normalized = str(owner_key).strip().lower()
    if not normalized:
        raise ValueError("owner_key is required")
    return normalized


def _looks_like_generic_platform_auth(value: str | Any) -> bool:
    normalized = str(value).strip().lower()
    if not normalized:
        return False
    if normalized.startswith("ic_install_"):
        return True
    if normalized.startswith("ic_org_"):
        return False
    if normalized.startswith("owner_") or normalized.startswith("customer_") or normalized.startswith("user_") or normalized.startswith("org_") or normalized.startswith("acct_"):
        return False
    if normalized.startswith("ic_"):
        return True

    generic_prefixes = (
        "sk_",
        "pk_",
        "rk_",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "ghl_",
        "github_pat_",
        "pat_",
        "personal_access_token",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "xoxr-",
        "token_",
        "secret_",
        "api_",
        "api-key",
        "api_key",
        "platform-api-key",
        "platform_api_key",
        "system-api-key",
        "system_api_key",
        "internal-platform-api-key",
        "internal_platform_api_key",
        "bearer ",
        "x-api-key",
    )
    if normalized.startswith(generic_prefixes):
        return True

    return ("platform" in normalized and ("key" in normalized or "token" in normalized or "secret" in normalized)) or ("system" in normalized and ("key" in normalized or "token" in normalized or "secret" in normalized)) or ("api" in normalized and "key" in normalized)


def _assert_valid_owner_identity(owner_key: str | Any, *, org_id: str | Any | None = None, customer_id: str | Any | None = None) -> str:
    normalized_owner = _canonical_owner_key(owner_key)
    if normalized_owner.startswith("ic_install_"):
        raise ValueError("owner_key must be a canonical customer or org identity, not an install-key value.")
    if _looks_like_generic_platform_auth(normalized_owner):
        raise ValueError("owner_key must be a canonical customer or org identity, not a generic platform auth value.")

    if org_id is not None:
        normalized_org_id = str(org_id).strip().lower()
        if not normalized_org_id:
            raise ValueError("org_id cannot be blank when provided")
        if normalized_owner.startswith("ic_org_") and normalized_owner != f"ic_org_{normalized_org_id}":
            raise ValueError(f"owner_key {normalized_owner!r} does not match org_id {normalized_org_id!r}")

    if customer_id is not None:
        normalized_customer_id = str(customer_id).strip()
        if not normalized_customer_id:
            raise ValueError("customer_id cannot be blank when provided")

    return normalized_owner


def _normalize_program(program: str | Any) -> ProgramCode:
    candidate = str(program).strip().lower() if program is not None else ""
    if not candidate:
        raise ValueError("program is required")

    canonical = InstallKeyFormatRegistry.normalize_program(candidate)
    if canonical is not None:
        return canonical

    raise ValueError(f"Invalid program: {program!r}. Must be one of {sorted(_VALID_PROGRAMS)}")


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _mask_key(raw_key: str) -> str:
    """
    Preserve the full program prefix intact, append '...', then show the
    last 4 characters of the secret token.

    Examples:
      ic_install_openclaw_<secret>     -> ic_install_openclaw_...Xy9z
      ic_install_claude_code_<secret>  -> ic_install_claude_code_...Xy9z

    For any key shorter than (prefix + 5) characters the entire value is
    masked with '*' so the secret body is never exposed under any input.
    """
    for prefix in _KNOWN_PREFIXES:
        if raw_key.startswith(prefix):
            secret_part = raw_key[len(prefix) :]
            if len(secret_part) < 5:
                return "*" * len(raw_key)
            return f"{prefix}...{secret_part[-4:]}"
    if len(raw_key) <= 12:
        return "*" * len(raw_key)
    return f"{raw_key[:10]}...{raw_key[-4:]}"


def _generate_raw_key(program: ProgramCode) -> str:
    normalized_program = _normalize_program(program)
    prefix = _PREFIX_BY_PROGRAM[normalized_program]
    return f"{prefix}{secrets.token_urlsafe(_INSTALL_KEY_SECRET_BYTES)}"


def _new_key_id() -> str:
    return f"ik_{secrets.token_hex(10)}"


def _constant_time_match(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _normalize_payment_status(value: Any) -> str:
    if value is None:
        return "unpaid"
    status = str(value).strip().lower()
    if not status:
        return "unpaid"
    if status in _PAID_PAYMENT_STATUSES:
        return "paid"
    return status


def _normalize_entitlement_status(value: Any) -> str:
    if value is None:
        return "not_active"
    status = str(value).strip().lower()
    if not status:
        return "not_active"
    if status in _ACTIVE_ENTITLEMENT_STATUSES:
        return "active"
    return status


def _is_paid_payment_status(value: Any) -> bool:
    return _normalize_payment_status(value) == "paid"


def _is_runtime_program(program: ProgramCode | str | Any) -> bool:
    try:
        return _normalize_program(program) in _RUNTIME_PROGRAMS
    except ValueError:
        return False


def _is_active_entitlement_status(value: Any) -> bool:
    return _normalize_entitlement_status(value) == "active"


def _sanitize_public_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        return {}

    sanitized: dict[str, Any] = {}
    for key, value in metadata.items():
        normalized_key = str(key).strip().lower()
        if not normalized_key:
            continue
        if normalized_key in _PUBLIC_METADATA_BLOCKLIST:
            continue
        if any(token in normalized_key for token in ("raw_key", "secret", "token", "api_key", "private_key", "key_material", "key_value", "install_key", "password")):
            continue
        if isinstance(value, dict):
            cleaned_value = _sanitize_public_metadata(value)
        elif isinstance(value, list):
            cleaned_value = [_sanitize_public_metadata(item) if isinstance(item, dict) else item for item in value]
        else:
            cleaned_value = value
        sanitized[str(key)] = cleaned_value
    return sanitized


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass
class InstallKeyRecord:
    key_id: str
    owner_key: str
    subscription_id: str
    program: ProgramCode
    raw_key: str = ""
    raw_key_hash: str = ""
    masked_key: str = ""
    label: str = ""
    active: bool = False
    payment_status: str = "unpaid"
    entitlements_status: str = "not_active"
    issued_after_payment: bool = False
    org_id: str | None = None
    customer_id: str | None = None
    units_consumed: int = 0
    created_at: datetime = field(default_factory=_utc_now)
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None
    purchase_reference: str | None = None
    checkout_session_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.program = _normalize_program(self.program)
        if self.program not in _VALID_PROGRAMS:
            raise ValueError(f"Invalid program: {self.program!r}. Must be one of {sorted(_VALID_PROGRAMS)}")
        if self.units_consumed < 0:
            raise ValueError("units_consumed cannot be negative")

        self.metadata = _sanitize_public_metadata(self.metadata)

        if self.raw_key:
            expected_prefix = _PREFIX_BY_PROGRAM.get(self.program, "")
            if expected_prefix and not self.raw_key.startswith(expected_prefix):
                raise ValueError(f"raw_key prefix does not match program {self.program!r}; expected {expected_prefix!r} but got {self.raw_key[: len(expected_prefix)]!r}.")

        self.owner_key = _assert_valid_owner_identity(self.owner_key, org_id=self.org_id, customer_id=self.customer_id)
        if self.org_id is not None and self.owner_key.startswith("ic_org_"):
            expected_org_owner = f"ic_org_{str(self.org_id).strip().lower()}"
            if self.owner_key != expected_org_owner:
                raise ValueError(f"owner_key {self.owner_key!r} does not match org_id {str(self.org_id).strip().lower()!r}")

        normalized_payment_status = _normalize_payment_status(self.payment_status)
        normalized_entitlement_status = _normalize_entitlement_status(self.entitlements_status)

        if self.active:
            if not self.issued_after_payment:
                raise ValueError("active install keys must be issued_after_payment=True and backed by a paid entitlement")
            if normalized_payment_status != "paid":
                raise ValueError("active install keys require payment_status='paid'")
            if normalized_entitlement_status != "active":
                raise ValueError("active install keys require entitlements_status='active'")

        self.payment_status = normalized_payment_status
        self.entitlements_status = normalized_entitlement_status
        if self.active:
            self.entitlements_status = "active"
            self.payment_status = "paid"
        if not self.raw_key_hash and self.raw_key:
            self.raw_key_hash = _hash_key(self.raw_key)
        if self.raw_key and not self.masked_key:
            self.masked_key = _mask_key(self.raw_key)
        if not self.masked_key and self.raw_key_hash:
            self.masked_key = "masked"
        if self.revoked_at is not None and self.active:
            self.active = False
            self.entitlements_status = "revoked"

    def to_db_row(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "owner_key": self.owner_key,
            "org_id": self.org_id,
            "customer_id": self.customer_id,
            "subscription_id": self.subscription_id,
            "program": self.program,
            "payment_status": self.payment_status,
            "entitlements_status": self.entitlements_status,
            "issued_after_payment": self.issued_after_payment,
            "raw_key_hash": self.raw_key_hash,
            "masked_key": self.masked_key,
            "label": self.label,
            "active": self.active,
            "units_consumed": self.units_consumed,
            "created_at": self.created_at.isoformat(),
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "purchase_reference": self.purchase_reference,
            "checkout_session_id": self.checkout_session_id,
            "metadata": _sanitize_public_metadata(self.metadata),
        }

    def public_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "owner_key": self.owner_key,
            "org_id": self.org_id,
            "customer_id": self.customer_id,
            "subscription_id": self.subscription_id,
            "program": self.program,
            "payment_status": self.payment_status,
            "entitlements_status": self.entitlements_status,
            "issued_after_payment": self.issued_after_payment,
            "masked_key": self.masked_key,
            "label": self.label,
            "active": self.active,
            "units_consumed": self.units_consumed,
            "created_at": self.created_at.isoformat(),
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "purchase_reference": self.purchase_reference,
            "checkout_session_id": self.checkout_session_id,
            "metadata": _sanitize_public_metadata(self.metadata),
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
            try:
                return datetime.fromisoformat(val)
            except ValueError:
                return None
        return None

    created_raw = _parse_dt(row.get("created_at"))
    created_at = created_raw if created_raw is not None else _utc_now()
    payment_status = _normalize_payment_status(row.get("payment_status"))
    entitlements_status = _normalize_entitlement_status(row.get("entitlements_status"))
    issued_after_payment = bool(row.get("issued_after_payment", payment_status == "paid"))
    active = bool(row.get("active", False))

    if active and not issued_after_payment:
        issued_after_payment = True

    raw_key_hash_value = row.get("raw_key_hash") or ""
    if raw_key and not raw_key_hash_value:
        raw_key_hash_value = _hash_key(raw_key)

    owner_key = row.get("owner_key")
    if owner_key is not None:
        _assert_valid_owner_identity(owner_key, org_id=row.get("org_id"), customer_id=row.get("customer_id"))

    record = InstallKeyRecord(
        key_id=row["key_id"],
        owner_key=row.get("owner_key") or "",
        subscription_id=row.get("subscription_id") or "",
        program=row["program"],
        raw_key=raw_key,
        raw_key_hash=raw_key_hash_value,
        masked_key=row.get("masked_key") or (_mask_key(raw_key) if raw_key else ""),
        label=row.get("label") or "",
        active=active,
        payment_status=payment_status,
        entitlements_status=entitlements_status,
        issued_after_payment=issued_after_payment,
        org_id=row.get("org_id"),
        customer_id=row.get("customer_id"),
        units_consumed=int(row.get("units_consumed", 0)),
        created_at=created_at,
        last_used_at=_parse_dt(row.get("last_used_at")),
        revoked_at=_parse_dt(row.get("revoked_at")),
        purchase_reference=row.get("purchase_reference"),
        checkout_session_id=row.get("checkout_session_id"),
        metadata=row.get("metadata") or {},
    )
    if record.active and record.payment_status != "paid":
        record.payment_status = "paid"
    if record.active and record.entitlements_status != "active":
        record.entitlements_status = "active"
    return record


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class InstallKeyError(Exception):
    """Base error for install key operations."""


class InstallKeyPaymentRequiredError(InstallKeyError):
    def __init__(self, owner_key: str, program: ProgramCode, reason: str = "") -> None:
        message = f"Install key generation requires a successful paid entitlement for owner {owner_key!r} and program {program!r}."
        if reason:
            message = f"{message} {reason}"
        super().__init__(message)
        self.owner_key = owner_key
        self.program = program
        self.reason = reason


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


def _is_current_paid_entitlement(record: InstallKeyRecord) -> bool:
    if record.revoked_at is not None or not record.active:
        return False
    if record.payment_status != "paid":
        return False
    if record.entitlements_status != "active":
        return False
    if not record.issued_after_payment:
        return False
    return True


def _is_durable_write_result(result: Any) -> bool:
    return result is not None


def _should_use_memory_fallback() -> bool:
    mode = os.environ.get("IRONCLAW_PERSISTENCE_MODE", "").strip().lower()
    if mode == "memory":
        return True
    try:
        return not is_supabase_configured()
    except Exception:
        return True


def _assert_durable_install_key_storage() -> None:
    """Refuse to issue paid install keys when Supabase persistence is required but unavailable."""
    mode = os.environ.get("IRONCLAW_PERSISTENCE_MODE", "").strip().lower()
    if mode == "supabase" and _should_use_memory_fallback():
        raise RuntimeError("Install-key issuance requires durable Supabase storage; refusing to keep paid keys in memory only.")


def _persist_install_key_update(*, key_id: str, action: str, callback: Any) -> bool:
    if _should_use_memory_fallback():
        _logger.info("install_keys: %s for %s skipped because persistence is running in memory-only mode", action, key_id)
        return True

    try:
        callback()
    except (SupabaseAPIError, SupabaseClientError, Exception):
        _logger.warning("install_keys: failed to persist %s for %s", action, key_id)
        return False
    return True


def _write_key_revocation(record: InstallKeyRecord, *, reason: str) -> None:
    client = get_supabase_service_client()
    revoked_at = (record.revoked_at or _utc_now()).isoformat()
    client.table(_T_INSTALL_KEYS).update(
        {
            "active": False,
            "entitlements_status": "revoked",
            "revoked_at": revoked_at,
            "metadata": record.metadata,
        }
    ).eq("key_id", record.key_id).execute()
    client.table(_T_INSTALL_KEY_STATE).update(
        {
            "active": False,
            "status": "revoked",
            "revoked_at": revoked_at,
            "updated_at": _utc_now_iso(),
        }
    ).eq("key_id", record.key_id).execute()
    client.table(_T_INSTALL_KEY_HISTORY).insert(
        {
            "history_id": f"hist_{secrets.token_hex(12)}",
            "key_id": record.key_id,
            "purchase_id": str(record.purchase_reference or record.subscription_id or "").strip() or None,
            "event_type": "revoked",
            "status": "revoked",
            "actor_type": "system",
            "reason": reason,
            "metadata": {"owner_key": record.owner_key, "program": record.program},
            "created_at": _utc_now_iso(),
            "updated_at": _utc_now_iso(),
        }
    ).execute()


def _canonical_install_key_event_id(*, owner_key: str, program: ProgramCode, purchase_reference: str | None, checkout_session_id: str | None) -> str:
    seed_parts = [
        str(owner_key).strip().lower(),
        str(program).strip().lower(),
        str(purchase_reference or "").strip(),
        str(checkout_session_id or "").strip(),
    ]
    return hashlib.sha256("|".join(seed_parts).encode("utf-8")).hexdigest()


def _canonical_install_key_issue_payload(*, owner_key: str, program: ProgramCode, purchase_reference: str | None, checkout_session_id: str | None, subscription_id: str | None, customer_id: str | None) -> dict[str, Any]:
    return {
        "event_type": "install_key_issued",
        "owner_key": str(owner_key).strip().lower(),
        "program": str(program).strip().lower(),
        "purchase_reference": str(purchase_reference or "").strip() or None,
        "checkout_session_id": str(checkout_session_id or "").strip() or None,
        "subscription_id": str(subscription_id or "").strip() or None,
        "customer_id": str(customer_id or "").strip() or None,
    }


def _read_event_ledger_record(*, event_id: str | None = None, purchase_reference: str | None = None, checkout_session_id: str | None = None, owner_key: str | None = None, program: ProgramCode | str | None = None) -> dict[str, Any] | None:
    if _should_use_memory_fallback():
        return None
    try:
        client = get_supabase_service_client()
        resp = client.table(_T_EVENT_IDEMPOTENCY).select("*").execute()
        rows = resp.data or []
        if isinstance(rows, dict):
            rows = [rows]
        for row in rows:
            row = dict(row)
            if event_id and str(row.get("event_id") or "").strip() == event_id:
                return row
            if purchase_reference and str(row.get("purchase_id") or row.get("purchase_reference") or "").strip() == str(purchase_reference).strip():
                return row
            if checkout_session_id and str(row.get("checkout_session_id") or "").strip() == str(checkout_session_id).strip():
                return row
            if owner_key and str(row.get("owner_key") or "").strip().lower() == str(owner_key).strip().lower():
                metadata = row.get("metadata") or {}
                if program and str(metadata.get("program") or "").strip().lower() == str(program).strip().lower():
                    return row
        return None
    except (SupabaseAPIError, SupabaseClientError, Exception):
        _logger.exception("install_keys: failed to read event ledger")
        return None


def _write_event_ledger_record(*, event_id: str, event_type: str, purchase_reference: str | None, checkout_session_id: str | None, owner_key: str | None, customer_id: str | None, program: ProgramCode | str | None, payload: dict[str, Any]) -> dict[str, Any]:
    if _should_use_memory_fallback():
        return {"event_id": event_id, "status": "memory_fallback"}
    payload_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()
    record = {
        "event_id": event_id,
        "source": "install_key",
        "event_type": event_type,
        "purchase_id": str(purchase_reference or "").strip() or None,
        "checkout_session_id": str(checkout_session_id or "").strip() or None,
        "owner_key": str(owner_key or "").strip().lower() or None,
        "customer_id": str(customer_id or "").strip() or None,
        "payload_hash": payload_hash,
        "processed_at": _utc_now_iso(),
        "metadata": {
            "program": str(program or "").strip().lower() if program is not None else None,
            **payload,
        },
    }
    try:
        client = get_supabase_service_client()
        client.table(_T_EVENT_IDEMPOTENCY).upsert(record, on_conflict="event_id", returning="representation").execute()
        return record
    except (SupabaseAPIError, SupabaseClientError, Exception):
        _logger.exception("install_keys: failed to write event ledger for event %s", event_id)
        return record


def _persist_install_key_state_record(record: InstallKeyRecord) -> None:
    state_row = {
        "key_id": record.key_id,
        "purchase_id": str(record.purchase_reference or record.subscription_id or "").strip() or None,
        "owner_key": record.owner_key,
        "customer_id": record.customer_id,
        "program": record.program,
        "checkout_session_id": record.checkout_session_id,
        "raw_key_hash": record.raw_key_hash,
        "masked_key": record.masked_key,
        "status": "active" if record.active else "revoked" if record.revoked_at is not None else "issued",
        "active": record.active,
        "issued_after_payment": record.issued_after_payment,
        "created_at": record.created_at.isoformat(),
        "updated_at": _utc_now_iso(),
        "revoked_at": record.revoked_at.isoformat() if record.revoked_at else None,
        "metadata": {
            **_sanitize_public_metadata(record.metadata),
            "checkout_session_id": record.checkout_session_id,
            "raw_key_hash": record.raw_key_hash,
        },
    }

    def _write_state() -> None:
        client = get_supabase_service_client()
        client.table(_T_INSTALL_KEY_STATE).upsert(state_row, on_conflict="key_id", returning="representation").execute()

    _persist_install_key_update(key_id=record.key_id, action="state_write", callback=_write_state)


def _persist_install_key_history_record(*, record: InstallKeyRecord, event_type: str, status: str, reason: str, metadata: dict[str, Any] | None = None) -> None:
    row = {
        "history_id": f"hist_{secrets.token_hex(12)}",
        "key_id": record.key_id,
        "purchase_id": str(record.purchase_reference or record.subscription_id or "").strip() or None,
        "event_type": event_type,
        "status": status,
        "actor_type": "system",
        "reason": reason,
        "metadata": {
            "owner_key": record.owner_key,
            "program": record.program,
            "checkout_session_id": record.checkout_session_id,
            **_sanitize_public_metadata(metadata or {}),
        },
        "created_at": _utc_now_iso(),
        "updated_at": _utc_now_iso(),
    }

    def _write_history() -> None:
        client = get_supabase_service_client()
        client.table(_T_INSTALL_KEY_HISTORY).insert(row).execute()

    _persist_install_key_update(key_id=record.key_id, action="history_write", callback=_write_history)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class InstallKeyRegistry:
    """
    Manages install keys for openclaw and claude_code programs.

    This registry enforces a hard entitlement gate:
      - no active install keys before successful payment/checkout completion
      - raw keys are returned exactly once, on generation
      - after issuance, the raw secret is never retrievable from the registry
      - one active key per program per owner is enforced
      - active keys are only allowed for paid customers
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._records_by_id: dict[str, InstallKeyRecord] = {}
        self._key_id_by_hash: dict[str, str] = {}
        self._loaded = False
        self._last_sync_at: datetime | None = None
        self._last_write_at: datetime | None = None
        self._pending_revocations: dict[str, tuple[InstallKeyRecord, str]] = {}

    # ------------------------------------------------------------------
    # Internal load
    # ------------------------------------------------------------------

    def _load_rows_from_supabase(self) -> list[dict[str, Any]]:
        if _should_use_memory_fallback():
            return []
        client = get_supabase_service_client()
        resp = client.table(_T_INSTALL_KEYS).select("*").execute()
        rows = resp.data or []
        if isinstance(rows, dict):
            rows = [rows]
        return [dict(row) for row in rows]

    def _rebuild_registry_from_rows(self, rows: list[dict[str, Any]]) -> None:
        rebuilt_by_id: dict[str, InstallKeyRecord] = {}
        rebuilt_hash_index: dict[str, str] = {}
        for row in rows:
            record = _record_from_row(row)
            pending = self._pending_revocations.get(record.key_id)
            if pending is not None:
                pending_record, pending_reason = pending
                if record.active and record.revoked_at is None:
                    record = pending_record
                    if _persist_install_key_update(
                        key_id=record.key_id,
                        action="revocation_retry",
                        callback=lambda r=pending_record, reason=pending_reason: _write_key_revocation(r, reason=reason),
                    ):
                        self._pending_revocations.pop(record.key_id, None)
                else:
                    self._pending_revocations.pop(record.key_id, None)
            rebuilt_by_id[record.key_id] = record
            if record.raw_key_hash:
                rebuilt_hash_index[record.raw_key_hash] = record.key_id
        self._records_by_id = rebuilt_by_id
        self._key_id_by_hash = rebuilt_hash_index
        self._loaded = True
        self._last_sync_at = _utc_now()

    def _refresh_from_supabase(self, *, force: bool = False) -> None:
        now = _utc_now()

        if self._records_by_id and self._last_write_at is not None:
            freshness_window = (now - self._last_write_at).total_seconds()
            if freshness_window < 5.0 and not force:
                self._loaded = True
                self._last_sync_at = now
                return

        try:
            rows = self._load_rows_from_supabase()
        except (SupabaseAPIError, SupabaseClientError, Exception):
            _logger.exception("install_keys: failed to refresh from Supabase; keeping in-memory cache until a clean reload is possible")
            self._loaded = bool(self._records_by_id)
            self._last_sync_at = now if self._loaded else None
            return

        snapshot = tuple(sorted((str(row.get("key_id") or "")) for row in rows))
        cached_snapshot = tuple(sorted(self._records_by_id))

        if not self._loaded or force:
            if not rows and not self._records_by_id:
                self._rebuild_registry_from_rows([])
                return
            if not rows and self._records_by_id:
                self._loaded = True
                self._last_sync_at = now
                return
            self._rebuild_registry_from_rows(rows)
            return

        if len(rows) != len(self._records_by_id) or snapshot != cached_snapshot:
            self._rebuild_registry_from_rows(rows)
            return

        for row in rows:
            record = _record_from_row(row)
            cached = self._records_by_id.get(record.key_id)
            if cached is None:
                self._rebuild_registry_from_rows(rows)
                return
            if cached.active != record.active or cached.payment_status != record.payment_status or cached.entitlements_status != record.entitlements_status or cached.revoked_at != record.revoked_at:
                self._rebuild_registry_from_rows(rows)
                return

        self._loaded = True
        self._last_sync_at = now

    def _ensure_loaded(self) -> None:
        if self._loaded:
            self._refresh_from_supabase(force=False)
            return
        self._refresh_from_supabase(force=True)

    # ------------------------------------------------------------------
    # Internal entitlement validation
    # ------------------------------------------------------------------

    def _assert_paid_entitlement(
        self,
        *,
        owner_key: str,
        program: ProgramCode,
        payment_status: Any,
        entitlements_status: Any,
        issued_after_payment: bool,
        checkout_session_id: str | None = None,
        purchase_reference: str | None = None,
        subscription_id: str | None = None,
    ) -> None:
        normalized_payment_status = _normalize_payment_status(payment_status)
        normalized_entitlement_status = _normalize_entitlement_status(entitlements_status)

        if not issued_after_payment:
            raise InstallKeyPaymentRequiredError(
                owner_key,
                program,
                reason="issued_after_payment is false; install keys cannot be created before a completed checkout.",
            )

        if not _is_paid_payment_status(normalized_payment_status):
            raise InstallKeyPaymentRequiredError(
                owner_key,
                program,
                reason=(f"payment_status is not paid; Stripe checkout must complete successfully before key issuance. payment_status={normalized_payment_status!r}"),
            )

        if not _is_active_entitlement_status(normalized_entitlement_status):
            raise InstallKeyPaymentRequiredError(
                owner_key,
                program,
                reason=(f"entitlements_status is not active; the customer does not have a valid paid entitlement. entitlements_status={normalized_entitlement_status!r}"),
            )

    def _has_replay_issue_for_purchase(
        self,
        *,
        owner_key: str,
        program: ProgramCode,
        purchase_reference: str | None,
        checkout_session_id: str | None,
        subscription_id: str | None,
    ) -> bool:
        if purchase_reference is None and checkout_session_id is None:
            return False

        payload = _canonical_install_key_issue_payload(
            owner_key=owner_key,
            program=program,
            purchase_reference=purchase_reference,
            checkout_session_id=checkout_session_id,
            subscription_id=subscription_id,
            customer_id=None,
        )
        event_id = _canonical_install_key_event_id(
            owner_key=owner_key,
            program=program,
            purchase_reference=purchase_reference,
            checkout_session_id=checkout_session_id,
        )
        existing = _read_event_ledger_record(
            event_id=event_id,
            purchase_reference=purchase_reference,
            checkout_session_id=checkout_session_id,
            owner_key=owner_key,
            program=program,
        )
        if existing is not None:
            return True

        if purchase_reference is not None:
            for record in self._records_by_id.values():
                if str(record.purchase_reference or "").strip() == str(purchase_reference).strip() and record.program == program and record.owner_key == owner_key:
                    return True

        if checkout_session_id is not None:
            for record in self._records_by_id.values():
                if str(record.checkout_session_id or "").strip() == str(checkout_session_id).strip() and record.program == program and record.owner_key == owner_key:
                    return True

        event_payload = {
            "source": "install_key",
            "event_type": "install_key_issued",
            **payload,
        }
        _write_event_ledger_record(
            event_id=event_id,
            event_type="install_key_issued",
            purchase_reference=purchase_reference,
            checkout_session_id=checkout_session_id,
            owner_key=owner_key,
            customer_id=None,
            program=program,
            payload=event_payload,
        )
        return False

    def _lock_inactive_key(self, record: InstallKeyRecord, *, reason: str) -> InstallKeyRecord:
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
            payment_status=record.payment_status,
            entitlements_status="not_active",
            issued_after_payment=record.issued_after_payment,
            org_id=record.org_id,
            customer_id=record.customer_id,
            units_consumed=record.units_consumed,
            created_at=record.created_at,
            last_used_at=record.last_used_at,
            revoked_at=_utc_now(),
            purchase_reference=record.purchase_reference,
            checkout_session_id=record.checkout_session_id,
            metadata={**record.metadata, "lock_reason": reason},
        )
        self._records_by_id[record.key_id] = updated

        def _persist_lock_state() -> None:
            client = get_supabase_service_client()
            client.table(_T_INSTALL_KEYS).update(
                {
                    "active": False,
                    "entitlements_status": "not_active",
                    "revoked_at": updated.revoked_at.isoformat(),
                    "metadata": updated.metadata,
                }
            ).eq("key_id", record.key_id).execute()

        _persist_install_key_update(key_id=record.key_id, action="lock_state", callback=_persist_lock_state)

        return updated

    def _reconcile_key_state(self, record: InstallKeyRecord) -> InstallKeyRecord:
        if not record.active:
            return record

        if record.payment_status != "paid" or record.entitlements_status != "active" or not record.issued_after_payment:
            return self._lock_inactive_key(record, reason="entitlement_inactive")

        wallet = get_unit_wallet_registry().get_wallet(record.owner_key)
        if wallet is not None and wallet.balance_units <= 0:
            return self._lock_inactive_key(record, reason="units_exhausted")

        return record

    # ------------------------------------------------------------------
    # generate_for_paid_customer
    # ------------------------------------------------------------------

    def generate_for_paid_customer(
        self,
        owner_key: str,
        subscription_id: str,
        program: ProgramCode,
        *,
        org_id: str | None = None,
        customer_id: str | None = None,
        payment_status: str | None = "paid",
        entitlements_status: str | None = "active",
        issued_after_payment: bool = True,
        purchase_reference: str | None = None,
        checkout_session_id: str | None = None,
        label: str = "",
        metadata: dict[str, Any] | None = None,
        secure_record_persistor: Callable[[InstallKeyRecord], None] | None = None,
    ) -> InstallKeyRecord:
        """
        Authoritative install-key issuance path.

        This is the only safe way to generate active install keys. It enforces a
        successful paid entitlement and prevents pre-purchase exposure.
        """
        normalized_program = _normalize_program(program)
        if normalized_program in _CONNECTOR_PROGRAMS:
            raise ValueError("Security Guardian is a shared install-key connector and cannot be issued as a runtime install key.")

        normalized_owner = _assert_valid_owner_identity(owner_key, org_id=org_id, customer_id=customer_id)
        if not str(subscription_id).strip():
            raise ValueError("subscription_id is required for paid issuance")

        normalized_payment_status = _normalize_payment_status(payment_status)
        normalized_entitlements_status = _normalize_entitlement_status(entitlements_status)
        self._assert_paid_entitlement(
            owner_key=normalized_owner,
            program=program,
            payment_status=normalized_payment_status,
            entitlements_status=normalized_entitlements_status,
            issued_after_payment=issued_after_payment,
            checkout_session_id=checkout_session_id,
            purchase_reference=purchase_reference,
            subscription_id=subscription_id,
        )

        with self._lock:
            self._ensure_loaded()

            for rec in self._records_by_id.values():
                if rec.owner_key == normalized_owner and rec.program == normalized_program and _is_current_paid_entitlement(rec):
                    raise InstallKeyAlreadyExistsError(normalized_owner, normalized_program)

            if self._has_replay_issue_for_purchase(
                owner_key=normalized_owner,
                program=normalized_program,
                purchase_reference=purchase_reference,
                checkout_session_id=checkout_session_id,
                subscription_id=subscription_id,
            ):
                raise InstallKeyAlreadyExistsError(normalized_owner, normalized_program)

            raw_key = _generate_raw_key(normalized_program)
            raw_key_hash = _hash_key(raw_key)
            key_id = _new_key_id()
            now = _utc_now()

            record = InstallKeyRecord(
                key_id=key_id,
                owner_key=normalized_owner,
                subscription_id=str(subscription_id).strip(),
                program=normalized_program,
                raw_key=raw_key,
                raw_key_hash=raw_key_hash,
                masked_key=_mask_key(raw_key),
                label=str(label).strip(),
                active=True,
                payment_status="paid",
                entitlements_status="active",
                issued_after_payment=True,
                org_id=org_id.strip() if isinstance(org_id, str) and org_id.strip() else None,
                customer_id=customer_id.strip() if isinstance(customer_id, str) and customer_id.strip() else None,
                units_consumed=0,
                created_at=now,
                last_used_at=None,
                revoked_at=None,
                purchase_reference=purchase_reference.strip() if isinstance(purchase_reference, str) and purchase_reference.strip() else None,
                checkout_session_id=checkout_session_id.strip() if isinstance(checkout_session_id, str) and checkout_session_id.strip() else None,
                metadata=dict(metadata or {}),
            )

            _assert_durable_install_key_storage()
            use_memory_fallback = _should_use_memory_fallback()
            if not use_memory_fallback:
                try:
                    client = get_supabase_service_client()
                    if secure_record_persistor is None:
                        insert_result = client.table(_T_INSTALL_KEYS).insert(record.to_db_row()).execute()
                        if not _is_durable_write_result(insert_result):
                            raise RuntimeError(f"Supabase insert returned no durable result for key {key_id!r}")
                    else:
                        secure_record_persistor(record)
                    state_result = (
                        client.table(_T_INSTALL_KEY_STATE)
                        .upsert(
                            {
                                "key_id": record.key_id,
                                "purchase_id": str(purchase_reference or subscription_id or "").strip() or None,
                                "owner_key": record.owner_key,
                                "customer_id": customer_id.strip() if isinstance(customer_id, str) and customer_id.strip() else None,
                                "program": record.program,
                                "checkout_session_id": checkout_session_id.strip() if isinstance(checkout_session_id, str) and checkout_session_id.strip() else None,
                                "raw_key_hash": record.raw_key_hash,
                                "masked_key": record.masked_key,
                                "status": "active",
                                "active": True,
                                "issued_after_payment": True,
                                "created_at": record.created_at.isoformat(),
                                "updated_at": _utc_now_iso(),
                                "metadata": {
                                    "owner_key": record.owner_key,
                                    "program": record.program,
                                    "purchase_reference": purchase_reference,
                                    "checkout_session_id": checkout_session_id,
                                    "source": "install_key_registry",
                                },
                            },
                            on_conflict="key_id",
                            returning="representation",
                        )
                        .execute()
                    )
                    if not _is_durable_write_result(state_result):
                        raise RuntimeError(f"Supabase state insert returned no durable result for key {key_id!r}")
                    history_row = {
                        "history_id": f"hist_{secrets.token_hex(12)}",
                        "key_id": key_id,
                        "purchase_id": str(purchase_reference or subscription_id or "").strip() or None,
                        "event_type": "issued",
                        "status": "active",
                        "actor_type": "system",
                        "reason": "paid_checkout_completion",
                        "metadata": {
                            "owner_key": record.owner_key,
                            "program": record.program,
                            "checkout_session_id": checkout_session_id,
                            "purchase_reference": purchase_reference,
                        },
                        "created_at": _utc_now_iso(),
                        "updated_at": _utc_now_iso(),
                    }
                    history_result = client.table(_T_INSTALL_KEY_HISTORY).insert(history_row).execute()
                    if not _is_durable_write_result(history_result):
                        raise RuntimeError(f"Supabase history insert returned no durable result for key {key_id!r}")
                    issue_event = _canonical_install_key_issue_payload(
                        owner_key=normalized_owner,
                        program=normalized_program,
                        purchase_reference=purchase_reference,
                        checkout_session_id=checkout_session_id,
                        subscription_id=subscription_id,
                        customer_id=customer_id,
                    )
                    issue_event_id = _canonical_install_key_event_id(
                        owner_key=normalized_owner,
                        program=normalized_program,
                        purchase_reference=purchase_reference,
                        checkout_session_id=checkout_session_id,
                    )
                    _write_event_ledger_record(
                        event_id=issue_event_id,
                        event_type="install_key_issued",
                        purchase_reference=purchase_reference,
                        checkout_session_id=checkout_session_id,
                        owner_key=normalized_owner,
                        customer_id=customer_id,
                        program=normalized_program,
                        payload={"event_type": "install_key_issued", **issue_event},
                    )
                except (SupabaseAPIError, SupabaseClientError, RuntimeError, Exception):
                    _logger.exception("install_keys: failed to persist new key %s", key_id)
                    raise
            elif secure_record_persistor is not None:
                secure_record_persistor(record)

            self._records_by_id[key_id] = record
            self._key_id_by_hash[raw_key_hash] = key_id
            self._loaded = True
            self._last_write_at = _utc_now()
            self._last_sync_at = self._last_write_at

            active_duplicate = next(
                (existing for existing in self._records_by_id.values() if existing.key_id != key_id and existing.owner_key == normalized_owner and existing.program == normalized_program and _is_current_paid_entitlement(existing)),
                None,
            )
            if active_duplicate is not None:
                self._records_by_id.pop(key_id, None)
                self._key_id_by_hash.pop(raw_key_hash, None)
                raise InstallKeyAlreadyExistsError(normalized_owner, normalized_program)

            _logger.info(
                "install_key_generated",
                extra={
                    "key_id": key_id,
                    "owner_key": normalized_owner,
                    "program": normalized_program,
                    "payment_status": "paid",
                    "issued_after_payment": True,
                    "checkout_session_id": checkout_session_id,
                    "purchase_reference": purchase_reference,
                },
            )
            return record

    # ------------------------------------------------------------------
    # Backward-compatible wrapper
    # ------------------------------------------------------------------

    def generate_install_key(
        self,
        owner_key: str,
        subscription_id: str,
        program: ProgramCode,
        *,
        label: str = "",
        metadata: dict[str, Any] | None = None,
        payment_status: str | None = None,
        entitlements_status: str | None = None,
        issued_after_payment: bool = True,
        org_id: str | None = None,
        customer_id: str | None = None,
        purchase_reference: str | None = None,
        checkout_session_id: str | None = None,
        secure_record_persistor: Callable[[InstallKeyRecord], None] | None = None,
    ) -> InstallKeyRecord:
        """
        Compatibility wrapper for the old call signature.

        It is intentionally gated to prevent creation without a successful paid
        entitlement. Old pre-purchase flows should not be allowed through this
        path anymore.
        """
        normalized_program = _normalize_program(program)
        if normalized_program in _CONNECTOR_PROGRAMS:
            raise ValueError("Security Guardian is a shared install-key connector and cannot be issued as a runtime install key.")

        effective_payment_status = payment_status
        if effective_payment_status is None and metadata is not None:
            effective_payment_status = metadata.get("payment_status")
        if effective_payment_status is None:
            effective_payment_status = "paid"

        effective_entitlements_status = entitlements_status
        if effective_entitlements_status is None and metadata is not None:
            effective_entitlements_status = metadata.get("entitlements_status")
        if effective_entitlements_status is None:
            effective_entitlements_status = "active"

        if purchase_reference is None and metadata is not None:
            purchase_reference = metadata.get("purchase_reference")
        if checkout_session_id is None and metadata is not None:
            checkout_session_id = metadata.get("checkout_session_id")

        normalized_payment_status = _normalize_payment_status(effective_payment_status)
        normalized_entitlements_status = _normalize_entitlement_status(effective_entitlements_status)
        has_paid_active_status = _is_paid_payment_status(normalized_payment_status) and _is_active_entitlement_status(normalized_entitlements_status)

        effective_purchase_reference = purchase_reference
        effective_checkout_session_id = checkout_session_id
        if metadata is not None and isinstance(metadata, dict):
            if effective_purchase_reference is None:
                effective_purchase_reference = metadata.get("purchase_reference")
            if effective_checkout_session_id is None:
                effective_checkout_session_id = metadata.get("checkout_session_id")

        has_real_payment_reference = bool((str(effective_purchase_reference or "").strip()) or (str(effective_checkout_session_id or "").strip()))

        if not has_real_payment_reference:
            raise InstallKeyPaymentRequiredError(
                owner_key,
                normalized_program,
                reason="legacy install-key generation requires a real purchase_reference or checkout_session_id from a completed paid checkout.",
            )

        if not has_paid_active_status:
            raise InstallKeyPaymentRequiredError(
                owner_key,
                normalized_program,
                reason="legacy install-key generation requires a paid-active entitlement with a real purchase_reference / checkout_session_id from a completed paid checkout.",
            )

        return self.generate_for_paid_customer(
            owner_key=owner_key,
            subscription_id=subscription_id,
            program=normalized_program,
            org_id=org_id,
            customer_id=customer_id,
            payment_status=effective_payment_status,
            entitlements_status=effective_entitlements_status,
            issued_after_payment=issued_after_payment,
            purchase_reference=purchase_reference,
            checkout_session_id=checkout_session_id,
            label=label,
            metadata=metadata,
            secure_record_persistor=secure_record_persistor,
        )

    # ------------------------------------------------------------------
    # get_keys_for_owner
    # ------------------------------------------------------------------

    def get_keys_for_owner(self, owner_key: str) -> list[InstallKeyRecord]:
        """Return all install key records (active and revoked) for the canonical owner_key."""
        normalized_owner = _canonical_owner_key(owner_key)
        with self._lock:
            self._ensure_loaded()
            reconciled: list[InstallKeyRecord] = []
            for record in self._records_by_id.values():
                if record.owner_key == normalized_owner:
                    reconciled.append(self._reconcile_key_state(record))
            return reconciled

    # ------------------------------------------------------------------
    # get_key_by_id
    # ------------------------------------------------------------------

    def get_key_by_id(self, key_id: str) -> InstallKeyRecord | None:
        with self._lock:
            self._ensure_loaded()
            record = self._records_by_id.get(key_id)
            if record is None:
                return None
            return self._reconcile_key_state(record)

    # ------------------------------------------------------------------
    # authenticate_install_key
    # ------------------------------------------------------------------

    def get_keys_for_purchase(self, purchase_reference: str) -> list[InstallKeyRecord]:
        reference = str(purchase_reference or "").strip()
        if not reference:
            return []
        with self._lock:
            self._ensure_loaded()
            return [record for record in self._records_by_id.values() if reference in {record.purchase_reference, record.checkout_session_id}]

    def authenticate_install_key(self, raw_key: str) -> InstallKeyRecord | None:
        """
        Constant-time authenticate an install key.
        Returns the record if the key is active, paid, and still entitled.
        Updates last_used_at on success.
        """
        if not isinstance(raw_key, str) or not raw_key.strip():
            return None

        candidate_hash = _hash_key(raw_key)

        with self._lock:
            self._ensure_loaded()
            key_id = self._key_id_by_hash.get(candidate_hash)
            if not key_id:
                return None
            record = self._records_by_id.get(key_id)
            if record is None:
                return None
            if record.revoked_at is not None:
                return None
            record = self._reconcile_key_state(record)
            if not record.active:
                return None
            if not record.raw_key_hash:
                return None
            if record.revoked_at is not None:
                return None
            if record.payment_status != "paid" or record.entitlements_status != "active" or not record.issued_after_payment:
                return None

            if not _constant_time_match(candidate_hash, record.raw_key_hash):
                return None

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
                payment_status=record.payment_status,
                entitlements_status=record.entitlements_status,
                issued_after_payment=record.issued_after_payment,
                org_id=record.org_id,
                customer_id=record.customer_id,
                units_consumed=record.units_consumed,
                created_at=record.created_at,
                last_used_at=now,
                revoked_at=record.revoked_at,
                purchase_reference=record.purchase_reference,
                checkout_session_id=record.checkout_session_id,
                metadata=record.metadata,
            )
            self._records_by_id[key_id] = updated

            def _persist_last_used() -> None:
                client = get_supabase_service_client()
                client.table(_T_INSTALL_KEYS).update({"last_used_at": now.isoformat()}).eq("key_id", key_id).execute()

            _persist_install_key_update(key_id=key_id, action="last_used_at", callback=_persist_last_used)

            return updated

    # ------------------------------------------------------------------
    # revoke_key
    # ------------------------------------------------------------------

    def revoke_key(self, key_id: str, *, reason: str = "install_key_revoked", finalize_inactive: bool = False) -> InstallKeyRecord:
        """Deactivate an install key. Returns the updated record.

        ``finalize_inactive`` upgrades keys already locked by reconciliation to the ``revoked`` entitlement state.
        """
        with self._lock:
            self._ensure_loaded()
            record = self._records_by_id.get(key_id)
            if record is None:
                raise InstallKeyNotFoundError(key_id)

            if not record.active and not (finalize_inactive and record.entitlements_status != "revoked"):
                return record

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
                active=False,
                payment_status=record.payment_status,
                entitlements_status="revoked",
                issued_after_payment=record.issued_after_payment,
                org_id=record.org_id,
                customer_id=record.customer_id,
                units_consumed=record.units_consumed,
                created_at=record.created_at,
                last_used_at=record.last_used_at,
                revoked_at=record.revoked_at or now,
                purchase_reference=record.purchase_reference,
                checkout_session_id=record.checkout_session_id,
                metadata={**record.metadata, "revoke_reason": reason},
            )
            self._records_by_id[key_id] = updated

            persisted = _persist_install_key_update(
                key_id=key_id,
                action="revocation",
                callback=lambda: _write_key_revocation(updated, reason=reason),
            )
            if persisted:
                self._pending_revocations.pop(key_id, None)
            else:
                self._pending_revocations[key_id] = (updated, reason)

            _logger.info("install_key_revoked", extra={"key_id": key_id, "owner_key": record.owner_key})
            return updated

    def _revoke_matching(self, predicate: Callable[[InstallKeyRecord], bool], *, reason: str) -> list[InstallKeyRecord]:
        with self._lock:
            self._ensure_loaded()
            matches = [record for record in self._records_by_id.values() if predicate(record)]
            for record in matches:
                self.revoke_key(record.key_id, reason=reason, finalize_inactive=True)
            return matches

    def revoke_keys_for_purchase(self, purchase_reference: str, *, reason: str = "refunded") -> list[InstallKeyRecord]:
        reference = str(purchase_reference or "").strip()
        if not reference:
            return []
        return self._revoke_matching(
            lambda record: reference in {record.purchase_reference, record.checkout_session_id},
            reason=reason,
        )

    def revoke_keys_for_refund(self, *, checkout_session_ids: set[str], payment_intent: str | None) -> list[InstallKeyRecord]:
        intent_value = str(payment_intent or "").strip()
        return self._revoke_matching(
            lambda record: record.checkout_session_id in checkout_session_ids or record.purchase_reference in checkout_session_ids or (intent_value and str(record.metadata.get("payment_intent") or "") == intent_value),
            reason="refunded",
        )

    # ------------------------------------------------------------------
    # record_key_usage
    # ------------------------------------------------------------------

    def record_key_usage(self, key_id: str, *, units: int) -> InstallKeyRecord:
        """
        Increment units_consumed for the given key_id and persist to Supabase.
        Raises InstallKeyNotFoundError if key_id is unknown.
        Raises InstallKeyUsageError if key is inactive or units <= 0.
        """
        if units <= 0:
            raise InstallKeyUsageError(key_id, "units must be a positive integer")

        with self._lock:
            self._ensure_loaded()
            record = self._records_by_id.get(key_id)
            if record is None:
                raise InstallKeyNotFoundError(key_id)
            if record.revoked_at is not None:
                raise InstallKeyUsageError(key_id, "key has been revoked and cannot record usage")
            record = self._reconcile_key_state(record)
            if not record.active:
                raise InstallKeyUsageError(key_id, "key is inactive and cannot record usage")
            if record.revoked_at is not None:
                raise InstallKeyUsageError(key_id, "key has been revoked and cannot record usage")
            if record.payment_status != "paid" or record.entitlements_status != "active" or not record.issued_after_payment:
                raise InstallKeyUsageError(key_id, "key is not backed by a valid paid entitlement")

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
                payment_status=record.payment_status,
                entitlements_status=record.entitlements_status,
                issued_after_payment=record.issued_after_payment,
                org_id=record.org_id,
                customer_id=record.customer_id,
                units_consumed=new_consumed,
                created_at=record.created_at,
                last_used_at=now,
                revoked_at=record.revoked_at,
                purchase_reference=record.purchase_reference,
                checkout_session_id=record.checkout_session_id,
                metadata=record.metadata,
            )
            self._records_by_id[key_id] = updated

            def _persist_usage() -> None:
                client = get_supabase_service_client()
                client.table(_T_INSTALL_KEYS).update(
                    {
                        "units_consumed": new_consumed,
                        "last_used_at": now.isoformat(),
                    }
                ).eq("key_id", key_id).execute()

            _persist_install_key_update(key_id=key_id, action="usage", callback=_persist_usage)

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
        cursor = sum(1 for r in records if r.program == "cursor")
        goose = sum(1 for r in records if r.program == "goose")
        gemini = sum(1 for r in records if r.program == "gemini_cli")
        copilot = sum(1 for r in records if r.program == "copilot")
        security_guardian = sum(1 for r in records if r.program == "security_guardian")
        hermes = sum(1 for r in records if r.program == "hermes")
        return {
            "total": total,
            "active": active,
            "revoked": total - active,
            "openclaw_keys": openclaw,
            "claude_code_keys": claude,
            "cursor_keys": cursor,
            "goose_keys": goose,
            "gemini_cli_keys": gemini,
            "copilot_keys": copilot,
            "hermes_keys": hermes,
            "security_guardian_keys": security_guardian,
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
    "InstallKeyPaymentRequiredError",
    "InstallKeyNotFoundError",
    "InstallKeyAlreadyExistsError",
    "InstallKeyUsageError",
    "InstallKeyRegistry",
    "ProgramCode",
    "get_install_key_registry",
    "_reset_install_key_registry_for_testing",
]
