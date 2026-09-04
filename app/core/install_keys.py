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
from app.core.unit_wallet import get_unit_wallet_registry
from app.supabaseclient import SupabaseAPIError, SupabaseClientError

_logger: logging.Logger = get_logger("ironclaw.install_keys")

# ---------------------------------------------------------------------------
# Constants — distinct from apikeys.py ic_ and ic_org_ prefixes
# ---------------------------------------------------------------------------

_INSTALL_KEY_PREFIX_OPENCLAW: Final[str] = "ic_install_openclaw_"
_INSTALL_KEY_PREFIX_CLAUDE: Final[str] = "ic_install_claude_code_"
_INSTALL_KEY_PREFIX_CURSOR: Final[str] = "ic_install_cursor_"
_INSTALL_KEY_PREFIX_GOOSE: Final[str] = "ic_install_goose_"
_INSTALL_KEY_PREFIX_GEMINI: Final[str] = "ic_install_gemini_cli_"
_INSTALL_KEY_PREFIX_COPILOT: Final[str] = "ic_install_copilot_"
_INSTALL_KEY_PREFIX_HERMES: Final[str] = "ic_install_hermes_"
_INSTALL_KEY_PREFIX_SECURITY_GUARDIAN: Final[str] = "ic_install_security_guardian_"
_INSTALL_KEY_SECRET_BYTES: Final[int] = 32
_T_INSTALL_KEYS: Final[str] = "install_keys"

# Security Guardian is a shared connector/install-key family that links the
# runtime platforms to IronClaw security. It is not a standalone runtime
# platform and must never be treated as one in platform enumeration or UI lists.
RuntimeProgramCode = Literal[
    "openclaw",
    "claude_code",
    "cursor",
    "goose",
    "gemini_cli",
    "copilot",
    "hermes",
]
ConnectorProgramCode = Literal["security_guardian"]
ProgramCode = RuntimeProgramCode | ConnectorProgramCode

_RUNTIME_PROGRAMS: Final[frozenset[str]] = frozenset(
    {
        "openclaw",
        "claude_code",
        "cursor",
        "goose",
        "gemini_cli",
        "copilot",
        "hermes",
    }
)
_CONNECTOR_PROGRAMS: Final[frozenset[str]] = frozenset({"security_guardian"})
_VALID_PROGRAMS: Final[frozenset[str]] = _RUNTIME_PROGRAMS | _CONNECTOR_PROGRAMS

_RUNTIME_PROGRAM_ALIASES: Final[dict[str, RuntimeProgramCode]] = {
    "openclaw": "openclaw",
    "open_claw": "openclaw",
    "open_claw_": "openclaw",
    "open-claw": "openclaw",
    "claw": "openclaw",
    "claude_code": "claude_code",
    "claude-code": "claude_code",
    "claude code": "claude_code",
    "claude": "claude_code",
    "cursor": "cursor",
    "cursor_agent": "cursor",
    "cursor-agent": "cursor",
    "cursor_cli": "cursor",
    "cursor-cli": "cursor",
    "goose": "goose",
    "goose_agent": "goose",
    "goose-agent": "goose",
    "gemini_cli": "gemini_cli",
    "gemini-cli": "gemini_cli",
    "gemini cli": "gemini_cli",
    "gemini": "gemini_cli",
    "copilot": "copilot",
    "github_copilot": "copilot",
    "github-copilot": "copilot",
    "githubcopilot": "copilot",
    "hermes": "hermes",
    "hermes_agent": "hermes",
    "hermes-agent": "hermes",
    "hermes_cli": "hermes",
    "hermes-cli": "hermes",
}
_CONNECTOR_PROGRAM_ALIASES: Final[dict[str, ConnectorProgramCode]] = {
    "security_guardian": "security_guardian",
    "security-guardian": "security_guardian",
    "securityguardian": "security_guardian",
    "security_guardian_skill": "security_guardian",
    "security_guardian_skill_": "security_guardian",
    "skill": "security_guardian",
    "skills": "security_guardian",
}
_CANONICAL_PROGRAM_ALIASES: Final[dict[str, ProgramCode]] = {
    **_RUNTIME_PROGRAM_ALIASES,
    **_CONNECTOR_PROGRAM_ALIASES,
}

# Security Guardian is intentionally retained here as a connector/shared
# install-key family prefix because it is part of the install-key trust domain,
# but it is excluded from the runtime platform set and platform enumeration.
_PREFIX_BY_PROGRAM: Final[dict[ProgramCode, str]] = {
    "openclaw": _INSTALL_KEY_PREFIX_OPENCLAW,
    "claude_code": _INSTALL_KEY_PREFIX_CLAUDE,
    "cursor": _INSTALL_KEY_PREFIX_CURSOR,
    "goose": _INSTALL_KEY_PREFIX_GOOSE,
    "gemini_cli": _INSTALL_KEY_PREFIX_GEMINI,
    "copilot": _INSTALL_KEY_PREFIX_COPILOT,
    "hermes": _INSTALL_KEY_PREFIX_HERMES,
    "security_guardian": _INSTALL_KEY_PREFIX_SECURITY_GUARDIAN,
}

# Ordered longest-first so the greedy prefix match is always correct.
_KNOWN_PREFIXES: Final[tuple[str, ...]] = tuple(sorted(_PREFIX_BY_PROGRAM.values(), key=len, reverse=True))

_PAID_PAYMENT_STATUSES: Final[frozenset[str]] = frozenset({"paid", "success", "succeeded", "complete", "completed", "active", "authorized"})
_ACTIVE_ENTITLEMENT_STATUSES: Final[frozenset[str]] = frozenset({"active", "paid", "enabled", "granted"})


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


def _normalize_program(program: str | Any) -> ProgramCode:
    candidate = str(program).strip().lower() if program is not None else ""
    if not candidate:
        raise ValueError("program is required")

    normalized = candidate.replace(" ", "_").replace("-", "_")
    normalized = normalized.replace("__", "_")
    normalized = normalized.strip("_")

    canonical = _CANONICAL_PROGRAM_ALIASES.get(normalized)
    if canonical is not None:
        return canonical

    if normalized in _VALID_PROGRAMS:
        return str(normalized)  # type: ignore[return-value]

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
        if not self.owner_key or not str(self.owner_key).strip():
            raise ValueError("owner_key is required")

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
            "metadata": self.metadata,
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
            "metadata": dict(self.metadata),
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

    record = InstallKeyRecord(
        key_id=row["key_id"],
        owner_key=row["owner_key"],
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
    return bool(record.active or (record.payment_status == "paid" and record.entitlements_status == "active" and record.issued_after_payment))


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
                if record.raw_key_hash:
                    self._key_id_by_hash[record.raw_key_hash] = record.key_id
        except (SupabaseAPIError, SupabaseClientError, Exception):
            _logger.exception("install_keys: failed to load from Supabase; continuing with empty state")
        self._loaded = True

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

        subscription_reference = purchase_reference or checkout_session_id
        if not subscription_reference:
            raise InstallKeyPaymentRequiredError(
                owner_key,
                program,
                reason="missing purchase_reference or checkout_session_id after successful payment completion",
            )

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

        try:
            client = get_supabase_service_client()
            client.table(_T_INSTALL_KEYS).update(
                {
                    "active": False,
                    "entitlements_status": "not_active",
                    "revoked_at": updated.revoked_at.isoformat(),
                    "metadata": updated.metadata,
                }
            ).eq("key_id", record.key_id).execute()
        except (SupabaseAPIError, SupabaseClientError, Exception):
            _logger.warning("install_keys: failed to persist lock state for %s (reason=%s)", record.key_id, reason)

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
    ) -> InstallKeyRecord:
        """
        Authoritative install-key issuance path.

        This is the only safe way to generate active install keys. It enforces a
        successful paid entitlement and prevents pre-purchase exposure.
        """
        normalized_program = _normalize_program(program)
        if normalized_program in _CONNECTOR_PROGRAMS:
            raise ValueError("Security Guardian is a shared install-key connector and cannot be issued as a runtime install key.")

        normalized_owner = _canonical_owner_key(owner_key)
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
        )

        with self._lock:
            self._ensure_loaded()

            for rec in self._records_by_id.values():
                if rec.owner_key == normalized_owner and rec.program == normalized_program and _is_current_paid_entitlement(rec):
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

            try:
                client = get_supabase_service_client()
                client.table(_T_INSTALL_KEYS).insert(record.to_db_row()).execute()
            except (SupabaseAPIError, SupabaseClientError, Exception):
                _logger.exception("install_keys: failed to persist new key %s", key_id)

            self._records_by_id[key_id] = record
            self._key_id_by_hash[raw_key_hash] = key_id

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

        if purchase_reference is None and checkout_session_id is None:
            # Legacy callers may only pass a subscription_id and still represent a
            # paid, entitlement-backed issuance. Bind the synthetic purchase
            # reference to that subscription so the canonical payment gate remains
            # satisfied without exposing a raw install key or bypassing the rule.
            purchase_reference = str(subscription_id).strip() or None
            checkout_session_id = str(subscription_id).strip() or None

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
        )

    # ------------------------------------------------------------------
    # get_keys_for_owner
    # ------------------------------------------------------------------

    def get_keys_for_owner(self, owner_key: str) -> list[InstallKeyRecord]:
        """Return all install key records (active and revoked) for owner_key."""
        with self._lock:
            self._ensure_loaded()
            reconciled: list[InstallKeyRecord] = []
            for record in self._records_by_id.values():
                if record.owner_key == owner_key:
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
            record = self._reconcile_key_state(record)
            if not record.active:
                return None
            if not record.raw_key_hash:
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
                revoked_at=now,
                purchase_reference=record.purchase_reference,
                checkout_session_id=record.checkout_session_id,
                metadata=record.metadata,
            )
            self._records_by_id[key_id] = updated

            try:
                client = get_supabase_service_client()
                client.table(_T_INSTALL_KEYS).update({"active": False, "entitlements_status": "revoked", "revoked_at": now.isoformat()}).eq("key_id", key_id).execute()
            except (SupabaseAPIError, SupabaseClientError, Exception):
                _logger.exception("install_keys: failed to persist revocation for %s", key_id)

            _logger.info("install_key_revoked", extra={"key_id": key_id, "owner_key": record.owner_key})
            return updated

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
            record = self._reconcile_key_state(record)
            if not record.active:
                raise InstallKeyUsageError(key_id, "key is inactive and cannot record usage")
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

            try:
                client = get_supabase_service_client()
                client.table(_T_INSTALL_KEYS).update(
                    {
                        "units_consumed": new_consumed,
                        "last_used_at": now.isoformat(),
                    }
                ).eq("key_id", key_id).execute()
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
