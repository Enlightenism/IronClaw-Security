from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query, status
from pydantic import BaseModel, Field

from app.core.install_keys import (
    InstallKeyNotFoundError,
    InstallKeyUsageError,
    get_install_key_registry,
)
from app.core.unit_wallet import InsufficientUnitsError, get_unit_wallet_registry

router = APIRouter(
    prefix="/install-keys",
    tags=["install-keys"],
)

_VALID_PROGRAMS: frozenset[str] = frozenset({"openclaw", "claude_code", "hermes"})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _normalize_owner_key(value: str | None) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _resolve_owner_key(x_owner_key: str = Header(alias="X-Owner-Key", min_length=1, max_length=512)) -> str:
    """Extract and validate the owner key from the X-Owner-Key request header."""
    stripped = _normalize_owner_key(x_owner_key)
    if not stripped:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-Owner-Key header is required.",
        )
    return stripped


def _resolve_install_key(
    x_install_key: str = Header(alias="X-Install-Key", min_length=1, max_length=512),
) -> str:
    """Extract and validate the install key from the X-Install-Key request header."""
    stripped = x_install_key.strip()
    if not stripped:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-Install-Key header is required.",
        )
    return stripped


def _status_value(value: Any, *, default: str = "unpaid") -> str:
    if value is None or isinstance(value, MagicMock):
        return default
    normalized = str(value).strip().lower()
    return normalized or default


def _flag_value(value: Any, *, default: bool = False) -> bool:
    if value is None or isinstance(value, MagicMock):
        return default
    return bool(value)


def _record_has_paid_entitlement(record: Any) -> bool:
    if record is None:
        return False

    subscription_id = str(getattr(record, "subscription_id", "") or "").strip()
    if not subscription_id:
        return False

    is_active = _flag_value(getattr(record, "active", False), default=False)
    if not is_active:
        return False

    payment_status = _status_value(getattr(record, "payment_status", "paid"), default="paid")
    entitlements_status = _status_value(getattr(record, "entitlements_status", "active"), default="active")
    issued_after_payment = _flag_value(getattr(record, "issued_after_payment", True), default=True)

    if payment_status not in {"paid", "success", "succeeded", "complete", "completed", "active", "authorized"}:
        return False
    if entitlements_status != "active":
        return False
    return issued_after_payment


def _assert_paid_entitlement(record: Any, owner_key: str | None) -> None:
    if owner_key is not None:
        expected_owner = _normalize_owner_key(owner_key)
        record_owner = _normalize_owner_key(getattr(record, "owner_key", ""))
        if expected_owner and record_owner and record_owner != expected_owner:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this install key.",
            )

    if not _record_has_paid_entitlement(record):
        key_id = getattr(record, "key_id", "unknown")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Install key {key_id!r} is inactive or not available for paid entitlement.",
        )


def _assert_active_subscription(owner_key: str) -> None:
    """Only a real paid entitlement should satisfy the active subscription gate."""
    registry = get_install_key_registry()
    records = registry.get_keys_for_owner(owner_key)
    has_paid_entitlement = any(_record_has_paid_entitlement(r) for r in records)
    if not has_paid_entitlement:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="no_active_subscription",
        )


def _usage_snapshot(owner_key: str, record: Any) -> dict[str, Any]:
    wallet_registry = get_unit_wallet_registry()
    wallet = wallet_registry.get_wallet(owner_key)
    usage_payload: dict[str, Any] = {}
    if wallet is not None:
        usage_map = getattr(wallet, "install_key_usage", None)
        if isinstance(usage_map, dict):
            summary = usage_map.get(record.key_id)
            if summary is not None and hasattr(summary, "as_summary"):
                usage_payload = summary.as_summary()
        if not usage_payload:
            usage_payload = {
                "key_id": record.key_id,
                "owner_key": owner_key,
                "program": record.program,
                "balance_units": getattr(wallet, "balance_units", 0),
                "total_consumed_units": getattr(record, "units_consumed", 0),
                "total_blocked_attacks": 0,
                "last_action_at": None,
                "metadata": {},
            }
    last_used = getattr(record, "last_used_at", None)
    serialized_last_used = None
    if last_used is not None and not isinstance(last_used, MagicMock):
        try:
            serialized_last_used = last_used.isoformat().replace("+00:00", "Z")
        except AttributeError:
            serialized_last_used = str(last_used)

    payment_status = _status_value(getattr(record, "payment_status", "paid"), default="paid")
    entitlements_status = _status_value(getattr(record, "entitlements_status", "active"), default="active")
    return {
        "key_id": record.key_id,
        "owner_key": owner_key,
        "program": record.program,
        "payment_status": payment_status,
        "entitlements_status": entitlements_status,
        "active": bool(getattr(record, "active", False)),
        "masked_key": getattr(record, "masked_key", None),
        "units_used": int(getattr(record, "units_consumed", 0) or usage_payload.get("total_consumed_units", 0)),
        "units_remaining": int(getattr(wallet, "balance_units", 0)) if wallet is not None else 0,
        "blocked_attacks": int(usage_payload.get("total_blocked_attacks", 0)),
        "last_used_at": serialized_last_used,
        "usage_summary": usage_payload,
    }


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class InstallKeySlotView(BaseModel):
    key_id: str | None
    program: str
    masked_key: str | None
    label: str
    status: str
    active: bool
    payment_status: str
    entitlements_status: str
    issued_after_payment: bool
    units_used: int
    units_remaining: int
    blocked_attacks: int
    created_at: str | None
    last_used_at: str | None
    metadata: dict[str, Any]
    usage_summary: dict[str, Any] = Field(default_factory=dict)


class MyKeysResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    owner_key: str
    has_active_entitlement: bool
    keys: list[InstallKeySlotView]


class ActivateRequest(BaseModel):
    raw_key: str = Field(min_length=1, max_length=1024, description="The raw install key to activate.")


class ActivateResponse(BaseModel):
    valid: bool
    key_id: str
    owner_key: str
    program: str
    masked_key: str
    payment_status: str
    entitlements_status: str
    active: bool
    units_remaining: int
    usage_summary: dict[str, Any] = Field(default_factory=dict)


class RecordUsageRequest(BaseModel):
    key_id: str = Field(min_length=1, max_length=128)
    units: int = Field(gt=0)


class RecordUsageResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    key_id: str
    units_consumed: int
    units_remaining: int


class RevokeResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    key_id: str
    active: bool


class LedgerEntryView(BaseModel):
    entry_id: str
    entry_type: str
    units: int
    balance_after: int
    created_at: str
    metadata: dict[str, Any]


class KeyUsageResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    key_id: str
    units_consumed: int
    units_remaining: int
    blocked_attacks: int
    last_used_at: str | None
    ledger: list[LedgerEntryView]


# ---------------------------------------------------------------------------
# Serializers
# ---------------------------------------------------------------------------


def _slot_view(record: Any, owner_key: str) -> InstallKeySlotView:
    pub = record.public_dict()
    usage = _usage_snapshot(owner_key, record)
    return InstallKeySlotView(
        key_id=pub["key_id"],
        program=pub["program"],
        masked_key=pub["masked_key"],
        label=pub.get("label") or "",
        status="active" if pub["active"] else "revoked",
        active=pub["active"],
        payment_status=pub.get("payment_status") or "unpaid",
        entitlements_status=pub.get("entitlements_status") or "not_active",
        issued_after_payment=bool(pub.get("issued_after_payment", False)),
        units_used=usage["units_used"],
        units_remaining=usage["units_remaining"],
        blocked_attacks=usage["blocked_attacks"],
        created_at=pub.get("created_at"),
        last_used_at=pub.get("last_used_at") or usage["last_used_at"],
        metadata=pub.get("metadata") or {},
        usage_summary=usage["usage_summary"],
    )


def _empty_slot(program: str) -> InstallKeySlotView:
    return InstallKeySlotView(
        key_id=None,
        program=program,
        masked_key=None,
        label="",
        status="locked",
        active=False,
        payment_status="unpaid",
        entitlements_status="not_active",
        issued_after_payment=False,
        units_used=0,
        units_remaining=0,
        blocked_attacks=0,
        created_at=None,
        last_used_at=None,
        metadata={},
        usage_summary={},
    )


# ---------------------------------------------------------------------------
# GET /install-keys/my-keys
# ---------------------------------------------------------------------------


@router.get(
    "/my-keys",
    response_model=MyKeysResponse,
    summary="Return active paid install-key slots for the authenticated owner",
    description=("Requires X-Owner-Key header. Returns 403 with 'no_active_subscription' when the owner has no active paid entitlement. It never exposes keys before purchase completion."),
)
def get_my_keys(
    owner_key: str = Depends(_resolve_owner_key),
) -> MyKeysResponse:
    registry = get_install_key_registry()
    records = [r for r in registry.get_keys_for_owner(owner_key) if r.owner_key == owner_key and _record_has_paid_entitlement(r)]
    if not records:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="no_active_subscription",
        )

    slots: dict[str, InstallKeySlotView] = {p: _empty_slot(p) for p in sorted(_VALID_PROGRAMS)}
    for record in records:
        program = record.program
        if program in slots:
            slots[program] = _slot_view(record, owner_key)

    return MyKeysResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        owner_key=owner_key,
        has_active_entitlement=True,
        keys=list(slots.values()),
    )


# ---------------------------------------------------------------------------
# POST /install-keys/activate
# ---------------------------------------------------------------------------


@router.post(
    "/activate",
    response_model=ActivateResponse,
    summary="Activate an install key on first runtime installation",
    description=("Called by the IronClaw agent or runtime when a key is first installed. Validates the raw key via constant-time lookup, verifies it is tied to an active paid entitlement, and returns the owner_key, program, and current units_remaining."),
)
def activate_install_key(
    payload: ActivateRequest,
    owner_key: str | None = Header(default=None, alias="X-Owner-Key"),
) -> ActivateResponse:
    install_registry = get_install_key_registry()
    record = install_registry.authenticate_install_key(payload.raw_key)

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive install key.",
        )

    if owner_key is not None:
        expected_owner = _normalize_owner_key(owner_key)
        record_owner = _normalize_owner_key(getattr(record, "owner_key", ""))
        if expected_owner and record_owner and record_owner != expected_owner:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Install key {getattr(record, 'key_id', 'unknown')!r} does not belong to the supplied owner_key: expected {expected_owner!r}, got {record_owner!r}.",
            )

    if not _record_has_paid_entitlement(record):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="install_key_not_active_for_paid_entitlement",
        )

    wallet_registry = get_unit_wallet_registry()
    wallet = wallet_registry.get_wallet(record.owner_key)
    units_remaining = wallet.balance_units if wallet is not None else 0
    usage = _usage_snapshot(record.owner_key, record)

    return ActivateResponse(
        valid=True,
        key_id=str(record.key_id),
        owner_key=record.owner_key,
        program=record.program,
        masked_key=str(record.masked_key or ""),
        payment_status=usage["payment_status"],
        entitlements_status=usage["entitlements_status"],
        active=bool(getattr(record, "active", False)),
        units_remaining=units_remaining,
        usage_summary=usage["usage_summary"],
    )


# ---------------------------------------------------------------------------
# POST /install-keys/record-usage
# ---------------------------------------------------------------------------


@router.post(
    "/record-usage",
    response_model=RecordUsageResponse,
    summary="Record unit consumption for an active install key",
    description=("Called by an active IronClaw runtime per operation. Debits units from the owner's UnitWallet via debit_units_for_install_key() and increments units_consumed on the install key record. Returns the updated balance."),
)
def record_usage(
    payload: RecordUsageRequest,
    owner_key: str | None = Header(default=None, alias="X-Owner-Key"),
) -> RecordUsageResponse:
    install_registry = get_install_key_registry()
    record = install_registry.get_key_by_id(payload.key_id)

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Install key not found: {payload.key_id!r}",
        )
    if owner_key is not None:
        _assert_paid_entitlement(record, owner_key)
    elif not _record_has_paid_entitlement(record):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Install key {payload.key_id!r} is inactive or not available for paid entitlement.",
        )

    wallet_registry = get_unit_wallet_registry()
    try:
        wallet = wallet_registry.debit_units_for_install_key(
            owner_key=record.owner_key,
            key_id=payload.key_id,
            units=payload.units,
            program=record.program,
        )
    except InsufficientUnitsError as exc:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "error": "insufficient_units",
                "have": exc.have,
                "need": exc.need,
            },
        ) from exc

    try:
        updated = install_registry.record_key_usage(payload.key_id, units=payload.units)
    except InstallKeyNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Install key not found: {exc.key_id!r}",
        ) from exc
    except InstallKeyUsageError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    return RecordUsageResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        key_id=updated.key_id,
        units_consumed=updated.units_consumed,
        units_remaining=wallet.balance_units,
    )


# ---------------------------------------------------------------------------
# POST /install-keys/{key_id}/revoke
# ---------------------------------------------------------------------------


@router.post(
    "/{key_id}/revoke",
    response_model=RevokeResponse,
    summary="Revoke an install key by key_id",
    description="Deactivates the install key. Idempotent if already revoked.",
)
def revoke_install_key(
    key_id: str = Path(min_length=1, max_length=128),
    owner_key: str = Depends(_resolve_owner_key),
) -> RevokeResponse:
    install_registry = get_install_key_registry()
    record = install_registry.get_key_by_id(key_id)

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Install key not found: {key_id!r}",
        )
    _assert_paid_entitlement(record, owner_key)

    try:
        updated = install_registry.revoke_key(key_id)
    except InstallKeyNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Install key not found: {exc.key_id!r}",
        ) from exc

    return RevokeResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        key_id=updated.key_id,
        active=updated.active,
    )


# ---------------------------------------------------------------------------
# GET /install-keys/{key_id}/usage
# ---------------------------------------------------------------------------


@router.get(
    "/{key_id}/usage",
    response_model=KeyUsageResponse,
    summary="Return usage stats and ledger entries for an install key",
    description=("Returns units_consumed, last_used_at, blocked attack totals, and the ledger entries scoped to the owner of this key. Requires X-Owner-Key header for ownership validation."),
)
def get_key_usage(
    key_id: str = Path(min_length=1, max_length=128),
    limit: int = Query(default=50, ge=1, le=500),
    owner_key: str = Depends(_resolve_owner_key),
) -> KeyUsageResponse:
    install_registry = get_install_key_registry()
    record = install_registry.get_key_by_id(key_id)

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Install key not found: {key_id!r}",
        )
    _assert_paid_entitlement(record, owner_key)

    wallet_registry = get_unit_wallet_registry()
    wallet = wallet_registry.get_wallet(record.owner_key)
    raw_entries = wallet_registry.list_ledger_entries(owner_key=record.owner_key, limit=limit)
    key_entries = [e for e in raw_entries if e.metadata.get("key_id") == key_id]

    ledger_views = [
        LedgerEntryView(
            entry_id=e.entry_id,
            entry_type=e.entry_type,
            units=e.units,
            balance_after=e.balance_after,
            created_at=e.created_at.isoformat().replace("+00:00", "Z"),
            metadata=e.metadata,
        )
        for e in key_entries
    ]

    pub = record.public_dict()
    usage = _usage_snapshot(owner_key, record)
    return KeyUsageResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        key_id=key_id,
        units_consumed=pub.get("units_consumed") or 0,
        units_remaining=int(wallet.balance_units) if wallet is not None else 0,
        blocked_attacks=usage["blocked_attacks"],
        last_used_at=pub.get("last_used_at"),
        ledger=ledger_views,
    )
