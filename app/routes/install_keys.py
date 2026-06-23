from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

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

_VALID_PROGRAMS: frozenset[str] = frozenset({"openclaw", "claude_code"})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _resolve_owner_key(x_owner_key: str = Header(alias="X-Owner-Key", min_length=1, max_length=512)) -> str:
    """Extract and validate the owner key from the X-Owner-Key request header."""
    stripped = x_owner_key.strip()
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


def _assert_active_subscription(owner_key: str) -> None:
    """
    Gate: owner must have at least one active install key record with a non-empty
    subscription_id. If no qualifying record exists we return 403 with the
    canonical error code 'no_active_subscription'.
    """
    registry = get_install_key_registry()
    records = registry.get_keys_for_owner(owner_key)
    has_subscription = any(bool(r.subscription_id and r.subscription_id.strip()) for r in records)
    if not has_subscription:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="no_active_subscription",
        )


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class InstallKeySlotView(BaseModel):
    key_id: str | None
    program: str
    masked_key: str | None
    label: str
    active: bool
    units_consumed: int
    created_at: str | None
    last_used_at: str | None
    metadata: dict[str, Any]


class MyKeysResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    owner_key: str
    keys: list[InstallKeySlotView]


class ActivateRequest(BaseModel):
    raw_key: str = Field(min_length=1, max_length=1024, description="The raw install key to activate.")


class ActivateResponse(BaseModel):
    valid: bool
    owner_key: str
    program: str
    units_remaining: int


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
    last_used_at: str | None
    ledger: list[LedgerEntryView]


# ---------------------------------------------------------------------------
# Serializers
# ---------------------------------------------------------------------------


def _slot_view(record: Any) -> InstallKeySlotView:
    pub = record.public_dict()
    return InstallKeySlotView(
        key_id=pub["key_id"],
        program=pub["program"],
        masked_key=pub["masked_key"],
        label=pub.get("label") or "",
        active=pub["active"],
        units_consumed=pub.get("units_consumed") or 0,
        created_at=pub.get("created_at"),
        last_used_at=pub.get("last_used_at"),
        metadata=pub.get("metadata") or {},
    )


def _empty_slot(program: str) -> InstallKeySlotView:
    return InstallKeySlotView(
        key_id=None,
        program=program,
        masked_key=None,
        label="",
        active=False,
        units_consumed=0,
        created_at=None,
        last_used_at=None,
        metadata={},
    )


# ---------------------------------------------------------------------------
# GET /install-keys/my-keys
# ---------------------------------------------------------------------------


@router.get(
    "/my-keys",
    response_model=MyKeysResponse,
    summary="Return both program install key slots for the authenticated owner",
    description=("Requires X-Owner-Key header. Returns 403 with 'no_active_subscription' if no subscription exists. Returns empty slot entries if keys have not been generated yet (pre-purchase state)."),
)
def get_my_keys(
    owner_key: str = Depends(_resolve_owner_key),
) -> MyKeysResponse:
    _assert_active_subscription(owner_key)

    registry = get_install_key_registry()
    records = registry.get_keys_for_owner(owner_key)

    slots: dict[str, InstallKeySlotView] = {p: _empty_slot(p) for p in sorted(_VALID_PROGRAMS)}
    for record in records:
        if record.active or slots[record.program].key_id is None:
            slots[record.program] = _slot_view(record)

    return MyKeysResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        owner_key=owner_key,
        keys=list(slots.values()),
    )


# ---------------------------------------------------------------------------
# POST /install-keys/activate
# ---------------------------------------------------------------------------


@router.post(
    "/activate",
    response_model=ActivateResponse,
    summary="Activate an install key on first runtime installation",
    description=("Called by the IronClaw agent or runtime when a key is first installed. Validates the raw key via constant-time lookup, marks last_used_at, and returns the owner_key, program, and current units_remaining."),
)
def activate_install_key(
    payload: ActivateRequest,
) -> ActivateResponse:
    install_registry = get_install_key_registry()
    record = install_registry.authenticate_install_key(payload.raw_key)

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive install key.",
        )

    wallet_registry = get_unit_wallet_registry()
    wallet = wallet_registry.get_wallet(record.owner_key)
    units_remaining = wallet.balance_units if wallet is not None else 0

    return ActivateResponse(
        valid=True,
        owner_key=record.owner_key,
        program=record.program,
        units_remaining=units_remaining,
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
) -> RecordUsageResponse:
    install_registry = get_install_key_registry()
    record = install_registry.get_key_by_id(payload.key_id)

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Install key not found: {payload.key_id!r}",
        )
    if not record.active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Install key {payload.key_id!r} is inactive and cannot record usage.",
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
    if record.owner_key != owner_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to revoke this install key.",
        )

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
    description=("Returns units_consumed, last_used_at, and the ledger entries scoped to the owner of this key. Requires X-Owner-Key header for ownership check."),
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
    if record.owner_key != owner_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to view usage for this install key.",
        )

    wallet_registry = get_unit_wallet_registry()
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
    return KeyUsageResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        key_id=key_id,
        units_consumed=pub.get("units_consumed") or 0,
        last_used_at=pub.get("last_used_at"),
        ledger=ledger_views,
    )
