from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Path, Query, status
from pydantic import BaseModel, Field

from app.core.billing import get_billing_registry
from app.core.install_keys import (
    InstallKeyAlreadyExistsError,
    InstallKeyNotFoundError,
    InstallKeyUsageError,
    ProgramCode,
    get_install_key_registry,
)

router = APIRouter(
    prefix="/customer-keys",
    tags=["customer-keys"],
)

_VALID_PROGRAMS: frozenset[str] = frozenset({"openclaw", "claude_code"})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _assert_valid_program(program: str) -> ProgramCode:
    if program not in _VALID_PROGRAMS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Invalid program {program!r}. Must be one of: {sorted(_VALID_PROGRAMS)}",
        )
    return program  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class GenerateInstallKeyRequest(BaseModel):
    owner_key: str = Field(min_length=1, max_length=512)
    subscription_id: str | None = Field(default=None, max_length=512)
    program: Literal["openclaw", "claude_code"] | None = None
    label: str = Field(default="", max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)


class InstallKeyView(BaseModel):
    key_id: str
    owner_key: str
    subscription_id: str
    program: str
    masked_key: str
    label: str
    active: bool
    units_consumed: int
    created_at: str
    last_used_at: str | None
    metadata: dict[str, Any]


class GenerateInstallKeyResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    raw_key: str
    key: InstallKeyView


class InstallKeyResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    key: InstallKeyView


class InstallKeyListResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    total: int
    items: list[InstallKeyView]


class RevokeInstallKeyResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    key_id: str
    program: str | None
    active: bool


class RecordUsageRequest(BaseModel):
    units: int = Field(gt=0)


class RecordUsageResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    key_id: str
    units_consumed: int


class SummaryResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    total: int
    active: int
    revoked: int
    openclaw_keys: int
    claude_code_keys: int


# ---------------------------------------------------------------------------
# Serializer
# ---------------------------------------------------------------------------


def _key_to_view(record: Any) -> InstallKeyView:
    public = record.public_dict()
    return InstallKeyView(
        key_id=public["key_id"],
        owner_key=public["owner_key"],
        subscription_id=public["subscription_id"],
        program=public["program"],
        masked_key=public["masked_key"],
        label=public["label"],
        active=public["active"],
        units_consumed=public["units_consumed"],
        created_at=public["created_at"],
        last_used_at=public.get("last_used_at"),
        metadata=public.get("metadata") or {},
    )


# ---------------------------------------------------------------------------
# POST /customer-keys/generate
# ---------------------------------------------------------------------------


@router.post(
    "/generate",
    response_model=GenerateInstallKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a post-purchase install key",
    description=(
        "Generates a new install key for the given owner_key + program combination. "
        "Enforces the post-purchase gate: requires an active billing subscription for "
        "the owner and raises 409 if an active key for the same owner and program "
        "already exists. The raw_key is returned exactly once and never stored in plaintext."
    ),
)
def generate_install_key(payload: GenerateInstallKeyRequest) -> GenerateInstallKeyResponse:
    if payload.program is not None:
        _assert_valid_program(payload.program)

    # Billing gate: owner must have an active subscription.
    billing = get_billing_registry()
    if not billing.has_active_subscription(payload.owner_key):
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="purchase_required",
        )

    subscription_id = payload.subscription_id or ""
    program: ProgramCode = payload.program or "openclaw"  # type: ignore[assignment]
    _assert_valid_program(program)

    registry = get_install_key_registry()

    try:
        record = registry.generate_install_key(
            owner_key=payload.owner_key,
            subscription_id=subscription_id,
            program=program,
            label=payload.label,
            metadata=payload.metadata,
        )
    except InstallKeyAlreadyExistsError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(f"An active install key for program {exc.program!r} already exists for owner {exc.owner_key!r}. Revoke it before generating a new one."),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    return GenerateInstallKeyResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        raw_key=record.raw_key,
        key=_key_to_view(record),
    )


# ---------------------------------------------------------------------------
# GET /customer-keys/summary  — MUST be registered before /{key_id}
# ---------------------------------------------------------------------------


@router.get(
    "/summary",
    response_model=SummaryResponse,
    summary="Aggregate summary of all install keys",
)
def install_key_summary() -> SummaryResponse:
    registry = get_install_key_registry()
    data = registry.summary()
    return SummaryResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        total=data["total"],
        active=data["active"],
        revoked=data["revoked"],
        openclaw_keys=data["openclaw_keys"],
        claude_code_keys=data["claude_code_keys"],
    )


# ---------------------------------------------------------------------------
# GET /customer-keys/owner/{owner_key}
# ---------------------------------------------------------------------------


@router.get(
    "/owner/{owner_key}",
    response_model=InstallKeyListResponse,
    summary="List all install keys for an owner",
)
def list_keys_for_owner(
    owner_key: str = Path(min_length=1, max_length=512),
    active_only: bool = Query(default=False),
) -> InstallKeyListResponse:
    registry = get_install_key_registry()
    records = registry.get_keys_for_owner(owner_key)
    if active_only:
        records = [r for r in records if r.active]
    return InstallKeyListResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        total=len(records),
        items=[_key_to_view(r) for r in records],
    )


# ---------------------------------------------------------------------------
# GET /customer-keys/{key_id}
# ---------------------------------------------------------------------------


@router.get(
    "/{key_id}",
    response_model=InstallKeyResponse,
    summary="Get a single install key by key_id",
)
def get_install_key(
    key_id: str = Path(min_length=1, max_length=128),
) -> InstallKeyResponse:
    registry = get_install_key_registry()
    record = registry.get_key_by_id(key_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Install key not found: {key_id!r}",
        )
    return InstallKeyResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        key=_key_to_view(record),
    )


# ---------------------------------------------------------------------------
# POST /customer-keys/{key_id}/revoke
# ---------------------------------------------------------------------------


@router.post(
    "/{key_id}/revoke",
    response_model=RevokeInstallKeyResponse,
    summary="Revoke an install key",
)
def revoke_install_key(
    key_id: str = Path(min_length=1, max_length=128),
) -> RevokeInstallKeyResponse:
    registry = get_install_key_registry()
    try:
        updated = registry.revoke_key(key_id)
    except InstallKeyNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Install key not found: {exc.key_id!r}",
        ) from exc
    public = updated.public_dict()
    return RevokeInstallKeyResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        key_id=updated.key_id,
        program=public.get("program"),
        active=updated.active,
    )


# ---------------------------------------------------------------------------
# POST /customer-keys/{key_id}/usage
# ---------------------------------------------------------------------------


@router.post(
    "/{key_id}/usage",
    response_model=RecordUsageResponse,
    summary="Record unit consumption for an install key",
)
def record_key_usage(
    payload: RecordUsageRequest,
    key_id: str = Path(min_length=1, max_length=128),
) -> RecordUsageResponse:
    registry = get_install_key_registry()
    try:
        updated = registry.record_key_usage(key_id, units=payload.units)
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
    )
