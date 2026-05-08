from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Path
from pydantic import BaseModel, Field

from app.core.apikeys import APIKeyRecord, get_api_key_registry, mask_api_key


router = APIRouter(prefix="/customer-keys", tags=["customer-keys-management"])


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _datetime_to_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _record_status(record: APIKeyRecord) -> str:
    return "active" if record.active else "revoked"


def _record_scopes(record: APIKeyRecord) -> list[str]:
    scopes = record.metadata.get("scopes", [])
    if not isinstance(scopes, list):
        return []
    return [str(scope) for scope in scopes]


def _record_owner_type(record: APIKeyRecord) -> str:
    return str(record.metadata.get("owner_type", "customer"))


def _record_owner_id(record: APIKeyRecord) -> str:
    return str(record.metadata.get("owner_id", "default-customer"))


def _record_environment(record: APIKeyRecord) -> str:
    return str(record.metadata.get("environment", "production"))


class CustomerKeyCreateRequest(BaseModel):
    label: str = Field(..., min_length=1, max_length=200)
    owner_type: str = Field(default="customer", min_length=1, max_length=100)
    owner_id: str = Field(default="default-customer", min_length=1, max_length=200)
    scopes: list[str] = Field(default_factory=list)
    environment: str = Field(default="production", min_length=1, max_length=100)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CustomerKeyActionResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    operation: str
    key_id: str
    label: str
    key_status: str
    masked_key: str
    revealed_once_key: str | None = None
    created_at: str
    last_used_at: str | None = None
    owner_type: str
    owner_id: str
    scopes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)


def _build_response(
    *,
    operation: str,
    record: APIKeyRecord,
    revealed_once_key: str | None = None,
    notes: list[str] | None = None,
) -> CustomerKeyActionResponse:
    raw_key = revealed_once_key or record.raw_key
    masked_key = mask_api_key(raw_key) if raw_key else "hidden"

    response_metadata = dict(record.metadata)
    response_metadata["environment"] = _record_environment(record)
    response_metadata["rotation_due"] = bool(record.metadata.get("rotation_due", False))

    return CustomerKeyActionResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        operation=operation,
        key_id=record.key_id,
        label=record.display_name,
        key_status=_record_status(record),
        masked_key=masked_key,
        revealed_once_key=revealed_once_key,
        created_at=_datetime_to_iso(record.created_at) or _utc_now_iso(),
        last_used_at=_datetime_to_iso(record.last_used_at),
        owner_type=_record_owner_type(record),
        owner_id=_record_owner_id(record),
        scopes=_record_scopes(record),
        metadata=response_metadata,
        notes=notes or [],
    )


@router.post("", response_model=CustomerKeyActionResponse)
def create_customer_key(payload: CustomerKeyCreateRequest) -> CustomerKeyActionResponse:
    registry = get_api_key_registry()

    metadata = dict(payload.metadata)
    metadata["owner_type"] = payload.owner_type
    metadata["owner_id"] = payload.owner_id
    metadata["scopes"] = list(payload.scopes)
    metadata["environment"] = payload.environment
    metadata.setdefault("rotation_due", False)

    record = registry.create_key(
        display_name=payload.label.strip(),
        metadata=metadata,
    )

    return _build_response(
        operation="create",
        record=record,
        revealed_once_key=record.raw_key,
        notes=[
            "The raw API key is only returned once during creation.",
            "Store the revealed key securely before leaving this response.",
            "This key is now available for authenticated customer workflows.",
        ],
    )


@router.post("/{key_id}/rotate", response_model=CustomerKeyActionResponse)
def rotate_customer_key(
    key_id: str = Path(..., min_length=1, max_length=255),
) -> CustomerKeyActionResponse:
    registry = get_api_key_registry()
    record = registry.rotate_key(key_id.strip())

    if record is None:
        raise HTTPException(status_code=404, detail="Customer key not found or not active")

    updated_metadata = dict(record.metadata)
    updated_metadata["rotation_due"] = False
    refreshed_record = APIKeyRecord(
        key_id=record.key_id,
        display_name=record.display_name,
        hashed_secret=record.hashed_secret,
        created_at=record.created_at,
        last_used_at=record.last_used_at,
        active=record.active,
        metadata=updated_metadata,
        raw_key=record.raw_key,
    )
    registry._keys_by_id[record.key_id] = refreshed_record

    return _build_response(
        operation="rotate",
        record=refreshed_record,
        revealed_once_key=refreshed_record.raw_key,
        notes=[
            "The previous key secret is no longer valid after rotation.",
            "The new raw API key is only returned once during rotation.",
            "Update any clients or integrations that depended on the prior key.",
        ],
    )


@router.post("/{key_id}/revoke", response_model=CustomerKeyActionResponse)
def revoke_customer_key(
    key_id: str = Path(..., min_length=1, max_length=255),
) -> CustomerKeyActionResponse:
    registry = get_api_key_registry()
    record = registry.revoke_key(key_id.strip())

    if record is None:
        raise HTTPException(status_code=404, detail="Customer key not found")

    return _build_response(
        operation="revoke",
        record=record,
        revealed_once_key=None,
        notes=[
            "Revoked keys can no longer authenticate requests.",
            "The key remains visible in inventory and detail views for auditability.",
            "Create or rotate a replacement key before revoking production traffic keys.",
        ],
    )
