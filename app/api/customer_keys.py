from __future__ import annotations


from datetime import UTC, datetime
from typing import Any


from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field


from app.core.apikeys import (
    APIKeyRecord,
    generate_api_key,
    get_api_key_registry,
    mask_api_key,
)
from app.core.auth import require_api_key



router = APIRouter(
    prefix="/customer-keys",
    tags=["customer-keys"],
    dependencies=[Depends(require_api_key)],
)



class CustomerKeyCreateRequest(BaseModel):
    display_name: str = Field(min_length=1, max_length=120)
    metadata: dict[str, Any] = Field(default_factory=dict)



class CustomerKeyView(BaseModel):
    key_id: str
    display_name: str
    masked_key: str
    created_at: str
    last_used_at: str | None = None
    active: bool
    metadata: dict[str, Any] = Field(default_factory=dict)



class CustomerKeyCreateResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    api_key: str
    key: CustomerKeyView



class CustomerKeyListResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    total_keys: int
    keys: list[CustomerKeyView] = Field(default_factory=list)



class CustomerKeyRevokeResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    revoked_key_id: str



def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")



def _to_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")



def _to_view(record: APIKeyRecord, masked_value: str | None = None) -> CustomerKeyView:
    return CustomerKeyView(
        key_id=record.key_id,
        display_name=record.display_name,
        masked_key=masked_value or mask_api_key(record.hashed_secret),
        created_at=_to_iso(record.created_at) or _utc_now_iso(),
        last_used_at=_to_iso(record.last_used_at),
        active=record.active,
        metadata=record.metadata or {},
    )



@router.get("", response_model=CustomerKeyListResponse)
def list_customer_keys() -> CustomerKeyListResponse:
    registry = get_api_key_registry()
    records = list(getattr(registry, "_keys_by_id", {}).values())
    records = sorted(records, key=lambda record: record.created_at, reverse=True)


    return CustomerKeyListResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        total_keys=len(records),
        keys=[_to_view(record) for record in records],
    )



@router.post(
    "",
    response_model=CustomerKeyCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_customer_key(payload: CustomerKeyCreateRequest) -> CustomerKeyCreateResponse:
    registry = get_api_key_registry()
    raw_api_key = generate_api_key()
    record = registry.register_key(
        display_name=payload.display_name.strip(),
        raw_secret=raw_api_key,
        metadata=payload.metadata,
    )


    return CustomerKeyCreateResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        api_key=raw_api_key,
        key=_to_view(record, masked_value=mask_api_key(raw_api_key)),
    )



@router.post("/{key_id}/revoke", response_model=CustomerKeyRevokeResponse)
def revoke_customer_key(key_id: str) -> CustomerKeyRevokeResponse:
    registry = get_api_key_registry()
    registry.deactivate_key(key_id)


    return CustomerKeyRevokeResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        revoked_key_id=key_id,
    )
