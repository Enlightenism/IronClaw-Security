from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from core.apikeys import ApiKeyRecord, KeyScope, KeyStatus, registry
from core.auth import AuthPrincipal, require_scope, resolve_api_key

router = APIRouter(prefix="/customerkeys", tags=["customer-keys"])


CustomerKeyStatus = Literal["active", "revoked"]


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


class CustomerApiKeyCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)


# Safe read model — never exposes raw_key
class CustomerApiKeyResponse(BaseModel):
    key_id: str
    name: str
    key_prefix: str
    key_hint: str
    scope: KeyScope
    status: KeyStatus
    owner_id: str | None = None
    created_by: str
    created_at: str
    updated_at: str
    last_used_at: str | None = None
    revoked_at: str | None = None


# Creation-only model — reveals raw_key exactly once
class CustomerApiKeyCreatedResponse(BaseModel):
    key_id: str
    name: str
    key_prefix: str
    key_hint: str
    scope: KeyScope
    status: KeyStatus
    owner_id: str | None = None
    created_by: str
    created_at: str
    updated_at: str
    last_used_at: str | None = None
    revoked_at: str | None = None
    revealed_key: str  # present only at creation; never returned again


# Rotate model — reveals raw_key exactly once
class CustomerApiKeyRotateResponse(BaseModel):
    key_id: str
    name: str
    key_prefix: str
    key_hint: str
    scope: KeyScope
    status: KeyStatus
    owner_id: str | None = None
    created_by: str
    created_at: str
    updated_at: str
    last_used_at: str | None = None
    revoked_at: str | None = None
    revealed_key: str  # present only at rotation; never returned again


class CustomerApiKeyListResponse(BaseModel):
    items: list[CustomerApiKeyResponse] = Field(default_factory=list)


def _to_response(record: ApiKeyRecord) -> CustomerApiKeyResponse:
    return CustomerApiKeyResponse(
        key_id=record.key_id,
        name=record.name,
        key_prefix=record.key_prefix,
        key_hint=record.key_hint,
        scope=record.scope,
        status=record.status,
        owner_id=record.owner_id,
        created_by=record.created_by,
        created_at=record.created_at,
        updated_at=record.updated_at,
        last_used_at=record.last_used_at,
        revoked_at=record.revoked_at,
    )


@router.get("", response_model=CustomerApiKeyListResponse)
def list_customer_keys(
    principal: AuthPrincipal = Depends(resolve_api_key),  # noqa: B008
) -> CustomerApiKeyListResponse:
    require_scope(principal, "customer", "internal")
    records = registry.list_keys(
        owner_id=principal.subject,
        scope="customer",
    )
    items = [_to_response(r) for r in records]
    return CustomerApiKeyListResponse(items=items)


@router.post(
    "",
    response_model=CustomerApiKeyCreatedResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_customer_key(
    body: CustomerApiKeyCreateRequest,
    principal: AuthPrincipal = Depends(resolve_api_key),  # noqa: B008
) -> CustomerApiKeyCreatedResponse:
    require_scope(principal, "customer", "internal")
    # created_by is always the authenticated user UID — never caller-supplied
    created_by = principal.subject
    record, raw_key = registry.create_key(
        name=body.name,
        scope="customer",
        owner_id=created_by,
        created_by=created_by,
        prefix="icpk",
    )
    return CustomerApiKeyCreatedResponse(
        key_id=record.key_id,
        name=record.name,
        key_prefix=record.key_prefix,
        key_hint=record.key_hint,
        scope=record.scope,
        status=record.status,
        owner_id=record.owner_id,
        created_by=record.created_by,
        created_at=record.created_at,
        updated_at=record.updated_at,
        last_used_at=record.last_used_at,
        revoked_at=record.revoked_at,
        revealed_key=raw_key,
    )


@router.post(
    "/{key_id}/rotate",
    response_model=CustomerApiKeyRotateResponse,
)
def rotate_customer_key(
    key_id: str,
    principal: AuthPrincipal = Depends(resolve_api_key),  # noqa: B008
) -> CustomerApiKeyRotateResponse:
    require_scope(principal, "customer", "internal")
    record = registry.get_key(key_id)
    if record is None or record.scope != "customer":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Customer API key not found",
        )
    if principal.principal_type == "customer" and record.owner_id != principal.subject:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not allowed to rotate this API key",
        )
    rotated, raw_key = registry.rotate_key(key_id=key_id, prefix="icpk")
    return CustomerApiKeyRotateResponse(
        key_id=rotated.key_id,
        name=rotated.name,
        key_prefix=rotated.key_prefix,
        key_hint=rotated.key_hint,
        scope=rotated.scope,
        status=rotated.status,
        owner_id=rotated.owner_id,
        created_by=rotated.created_by,
        created_at=rotated.created_at,
        updated_at=rotated.updated_at,
        last_used_at=rotated.last_used_at,
        revoked_at=rotated.revoked_at,
        revealed_key=raw_key,
    )


@router.post(
    "/{key_id}/revoke",
    response_model=CustomerApiKeyResponse,
)
def revoke_customer_key(
    key_id: str,
    principal: AuthPrincipal = Depends(resolve_api_key),  # noqa: B008
) -> CustomerApiKeyResponse:
    require_scope(principal, "customer", "internal")
    record = registry.get_key(key_id)
    if record is None or record.scope != "customer":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Customer API key not found",
        )
    if principal.principal_type == "customer" and record.owner_id != principal.subject:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not allowed to revoke this API key",
        )
    if record.status == "revoked":
        return _to_response(record)
    now = _utc_now_iso()
    record.status = "revoked"
    record.revoked_at = now
    record.updated_at = now
    return _to_response(record)


@router.get(
    "/{key_id}",
    response_model=CustomerApiKeyResponse,
)
def get_customer_key(
    key_id: str,
    principal: AuthPrincipal = Depends(resolve_api_key),  # noqa: B008
) -> CustomerApiKeyResponse:
    require_scope(principal, "customer", "internal")
    record = registry.get_key(key_id)
    if record is None or record.scope != "customer":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Customer API key not found",
        )
    if principal.principal_type == "customer" and record.owner_id != principal.subject:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not allowed to view this API key",
        )
    return _to_response(record)
