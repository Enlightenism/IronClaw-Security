from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.services.secretservice import SecretService

router = APIRouter(prefix="/integrations", tags=["integrations"])

_service = SecretService()


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_metadata(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


class IntegrationSecretSetRequest(BaseModel):
    key: str = Field(..., min_length=1, max_length=200)
    value: str = Field(..., min_length=1, max_length=10000)
    updated_by: str | None = Field(default=None, min_length=1, max_length=120)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationSecretDeleteRequest(BaseModel):
    deleted_by: str | None = Field(default=None, min_length=1, max_length=120)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationSecretValueView(BaseModel):
    key: str
    masked_value: str
    created_at: str
    updated_at: str
    updated_by: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationSecretListResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    integration_id: str
    total: int
    items: list[IntegrationSecretValueView]


class IntegrationSecretResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    integration_id: str
    secret: IntegrationSecretValueView


class IntegrationSecretDeleteResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    integration_id: str
    key: str
    deleted: bool


def _build_secret_view(key: str, record: Any) -> IntegrationSecretValueView:
    if hasattr(record, "model_dump"):
        data = record.model_dump()
    elif isinstance(record, dict):
        data = dict(record)
    else:
        data = {
            "value": str(record),
        }

    raw_value = str(data.get("value", ""))
    masked_value = data.get("masked_value") or _service.mask(raw_value)
    created_at = data.get("created_at") or data.get("createdat") or _utcnow()
    updated_at = data.get("updated_at") or data.get("updatedat") or created_at
    updated_by = data.get("updated_by") or data.get("updatedby")
    metadata = _normalize_metadata(data.get("metadata"))

    return IntegrationSecretValueView(
        key=key,
        masked_value=masked_value,
        created_at=created_at,
        updated_at=updated_at,
        updated_by=updated_by,
        metadata=metadata,
    )


def _list_secret_items(integration_id: str) -> list[IntegrationSecretValueView]:
    records = _service.list_for_integration(integration_id)
    items: list[IntegrationSecretValueView] = []

    if isinstance(records, dict):
        iterable = records.items()
    else:
        iterable = []
        for entry in records or []:
            if isinstance(entry, tuple) and len(entry) == 2:
                iterable.append(entry)
            elif isinstance(entry, dict):
                key = entry.get("key")
                if key:
                    iterable.append((key, entry))
            elif hasattr(entry, "key"):
                iterable.append((entry.key, entry))

    for key, record in iterable:
        items.append(_build_secret_view(str(key), record))

    items.sort(key=lambda item: item.key.lower())
    return items


@router.get(
    "/{integration_id}/secrets",
    response_model=IntegrationSecretListResponse,
    summary="List integration secrets",
)
def list_integration_secrets(integration_id: str) -> IntegrationSecretListResponse:
    items = _list_secret_items(integration_id)
    return IntegrationSecretListResponse(
        status="ok",
        service="integration-secrets",
        timestamp=_utcnow(),
        integration_id=integration_id,
        total=len(items),
        items=items,
    )


@router.get(
    "/{integration_id}/secrets/{key}",
    response_model=IntegrationSecretResponse,
    summary="Get integration secret",
)
def get_integration_secret(integration_id: str, key: str) -> IntegrationSecretResponse:
    record = _service.get(integration_id, key)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"secret '{key}' not found for integration '{integration_id}'",
        )

    return IntegrationSecretResponse(
        status="ok",
        service="integration-secrets",
        timestamp=_utcnow(),
        integration_id=integration_id,
        secret=_build_secret_view(key, record),
    )


@router.put(
    "/{integration_id}/secrets/{key}",
    response_model=IntegrationSecretResponse,
    summary="Set integration secret",
)
def set_integration_secret(
    integration_id: str,
    key: str,
    request: IntegrationSecretSetRequest,
) -> IntegrationSecretResponse:
    payload = request.model_dump()
    payload["key"] = key

    try:
        record = _service.set(
            integration_id=integration_id,
            key=key,
            value=request.value,
            updated_by=request.updated_by,
            metadata=request.metadata,
        )
    except TypeError:
        try:
            record = _service.set(integration_id, key, request.value)
        except TypeError:
            record = _service.set(integration_id, payload)

    return IntegrationSecretResponse(
        status="ok",
        service="integration-secrets",
        timestamp=_utcnow(),
        integration_id=integration_id,
        secret=_build_secret_view(key, record),
    )


@router.delete(
    "/{integration_id}/secrets/{key}",
    response_model=IntegrationSecretDeleteResponse,
    summary="Delete integration secret",
)
def delete_integration_secret(
    integration_id: str,
    key: str,
    request: IntegrationSecretDeleteRequest | None = None,
) -> IntegrationSecretDeleteResponse:
    deleted = False

    try:
        deleted = bool(
            _service.delete(
                integration_id=integration_id,
                key=key,
                deleted_by=request.deleted_by if request else None,
                metadata=request.metadata if request else {},
            )
        )
    except TypeError:
        try:
            deleted = bool(_service.delete(integration_id, key))
        except KeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"secret '{key}' not found for integration '{integration_id}'",
        )

    return IntegrationSecretDeleteResponse(
        status="ok",
        service="integration-secrets",
        timestamp=_utcnow(),
        integration_id=integration_id,
        key=key,
        deleted=True,
    )