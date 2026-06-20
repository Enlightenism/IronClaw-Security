from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Path
from pydantic import BaseModel, Field

from app.adapters.secret_scanner_adapter import scan_for_secrets
from app.services.secretservice import SecretRecord, get_secret_service

router = APIRouter(prefix="/integrations", tags=["integration-secrets"])


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _datetime_to_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _normalize_metadata(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _guard_secret_value(value: str, location: str) -> None:
    result = scan_for_secrets(prompt_text=value)
    if result.verdict == "block":
        patterns = ", ".join({m.pattern_type for m in result.matches})
        raise HTTPException(
            status_code=400,
            detail=(f"Secret value rejected by IronClaw secret scanner at '{location}': {result.block_matches} high-severity pattern(s) detected [{patterns}]. Do not submit live credentials as secret values."),
        )


class SecretCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    value: str = Field(..., min_length=1, max_length=10_000)
    provider: str = Field(..., min_length=1, max_length=200)
    kind: str = Field(default="api_key", min_length=1, max_length=100)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecretRotateRequest(BaseModel):
    value: str = Field(..., min_length=1, max_length=10_000)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecretActionResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    integration_id: str
    operation: str
    secret_id: str
    name: str
    provider: str
    kind: str
    secret_status: str
    masked_value: str
    revealed_once_value: str | None = None
    created_at: str
    updated_at: str
    last_used_at: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)


class SecretSummaryItem(BaseModel):
    secret_id: str
    name: str
    provider: str
    kind: str
    secret_status: str
    masked_value: str
    created_at: str
    updated_at: str
    last_used_at: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecretListResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    integration_id: str
    total: int
    active: int
    inactive: int
    secrets: list[SecretSummaryItem] = Field(default_factory=list)


def _status_for_record(record: SecretRecord) -> str:
    return "active" if getattr(record, "active", False) else "revoked"


def _record_belongs_to_integration(record: SecretRecord, integration_id: str) -> bool:
    metadata = _normalize_metadata(getattr(record, "metadata", {}))
    candidates = {
        str(metadata.get("integration_id", "")).strip(),
        str(metadata.get("integration", "")).strip(),
        str(metadata.get("adapter_id", "")).strip(),
        str(metadata.get("release_id", "")).strip(),
    }
    candidates.discard("")
    return integration_id in candidates


def _filtered_records(integration_id: str) -> list[SecretRecord]:
    service = get_secret_service()
    records = service.list_secrets(include_inactive=True)
    return [record for record in records if _record_belongs_to_integration(record, integration_id)]


def _get_record_for_integration(integration_id: str, secret_id: str) -> SecretRecord | None:
    for record in _filtered_records(integration_id):
        if record.secret_id == secret_id:
            return record
    return None


def _build_action_response(
    *,
    integration_id: str,
    operation: str,
    record: SecretRecord,
    revealed_once_value: str | None = None,
    notes: list[str] | None = None,
) -> SecretActionResponse:
    metadata = _normalize_metadata(getattr(record, "metadata", {}))
    return SecretActionResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        integration_id=integration_id,
        operation=operation,
        secret_id=record.secret_id,
        name=record.name,
        provider=record.provider,
        kind=record.kind,
        secret_status=_status_for_record(record),
        masked_value=record.masked_value,
        revealed_once_value=revealed_once_value,
        created_at=_datetime_to_iso(record.created_at) or _utc_now_iso(),
        updated_at=_datetime_to_iso(record.updated_at) or _utc_now_iso(),
        last_used_at=_datetime_to_iso(record.last_used_at),
        metadata=metadata,
        notes=notes or [],
    )


def _build_summary_item(record: SecretRecord) -> SecretSummaryItem:
    metadata = _normalize_metadata(getattr(record, "metadata", {}))
    return SecretSummaryItem(
        secret_id=record.secret_id,
        name=record.name,
        provider=record.provider,
        kind=record.kind,
        secret_status=_status_for_record(record),
        masked_value=record.masked_value,
        created_at=_datetime_to_iso(record.created_at) or _utc_now_iso(),
        updated_at=_datetime_to_iso(record.updated_at) or _utc_now_iso(),
        last_used_at=_datetime_to_iso(record.last_used_at),
        metadata=metadata,
    )


@router.get("/{integration_id}/secrets", response_model=SecretListResponse)
def list_integration_secrets(
    integration_id: str = Path(..., min_length=1, max_length=255),
) -> SecretListResponse:
    normalized_integration_id = integration_id.strip()
    records = _filtered_records(normalized_integration_id)

    return SecretListResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        integration_id=normalized_integration_id,
        total=len(records),
        active=sum(1 for record in records if getattr(record, "active", False)),
        inactive=sum(1 for record in records if not getattr(record, "active", False)),
        secrets=[_build_summary_item(record) for record in records],
    )


@router.post("/{integration_id}/secrets", response_model=SecretActionResponse)
def create_integration_secret(
    payload: SecretCreateRequest,
    integration_id: str = Path(..., min_length=1, max_length=255),
) -> SecretActionResponse:
    normalized_integration_id = integration_id.strip()

    _guard_secret_value(payload.value, location="create.value")

    service = get_secret_service()
    metadata = _normalize_metadata(payload.metadata)
    metadata.setdefault("integration_id", normalized_integration_id)

    try:
        record = service.create_secret(
            name=payload.name.strip(),
            value=payload.value,
            provider=payload.provider.strip(),
            kind=payload.kind.strip(),
            metadata=metadata,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return _build_action_response(
        integration_id=normalized_integration_id,
        operation="create",
        record=record,
        revealed_once_value=getattr(record, "raw_value", None),
        notes=[
            "The raw secret is only returned once during creation.",
            "Store the revealed secret securely before leaving this response.",
            "The secret is now bound to this integration for install, verify, and rollout workflows.",
        ],
    )


@router.post("/{integration_id}/secrets/{secret_id}/rotate", response_model=SecretActionResponse)
def rotate_integration_secret(
    payload: SecretRotateRequest,
    integration_id: str = Path(..., min_length=1, max_length=255),
    secret_id: str = Path(..., min_length=1, max_length=255),
) -> SecretActionResponse:
    normalized_integration_id = integration_id.strip()
    normalized_secret_id = secret_id.strip()

    _guard_secret_value(payload.value, location="rotate.value")

    existing = _get_record_for_integration(normalized_integration_id, normalized_secret_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Integration secret not found")

    service = get_secret_service()
    metadata = _normalize_metadata(payload.metadata)
    existing_metadata = _normalize_metadata(getattr(existing, "metadata", {}))
    merged_metadata = {**existing_metadata, **metadata, "integration_id": normalized_integration_id}

    try:
        record = service.rotate_secret(
            secret_id=normalized_secret_id,
            new_value=payload.value,
            metadata=merged_metadata,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if record is None:
        raise HTTPException(status_code=404, detail="Integration secret not found or inactive")

    return _build_action_response(
        integration_id=normalized_integration_id,
        operation="rotate",
        record=record,
        revealed_once_value=getattr(record, "raw_value", None),
        notes=[
            "The previous secret value should be considered replaced immediately.",
            "The new secret is only returned once during rotation.",
            "Update any dependent integration configurations after rotating this secret.",
        ],
    )


@router.post("/{integration_id}/secrets/{secret_id}/revoke", response_model=SecretActionResponse)
def revoke_integration_secret(
    integration_id: str = Path(..., min_length=1, max_length=255),
    secret_id: str = Path(..., min_length=1, max_length=255),
) -> SecretActionResponse:
    normalized_integration_id = integration_id.strip()
    normalized_secret_id = secret_id.strip()

    existing = _get_record_for_integration(normalized_integration_id, normalized_secret_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Integration secret not found")

    service = get_secret_service()
    record = service.revoke_secret(normalized_secret_id)

    if record is None:
        raise HTTPException(status_code=404, detail="Integration secret not found")

    return _build_action_response(
        integration_id=normalized_integration_id,
        operation="revoke",
        record=record,
        revealed_once_value=None,
        notes=[
            "Revoked secrets can no longer be used by active integrations.",
            "The secret remains visible in the integration inventory for operator auditability.",
            "Create or rotate a replacement secret before revoking production credentials.",
        ],
    )
