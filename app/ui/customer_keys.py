from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.apikeys import get_api_key_registry, mask_api_key
from app.core.auth import require_api_key

router = APIRouter(
    prefix="/ui/customer-keys",
    tags=["customer-keys"],
    dependencies=[Depends(require_api_key)],
)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _datetime_to_iso(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value.replace("+00:00", "Z")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


class CustomerKeyItemView(BaseModel):
    key_id: str
    display_name: str
    label: str
    status: str
    owner_type: str
    owner_id: str
    created_at: str
    last_used_at: str | None = None
    scopes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CustomerKeySummaryView(BaseModel):
    total_keys: int
    active_keys: int
    revoked_keys: int
    stale_keys: int
    rotation_recommended: bool
    latest_created_at: str | None = None


class CustomerKeyActionView(BaseModel):
    action_id: str
    label: str
    method: str
    path: str
    description: str
    requires_api_key: bool = True


class CustomerKeysResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    title: str
    keys: list[CustomerKeyItemView] = Field(default_factory=list)
    summary: CustomerKeySummaryView
    actions: list[CustomerKeyActionView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _build_customer_keys() -> list[CustomerKeyItemView]:
    registry = get_api_key_registry()
    records = registry.list_keys()

    if not records:
        return [
            CustomerKeyItemView(
                key_id="ck_demo_primary",
                display_name="Primary Production Key",
                label="Primary Production Key",
                status="active",
                owner_type="customer",
                owner_id="default-customer",
                created_at=_utc_now_iso(),
                last_used_at=None,
                scopes=["scan:write", "history:read", "billing:read"],
                metadata={
                    "masked_key": "icg1_dem…mary",
                    "environment": "production",
                    "rotation_due": False,
                    "source": "demo-fallback",
                },
            ),
            CustomerKeyItemView(
                key_id="ck_demo_staging",
                display_name="Staging Validation Key",
                label="Staging Validation Key",
                status="active",
                owner_type="customer",
                owner_id="default-customer",
                created_at=_utc_now_iso(),
                last_used_at=None,
                scopes=["scan:write", "history:read"],
                metadata={
                    "masked_key": "icg1_dem…ging",
                    "environment": "staging",
                    "rotation_due": True,
                    "source": "demo-fallback",
                },
            ),
            CustomerKeyItemView(
                key_id="ck_demo_old",
                display_name="Legacy Revoked Key",
                label="Legacy Revoked Key",
                status="revoked",
                owner_type="customer",
                owner_id="default-customer",
                created_at=_utc_now_iso(),
                last_used_at=None,
                scopes=["scan:write"],
                metadata={
                    "masked_key": "icg1_dem…gacy",
                    "environment": "production",
                    "rotation_due": False,
                    "source": "demo-fallback",
                },
            ),
        ]

    views: list[CustomerKeyItemView] = []
    for record in records:
        owner_type = str(record.metadata.get("owner_type", "customer"))
        owner_id = str(record.metadata.get("owner_id", "default-customer"))
        scopes_value = record.metadata.get("scopes", [])
        scopes = [str(s) for s in scopes_value] if isinstance(scopes_value, list) else []

        raw_key = getattr(record, "api_key", None) or ""
        masked_key = mask_api_key(raw_key) if raw_key else "hidden"

        metadata: dict[str, Any] = {
            "masked_key": masked_key,
            "environment": record.metadata.get("environment", "unknown"),
            "rotation_due": bool(record.metadata.get("rotation_due", False)),
            "source": "registry",
        }
        for key, value in record.metadata.items():
            if key not in {"owner_type", "owner_id", "scopes", "environment", "rotation_due"}:
                metadata[key] = value

        views.append(
            CustomerKeyItemView(
                key_id=record.key_id,
                display_name=record.display_name,
                label=record.display_name,
                status="active" if record.active else "revoked",
                owner_type=owner_type,
                owner_id=owner_id,
                created_at=_datetime_to_iso(record.created_at) or _utc_now_iso(),
                last_used_at=_datetime_to_iso(record.last_used_at),
                scopes=scopes,
                metadata=metadata,
            )
        )

    views.sort(key=lambda item: item.created_at, reverse=True)
    return views


def _build_summary(keys: list[CustomerKeyItemView]) -> CustomerKeySummaryView:
    active_keys = sum(1 for k in keys if k.status == "active")
    revoked_keys = sum(1 for k in keys if k.status == "revoked")
    stale_keys = sum(1 for k in keys if k.last_used_at is None)
    latest_created_at = max((k.created_at for k in keys), default=None)

    return CustomerKeySummaryView(
        total_keys=len(keys),
        active_keys=active_keys,
        revoked_keys=revoked_keys,
        stale_keys=stale_keys,
        rotation_recommended=any(bool(k.metadata.get("rotation_due")) for k in keys),
        latest_created_at=latest_created_at,
    )


def _build_actions() -> list[CustomerKeyActionView]:
    return [
        CustomerKeyActionView(
            action_id="list-customer-keys",
            label="List customer keys",
            method="GET",
            path="/customer-keys",
            description="Returns the currently registered customer API keys.",
        ),
        CustomerKeyActionView(
            action_id="create-customer-key",
            label="Create customer key",
            method="POST",
            path="/customer-keys",
            description="Creates a new customer API key for a tenant or operator workflow.",
        ),
        CustomerKeyActionView(
            action_id="rotate-customer-key",
            label="Rotate customer key",
            method="POST",
            path="/customer-keys/{key_id}/rotate",
            description="Rotates an existing customer API key and returns a new secret once.",
        ),
        CustomerKeyActionView(
            action_id="revoke-customer-key",
            label="Revoke customer key",
            method="POST",
            path="/customer-keys/{key_id}/revoke",
            description="Revokes an existing customer API key and prevents future use.",
        ),
    ]


@router.get("", response_model=CustomerKeysResponse)
def get_customer_keys() -> CustomerKeysResponse:
    keys = _build_customer_keys()

    return CustomerKeysResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        title="Customer Keys",
        keys=keys,
        summary=_build_summary(keys),
        actions=_build_actions(),
        notes=[
            "Customer keys control authenticated access to tenant-facing IronClaw routes.",
            "Revoked keys remain visible for auditability and operator review.",
            "Rotation recommendations help identify keys that should be replaced proactively.",
        ],
    )
