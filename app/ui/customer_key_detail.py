from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Path
from pydantic import BaseModel, Field

router = APIRouter(prefix="/customer-keys/detail", tags=["customer-key-detail"])


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class CustomerKeyDetailOwnerView(BaseModel):
    owner_type: str
    owner_id: str
    owner_display_name: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class CustomerKeyDetailUsageView(BaseModel):
    last_used_at: str | None = None
    total_requests: int
    total_scans: int
    total_blocks: int
    total_warnings: int
    metadata: dict[str, Any] = Field(default_factory=dict)


class CustomerKeyDetailPolicyView(BaseModel):
    scopes: list[str] = Field(default_factory=list)
    environment: str
    rotation_due: bool
    revocable: bool
    metadata: dict[str, Any] = Field(default_factory=dict)


class CustomerKeyDetailActionView(BaseModel):
    action_id: str
    label: str
    method: str
    path: str
    description: str
    requires_api_key: bool = True


class CustomerKeyDetailResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    key_id: str
    label: str
    key_status: str
    masked_key: str
    created_at: str
    owner: CustomerKeyDetailOwnerView
    usage: CustomerKeyDetailUsageView
    policy: CustomerKeyDetailPolicyView
    actions: list[CustomerKeyDetailActionView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _build_actions(key_id: str) -> list[CustomerKeyDetailActionView]:
    return [
        CustomerKeyDetailActionView(
            action_id="list-customer-keys",
            label="List customer keys",
            method="GET",
            path="/ui/customer-keys",
            description="Returns the customer key inventory view.",
            requires_api_key=False,
        ),
        CustomerKeyDetailActionView(
            action_id="read-customer-key",
            label="Read customer key detail",
            method="GET",
            path=f"/ui/customer-keys/detail/{key_id}",
            description="Returns the detailed UI view for the selected customer key.",
            requires_api_key=False,
        ),
        CustomerKeyDetailActionView(
            action_id="revoke-customer-key",
            label="Revoke customer key",
            method="POST",
            path=f"/customer-keys/{key_id}/revoke",
            description="Revokes the selected customer API key.",
        ),
    ]


@router.get("/{key_id}", response_model=CustomerKeyDetailResponse)
def get_customer_key_detail(
    key_id: str = Path(..., min_length=1, max_length=255),
) -> CustomerKeyDetailResponse:
    normalized_key_id = key_id.strip()

    return CustomerKeyDetailResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        key_id=normalized_key_id,
        label="Customer Key Detail",
        key_status="active",
        masked_key=f"{normalized_key_id[:12]}..." if len(normalized_key_id) > 12 else normalized_key_id,
        created_at=_utc_now_iso(),
        owner=CustomerKeyDetailOwnerView(
            owner_type="customer",
            owner_id="default-customer",
            owner_display_name="Default Customer",
            metadata={
                "tenant_state": "active",
                "source": "customer-key-detail-ui",
            },
        ),
        usage=CustomerKeyDetailUsageView(
            last_used_at=None,
            total_requests=0,
            total_scans=0,
            total_blocks=0,
            total_warnings=0,
            metadata={
                "usage_state": "no-activity",
                "window": "lifetime",
            },
        ),
        policy=CustomerKeyDetailPolicyView(
            scopes=["scan:write", "history:read", "billing:read"],
            environment="production",
            rotation_due=False,
            revocable=True,
            metadata={
                "policy_profile": "default-customer-access",
                "supports_billing": True,
            },
        ),
        actions=_build_actions(normalized_key_id),
        notes=[
            "Customer key detail gives operators a focused view of ownership, usage, and access scope.",
            "Masked key material is returned for identification without exposing the full secret.",
            "Detailed usage and rotation posture can be expanded later as the customer key services evolve.",
        ],
    )