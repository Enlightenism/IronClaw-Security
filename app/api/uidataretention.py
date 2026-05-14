from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field

from app.dependencies.auth import require_api_key

router = APIRouter(prefix="/ui", tags=["admin-data-retention"])


class DataRetentionPolicyItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(min_length=1)
    retention_days: int = Field(ge=0)
    storage_class: Literal["standard", "hot", "protected", "archive"]
    status: Literal["active", "review_required"]


class DataRetentionSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_policies: int = Field(ge=0)
    active: int = Field(ge=0)
    review_required: int = Field(ge=0)


class AdminDataRetentionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str
    status: Literal["ok"]
    summary: DataRetentionSummary
    policies: list[DataRetentionPolicyItem]
    request_id: str | None = None


_POLICIES: tuple[DataRetentionPolicyItem, ...] = (
    DataRetentionPolicyItem(
        domain="audit_logs",
        retention_days=365,
        storage_class="standard",
        status="active",
    ),
    DataRetentionPolicyItem(
        domain="request_stream",
        retention_days=30,
        storage_class="hot",
        status="active",
    ),
    DataRetentionPolicyItem(
        domain="detonation_artifacts",
        retention_days=90,
        storage_class="protected",
        status="active",
    ),
    DataRetentionPolicyItem(
        domain="telemetry_rollups",
        retention_days=180,
        storage_class="archive",
        status="active",
    ),
)


@router.get(
    "/admin/data-retention",
    response_model=AdminDataRetentionResponse,
    summary="Get Admin Data Retention Policies",
)
def get_data_retention_settings(
    request: Request,
    _: str | None = Depends(require_api_key),
) -> AdminDataRetentionResponse:
    request_id = getattr(request.state, "request_id", None)

    policies = list(_POLICIES)
    summary = DataRetentionSummary(
        total_policies=len(policies),
        active=sum(1 for policy in policies if policy.status == "active"),
        review_required=sum(1 for policy in policies if policy.status == "review_required"),
    )

    return AdminDataRetentionResponse(
        title="Data Retention",
        status="ok",
        summary=summary,
        policies=policies,
        request_id=request_id,
    )
