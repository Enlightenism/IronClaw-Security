from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from app.core.auth import AuthContext, require_auth_context

router = APIRouter(prefix="/ui", tags=["admin-data-retention"])


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class DataRetentionRuleMetadata(BaseModel):
    model_config = ConfigDict(extra="allow")

    contains_content: bool
    compliance_scope: str | None = None


class DataRetentionRuleItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    category: str = Field(min_length=1)
    retention_days: int = Field(gt=0)
    storage_scope: str = Field(min_length=1)
    purge_behavior: Literal["rolling-window", "archive-then-purge", "immediate-purge"]
    description: str = Field(min_length=1)
    metadata: DataRetentionRuleMetadata


class AdminDataRetentionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ok"]
    service: str
    timestamp: str
    requested_by: str
    total_rules: int = Field(ge=0)
    rules: list[DataRetentionRuleItem]
    metadata: dict[str, Any] = Field(default_factory=dict)


_RULES: tuple[DataRetentionRuleItem, ...] = (
    DataRetentionRuleItem(
        rule_id="requests",
        name="Request Stream",
        category="operational",
        retention_days=30,
        storage_scope="hot",
        purge_behavior="rolling-window",
        description="Retain raw request/response stream data for short-term operational review.",
        metadata=DataRetentionRuleMetadata(contains_content=False, compliance_scope=None),
    ),
    DataRetentionRuleItem(
        rule_id="telemetry",
        name="Telemetry Rollups",
        category="observability",
        retention_days=14,
        storage_scope="standard",
        purge_behavior="rolling-window",
        description="Aggregated telemetry signals retained for observability dashboards.",
        metadata=DataRetentionRuleMetadata(contains_content=False, compliance_scope=None),
    ),
    DataRetentionRuleItem(
        rule_id="review-queue",
        name="Review Queue Items",
        category="security-review",
        retention_days=90,
        storage_scope="protected",
        purge_behavior="archive-then-purge",
        description="Flagged items pending or completed human review; retained for audit trail.",
        metadata=DataRetentionRuleMetadata(contains_content=True, compliance_scope="security-ops"),
    ),
    DataRetentionRuleItem(
        rule_id="audit-log",
        name="Audit Log",
        category="audit",
        retention_days=180,
        storage_scope="archive",
        purge_behavior="archive-then-purge",
        description="Full audit event log retained for compliance and forensic investigation.",
        metadata=DataRetentionRuleMetadata(contains_content=True, compliance_scope="compliance"),
    ),
)


@router.get(
    "/data-retention",
    response_model=AdminDataRetentionResponse,
    summary="Get Admin Data Retention Policies",
)
def get_data_retention_settings(
    request: Request,
    requested_by: str = Query("ui-data-retention", min_length=1),
    context: AuthContext = Depends(require_auth_context),
) -> AdminDataRetentionResponse:
    caller = context.principal_id or requested_by
    rules = list(_RULES)

    return AdminDataRetentionResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        requested_by=caller,
        total_rules=len(rules),
        rules=rules,
        metadata={"requested_by": caller},
    )
