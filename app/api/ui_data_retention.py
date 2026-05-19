from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from app.core.auth import require_api_key
from app.core.errors import AppError

router = APIRouter(
    prefix="/ui",
    tags=["ui-data-retention"],
)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class RetentionRuleView(BaseModel):
    rule_id: str
    name: str
    category: str
    retention_days: int
    storage_scope: str
    purge_behavior: str
    description: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class UIDataRetentionResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    requested_by: str
    rules: list[RetentionRuleView] = Field(default_factory=list)
    total_rules: int
    metadata: dict[str, Any] = Field(default_factory=dict)


def _build_retention_rules() -> list[RetentionRuleView]:
    return [
        RetentionRuleView(
            rule_id="requests",
            name="Request context",
            category="operational",
            retention_days=30,
            storage_scope="request-ingress",
            purge_behavior="rolling-window",
            description="Retains request metadata long enough for investigation and trace correlation.",
            metadata={"contains_content": False},
        ),
        RetentionRuleView(
            rule_id="telemetry",
            name="Telemetry events",
            category="observability",
            retention_days=14,
            storage_scope="telemetry",
            purge_behavior="rolling-window",
            description="Keeps lightweight operational telemetry for dashboards and performance monitoring.",
            metadata={"contains_content": False},
        ),
        RetentionRuleView(
            rule_id="review-queue",
            name="Review queue items",
            category="security-review",
            retention_days=90,
            storage_scope="guard-review",
            purge_behavior="archive-then-purge",
            description="Stores manual review items for analyst follow-up, auditability, and decision history.",
            metadata={"contains_content": True},
        ),
        RetentionRuleView(
            rule_id="audit-log",
            name="Security audit log",
            category="audit",
            retention_days=180,
            storage_scope="audit-log",
            purge_behavior="archive-then-purge",
            description="Preserves security-relevant decisions and actions for compliance and investigations.",
            metadata={"contains_content": True},
        ),
    ]


@router.get("/data-retention", response_model=UIDataRetentionResponse)
async def get_data_retention(
    requested_by: str = Query("ui-data-retention", min_length=1),
    api_key: str = Depends(require_api_key),
) -> UIDataRetentionResponse:
    if not api_key:
        raise AppError(
            status_code=401,
            error="missing_api_key",
            message="X-API-Key header is required",
        )

    rules = _build_retention_rules()
    return UIDataRetentionResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        requested_by=requested_by,
        rules=rules,
        total_rules=len(rules),
        metadata={
            "requested_by": requested_by,
        },
    )
