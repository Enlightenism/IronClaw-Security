from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.core.auth import AuthContext, require_auth_context

router = APIRouter(prefix="/ui", tags=["UI"])


class RetentionRule(BaseModel):
    rule_id: str
    name: str
    category: str
    retention_days: int
    storage_scope: str
    purge_behavior: str
    description: str
    metadata: dict[str, Any]


class DataRetentionResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    requested_by: str
    rules: list[RetentionRule]
    total_rules: int
    metadata: dict[str, Any]


_RETENTION_RULES: list[dict[str, Any]] = [
    {
        "rule_id": "requests",
        "name": "Request Logs",
        "category": "operational",
        "retention_days": 30,
        "storage_scope": "supabase",
        "purge_behavior": "rolling-window",
        "description": "Inbound and outbound request metadata retained for operational debugging.",
        "metadata": {
            "contains_content": False,
            "compliance_notes": "No PII in request metadata.",
        },
    },
    {
        "rule_id": "telemetry",
        "name": "Telemetry Events",
        "category": "observability",
        "retention_days": 14,
        "storage_scope": "supabase",
        "purge_behavior": "rolling-window",
        "description": "Lightweight telemetry signals for latency, verdicts, and policy hits.",
        "metadata": {
            "contains_content": False,
            "compliance_notes": "Aggregated metrics only.",
        },
    },
    {
        "rule_id": "review-queue",
        "name": "Review Queue Items",
        "category": "security-review",
        "retention_days": 90,
        "storage_scope": "supabase",
        "purge_behavior": "archive-then-purge",
        "description": "Flagged items pending human review, including full prompt and tool call content.",
        "metadata": {
            "contains_content": True,
            "compliance_notes": "May contain sensitive content; access-controlled.",
        },
    },
    {
        "rule_id": "audit-log",
        "name": "Audit Log",
        "category": "audit",
        "retention_days": 180,
        "storage_scope": "supabase",
        "purge_behavior": "archive-then-purge",
        "description": "Immutable audit trail of all enforcement decisions and policy changes.",
        "metadata": {
            "contains_content": True,
            "compliance_notes": "Required for compliance; longest retention tier.",
        },
    },
]


@router.get(
    "/data-retention",
    response_model=DataRetentionResponse,
    summary="Get data retention rules",
)
def get_data_retention(
    requested_by: str = Query(
        default="ui-data-retention",
        min_length=1,
        description="Caller identifier for audit purposes.",
    ),
    auth: AuthContext = Depends(require_auth_context),
) -> DataRetentionResponse:
    effective_requested_by = auth.principal_id if auth.principal_id is not None else requested_by

    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    return DataRetentionResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=now,
        requested_by=effective_requested_by,
        rules=[RetentionRule(**r) for r in _RETENTION_RULES],
        total_rules=len(_RETENTION_RULES),
        metadata={
            "requested_by": effective_requested_by,
            "policy_version": "1.0.0",
            "enforcement": "read-only",
        },
    )
