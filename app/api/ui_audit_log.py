from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from app.api.auth import require_api_key

router = APIRouter(
    prefix="/ui",
    tags=["audit-log"],
    dependencies=[Depends(require_api_key)],
)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class AuditLogItemView(BaseModel):
    event_id: str
    timestamp: str
    event_type: str
    severity: str
    actor_id: str | None = None
    session_id: str | None = None
    request_id: str | None = None
    trace_id: str | None = None
    target: str | None = None
    summary: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditLogResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    requested_by: str
    total: int
    items: list[AuditLogItemView] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _build_audit_items() -> list[AuditLogItemView]:
    return [
        AuditLogItemView(
            event_id="audit-001",
            timestamp="2026-04-21T14:05:00Z",
            event_type="policy.decision",
            severity="high",
            actor_id="operator-alpha",
            session_id="sess-alpha-100",
            request_id="req-100",
            trace_id="trace-100",
            target="powershell.exe",
            summary="High-risk shell execution request blocked by policy boundary.",
            metadata={
                "policy_verdict": "block",
                "action_type": "shell_execute",
            },
        ),
        AuditLogItemView(
            event_id="audit-002",
            timestamp="2026-04-21T14:12:00Z",
            event_type="review.queue",
            severity="medium",
            actor_id="operator-beta",
            session_id="sess-beta-210",
            request_id="req-210",
            trace_id="trace-210",
            target="https://example.test/source",
            summary="Fetched content was escalated for analyst review.",
            metadata={
                "policy_verdict": "quarantine",
                "action_type": "web_fetch",
            },
        ),
        AuditLogItemView(
            event_id="audit-003",
            timestamp="2026-04-21T14:18:00Z",
            event_type="review.resolve",
            severity="low",
            actor_id="operator-beta",
            session_id="sess-beta-210",
            request_id="req-211",
            trace_id="trace-211",
            target="review-203",
            summary="Review item approved and execution released.",
            metadata={
                "review_status": "approved",
                "execution_state": "completed",
            },
        ),
    ]


@router.get("/audit-log", response_model=AuditLogResponse)
def get_audit_log(
    requested_by: str = Query("ui-audit-log", min_length=1),
    limit: int = Query(50, ge=1, le=500),
) -> AuditLogResponse:
    items = _build_audit_items()[:limit]
    return AuditLogResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        requested_by=requested_by,
        total=len(items),
        items=items,
        metadata={
            "requested_by": requested_by,
            "limit": limit,
        },
    )