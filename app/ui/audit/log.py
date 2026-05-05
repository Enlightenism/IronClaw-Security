from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/audit",
    tags=["audit-log"],
)


class AuditLogItem(BaseModel):
    eventid: str
    timestamp: str
    eventtype: str
    actorid: Optional[str] = None
    sessionid: Optional[str] = None
    executionid: Optional[str] = None
    reviewitemid: Optional[str] = None
    actiontype: Optional[str] = None
    target: Optional[str] = None
    policyverdict: Optional[str] = None
    executionstate: Optional[str] = None
    responsestatus: Optional[str] = None
    message: str


class AuditLogResponse(BaseModel):
    items: list[AuditLogItem] = Field(default_factory=list)
    total: int = 0
    generatedat: str


def _utc_iso(year: int, month: int, day: int, hour: int, minute: int = 0) -> str:
    return datetime(year, month, day, hour, minute, 0, tzinfo=timezone.utc).isoformat()


def _build_placeholder_items() -> list[AuditLogItem]:
    return [
        AuditLogItem(
            eventid="audit-001",
            timestamp=_utc_iso(2026, 4, 18, 8, 0),
            eventtype="execution.created",
            actorid="client-alpha",
            sessionid="sess-alpha-001",
            executionid="exec-201",
            reviewitemid=None,
            actiontype="httpfetch",
            target="https://example.com",
            policyverdict="allow",
            executionstate="executed",
            responsestatus="completed",
            message="Low-risk public fetch execution was created and completed.",
        ),
        AuditLogItem(
            eventid="audit-002",
            timestamp=_utc_iso(2026, 4, 18, 9, 5),
            eventtype="execution.denied",
            actorid="client-alpha",
            sessionid="sess-alpha-001",
            executionid="exec-202",
            reviewitemid="review-202",
            actiontype="toolcall",
            target="shell",
            policyverdict="block",
            executionstate="denied",
            responsestatus="denied",
            message="High-risk shell tool call was blocked by the execution boundary.",
        ),
        AuditLogItem(
            eventid="audit-003",
            timestamp=_utc_iso(2026, 4, 18, 10, 10),
            eventtype="review.queued",
            actorid="client-beta",
            sessionid="sess-beta-001",
            executionid="exec-203",
            reviewitemid="review-203",
            actiontype="httpfetch",
            target="https://example.com/docs",
            policyverdict="review",
            executionstate="dryrun",
            responsestatus="queuedforreview",
            message="Mid-risk execution was queued for manual review.",
        ),
        AuditLogItem(
            eventid="audit-004",
            timestamp=_utc_iso(2026, 4, 18, 11, 30),
            eventtype="review.approved",
            actorid="security-analyst-001",
            sessionid="sess-beta-001",
            executionid="exec-203",
            reviewitemid="review-203",
            actiontype="httpfetch",
            target="https://example.com/docs",
            policyverdict="allow",
            executionstate="executed",
            responsestatus="completed",
            message="Queued review item was approved by an analyst.",
        ),
    ]


@router.get("/log", response_model=AuditLogResponse)
def get_audit_log() -> AuditLogResponse:
    items = _build_placeholder_items()
    return AuditLogResponse(
        items=items,
        total=len(items),
        generatedat=datetime.now(timezone.utc).isoformat(),
    )