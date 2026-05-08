from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from app.core.auth import require_api_key

router = APIRouter(
    prefix="/ui",
    tags=["incident-triage"],
    dependencies=[Depends(require_api_key)],
)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class IncidentTriageItemView(BaseModel):
    incident_id: str
    timestamp: str
    severity: str
    status: str
    source: str
    title: str
    summary: str
    client_id: str | None = None
    session_id: str | None = None
    execution_id: str | None = None
    review_item_id: str | None = None
    recommended_action: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class IncidentTriageResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    requested_by: str
    total: int
    open_count: int
    acknowledged_count: int
    resolved_count: int
    items: list[IncidentTriageItemView] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _build_incident_items() -> list[IncidentTriageItemView]:
    return [
        IncidentTriageItemView(
            incident_id="incident-001",
            timestamp="2026-04-21T15:02:00Z",
            severity="critical",
            status="open",
            source="policy-boundary",
            title="Blocked destructive shell action",
            summary="A destructive shell command was blocked before execution and requires immediate review.",
            client_id="client-alpha",
            session_id="sess-alpha-22",
            execution_id="exec-410",
            review_item_id="review-410",
            recommended_action="Escalate to security operator and preserve trace context.",
            metadata={
                "policy_verdict": "block",
                "action_type": "shell_execute",
            },
        ),
        IncidentTriageItemView(
            incident_id="incident-002",
            timestamp="2026-04-21T15:18:00Z",
            severity="high",
            status="acknowledged",
            source="prompt-ingress",
            title="Prompt injection attempt detected",
            summary="Suspicious instruction chaining was detected in inbound content and queued for analyst review.",
            client_id="client-beta",
            session_id="sess-beta-14",
            execution_id="exec-411",
            review_item_id="review-411",
            recommended_action="Inspect upstream content source and confirm quarantine decision.",
            metadata={
                "policy_verdict": "quarantine",
                "action_type": "prompt_guard",
            },
        ),
        IncidentTriageItemView(
            incident_id="incident-003",
            timestamp="2026-04-21T15:30:00Z",
            severity="medium",
            status="resolved",
            source="review-queue",
            title="Queued review resolved",
            summary="A previously quarantined execution was reviewed, approved, and documented.",
            client_id="client-gamma",
            session_id="sess-gamma-05",
            execution_id="exec-412",
            review_item_id="review-412",
            recommended_action="No further action required.",
            metadata={
                "review_status": "approved",
                "execution_state": "completed",
            },
        ),
    ]


@router.get("/incident-triage", response_model=IncidentTriageResponse)
def get_incident_triage(
    requested_by: str = Query("ui-incident-triage", min_length=1),
) -> IncidentTriageResponse:
    items = _build_incident_items()
    open_count = sum(1 for item in items if item.status == "open")
    acknowledged_count = sum(1 for item in items if item.status == "acknowledged")
    resolved_count = sum(1 for item in items if item.status == "resolved")

    return IncidentTriageResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        requested_by=requested_by,
        total=len(items),
        open_count=open_count,
        acknowledged_count=acknowledged_count,
        resolved_count=resolved_count,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )
