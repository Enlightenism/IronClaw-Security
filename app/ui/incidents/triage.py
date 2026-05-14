from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/incidents",
    tags=["incident-triage"],
)


class IncidentExecutionRef(BaseModel):
    executionid: str
    reviewitemid: str | None = None
    riskscore: int
    executionstate: str
    policyverdict: str


class IncidentTriageItem(BaseModel):
    incidentid: str
    createdat: str
    status: str
    priority: str
    title: str
    summary: str
    clientid: str | None = None
    sessionid: str | None = None
    relatedexecutions: list[IncidentExecutionRef] = Field(default_factory=list)


class IncidentTriageResponse(BaseModel):
    generatedat: str
    items: list[IncidentTriageItem] = Field(default_factory=list)
    total: int = 0
    open: int = 0
    investigating: int = 0
    resolved: int = 0


def _utc_iso(year: int, month: int, day: int, hour: int, minute: int = 0) -> str:
    return datetime(year, month, day, hour, minute, 0, tzinfo=UTC).isoformat()


def _build_placeholder_items() -> list[IncidentTriageItem]:
    return [
        IncidentTriageItem(
            incidentid="incident-001",
            createdat=_utc_iso(2026, 4, 18, 9, 15),
            status="open",
            priority="critical",
            title="Repeated shell prompt-injection attempts",
            summary="Multiple high-risk shell actions were blocked for the same client/session combination.",
            clientid="client-alpha",
            sessionid="sess-alpha-001",
            relatedexecutions=[
                IncidentExecutionRef(
                    executionid="exec-202",
                    reviewitemid="review-202",
                    riskscore=91,
                    executionstate="denied",
                    policyverdict="block",
                ),
                IncidentExecutionRef(
                    executionid="exec-206",
                    reviewitemid="review-206",
                    riskscore=88,
                    executionstate="denied",
                    policyverdict="quarantine",
                ),
            ],
        ),
        IncidentTriageItem(
            incidentid="incident-002",
            createdat=_utc_iso(2026, 4, 18, 10, 25),
            status="investigating",
            priority="high",
            title="Cluster of review-queued fetch requests",
            summary="A series of mid-risk fetch executions are awaiting analyst review for the same client.",
            clientid="client-beta",
            sessionid=None,
            relatedexecutions=[
                IncidentExecutionRef(
                    executionid="exec-203",
                    reviewitemid="review-203",
                    riskscore=52,
                    executionstate="dryrun",
                    policyverdict="review",
                ),
                IncidentExecutionRef(
                    executionid="exec-207",
                    reviewitemid="review-207",
                    riskscore=57,
                    executionstate="dryrun",
                    policyverdict="review",
                ),
            ],
        ),
        IncidentTriageItem(
            incidentid="incident-003",
            createdat=_utc_iso(2026, 4, 18, 11, 40),
            status="resolved",
            priority="medium",
            title="Reviewed public fetch execution cluster",
            summary="Queued review items were validated and resolved without escalation.",
            clientid="client-gamma",
            sessionid="sess-gamma-001",
            relatedexecutions=[
                IncidentExecutionRef(
                    executionid="exec-208",
                    reviewitemid="review-208",
                    riskscore=44,
                    executionstate="executed",
                    policyverdict="allow",
                ),
            ],
        ),
    ]


@router.get("/triage", response_model=IncidentTriageResponse)
def get_incident_triage() -> IncidentTriageResponse:
    items = _build_placeholder_items()
    return IncidentTriageResponse(
        generatedat=datetime.now(UTC).isoformat(),
        items=items,
        total=len(items),
        open=sum(1 for item in items if item.status == "open"),
        investigating=sum(1 for item in items if item.status == "investigating"),
        resolved=sum(1 for item in items if item.status == "resolved"),
    )
