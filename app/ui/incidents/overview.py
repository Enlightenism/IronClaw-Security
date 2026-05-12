from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/incidents",
    tags=["incidents-overview"],
)


class IncidentKpiView(BaseModel):
    label: str
    value: int
    trendlabel: str | None = None
    status: str = "neutral"


class IncidentSeverityCount(BaseModel):
    severity: str
    count: int


class IncidentStatusCount(BaseModel):
    status: str
    count: int


class IncidentTimelinePoint(BaseModel):
    timestamp: str
    createdcount: int
    resolvedcount: int
    criticalopen: int


class IncidentOverviewItem(BaseModel):
    incidentid: str
    title: str
    summary: str
    severity: str
    status: str
    clientid: str | None = None
    sessionid: str | None = None
    executionid: str | None = None
    reviewitemid: str | None = None
    assignee: str | None = None
    createdat: str
    updatedat: str
    source: str
    tags: list[str] = Field(default_factory=list)


class IncidentAlertItem(BaseModel):
    alertid: str
    incidentid: str | None = None
    timestamp: str
    severity: str
    category: str
    title: str
    acknowledged: bool = False


class IncidentOverviewResponse(BaseModel):
    generatedat: str
    environment: str
    overallstatus: str
    kpis: list[IncidentKpiView] = Field(default_factory=list)
    severitycounts: list[IncidentSeverityCount] = Field(default_factory=list)
    statuscounts: list[IncidentStatusCount] = Field(default_factory=list)
    timeline: list[IncidentTimelinePoint] = Field(default_factory=list)
    incidents: list[IncidentOverviewItem] = Field(default_factory=list)
    activealerts: list[IncidentAlertItem] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _utc_iso(year: int, month: int, day: int, hour: int, minute: int = 0) -> str:
    return datetime(year, month, day, hour, minute, 0, tzinfo=UTC).isoformat()


def _sample_incident_records() -> list[dict[str, object]]:
    return [
        {
            "incidentid": "incident-001",
            "title": "Repeated shell prompt-injection attempts",
            "summary": "Multiple high-risk shell-oriented requests were denied and grouped into one active incident.",
            "severity": "critical",
            "status": "open",
            "clientid": "client-alpha",
            "sessionid": "sess-alpha-001",
            "executionid": "exec-202",
            "reviewitemid": "review-202",
            "assignee": "analyst-01",
            "createdat": _utc_iso(2026, 4, 18, 9, 15),
            "updatedat": _utc_iso(2026, 4, 18, 13, 5),
            "source": "guard-execution",
            "tags": ["prompt-injection", "shell", "boundary-block"],
        },
        {
            "incidentid": "incident-002",
            "title": "Cluster of review-queued fetch requests",
            "summary": "Related medium-risk requests accumulated in review and triggered analyst attention.",
            "severity": "high",
            "status": "investigating",
            "clientid": "client-beta",
            "sessionid": "sess-beta-001",
            "executionid": "exec-203",
            "reviewitemid": "review-203",
            "assignee": "analyst-02",
            "createdat": _utc_iso(2026, 4, 18, 10, 25),
            "updatedat": _utc_iso(2026, 4, 18, 12, 45),
            "source": "review-queue",
            "tags": ["review", "fetch", "pattern-cluster"],
        },
        {
            "incidentid": "incident-003",
            "title": "Sensitive filesystem action held for manual review",
            "summary": "A risky file-oriented action was isolated before execution and remains under analyst review.",
            "severity": "high",
            "status": "contained",
            "clientid": "client-delta",
            "sessionid": "sess-delta-001",
            "executionid": "exec-205",
            "reviewitemid": "review-205",
            "assignee": "analyst-03",
            "createdat": _utc_iso(2026, 4, 18, 12, 10),
            "updatedat": _utc_iso(2026, 4, 18, 12, 55),
            "source": "quarantine",
            "tags": ["filesystem", "quarantine", "manual-review"],
        },
        {
            "incidentid": "incident-004",
            "title": "Quarantine escalation after repeated risky tool pattern",
            "summary": "A repeated risky pattern crossed policy threshold and escalated to quarantine for containment.",
            "severity": "medium",
            "status": "resolved",
            "clientid": "client-alpha",
            "sessionid": "sess-alpha-002",
            "executionid": "exec-206",
            "reviewitemid": "review-206",
            "assignee": "analyst-01",
            "createdat": _utc_iso(2026, 4, 18, 13, 0),
            "updatedat": _utc_iso(2026, 4, 18, 14, 20),
            "source": "policy-threshold",
            "tags": ["quarantine", "repeat-pattern", "resolved"],
        },
    ]


def _sample_alerts() -> list[IncidentAlertItem]:
    return [
        IncidentAlertItem(
            alertid="incident-alert-001",
            incidentid="incident-001",
            timestamp=_utc_iso(2026, 4, 18, 9, 5),
            severity="critical",
            category="boundary-block",
            title="Critical shell-oriented request blocked by boundary",
            acknowledged=False,
        ),
        IncidentAlertItem(
            alertid="incident-alert-002",
            incidentid="incident-002",
            timestamp=_utc_iso(2026, 4, 18, 10, 25),
            severity="high",
            category="review-surge",
            title="Review queue surge triggered incident correlation",
            acknowledged=False,
        ),
        IncidentAlertItem(
            alertid="incident-alert-003",
            incidentid="incident-003",
            timestamp=_utc_iso(2026, 4, 18, 12, 10),
            severity="high",
            category="quarantine-hold",
            title="Sensitive filesystem action isolated for containment",
            acknowledged=True,
        ),
    ]


def _to_incident_item(record: dict[str, object]) -> IncidentOverviewItem:
    return IncidentOverviewItem(
        incidentid=str(record.get("incidentid") or "unknown-incident"),
        title=str(record.get("title") or "Untitled incident"),
        summary=str(record.get("summary") or "No summary available."),
        severity=str(record.get("severity") or "unknown"),
        status=str(record.get("status") or "unknown"),
        clientid=record.get("clientid") if isinstance(record.get("clientid"), str) else None,
        sessionid=record.get("sessionid") if isinstance(record.get("sessionid"), str) else None,
        executionid=record.get("executionid") if isinstance(record.get("executionid"), str) else None,
        reviewitemid=record.get("reviewitemid") if isinstance(record.get("reviewitemid"), str) else None,
        assignee=record.get("assignee") if isinstance(record.get("assignee"), str) else None,
        createdat=str(record.get("createdat") or datetime.now(UTC).isoformat()),
        updatedat=str(record.get("updatedat") or datetime.now(UTC).isoformat()),
        source=str(record.get("source") or "unknown"),
        tags=[str(tag) for tag in record.get("tags", []) if isinstance(tag, str)],
    )


def _build_severity_counts(records: list[dict[str, object]]) -> list[IncidentSeverityCount]:
    counts = Counter(str(record.get("severity") or "unknown") for record in records)
    return [
        IncidentSeverityCount(severity=severity, count=count)
        for severity, count in sorted(counts.items())
    ]


def _build_status_counts(records: list[dict[str, object]]) -> list[IncidentStatusCount]:
    counts = Counter(str(record.get("status") or "unknown") for record in records)
    return [
        IncidentStatusCount(status=status, count=count)
        for status, count in sorted(counts.items())
    ]


def _build_timeline(records: list[dict[str, object]]) -> list[IncidentTimelinePoint]:
    hourly_created: dict[str, int] = {}
    hourly_resolved: dict[str, int] = {}
    running_critical_open: dict[str, int] = {}

    created_buckets = sorted(
        {str(record.get("createdat") or "")[:13] + ":00:00+00:00" for record in records}
    )

    critical_open_count = 0
    for bucket in created_buckets:
        created_in_bucket = 0
        resolved_in_bucket = 0

        for record in records:
            createdat = str(record.get("createdat") or "")
            updatedat = str(record.get("updatedat") or "")
            severity = str(record.get("severity") or "unknown")
            status = str(record.get("status") or "unknown")

            if createdat.startswith(bucket[:13]):
                created_in_bucket += 1
                if severity == "critical" and status != "resolved":
                    critical_open_count += 1

            if updatedat.startswith(bucket[:13]) and status == "resolved":
                resolved_in_bucket += 1
                if severity == "critical" and critical_open_count > 0:
                    critical_open_count -= 1

        hourly_created[bucket] = created_in_bucket
        hourly_resolved[bucket] = resolved_in_bucket
        running_critical_open[bucket] = critical_open_count

    return [
        IncidentTimelinePoint(
            timestamp=bucket,
            createdcount=hourly_created.get(bucket, 0),
            resolvedcount=hourly_resolved.get(bucket, 0),
            criticalopen=running_critical_open.get(bucket, 0),
        )
        for bucket in created_buckets
    ]


@router.get("/overview", response_model=IncidentOverviewResponse)
def get_incidents_overview() -> IncidentOverviewResponse:
    incident_records = _sample_incident_records()
    incidents = [
        _to_incident_item(record)
        for record in sorted(
            incident_records,
            key=lambda item: str(item.get("updatedat") or ""),
            reverse=True,
        )
    ]
    activealerts = _sample_alerts()

    totalincidents = len(incident_records)
    openincidents = sum(
        1 for record in incident_records if str(record.get("status") or "") != "resolved"
    )
    criticalincidents = sum(
        1 for record in incident_records if str(record.get("severity") or "") == "critical"
    )
    unacknowledgedalerts = sum(1 for alert in activealerts if not alert.acknowledged)

    kpis = [
        IncidentKpiView(
            label="totalincidents",
            value=totalincidents,
            trendlabel="Current incident volume snapshot",
            status="healthy" if totalincidents == 0 else "warning",
        ),
        IncidentKpiView(
            label="openincidents",
            value=openincidents,
            trendlabel="Incidents still requiring operator action",
            status="critical" if openincidents > 0 else "healthy",
        ),
        IncidentKpiView(
            label="criticalincidents",
            value=criticalincidents,
            trendlabel="Highest-severity incidents detected",
            status="critical" if criticalincidents > 0 else "healthy",
        ),
        IncidentKpiView(
            label="unacknowledgedalerts",
            value=unacknowledgedalerts,
            trendlabel="Incident alerts awaiting acknowledgment",
            status="warning" if unacknowledgedalerts > 0 else "healthy",
        ),
    ]

    overallstatus = "healthy"
    if criticalincidents > 0:
        overallstatus = "critical"
    elif openincidents > 0 or unacknowledgedalerts > 0:
        overallstatus = "attention"

    return IncidentOverviewResponse(
        generatedat=datetime.now(UTC).isoformat(),
        environment="local",
        overallstatus=overallstatus,
        kpis=kpis,
        severitycounts=_build_severity_counts(incident_records),
        statuscounts=_build_status_counts(incident_records),
        timeline=_build_timeline(incident_records),
        incidents=incidents,
        activealerts=activealerts,
        notes=[
            "Incident overview aggregates active security incidents, severity mix, and operator alert state.",
            "All values are placeholder UI contract data for the current local-first Gen1 build.",
            "This page is ready to be wired to live incident, review, quarantine, and audit correlation services.",
        ],
    )