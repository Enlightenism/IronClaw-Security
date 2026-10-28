from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.config import RISK_THRESHOLD_BLOCK_MIN

router = APIRouter(
    prefix="/ui/quarantine",
    tags=["quarantine-overview"],
)


class QuarantineKpiView(BaseModel):
    label: str
    value: int
    trendlabel: str | None = None
    status: str = "neutral"


class QuarantineStatusCount(BaseModel):
    status: str
    count: int


class QuarantineSeverityCount(BaseModel):
    severity: str
    count: int


class QuarantineTimelinePoint(BaseModel):
    timestamp: str
    isolatedcount: int
    releasedcount: int
    activecount: int


class QuarantineItemView(BaseModel):
    quarantineid: str
    executionid: str | None = None
    reviewitemid: str | None = None
    incidentid: str | None = None
    clientid: str | None = None
    sessionid: str | None = None
    target: str
    actiontype: str
    severity: str
    status: str
    policyverdict: str
    riskscore: int
    isolatedat: str
    updatedat: str
    reason: str
    tags: list[str] = Field(default_factory=list)


class QuarantineAlertItem(BaseModel):
    alertid: str
    quarantineid: str | None = None
    timestamp: str
    severity: str
    category: str
    title: str
    acknowledged: bool = False


class QuarantineOverviewResponse(BaseModel):
    generatedat: str
    environment: str
    overallstatus: str
    kpis: list[QuarantineKpiView] = Field(default_factory=list)
    statuscounts: list[QuarantineStatusCount] = Field(default_factory=list)
    severitycounts: list[QuarantineSeverityCount] = Field(default_factory=list)
    timeline: list[QuarantineTimelinePoint] = Field(default_factory=list)
    items: list[QuarantineItemView] = Field(default_factory=list)
    activealerts: list[QuarantineAlertItem] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _utc_iso(year: int, month: int, day: int, hour: int, minute: int = 0) -> str:
    return datetime(year, month, day, hour, minute, 0, tzinfo=UTC).isoformat()


def _sample_quarantine_records() -> list[dict[str, object]]:
    return [
        {
            "quarantineid": "quarantine-001",
            "executionid": "exec-206",
            "reviewitemid": "review-206",
            "incidentid": "incident-004",
            "clientid": "client-alpha",
            "sessionid": "sess-alpha-002",
            "target": "shell",
            "actiontype": "toolcall",
            "severity": "high",
            "status": "active",
            "policyverdict": "block",
            "riskscore": max(RISK_THRESHOLD_BLOCK_MIN, 88),
            "isolatedat": _utc_iso(2026, 4, 18, 13, 0),
            "updatedat": _utc_iso(2026, 4, 18, 13, 12),
            "reason": "Repeated risky shell-oriented pattern triggered quarantine containment.",
            "tags": ["shell", "repeat-pattern", "containment"],
        },
        {
            "quarantineid": "quarantine-002",
            "executionid": "exec-205",
            "reviewitemid": "review-205",
            "incidentid": "incident-003",
            "clientid": "client-delta",
            "sessionid": "sess-delta-001",
            "target": "filesystem",
            "actiontype": "toolcall",
            "severity": "high",
            "status": "pendingrelease",
            "policyverdict": "block",
            "riskscore": max(RISK_THRESHOLD_BLOCK_MIN, 67),
            "isolatedat": _utc_iso(2026, 4, 18, 12, 10),
            "updatedat": _utc_iso(2026, 4, 18, 12, 55),
            "reason": "Sensitive file-oriented action isolated while analyst review remains pending.",
            "tags": ["filesystem", "manual-review", "hold"],
        },
        {
            "quarantineid": "quarantine-003",
            "executionid": "exec-202",
            "reviewitemid": "review-202",
            "incidentid": "incident-001",
            "clientid": "client-alpha",
            "sessionid": "sess-alpha-001",
            "target": "shell",
            "actiontype": "toolcall",
            "severity": "critical",
            "status": "active",
            "policyverdict": "block",
            "riskscore": max(RISK_THRESHOLD_BLOCK_MIN, 91),
            "isolatedat": _utc_iso(2026, 4, 18, 9, 5),
            "updatedat": _utc_iso(2026, 4, 18, 11, 40),
            "reason": "Blocked shell-style request remained isolated for investigation and evidence retention.",
            "tags": ["critical", "shell", "evidence"],
        },
        {
            "quarantineid": "quarantine-004",
            "executionid": "exec-188",
            "reviewitemid": None,
            "incidentid": None,
            "clientid": "client-gamma",
            "sessionid": "sess-gamma-008",
            "target": "https://example.com/archive",
            "actiontype": "httpfetch",
            "severity": "medium",
            "status": "released",
            "policyverdict": "block",
            "riskscore": max(RISK_THRESHOLD_BLOCK_MIN, 49),
            "isolatedat": _utc_iso(2026, 4, 18, 7, 45),
            "updatedat": _utc_iso(2026, 4, 18, 8, 30),
            "reason": "Fetch was temporarily isolated and later released after manual review.",
            "tags": ["fetch", "released", "reviewed"],
        },
    ]


def _sample_alerts() -> list[QuarantineAlertItem]:
    return [
        QuarantineAlertItem(
            alertid="quarantine-alert-001",
            quarantineid="quarantine-003",
            timestamp=_utc_iso(2026, 4, 18, 9, 5),
            severity="critical",
            category="containment",
            title="Critical shell-oriented request isolated for evidence retention",
            acknowledged=False,
        ),
        QuarantineAlertItem(
            alertid="quarantine-alert-002",
            quarantineid="quarantine-002",
            timestamp=_utc_iso(2026, 4, 18, 12, 10),
            severity="high",
            category="manual-review",
            title="Sensitive filesystem action remains isolated pending analyst decision",
            acknowledged=False,
        ),
        QuarantineAlertItem(
            alertid="quarantine-alert-003",
            quarantineid="quarantine-001",
            timestamp=_utc_iso(2026, 4, 18, 13, 0),
            severity="high",
            category="repeat-pattern",
            title="Repeated risky shell pattern escalated into active quarantine",
            acknowledged=True,
        ),
    ]


def _to_quarantine_item(record: dict[str, object]) -> QuarantineItemView:
    return QuarantineItemView(
        quarantineid=str(record.get("quarantineid") or "unknown-quarantine"),
        executionid=record.get("executionid") if isinstance(record.get("executionid"), str) else None,
        reviewitemid=record.get("reviewitemid") if isinstance(record.get("reviewitemid"), str) else None,
        incidentid=record.get("incidentid") if isinstance(record.get("incidentid"), str) else None,
        clientid=record.get("clientid") if isinstance(record.get("clientid"), str) else None,
        sessionid=record.get("sessionid") if isinstance(record.get("sessionid"), str) else None,
        target=str(record.get("target") or "unknown"),
        actiontype=str(record.get("actiontype") or "unknown"),
        severity=str(record.get("severity") or "unknown"),
        status=str(record.get("status") or "unknown"),
        policyverdict=str(record.get("policyverdict") or "unknown"),
        riskscore=int(record.get("riskscore") or 0),
        isolatedat=str(record.get("isolatedat") or datetime.now(UTC).isoformat()),
        updatedat=str(record.get("updatedat") or datetime.now(UTC).isoformat()),
        reason=str(record.get("reason") or "No reason provided."),
        tags=[str(tag) for tag in record.get("tags", []) if isinstance(tag, str)],
    )


def _build_status_counts(records: list[dict[str, object]]) -> list[QuarantineStatusCount]:
    counts = Counter(str(record.get("status") or "unknown") for record in records)
    return [QuarantineStatusCount(status=status, count=count) for status, count in sorted(counts.items())]


def _build_severity_counts(records: list[dict[str, object]]) -> list[QuarantineSeverityCount]:
    counts = Counter(str(record.get("severity") or "unknown") for record in records)
    return [QuarantineSeverityCount(severity=severity, count=count) for severity, count in sorted(counts.items())]


def _build_timeline(records: list[dict[str, object]]) -> list[QuarantineTimelinePoint]:
    hourly_isolated: dict[str, int] = {}
    hourly_released: dict[str, int] = {}
    running_active: dict[str, int] = {}

    buckets = sorted({str(record.get("isolatedat") or "")[:13] + ":00:00+00:00" for record in records})

    active_count = 0
    for bucket in buckets:
        isolated_in_bucket = 0
        released_in_bucket = 0

        for record in records:
            isolatedat = str(record.get("isolatedat") or "")
            updatedat = str(record.get("updatedat") or "")
            status = str(record.get("status") or "unknown")

            if isolatedat.startswith(bucket[:13]):
                isolated_in_bucket += 1
                if status != "released":
                    active_count += 1

            if updatedat.startswith(bucket[:13]) and status == "released":
                released_in_bucket += 1
                if active_count > 0:
                    active_count -= 1

        hourly_isolated[bucket] = isolated_in_bucket
        hourly_released[bucket] = released_in_bucket
        running_active[bucket] = active_count

    return [
        QuarantineTimelinePoint(
            timestamp=bucket,
            isolatedcount=hourly_isolated.get(bucket, 0),
            releasedcount=hourly_released.get(bucket, 0),
            activecount=running_active.get(bucket, 0),
        )
        for bucket in buckets
    ]


@router.get("/overview", response_model=QuarantineOverviewResponse)
def get_quarantine_overview() -> QuarantineOverviewResponse:
    quarantine_records = _sample_quarantine_records()
    items = [
        _to_quarantine_item(record)
        for record in sorted(
            quarantine_records,
            key=lambda item: str(item.get("updatedat") or ""),
            reverse=True,
        )
    ]
    activealerts = _sample_alerts()

    totalitems = len(quarantine_records)
    activeitems = sum(1 for record in quarantine_records if str(record.get("status") or "") != "released")
    criticalitems = sum(1 for record in quarantine_records if str(record.get("severity") or "") == "critical")
    unacknowledgedalerts = sum(1 for alert in activealerts if not alert.acknowledged)

    kpis = [
        QuarantineKpiView(
            label="totalisolated",
            value=totalitems,
            trendlabel="Current quarantine item volume snapshot",
            status="warning" if totalitems > 0 else "healthy",
        ),
        QuarantineKpiView(
            label="activeisolated",
            value=activeitems,
            trendlabel="Items still contained in quarantine",
            status="critical" if activeitems > 0 else "healthy",
        ),
        QuarantineKpiView(
            label="criticalisolated",
            value=criticalitems,
            trendlabel="Highest-severity quarantined items",
            status="critical" if criticalitems > 0 else "healthy",
        ),
        QuarantineKpiView(
            label="unacknowledgedalerts",
            value=unacknowledgedalerts,
            trendlabel="Containment alerts awaiting acknowledgment",
            status="warning" if unacknowledgedalerts > 0 else "healthy",
        ),
    ]

    overallstatus = "healthy"
    if criticalitems > 0:
        overallstatus = "critical"
    elif activeitems > 0 or unacknowledgedalerts > 0:
        overallstatus = "attention"

    return QuarantineOverviewResponse(
        generatedat=datetime.now(UTC).isoformat(),
        environment="local",
        overallstatus=overallstatus,
        kpis=kpis,
        statuscounts=_build_status_counts(quarantine_records),
        severitycounts=_build_severity_counts(quarantine_records),
        timeline=_build_timeline(quarantine_records),
        items=items,
        activealerts=activealerts,
        notes=[
            "Quarantine overview aggregates isolated actions, containment status, and alert visibility.",
            "All values are placeholder UI contract data for the current local-first Gen1 build.",
            "This page is ready to be wired to live containment, release, review, and incident correlation services.",
        ],
    )
