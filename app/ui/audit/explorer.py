from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/audit",
    tags=["audit-explorer"],
)


class AuditKpiView(BaseModel):
    label: str
    value: int
    trendlabel: str | None = None
    status: str = "neutral"


class AuditCategoryCount(BaseModel):
    category: str
    count: int


class AuditVerdictCount(BaseModel):
    verdict: str
    count: int


class AuditTimelinePoint(BaseModel):
    timestamp: str
    totalevents: int
    blockedevents: int
    reviewevents: int


class AuditEventView(BaseModel):
    auditeventid: str
    timestamp: str
    category: str
    severity: str
    actorid: str | None = None
    sessionid: str | None = None
    requestid: str | None = None
    traceid: str | None = None
    executionid: str | None = None
    reviewitemid: str | None = None
    incidentid: str | None = None
    verdict: str | None = None
    actiontype: str | None = None
    target: str | None = None
    summary: str
    details: dict[str, str] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class AuditFilterView(BaseModel):
    filterkey: str
    values: list[str] = Field(default_factory=list)


class AuditExplorerResponse(BaseModel):
    generatedat: str
    environment: str
    overallstatus: str
    kpis: list[AuditKpiView] = Field(default_factory=list)
    categorycounts: list[AuditCategoryCount] = Field(default_factory=list)
    verdictcounts: list[AuditVerdictCount] = Field(default_factory=list)
    timeline: list[AuditTimelinePoint] = Field(default_factory=list)
    events: list[AuditEventView] = Field(default_factory=list)
    filters: list[AuditFilterView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _utc_iso(year: int, month: int, day: int, hour: int, minute: int = 0) -> str:
    return datetime(year, month, day, hour, minute, 0, tzinfo=UTC).isoformat()


def _sample_audit_events() -> list[dict[str, object]]:
    return [
        {
            "auditeventid": "audit-001",
            "timestamp": _utc_iso(2026, 4, 18, 9, 5),
            "category": "boundary-block",
            "severity": "critical",
            "actorid": "client-alpha",
            "sessionid": "sess-alpha-001",
            "requestid": "req-202",
            "traceid": "trace-alpha-001",
            "executionid": "exec-202",
            "reviewitemid": "review-202",
            "incidentid": "incident-001",
            "verdict": "block",
            "actiontype": "toolcall",
            "target": "shell",
            "summary": "Boundary blocked a shell-oriented request before execution.",
            "details": {
                "responsestatus": "denied",
                "source": "executor-boundary",
                "reason": "High-risk shell request denied by runtime boundary.",
            },
            "tags": ["shell", "boundary", "critical"],
        },
        {
            "auditeventid": "audit-002",
            "timestamp": _utc_iso(2026, 4, 18, 10, 10),
            "category": "review-queued",
            "severity": "high",
            "actorid": "client-beta",
            "sessionid": "sess-beta-001",
            "requestid": "req-203",
            "traceid": "trace-beta-001",
            "executionid": "exec-203",
            "reviewitemid": "review-203",
            "incidentid": "incident-002",
            "verdict": "block",
            "actiontype": "httpfetch",
            "target": "https://example.com/docs",
            "summary": "Suspicious fetch request was blocked and routed into manual review.",
            "details": {
                "responsestatus": "queuedforreview",
                "source": "review-queue",
                "reason": "Suspicious pattern cluster was blocked before execution and queued for review.",
            },
            "tags": ["review", "fetch", "queued"],
        },
        {
            "auditeventid": "audit-003",
            "timestamp": _utc_iso(2026, 4, 18, 12, 10),
            "category": "quarantine-hold",
            "severity": "high",
            "actorid": "client-delta",
            "sessionid": "sess-delta-001",
            "requestid": "req-205",
            "traceid": "trace-delta-001",
            "executionid": "exec-205",
            "reviewitemid": "review-205",
            "incidentid": "incident-003",
            "verdict": "block",
            "actiontype": "toolcall",
            "target": "filesystem",
            "summary": "Sensitive filesystem action was isolated while review remained pending.",
            "details": {
                "responsestatus": "queuedforreview",
                "source": "quarantine",
                "reason": "Sensitive file-oriented action isolated for containment.",
            },
            "tags": ["filesystem", "containment", "review"],
        },
        {
            "auditeventid": "audit-004",
            "timestamp": _utc_iso(2026, 4, 18, 13, 0),
            "category": "policy-escalation",
            "severity": "high",
            "actorid": "client-alpha",
            "sessionid": "sess-alpha-002",
            "requestid": "req-206",
            "traceid": "trace-alpha-002",
            "executionid": "exec-206",
            "reviewitemid": "review-206",
            "incidentid": "incident-004",
            "verdict": "block",
            "actiontype": "toolcall",
            "target": "shell",
            "summary": "Repeated risky pattern crossed threshold and was blocked.",
            "details": {
                "responsestatus": "denied",
                "source": "policy-threshold",
                "reason": "Repeated risky shell pattern exceeded configured threshold.",
            },
            "tags": ["containment", "repeat-pattern", "policy"],
        },
        {
            "auditeventid": "audit-005",
            "timestamp": _utc_iso(2026, 4, 18, 14, 5),
            "category": "review-resolution",
            "severity": "medium",
            "actorid": "analyst-01",
            "sessionid": "sess-alpha-002",
            "requestid": "req-206",
            "traceid": "trace-alpha-002",
            "executionid": "exec-206",
            "reviewitemid": "review-206",
            "incidentid": "incident-004",
            "verdict": "block",
            "actiontype": "reviewaction",
            "target": "review-206",
            "summary": "Analyst finalized the quarantine-associated review outcome.",
            "details": {
                "responsestatus": "completed",
                "source": "analyst-review",
                "reason": "Analyst rejected the request after containment review.",
            },
            "tags": ["analyst", "resolution", "block"],
        },
    ]


def _to_audit_event(record: dict[str, object]) -> AuditEventView:
    details = record.get("details")
    details_dict: dict[str, str] = {}
    if isinstance(details, dict):
        details_dict = {str(key): str(value) for key, value in details.items() if value is not None}

    return AuditEventView(
        auditeventid=str(record.get("auditeventid") or "unknown-audit-event"),
        timestamp=str(record.get("timestamp") or datetime.now(UTC).isoformat()),
        category=str(record.get("category") or "unknown"),
        severity=str(record.get("severity") or "unknown"),
        actorid=record.get("actorid") if isinstance(record.get("actorid"), str) else None,
        sessionid=record.get("sessionid") if isinstance(record.get("sessionid"), str) else None,
        requestid=record.get("requestid") if isinstance(record.get("requestid"), str) else None,
        traceid=record.get("traceid") if isinstance(record.get("traceid"), str) else None,
        executionid=record.get("executionid") if isinstance(record.get("executionid"), str) else None,
        reviewitemid=record.get("reviewitemid") if isinstance(record.get("reviewitemid"), str) else None,
        incidentid=record.get("incidentid") if isinstance(record.get("incidentid"), str) else None,
        verdict=record.get("verdict") if isinstance(record.get("verdict"), str) else None,
        actiontype=record.get("actiontype") if isinstance(record.get("actiontype"), str) else None,
        target=record.get("target") if isinstance(record.get("target"), str) else None,
        summary=str(record.get("summary") or "No summary available."),
        details=details_dict,
        tags=[str(tag) for tag in record.get("tags", []) if isinstance(tag, str)],
    )


def _build_category_counts(records: list[dict[str, object]]) -> list[AuditCategoryCount]:
    counts = Counter(str(record.get("category") or "unknown") for record in records)
    return [AuditCategoryCount(category=category, count=count) for category, count in sorted(counts.items())]


def _build_verdict_counts(records: list[dict[str, object]]) -> list[AuditVerdictCount]:
    counts = Counter(str(record.get("verdict") or "unknown") for record in records)
    return [AuditVerdictCount(verdict=verdict, count=count) for verdict, count in sorted(counts.items())]


def _is_pending_review(record: dict[str, object]) -> bool:
    details = record.get("details")
    return isinstance(details, dict) and details.get("responsestatus") == "queuedforreview"


def _build_timeline(records: list[dict[str, object]]) -> list[AuditTimelinePoint]:
    buckets = sorted({str(record.get("timestamp") or "")[:13] + ":00:00+00:00" for record in records})

    points: list[AuditTimelinePoint] = []
    for bucket in buckets:
        bucket_records = [record for record in records if str(record.get("timestamp") or "").startswith(bucket[:13])]
        blocked = sum(1 for record in bucket_records if str(record.get("verdict") or "") == "block")
        review = sum(1 for record in bucket_records if _is_pending_review(record))

        points.append(
            AuditTimelinePoint(
                timestamp=bucket,
                totalevents=len(bucket_records),
                blockedevents=blocked,
                reviewevents=review,
            ),
        )
    return points


def _build_filters(records: list[dict[str, object]]) -> list[AuditFilterView]:
    categories = sorted({str(record.get("category") or "unknown") for record in records})
    severities = sorted({str(record.get("severity") or "unknown") for record in records})
    verdicts = sorted({str(record.get("verdict") or "unknown") for record in records})
    actors = sorted(
        {str(record.get("actorid")) for record in records if isinstance(record.get("actorid"), str) and str(record.get("actorid")).strip()},
    )

    return [
        AuditFilterView(filterkey="category", values=categories),
        AuditFilterView(filterkey="severity", values=severities),
        AuditFilterView(filterkey="verdict", values=verdicts),
        AuditFilterView(filterkey="actorid", values=actors),
    ]


@router.get("/explorer", response_model=AuditExplorerResponse)
def get_audit_explorer() -> AuditExplorerResponse:
    audit_records = _sample_audit_events()
    events = [
        _to_audit_event(record)
        for record in sorted(
            audit_records,
            key=lambda item: str(item.get("timestamp") or ""),
            reverse=True,
        )
    ]

    totalevents = len(audit_records)
    blockevents = sum(1 for record in audit_records if str(record.get("verdict") or "") == "block")
    reviewevents = sum(1 for record in audit_records if _is_pending_review(record))
    criticalevents = sum(1 for record in audit_records if str(record.get("severity") or "") == "critical")

    kpis = [
        AuditKpiView(
            label="totalevents",
            value=totalevents,
            trendlabel="Current audit event volume snapshot",
            status="healthy" if totalevents == 0 else "warning",
        ),
        AuditKpiView(
            label="blockevents",
            value=blockevents,
            trendlabel="Events that ended in hard block",
            status="critical" if blockevents > 0 else "healthy",
        ),
        AuditKpiView(
            label="reviewevents",
            value=reviewevents,
            trendlabel="Events requiring analyst intervention",
            status="warning" if reviewevents > 0 else "healthy",
        ),
        AuditKpiView(
            label="criticalevents",
            value=criticalevents,
            trendlabel="Highest-severity audit events observed",
            status="critical" if criticalevents > 0 else "healthy",
        ),
    ]

    overallstatus = "healthy"
    if criticalevents > 0 or blockevents > 0:
        overallstatus = "critical"
    elif reviewevents > 0:
        overallstatus = "attention"

    return AuditExplorerResponse(
        generatedat=datetime.now(UTC).isoformat(),
        environment="local",
        overallstatus=overallstatus,
        kpis=kpis,
        categorycounts=_build_category_counts(audit_records),
        verdictcounts=_build_verdict_counts(audit_records),
        timeline=_build_timeline(audit_records),
        events=events,
        filters=_build_filters(audit_records),
        notes=[
            "Audit explorer aggregates policy, review, quarantine, and analyst action traces into one searchable UI contract.",
            "All values are placeholder UI contract data for the current local-first Gen1 build.",
            "This page is ready to be wired to live guard audit endpoints, trace drilldowns, and filter-backed search services.",
        ],
    )
