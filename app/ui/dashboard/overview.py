from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/dashboard",
    tags=["dashboard-overview"],
)


class DashboardKpiView(BaseModel):
    label: str
    value: int
    trendlabel: str | None = None
    status: str = "neutral"


class DashboardVerdictCount(BaseModel):
    policyverdict: str
    count: int


class DashboardExecutionStateCount(BaseModel):
    executionstate: str
    count: int


class DashboardRiskTrendPoint(BaseModel):
    timestamp: str
    average_riskscore: float
    totalexecutions: int


class DashboardRecentExecutionItem(BaseModel):
    executionid: str
    timestamp: str
    clientid: str | None = None
    sessionid: str | None = None
    actiontype: str
    target: str
    riskscore: int
    executionstate: str
    responsestatus: str
    policyverdict: str
    reviewitemid: str | None = None
    reason: str | None = None


class DashboardRecentReviewItem(BaseModel):
    reviewitemid: str
    executionid: str
    timestamp: str
    reviewstatus: str
    clientid: str | None = None
    sessionid: str | None = None
    riskscore: int
    policyverdict: str
    responsestatus: str
    reason: str | None = None


class DashboardRecentIncidentItem(BaseModel):
    incidentid: str
    createdat: str
    status: str
    priority: str
    title: str
    clientid: str | None = None
    sessionid: str | None = None


class DashboardAlertItem(BaseModel):
    alertid: str
    timestamp: str
    severity: str
    category: str
    title: str
    acknowledged: bool = False
    executionid: str | None = None
    reviewitemid: str | None = None


class DashboardOverviewResponse(BaseModel):
    generatedat: str
    environment: str
    overallstatus: str
    kpis: list[DashboardKpiView] = Field(default_factory=list)
    verdictcounts: list[DashboardVerdictCount] = Field(default_factory=list)
    executionstatecounts: list[DashboardExecutionStateCount] = Field(default_factory=list)
    risktrend: list[DashboardRiskTrendPoint] = Field(default_factory=list)
    recentexecutions: list[DashboardRecentExecutionItem] = Field(default_factory=list)
    recentreviews: list[DashboardRecentReviewItem] = Field(default_factory=list)
    recentincidents: list[DashboardRecentIncidentItem] = Field(default_factory=list)
    activealerts: list[DashboardAlertItem] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _utc_iso(year: int, month: int, day: int, hour: int, minute: int = 0) -> str:
    return datetime(year, month, day, hour, minute, 0, tzinfo=UTC).isoformat()


def _sample_execution_records() -> list[dict[str, object]]:
    return [
        {
            "executionid": "exec-201",
            "timestamp": _utc_iso(2026, 4, 18, 8, 0),
            "clientid": "client-alpha",
            "sessionid": "sess-alpha-001",
            "actiontype": "httpfetch",
            "target": "https://example.com",
            "riskscore": 4,
            "executionstate": "executed",
            "responsestatus": "completed",
            "policyverdict": "allow",
            "reviewitemid": None,
            "reason": "Low-risk public fetch completed successfully.",
        },
        {
            "executionid": "exec-202",
            "timestamp": _utc_iso(2026, 4, 18, 9, 5),
            "clientid": "client-alpha",
            "sessionid": "sess-alpha-001",
            "actiontype": "toolcall",
            "target": "shell",
            "riskscore": 91,
            "executionstate": "denied",
            "responsestatus": "denied",
            "policyverdict": "block",
            "reviewitemid": "review-202",
            "reason": "High-risk shell request blocked by runtime boundary.",
        },
        {
            "executionid": "exec-203",
            "timestamp": _utc_iso(2026, 4, 18, 10, 10),
            "clientid": "client-beta",
            "sessionid": "sess-beta-001",
            "actiontype": "httpfetch",
            "target": "https://example.com/docs",
            "riskscore": 52,
            "executionstate": "dryrun",
            "responsestatus": "queuedforreview",
            "policyverdict": "review",
            "reviewitemid": "review-203",
            "reason": "Mid-risk fetch queued for analyst review.",
        },
        {
            "executionid": "exec-204",
            "timestamp": _utc_iso(2026, 4, 18, 11, 20),
            "clientid": "client-gamma",
            "sessionid": "sess-gamma-001",
            "actiontype": "httpfetch",
            "target": "https://example.com/public-report",
            "riskscore": 12,
            "executionstate": "executed",
            "responsestatus": "completed",
            "policyverdict": "allow",
            "reviewitemid": None,
            "reason": "Public report fetch completed.",
        },
        {
            "executionid": "exec-205",
            "timestamp": _utc_iso(2026, 4, 18, 12, 10),
            "clientid": "client-delta",
            "sessionid": "sess-delta-001",
            "actiontype": "toolcall",
            "target": "filesystem",
            "riskscore": 67,
            "executionstate": "dryrun",
            "responsestatus": "queuedforreview",
            "policyverdict": "review",
            "reviewitemid": "review-205",
            "reason": "Sensitive file-oriented action held for review.",
        },
        {
            "executionid": "exec-206",
            "timestamp": _utc_iso(2026, 4, 18, 13, 0),
            "clientid": "client-alpha",
            "sessionid": "sess-alpha-002",
            "actiontype": "toolcall",
            "target": "shell",
            "riskscore": 88,
            "executionstate": "denied",
            "responsestatus": "denied",
            "policyverdict": "quarantine",
            "reviewitemid": "review-206",
            "reason": "Repeated risky shell-adjacent pattern escalated to quarantine.",
        },
    ]


def _sample_review_items() -> list[DashboardRecentReviewItem]:
    return [
        DashboardRecentReviewItem(
            reviewitemid="review-205",
            executionid="exec-205",
            timestamp=_utc_iso(2026, 4, 18, 12, 10),
            reviewstatus="pending",
            clientid="client-delta",
            sessionid="sess-delta-001",
            riskscore=67,
            policyverdict="review",
            responsestatus="queuedforreview",
            reason="Sensitive file-oriented action requires analyst approval.",
        ),
        DashboardRecentReviewItem(
            reviewitemid="review-203",
            executionid="exec-203",
            timestamp=_utc_iso(2026, 4, 18, 10, 10),
            reviewstatus="pending",
            clientid="client-beta",
            sessionid="sess-beta-001",
            riskscore=52,
            policyverdict="review",
            responsestatus="queuedforreview",
            reason="Mid-risk fetch awaiting analyst review.",
        ),
        DashboardRecentReviewItem(
            reviewitemid="review-202",
            executionid="exec-202",
            timestamp=_utc_iso(2026, 4, 18, 9, 5),
            reviewstatus="rejected",
            clientid="client-alpha",
            sessionid="sess-alpha-001",
            riskscore=91,
            policyverdict="block",
            responsestatus="denied",
            reason="High-risk shell request rejected by boundary and reviewer policy.",
        ),
    ]


def _sample_incidents() -> list[DashboardRecentIncidentItem]:
    return [
        DashboardRecentIncidentItem(
            incidentid="incident-001",
            createdat=_utc_iso(2026, 4, 18, 9, 15),
            status="open",
            priority="critical",
            title="Repeated shell prompt-injection attempts",
            clientid="client-alpha",
            sessionid="sess-alpha-001",
        ),
        DashboardRecentIncidentItem(
            incidentid="incident-002",
            createdat=_utc_iso(2026, 4, 18, 10, 25),
            status="investigating",
            priority="high",
            title="Cluster of review-queued fetch requests",
            clientid="client-beta",
            sessionid=None,
        ),
    ]


def _sample_alerts() -> list[DashboardAlertItem]:
    return [
        DashboardAlertItem(
            alertid="alert-001",
            timestamp=_utc_iso(2026, 4, 18, 9, 5),
            severity="critical",
            category="boundary-block",
            title="High-risk shell request blocked",
            acknowledged=False,
            executionid="exec-202",
            reviewitemid="review-202",
        ),
        DashboardAlertItem(
            alertid="alert-002",
            timestamp=_utc_iso(2026, 4, 18, 12, 10),
            severity="high",
            category="review-queue",
            title="Manual review required for sensitive file action",
            acknowledged=False,
            executionid="exec-205",
            reviewitemid="review-205",
        ),
        DashboardAlertItem(
            alertid="alert-003",
            timestamp=_utc_iso(2026, 4, 18, 13, 0),
            severity="high",
            category="quarantine",
            title="Quarantine verdict triggered for repeated risky pattern",
            acknowledged=True,
            executionid="exec-206",
            reviewitemid="review-206",
        ),
    ]


def _to_recent_execution_item(record: dict[str, object]) -> DashboardRecentExecutionItem:
    return DashboardRecentExecutionItem(
        executionid=str(record.get("executionid") or "unknown-execution"),
        timestamp=str(record.get("timestamp") or datetime.now(UTC).isoformat()),
        clientid=record.get("clientid") if isinstance(record.get("clientid"), str) else None,
        sessionid=record.get("sessionid") if isinstance(record.get("sessionid"), str) else None,
        actiontype=str(record.get("actiontype") or "unknown"),
        target=str(record.get("target") or "unknown"),
        riskscore=int(record.get("riskscore") or 0),
        executionstate=str(record.get("executionstate") or "unknown"),
        responsestatus=str(record.get("responsestatus") or "completed"),
        policyverdict=str(record.get("policyverdict") or "allow"),
        reviewitemid=record.get("reviewitemid") if isinstance(record.get("reviewitemid"), str) else None,
        reason=record.get("reason") if isinstance(record.get("reason"), str) else None,
    )


def _build_verdict_counts(records: list[dict[str, object]]) -> list[DashboardVerdictCount]:
    counts = Counter(str(record.get("policyverdict") or "unknown") for record in records)
    return [DashboardVerdictCount(policyverdict=verdict, count=count) for verdict, count in sorted(counts.items())]


def _build_execution_state_counts(
    records: list[dict[str, object]],
) -> list[DashboardExecutionStateCount]:
    counts = Counter(str(record.get("executionstate") or "unknown") for record in records)
    return [DashboardExecutionStateCount(executionstate=state, count=count) for state, count in sorted(counts.items())]


def _build_risk_trend(records: list[dict[str, object]]) -> list[DashboardRiskTrendPoint]:
    buckets: dict[str, list[int]] = {}

    for record in records:
        timestamp = str(record.get("timestamp") or datetime.now(UTC).isoformat())
        bucket_key = timestamp[:13] + ":00:00+00:00"
        buckets.setdefault(bucket_key, []).append(int(record.get("riskscore") or 0))

    points: list[DashboardRiskTrendPoint] = []
    for bucket_key in sorted(buckets.keys()):
        scores = buckets[bucket_key]
        average = round(sum(scores) / len(scores), 2) if scores else 0.0
        points.append(
            DashboardRiskTrendPoint(
                timestamp=bucket_key,
                average_riskscore=average,
                totalexecutions=len(scores),
            ),
        )
    return points


@router.get("/overview", response_model=DashboardOverviewResponse)
def get_dashboard_overview() -> DashboardOverviewResponse:
    execution_records = _sample_execution_records()
    recentexecutions = [
        _to_recent_execution_item(record)
        for record in sorted(
            execution_records,
            key=lambda item: str(item.get("timestamp") or ""),
            reverse=True,
        )[:5]
    ]
    recentreviews = _sample_review_items()
    recentincidents = _sample_incidents()
    activealerts = _sample_alerts()

    totalexecutions = len(execution_records)
    pendingreviews = sum(1 for item in recentreviews if item.reviewstatus == "pending")
    openincidents = sum(1 for item in recentincidents if item.status != "resolved")
    unacknowledgedalerts = sum(1 for item in activealerts if not item.acknowledged)

    kpis = [
        DashboardKpiView(
            label="totalexecutions",
            value=totalexecutions,
            trendlabel="Latest guarded execution volume snapshot",
            status="healthy",
        ),
        DashboardKpiView(
            label="pendingreviews",
            value=pendingreviews,
            trendlabel="Requires analyst attention",
            status="warning" if pendingreviews else "healthy",
        ),
        DashboardKpiView(
            label="openincidents",
            value=openincidents,
            trendlabel="Active triage workload",
            status="critical" if openincidents else "healthy",
        ),
        DashboardKpiView(
            label="unacknowledgedalerts",
            value=unacknowledgedalerts,
            trendlabel="Alerts still awaiting acknowledgment",
            status="warning" if unacknowledgedalerts else "healthy",
        ),
    ]

    overallstatus = "healthy"
    if any(item.priority == "critical" for item in recentincidents):
        overallstatus = "critical"
    elif pendingreviews or unacknowledgedalerts:
        overallstatus = "attention"

    return DashboardOverviewResponse(
        generatedat=datetime.now(UTC).isoformat(),
        environment="local",
        overallstatus=overallstatus,
        kpis=kpis,
        verdictcounts=_build_verdict_counts(execution_records),
        executionstatecounts=_build_execution_state_counts(execution_records),
        risktrend=_build_risk_trend(execution_records),
        recentexecutions=recentexecutions,
        recentreviews=recentreviews,
        recentincidents=recentincidents,
        activealerts=activealerts,
        notes=[
            "Dashboard aggregates guarded execution, review, incident, and alert snapshots.",
            "All values are placeholder UI contract data for the current local-first Gen1 build.",
            "This page is ready to be wired to live services after backend aggregation endpoints are added.",
        ],
    )
