from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from app.config import RISK_THRESHOLD_BLOCK_MIN

router = APIRouter(
    prefix="/ui/executions",
    tags=["execution-explorer"],
)


class ExecutionKpiView(BaseModel):
    label: str
    value: int
    trendlabel: str | None = None
    status: str = "neutral"


class ExecutionStateCount(BaseModel):
    executionstate: str
    count: int


class ExecutionVerdictCount(BaseModel):
    policyverdict: str
    count: int


class ExecutionTimelinePoint(BaseModel):
    timestamp: str
    totalexecutions: int
    deniedexecutions: int
    reviewexecutions: int
    completedexecutions: int


class ExecutionFilterView(BaseModel):
    filterkey: str
    values: list[str] = Field(default_factory=list)


class ExecutionExplorerItem(BaseModel):
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
    shouldexecute: bool
    haltedbyboundary: bool
    reviewitemid: str | None = None
    traceid: str | None = None
    reason: str | None = None


class ExecutionExplorerResponse(BaseModel):
    generatedat: str
    environment: str
    overallstatus: str
    total: int = 0
    appliedfilters: dict[str, Any] = Field(default_factory=dict)
    kpis: list[ExecutionKpiView] = Field(default_factory=list)
    executionstatecounts: list[ExecutionStateCount] = Field(default_factory=list)
    verdictcounts: list[ExecutionVerdictCount] = Field(default_factory=list)
    timeline: list[ExecutionTimelinePoint] = Field(default_factory=list)
    filters: list[ExecutionFilterView] = Field(default_factory=list)
    items: list[ExecutionExplorerItem] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _utc_iso(year: int, month: int, day: int, hour: int, minute: int = 0) -> str:
    return datetime(year, month, day, hour, minute, 0, tzinfo=UTC).isoformat()


def _safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "y", "on"}:
            return True
        if lowered in {"false", "0", "no", "n", "off"}:
            return False
    return bool(value)


def _sample_execution_records() -> list[dict[str, Any]]:
    return [
        {
            "executionid": "exec-201",
            "timestamp": _utc_iso(2026, 4, 18, 8, 0),
            "clientid": "client-alpha",
            "sessionid": "sess-alpha-001",
            "actiontype": "httpfetch",
            "target": "https://example.com",
            "riskscore": 3,
            "executionstate": "executed",
            "responsestatus": "completed",
            "policyverdict": "allow",
            "shouldexecute": True,
            "haltedbyboundary": False,
            "reviewitemid": None,
            "traceid": "trace-201",
            "reason": "Low-risk public fetch completed successfully.",
        },
        {
            "executionid": "exec-202",
            "timestamp": _utc_iso(2026, 4, 18, 9, 5),
            "clientid": "client-alpha",
            "sessionid": "sess-alpha-001",
            "actiontype": "toolcall",
            "target": "shell",
            "riskscore": max(RISK_THRESHOLD_BLOCK_MIN, 91),
            "executionstate": "denied",
            "responsestatus": "denied",
            "policyverdict": "block",
            "shouldexecute": False,
            "haltedbyboundary": True,
            "reviewitemid": "review-202",
            "traceid": "trace-202",
            "reason": "High-risk shell request denied by runtime boundary.",
        },
        {
            "executionid": "exec-203",
            "timestamp": _utc_iso(2026, 4, 18, 10, 10),
            "clientid": "client-beta",
            "sessionid": "sess-beta-001",
            "actiontype": "httpfetch",
            "target": "https://example.com/docs",
            "riskscore": max(RISK_THRESHOLD_BLOCK_MIN, 52),
            "executionstate": "dryrun",
            "responsestatus": "queuedforreview",
            "policyverdict": "block",
            "shouldexecute": False,
            "haltedbyboundary": True,
            "reviewitemid": "review-203",
            "traceid": "trace-203",
            "reason": "Suspicious fetch request was blocked and queued for analyst review.",
        },
        {
            "executionid": "exec-204",
            "timestamp": _utc_iso(2026, 4, 18, 11, 15),
            "clientid": "client-gamma",
            "sessionid": "sess-gamma-001",
            "actiontype": "httpfetch",
            "target": "https://example.com/report",
            "riskscore": 11,
            "executionstate": "executed",
            "responsestatus": "completed",
            "policyverdict": "allow",
            "shouldexecute": True,
            "haltedbyboundary": False,
            "reviewitemid": None,
            "traceid": "trace-204",
            "reason": "Known-safe report fetch completed successfully.",
        },
        {
            "executionid": "exec-205",
            "timestamp": _utc_iso(2026, 4, 18, 12, 20),
            "clientid": "client-delta",
            "sessionid": "sess-delta-001",
            "actiontype": "toolcall",
            "target": "filesystem",
            "riskscore": max(RISK_THRESHOLD_BLOCK_MIN, 68),
            "executionstate": "dryrun",
            "responsestatus": "queuedforreview",
            "policyverdict": "block",
            "shouldexecute": False,
            "haltedbyboundary": True,
            "reviewitemid": "review-205",
            "traceid": "trace-205",
            "reason": "Sensitive file-oriented action held for analyst approval.",
        },
        {
            "executionid": "exec-206",
            "timestamp": _utc_iso(2026, 4, 18, 13, 0),
            "clientid": "client-alpha",
            "sessionid": "sess-alpha-002",
            "actiontype": "toolcall",
            "target": "shell",
            "riskscore": max(RISK_THRESHOLD_BLOCK_MIN, 88),
            "executionstate": "denied",
            "responsestatus": "denied",
            "policyverdict": "block",
            "shouldexecute": False,
            "haltedbyboundary": True,
            "reviewitemid": "review-206",
            "traceid": "trace-206",
            "reason": "Repeated risky shell pattern was blocked before execution.",
        },
    ]


def _to_item(record: dict[str, Any]) -> ExecutionExplorerItem:
    return ExecutionExplorerItem(
        executionid=_safe_str(record.get("executionid"), "unknown-execution"),
        timestamp=_safe_str(record.get("timestamp"), datetime.now(UTC).isoformat()),
        clientid=record.get("clientid") if isinstance(record.get("clientid"), str) else None,
        sessionid=record.get("sessionid") if isinstance(record.get("sessionid"), str) else None,
        actiontype=_safe_str(record.get("actiontype"), "unknown"),
        target=_safe_str(record.get("target"), "unknown"),
        riskscore=_safe_int(record.get("riskscore"), 0),
        executionstate=_safe_str(record.get("executionstate"), "unknown"),
        responsestatus=_safe_str(record.get("responsestatus"), "completed"),
        policyverdict=_safe_str(record.get("policyverdict"), "allow"),
        shouldexecute=_safe_bool(record.get("shouldexecute"), False),
        haltedbyboundary=_safe_bool(record.get("haltedbyboundary"), False),
        reviewitemid=record.get("reviewitemid") if isinstance(record.get("reviewitemid"), str) else None,
        traceid=record.get("traceid") if isinstance(record.get("traceid"), str) else None,
        reason=record.get("reason") if isinstance(record.get("reason"), str) else None,
    )


def _matches_text(value: str | None, expected: str | None) -> bool:
    if not expected:
        return True
    actual = _safe_str(value).lower()
    return expected.strip().lower() in actual


def _build_execution_state_counts(records: list[dict[str, Any]]) -> list[ExecutionStateCount]:
    counts = Counter(_safe_str(record.get("executionstate"), "unknown") for record in records)
    return [ExecutionStateCount(executionstate=executionstate, count=count) for executionstate, count in sorted(counts.items())]


def _build_verdict_counts(records: list[dict[str, Any]]) -> list[ExecutionVerdictCount]:
    counts = Counter(_safe_str(record.get("policyverdict"), "unknown") for record in records)
    return [ExecutionVerdictCount(policyverdict=policyverdict, count=count) for policyverdict, count in sorted(counts.items())]


def _build_timeline(records: list[dict[str, Any]]) -> list[ExecutionTimelinePoint]:
    buckets = sorted({_safe_str(record.get("timestamp"))[:13] + ":00:00+00:00" for record in records})

    points: list[ExecutionTimelinePoint] = []
    for bucket in buckets:
        bucket_records = [record for record in records if _safe_str(record.get("timestamp")).startswith(bucket[:13])]
        denied = sum(1 for record in bucket_records if _safe_str(record.get("executionstate")) == "denied")
        review = sum(1 for record in bucket_records if _safe_str(record.get("responsestatus")) == "queuedforreview")
        completed = sum(1 for record in bucket_records if _safe_str(record.get("responsestatus")) == "completed")

        points.append(
            ExecutionTimelinePoint(
                timestamp=bucket,
                totalexecutions=len(bucket_records),
                deniedexecutions=denied,
                reviewexecutions=review,
                completedexecutions=completed,
            ),
        )
    return points


def _build_filters(records: list[dict[str, Any]]) -> list[ExecutionFilterView]:
    actiontypes = sorted({_safe_str(record.get("actiontype"), "unknown") for record in records})
    executionstates = sorted({_safe_str(record.get("executionstate"), "unknown") for record in records})
    responsestatuses = sorted({_safe_str(record.get("responsestatus"), "unknown") for record in records})
    verdicts = sorted({_safe_str(record.get("policyverdict"), "unknown") for record in records})
    clients = sorted(
        {_safe_str(record.get("clientid")) for record in records if _safe_str(record.get("clientid")).strip()},
    )

    return [
        ExecutionFilterView(filterkey="actiontype", values=actiontypes),
        ExecutionFilterView(filterkey="executionstate", values=executionstates),
        ExecutionFilterView(filterkey="responsestatus", values=responsestatuses),
        ExecutionFilterView(filterkey="policyverdict", values=verdicts),
        ExecutionFilterView(filterkey="clientid", values=clients),
    ]


@router.get("/explorer", response_model=ExecutionExplorerResponse)
def get_execution_explorer(
    actiontype: str | None = Query(default=None),
    target: str | None = Query(default=None),
    clientid: str | None = Query(default=None),
    sessionid: str | None = Query(default=None),
    executionstate: str | None = Query(default=None),
    responsestatus: str | None = Query(default=None),
    policyverdict: str | None = Query(default=None),
    minriskscore: int | None = Query(default=None, ge=0, le=100),
    maxriskscore: int | None = Query(default=None, ge=0, le=100),
    reviewonly: bool = Query(default=False),
) -> ExecutionExplorerResponse:
    records = _sample_execution_records()
    filtered: list[dict[str, Any]] = []

    for record in records:
        record_riskscore = _safe_int(record.get("riskscore"), 0)

        if not _matches_text(record.get("actiontype"), actiontype):
            continue
        if not _matches_text(record.get("target"), target):
            continue
        if not _matches_text(record.get("clientid"), clientid):
            continue
        if not _matches_text(record.get("sessionid"), sessionid):
            continue
        if not _matches_text(record.get("executionstate"), executionstate):
            continue
        if not _matches_text(record.get("responsestatus"), responsestatus):
            continue
        if not _matches_text(record.get("policyverdict"), policyverdict):
            continue
        if minriskscore is not None and record_riskscore < minriskscore:
            continue
        if maxriskscore is not None and record_riskscore > maxriskscore:
            continue
        if reviewonly and not record.get("reviewitemid"):
            continue

        filtered.append(record)

    sorted_filtered = sorted(
        filtered,
        key=lambda item: _safe_str(item.get("timestamp")),
        reverse=True,
    )
    items = [_to_item(record) for record in sorted_filtered]

    total = len(items)
    deniedcount = sum(1 for record in filtered if _safe_str(record.get("executionstate")) == "denied")
    reviewcount = sum(1 for record in filtered if _safe_str(record.get("responsestatus")) == "queuedforreview")
    highriskcount = sum(1 for record in filtered if _safe_int(record.get("riskscore"), 0) >= 75)
    boundaryhaltcount = sum(1 for record in filtered if _safe_bool(record.get("haltedbyboundary"), False))

    kpis = [
        ExecutionKpiView(
            label="visibleexecutions",
            value=total,
            trendlabel="Execution records matching current filters",
            status="healthy" if total == 0 else "warning",
        ),
        ExecutionKpiView(
            label="deniedexecutions",
            value=deniedcount,
            trendlabel="Executions denied by guard or boundary controls",
            status="critical" if deniedcount > 0 else "healthy",
        ),
        ExecutionKpiView(
            label="reviewexecutions",
            value=reviewcount,
            trendlabel="Executions routed into analyst review",
            status="warning" if reviewcount > 0 else "healthy",
        ),
        ExecutionKpiView(
            label="boundaryhalts",
            value=boundaryhaltcount,
            trendlabel="Requests halted directly by runtime boundary",
            status="critical" if boundaryhaltcount > 0 else "healthy",
        ),
    ]

    overallstatus = "healthy"
    if deniedcount > 0 or highriskcount > 0:
        overallstatus = "critical"
    elif reviewcount > 0 or boundaryhaltcount > 0:
        overallstatus = "attention"

    return ExecutionExplorerResponse(
        generatedat=datetime.now(UTC).isoformat(),
        environment="local",
        overallstatus=overallstatus,
        total=total,
        appliedfilters={
            "actiontype": actiontype,
            "target": target,
            "clientid": clientid,
            "sessionid": sessionid,
            "executionstate": executionstate,
            "responsestatus": responsestatus,
            "policyverdict": policyverdict,
            "minriskscore": minriskscore,
            "maxriskscore": maxriskscore,
            "reviewonly": reviewonly,
        },
        kpis=kpis,
        executionstatecounts=_build_execution_state_counts(filtered),
        verdictcounts=_build_verdict_counts(filtered),
        timeline=_build_timeline(filtered),
        filters=_build_filters(records),
        items=items,
        notes=[
            "Execution explorer exposes guarded execution outcomes, boundary halts, and review-linked runtime activity.",
            "All values are placeholder UI contract data for the current local-first Gen1 build.",
            "This page is ready to be wired to live execution history, filter-backed search, and trace drilldown services.",
        ],
    )
