from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/activity",
    tags=["client-session-activity"],
)


class ActivityExecutionItem(BaseModel):
    executionid: str
    timestamp: str
    actiontype: str
    target: str
    riskscore: int
    executionstate: str
    responsestatus: str
    policyverdict: str
    reviewitemid: str | None = None


class ClientActivitySummary(BaseModel):
    clientid: str
    totalexecutions: int
    average_riskscore: float
    highest_riskscore: int
    pendingreviews: int
    verdictcounts: dict[str, int] = Field(default_factory=dict)
    recentexecutions: list[ActivityExecutionItem] = Field(default_factory=list)


class SessionActivitySummary(BaseModel):
    sessionid: str
    clientid: str | None = None
    totalexecutions: int
    average_riskscore: float
    highest_riskscore: int
    pendingreviews: int
    verdictcounts: dict[str, int] = Field(default_factory=dict)
    recentexecutions: list[ActivityExecutionItem] = Field(default_factory=list)


class ClientSessionActivityResponse(BaseModel):
    generatedat: str
    clients: list[ClientActivitySummary] = Field(default_factory=list)
    sessions: list[SessionActivitySummary] = Field(default_factory=list)


def _utc_iso(year: int, month: int, day: int, hour: int, minute: int = 0) -> str:
    return datetime(year, month, day, hour, minute, 0, tzinfo=UTC).isoformat()


def _safe_str(value: Any, default: str) -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _sample_activity_records() -> list[dict[str, Any]]:
    return [
        {
            "executionid": "exec-101",
            "timestamp": _utc_iso(2026, 4, 18, 8, 15),
            "clientid": "client-alpha",
            "sessionid": "sess-alpha-001",
            "actiontype": "httpfetch",
            "target": "https://example.com",
            "riskscore": 4,
            "executionstate": "executed",
            "responsestatus": "completed",
            "policyverdict": "allow",
            "reviewitemid": None,
        },
        {
            "executionid": "exec-102",
            "timestamp": _utc_iso(2026, 4, 18, 9, 10),
            "clientid": "client-alpha",
            "sessionid": "sess-alpha-001",
            "actiontype": "toolcall",
            "target": "shell",
            "riskscore": 74,
            "executionstate": "dryrun",
            "responsestatus": "queuedforreview",
            "policyverdict": "review",
            "reviewitemid": "review-102",
        },
        {
            "executionid": "exec-103",
            "timestamp": _utc_iso(2026, 4, 18, 10, 5),
            "clientid": "client-beta",
            "sessionid": "sess-beta-001",
            "actiontype": "httpfetch",
            "target": "https://example.com/docs",
            "riskscore": 52,
            "executionstate": "dryrun",
            "responsestatus": "queuedforreview",
            "policyverdict": "review",
            "reviewitemid": "review-103",
        },
        {
            "executionid": "exec-104",
            "timestamp": _utc_iso(2026, 4, 18, 11, 20),
            "clientid": "client-beta",
            "sessionid": "sess-beta-002",
            "actiontype": "toolcall",
            "target": "shell",
            "riskscore": 96,
            "executionstate": "denied",
            "responsestatus": "denied",
            "policyverdict": "block",
            "reviewitemid": "review-104",
        },
        {
            "executionid": "exec-105",
            "timestamp": _utc_iso(2026, 4, 18, 12, 0),
            "clientid": "client-gamma",
            "sessionid": "sess-gamma-001",
            "actiontype": "httpfetch",
            "target": "https://example.com/public-report",
            "riskscore": 7,
            "executionstate": "executed",
            "responsestatus": "completed",
            "policyverdict": "allow",
            "reviewitemid": None,
        },
        {
            "executionid": "exec-106",
            "timestamp": _utc_iso(2026, 4, 18, 12, 45),
            "clientid": "client-alpha",
            "sessionid": "sess-alpha-002",
            "actiontype": "httpfetch",
            "target": "https://example.com/override",
            "riskscore": 18,
            "executionstate": "executed",
            "responsestatus": "completed",
            "policyverdict": "allow",
            "reviewitemid": None,
        },
    ]


def _to_execution_item(record: dict[str, Any]) -> ActivityExecutionItem:
    return ActivityExecutionItem(
        executionid=_safe_str(record.get("executionid"), "unknown-execution"),
        timestamp=_safe_str(record.get("timestamp"), datetime.now(UTC).isoformat()),
        actiontype=_safe_str(record.get("actiontype"), "unknown"),
        target=_safe_str(record.get("target"), "unknown"),
        riskscore=_safe_int(record.get("riskscore"), 0),
        executionstate=_safe_str(record.get("executionstate"), "unknown"),
        responsestatus=_safe_str(record.get("responsestatus"), "completed"),
        policyverdict=_safe_str(record.get("policyverdict"), "allow"),
        reviewitemid=record.get("reviewitemid"),
    )


def _recent_items(records: list[dict[str, Any]], limit: int = 5) -> list[ActivityExecutionItem]:
    sorted_records = sorted(
        records,
        key=lambda item: _safe_str(item.get("timestamp"), ""),
        reverse=True,
    )
    return [_to_execution_item(record) for record in sorted_records[:limit]]


def _verdict_counts(records: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(_safe_str(record.get("policyverdict"), "unknown") for record in records)
    return dict(sorted(counts.items()))


def _average_risk(records: list[dict[str, Any]]) -> float:
    if not records:
        return 0.0
    total = sum(_safe_int(record.get("riskscore"), 0) for record in records)
    return round(total / len(records), 2)


def _highest_risk(records: list[dict[str, Any]]) -> int:
    if not records:
        return 0
    return max(_safe_int(record.get("riskscore"), 0) for record in records)


def _pending_reviews(records: list[dict[str, Any]]) -> int:
    return sum(1 for record in records if record.get("reviewitemid"))


def _build_client_summaries(records: list[dict[str, Any]]) -> list[ClientActivitySummary]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        clientid = _safe_str(record.get("clientid"), "unknown-client")
        grouped[clientid].append(record)

    summaries: list[ClientActivitySummary] = []
    for clientid in sorted(grouped.keys()):
        group = grouped[clientid]
        summaries.append(
            ClientActivitySummary(
                clientid=clientid,
                totalexecutions=len(group),
                average_riskscore=_average_risk(group),
                highest_riskscore=_highest_risk(group),
                pendingreviews=_pending_reviews(group),
                verdictcounts=_verdict_counts(group),
                recentexecutions=_recent_items(group),
            )
        )
    return summaries


def _build_session_summaries(records: list[dict[str, Any]]) -> list[SessionActivitySummary]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        sessionid = _safe_str(record.get("sessionid"), "unknown-session")
        grouped[sessionid].append(record)

    summaries: list[SessionActivitySummary] = []
    for sessionid in sorted(grouped.keys()):
        group = grouped[sessionid]
        clientid = _safe_str(group[0].get("clientid"), "unknown-client") if group else None
        summaries.append(
            SessionActivitySummary(
                sessionid=sessionid,
                clientid=clientid,
                totalexecutions=len(group),
                average_riskscore=_average_risk(group),
                highest_riskscore=_highest_risk(group),
                pendingreviews=_pending_reviews(group),
                verdictcounts=_verdict_counts(group),
                recentexecutions=_recent_items(group),
            )
        )
    return summaries


@router.get("/client-session", response_model=ClientSessionActivityResponse)
def get_client_session_activity() -> ClientSessionActivityResponse:
    records = _sample_activity_records()
    return ClientSessionActivityResponse(
        generatedat=datetime.now(UTC).isoformat(),
        clients=_build_client_summaries(records),
        sessions=_build_session_summaries(records),
    )