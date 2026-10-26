from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

router = APIRouter(tags=["request-stream"])


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _tone_for_risk(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _tone_for_status(status: str) -> str:
    mapping = {
        "blocked": "critical",
        "quarantined": "high",
        "review": "warning",
        "allowed": "success",
        "completed": "success",
        "active": "info",
        "degraded": "warning",
    }
    return mapping.get(status.lower(), "neutral")


class RequestStreamKpi(BaseModel):
    label: str
    value: str
    tone: str = "neutral"


class RequestStreamFilterOption(BaseModel):
    key: str
    label: str
    value: str
    count: int = Field(default=0)


class RequestStreamItem(BaseModel):
    request_id: str
    timestamp: str
    client_id: str
    session_id: str
    route: str
    method: str
    source: str
    policy_verdict: str
    execution_state: str
    review_state: str
    response_status: str
    risk_score: int
    risk_tone: str
    status_tone: str
    target: str
    summary: str
    trace_id: str
    units_consumed: int
    latency_ms: int
    flagged: bool
    metadata: dict[str, Any] = Field(default_factory=dict)


class RequestStreamResponse(BaseModel):
    generated_at: str
    environment: str
    total: int
    filtered_total: int
    active_filters: dict[str, Any]
    kpis: list[RequestStreamKpi]
    filter_options: dict[str, list[RequestStreamFilterOption]]
    items: list[RequestStreamItem]
    metadata: dict[str, Any] = Field(default_factory=dict)


def _seed_items() -> list[RequestStreamItem]:
    base = datetime.now(UTC).replace(microsecond=0)

    raw_items = [
        {
            "request_id": "req_ironclaw_0001",
            "minutes_ago": 2,
            "client_id": "guard-console",
            "session_id": "sess_ops_001",
            "route": "/guard/execute",
            "method": "POST",
            "source": "runtime",
            "policy_verdict": "allow",
            "execution_state": "completed",
            "review_state": "none",
            "response_status": "200 OK",
            "risk_score": 14,
            "target": "sandbox://workspace/report.md",
            "summary": "Low-risk guarded execute completed successfully.",
            "trace_id": "trace_ops_0001",
            "units_consumed": 9,
            "latency_ms": 184,
            "flagged": False,
        },
        {
            "request_id": "req_ironclaw_0002",
            "minutes_ago": 5,
            "client_id": "guard-console",
            "session_id": "sess_ops_001",
            "route": "/guard/action",
            "method": "POST",
            "source": "policy",
            "policy_verdict": "warn",
            "execution_state": "review",
            "review_state": "pending",
            "response_status": "202 Accepted",
            "risk_score": 52,
            "target": "shell://powershell.exe",
            "summary": "Shell command routed to review because policy matched elevated execution behavior.",
            "trace_id": "trace_ops_0002",
            "units_consumed": 4,
            "latency_ms": 233,
            "flagged": True,
        },
        {
            "request_id": "req_ironclaw_0003",
            "minutes_ago": 9,
            "client_id": "api-key-prod-a",
            "session_id": "sess_prod_184",
            "route": "/scan",
            "method": "POST",
            "source": "scan",
            "policy_verdict": "quarantine",
            "execution_state": "blocked",
            "review_state": "queued",
            "response_status": "403 Forbidden",
            "risk_score": 81,
            "target": "prompt://upload/intake.txt",
            "summary": "Prompt payload quarantined after multi-pattern injection indicators were detected.",
            "trace_id": "trace_prod_1841",
            "units_consumed": 2,
            "latency_ms": 141,
            "flagged": True,
        },
        {
            "request_id": "req_ironclaw_0004",
            "minutes_ago": 14,
            "client_id": "api-key-stage-b",
            "session_id": "sess_stage_044",
            "route": "/guard/action-decision",
            "method": "POST",
            "source": "policy+scan",
            "policy_verdict": "block",
            "execution_state": "blocked",
            "review_state": "none",
            "response_status": "403 Forbidden",
            "risk_score": 93,
            "target": "network://pastebin.com/raw/xyz",
            "summary": "Outbound fetch blocked due to critical exfiltration and hostile-context indicators.",
            "trace_id": "trace_stage_0442",
            "units_consumed": 1,
            "latency_ms": 119,
            "flagged": True,
        },
        {
            "request_id": "req_ironclaw_0005",
            "minutes_ago": 20,
            "client_id": "guard-console",
            "session_id": "sess_ops_002",
            "route": "/request-context",
            "method": "GET",
            "source": "ui",
            "policy_verdict": "allow",
            "execution_state": "completed",
            "review_state": "none",
            "response_status": "200 OK",
            "risk_score": 8,
            "target": "context://session/sess_ops_002",
            "summary": "Request context fetched for operator workflow inspection.",
            "trace_id": "trace_ops_0003",
            "units_consumed": 0,
            "latency_ms": 72,
            "flagged": False,
        },
        {
            "request_id": "req_ironclaw_0006",
            "minutes_ago": 28,
            "client_id": "api-key-prod-a",
            "session_id": "sess_prod_185",
            "route": "/guard/execute",
            "method": "POST",
            "source": "runtime",
            "policy_verdict": "allow",
            "execution_state": "active",
            "review_state": "none",
            "response_status": "200 OK",
            "risk_score": 24,
            "target": "file://workspace/src/main.py",
            "summary": "Active guarded execution in progress for file edit task.",
            "trace_id": "trace_prod_1850",
            "units_consumed": 7,
            "latency_ms": 410,
            "flagged": False,
        },
        {
            "request_id": "req_ironclaw_0007",
            "minutes_ago": 34,
            "client_id": "api-key-dev-c",
            "session_id": "sess_dev_901",
            "route": "/guard/action-policy",
            "method": "POST",
            "source": "policy",
            "policy_verdict": "warn",
            "execution_state": "review",
            "review_state": "approved",
            "response_status": "200 OK",
            "risk_score": 47,
            "target": "git://repo/feature-branch",
            "summary": "Git operation required review and was later approved by operator.",
            "trace_id": "trace_dev_9012",
            "units_consumed": 3,
            "latency_ms": 201,
            "flagged": True,
        },
        {
            "request_id": "req_ironclaw_0008",
            "minutes_ago": 41,
            "client_id": "api-key-dev-c",
            "session_id": "sess_dev_902",
            "route": "/scan/batch",
            "method": "POST",
            "source": "scan",
            "policy_verdict": "allow",
            "execution_state": "completed",
            "review_state": "none",
            "response_status": "200 OK",
            "risk_score": 19,
            "target": "batch://artifacts/7",
            "summary": "Batch scan completed with low-risk findings only.",
            "trace_id": "trace_dev_9021",
            "units_consumed": 11,
            "latency_ms": 522,
            "flagged": False,
        },
    ]

    items: list[RequestStreamItem] = []
    for entry in raw_items:
        timestamp = (base - timedelta(minutes=entry["minutes_ago"])).isoformat().replace("+00:00", "Z")
        items.append(
            RequestStreamItem(
                request_id=entry["request_id"],
                timestamp=timestamp,
                client_id=entry["client_id"],
                session_id=entry["session_id"],
                route=entry["route"],
                method=entry["method"],
                source=entry["source"],
                policy_verdict=entry["policy_verdict"],
                execution_state=entry["execution_state"],
                review_state=entry["review_state"],
                response_status=entry["response_status"],
                risk_score=entry["risk_score"],
                risk_tone=_tone_for_risk(entry["risk_score"]),
                status_tone=_tone_for_status(entry["execution_state"]),
                target=entry["target"],
                summary=entry["summary"],
                trace_id=entry["trace_id"],
                units_consumed=entry["units_consumed"],
                latency_ms=entry["latency_ms"],
                flagged=entry["flagged"],
                metadata={
                    "operator_visible": True,
                    "requires_followup": entry["policy_verdict"] in {"warn", "quarantine", "block"},
                },
            ),
        )
    return items


def _build_filter_options(
    items: list[RequestStreamItem],
) -> dict[str, list[RequestStreamFilterOption]]:
    def build(values: list[str], key: str, labels: dict[str, str] | None = None) -> list[RequestStreamFilterOption]:
        counts = Counter(values)
        options = []
        for value in sorted(counts):
            options.append(
                RequestStreamFilterOption(
                    key=key,
                    label=(labels or {}).get(value, value.replace("-", " ").title()),
                    value=value,
                    count=counts[value],
                ),
            )
        return options

    return {
        "policy_verdict": build([item.policy_verdict for item in items], "policy_verdict"),
        "execution_state": build([item.execution_state for item in items], "execution_state"),
        "source": build([item.source for item in items], "source"),
        "review_state": build([item.review_state for item in items], "review_state"),
        "client_id": build([item.client_id for item in items], "client_id"),
    }


@router.get("/ui/guard/request-stream", response_model=RequestStreamResponse)
def get_request_stream(
    policy_verdict: str | None = Query(default=None),
    execution_state: str | None = Query(default=None),
    source: str | None = Query(default=None),
    review_state: str | None = Query(default=None),
    client_id: str | None = Query(default=None),
    flagged_only: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=200),
) -> RequestStreamResponse:
    items = _seed_items()

    filtered = items
    if policy_verdict:
        filtered = [item for item in filtered if item.policy_verdict == policy_verdict]
    if execution_state:
        filtered = [item for item in filtered if item.execution_state == execution_state]
    if source:
        filtered = [item for item in filtered if item.source == source]
    if review_state:
        filtered = [item for item in filtered if item.review_state == review_state]
    if client_id:
        filtered = [item for item in filtered if item.client_id == client_id]
    if flagged_only:
        filtered = [item for item in filtered if item.flagged]

    filtered = sorted(filtered, key=lambda item: item.timestamp, reverse=True)[:limit]

    blocked_count = sum(1 for item in filtered if item.policy_verdict == "block")
    review_count = sum(1 for item in filtered if item.review_state in {"pending", "queued"})
    avg_latency = round(sum(item.latency_ms for item in filtered) / len(filtered)) if filtered else 0
    total_units = sum(item.units_consumed for item in filtered)

    return RequestStreamResponse(
        generated_at=_now_iso(),
        environment="local",
        total=len(items),
        filtered_total=len(filtered),
        active_filters={
            "policy_verdict": policy_verdict,
            "execution_state": execution_state,
            "source": source,
            "review_state": review_state,
            "client_id": client_id,
            "flagged_only": flagged_only,
            "limit": limit,
        },
        kpis=[
            RequestStreamKpi(label="Visible Requests", value=str(len(filtered)), tone="info"),
            RequestStreamKpi(
                label="Blocked",
                value=str(blocked_count),
                tone="critical" if blocked_count else "neutral",
            ),
            RequestStreamKpi(
                label="Pending Review",
                value=str(review_count),
                tone="warning" if review_count else "neutral",
            ),
            RequestStreamKpi(label="Avg Latency", value=f"{avg_latency} ms", tone="info"),
            RequestStreamKpi(label="Units Consumed", value=str(total_units), tone="neutral"),
        ],
        filter_options=_build_filter_options(items),
        items=filtered,
        metadata={
            "page_id": "guard-request-stream",
            "title": "Request Stream",
            "section": "Guard",
            "supports_live_polling": True,
        },
    )
