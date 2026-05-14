from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/insights",
    tags=["policy-insights"],
)


class PolicyVerdictCount(BaseModel):
    policyverdict: str
    count: int


class ExecutionStateCount(BaseModel):
    executionstate: str
    count: int


class RiskTrendPoint(BaseModel):
    timestamp: str
    average_riskscore: float
    totalexecutions: int


class ReasonLabelCount(BaseModel):
    source: str
    label: str
    count: int


class PolicyInsightsResponse(BaseModel):
    generatedat: str
    totalexecutions: int
    totalreviewitems: int
    verdictcounts: list[PolicyVerdictCount] = Field(default_factory=list)
    executionstatecounts: list[ExecutionStateCount] = Field(default_factory=list)
    risktrend: list[RiskTrendPoint] = Field(default_factory=list)
    commonreasons: list[ReasonLabelCount] = Field(default_factory=list)


def _utc_iso(year: int, month: int, day: int, hour: int = 0) -> str:
    return datetime(year, month, day, hour, 0, 0, tzinfo=UTC).isoformat()


def _sample_execution_records() -> list[dict]:
    return [
        {
            "executionid": "exec-001",
            "timestamp": _utc_iso(2026, 4, 18, 8),
            "riskscore": 3,
            "executionstate": "executed",
            "policyverdict": "allow",
            "reviewitemid": None,
            "reasons": [{"source": "policy", "label": "low-risk-httpfetch"}],
        },
        {
            "executionid": "exec-002",
            "timestamp": _utc_iso(2026, 4, 18, 9),
            "riskscore": 55,
            "executionstate": "dryrun",
            "policyverdict": "review",
            "reviewitemid": "review-002",
            "reasons": [{"source": "policy", "label": "mid-risk-fetch"}],
        },
        {
            "executionid": "exec-003",
            "timestamp": _utc_iso(2026, 4, 18, 10),
            "riskscore": 95,
            "executionstate": "denied",
            "policyverdict": "block",
            "reviewitemid": "review-003",
            "reasons": [
                {"source": "policy", "label": "high-risk-shell"},
                {"source": "boundary", "label": "execution-halted"},
            ],
        },
        {
            "executionid": "exec-004",
            "timestamp": _utc_iso(2026, 4, 18, 11),
            "riskscore": 48,
            "executionstate": "executed",
            "policyverdict": "allow",
            "reviewitemid": None,
            "reasons": [{"source": "policy", "label": "review-cleared"}],
        },
        {
            "executionid": "exec-005",
            "timestamp": _utc_iso(2026, 4, 18, 12),
            "riskscore": 74,
            "executionstate": "dryrun",
            "policyverdict": "review",
            "reviewitemid": "review-005",
            "reasons": [{"source": "policy", "label": "sensitive-tooling"}],
        },
        {
            "executionid": "exec-006",
            "timestamp": _utc_iso(2026, 4, 18, 13),
            "riskscore": 88,
            "executionstate": "denied",
            "policyverdict": "quarantine",
            "reviewitemid": "review-006",
            "reasons": [{"source": "policy", "label": "exfiltration-pattern"}],
        },
    ]


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_str(value: object, default: str) -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _build_verdict_counts(records: list[dict]) -> list[PolicyVerdictCount]:
    counts = Counter(_safe_str(record.get("policyverdict"), "unknown") for record in records)
    return [PolicyVerdictCount(policyverdict=verdict, count=count) for verdict, count in sorted(counts.items())]


def _build_executionstate_counts(records: list[dict]) -> list[ExecutionStateCount]:
    counts = Counter(_safe_str(record.get("executionstate"), "unknown") for record in records)
    return [ExecutionStateCount(executionstate=state, count=count) for state, count in sorted(counts.items())]


def _build_risk_trend(records: list[dict]) -> list[RiskTrendPoint]:
    buckets: dict[str, list[int]] = {}

    for record in records:
        timestamp = _safe_str(record.get("timestamp"), datetime.now(UTC).isoformat())
        bucket_key = timestamp[:13] + ":00:00+00:00"
        buckets.setdefault(bucket_key, []).append(_safe_int(record.get("riskscore"), 0))

    points: list[RiskTrendPoint] = []
    for bucket_key in sorted(buckets.keys()):
        scores = buckets[bucket_key]
        average = sum(scores) / len(scores) if scores else 0.0
        points.append(
            RiskTrendPoint(
                timestamp=bucket_key,
                average_riskscore=round(average, 2),
                totalexecutions=len(scores),
            ),
        )
    return points


def _build_common_reasons(records: list[dict]) -> list[ReasonLabelCount]:
    counts: Counter[tuple[str, str]] = Counter()

    for record in records:
        reasons = record.get("reasons") or []
        if not isinstance(reasons, list):
            continue

        for reason in reasons:
            if not isinstance(reason, dict):
                continue
            source = _safe_str(reason.get("source"), "runtime")
            label = _safe_str(reason.get("label"), "unspecified-reason")
            counts[(source, label)] += 1

    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0][0], item[0][1]))
    return [ReasonLabelCount(source=source, label=label, count=count) for (source, label), count in ordered]


@router.get("/policy", response_model=PolicyInsightsResponse)
def get_policy_insights() -> PolicyInsightsResponse:
    records = _sample_execution_records()
    totalreviewitems = sum(1 for record in records if record.get("reviewitemid"))

    return PolicyInsightsResponse(
        generatedat=datetime.now(UTC).isoformat(),
        totalexecutions=len(records),
        totalreviewitems=totalreviewitems,
        verdictcounts=_build_verdict_counts(records),
        executionstatecounts=_build_executionstate_counts(records),
        risktrend=_build_risk_trend(records),
        commonreasons=_build_common_reasons(records),
    )
