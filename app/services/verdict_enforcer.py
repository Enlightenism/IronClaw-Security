from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal, TypedDict

from app.services.groq_security_brain import GroqSecurityDecision

VerdictType = Literal["allow", "warn", "quarantine", "block"]


class EnforcedVerdict(TypedDict):
    # Core identity
    action_type: str
    target: str
    content: str
    # Final ruling
    verdict: VerdictType
    summary: str
    risk_score: int
    should_halt: bool
    should_warn: bool
    # Trace / audit
    scan_id: str | None
    matched_patterns: list[str]
    categories: list[str]
    decision_source: str
    policy_mode: str | None
    client_id: str | None
    session_id: str | None
    agent_id: str | None
    reasons: list[dict[str, object]]
    drift_report: dict[str, Any] | None
    # Groq telemetry
    groq_verdict: str | None
    groq_risk_score: int | None
    groq_confidence: float | None
    groq_latency_ms: float | None
    groq_model_name: str | None
    groq_signals: list[str]
    groq_summary: str | None
    groq_decided_at: str | None
    # Enforcer stamp
    enforced_at: str


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _verdict_rank(verdict: str) -> int:
    return {"allow": 1, "warn": 2, "quarantine": 3, "block": 4}.get(verdict, 0)


def _max_verdict(a: str, b: str) -> VerdictType:
    return a if _verdict_rank(a) >= _verdict_rank(b) else b  # type: ignore[return-value]


def _extract_groq_telemetry(
    decision: GroqSecurityDecision | None,
) -> dict[str, Any]:
    if decision is None:
        return {
            "groq_verdict": None,
            "groq_risk_score": None,
            "groq_confidence": None,
            "groq_latency_ms": None,
            "groq_model_name": None,
            "groq_signals": [],
            "groq_summary": None,
            "groq_decided_at": None,
        }
    return {
        "groq_verdict": decision.verdict,
        "groq_risk_score": decision.risk_score,
        "groq_confidence": getattr(decision, "confidence", None),
        "groq_latency_ms": getattr(decision, "latency_ms", None),
        "groq_model_name": decision.model_name,
        "groq_signals": list(decision.signals),
        "groq_summary": decision.summary,
        "groq_decided_at": decision.decided_at,
    }


def enforce_verdict(
    *,
    action_type: str,
    target: str,
    content: str = "",
    verdict: VerdictType,
    summary: str,
    risk_score: int,
    should_halt: bool,
    should_warn: bool,
    scan_id: str | None = None,
    matched_patterns: list[str] | None = None,
    categories: list[str] | None = None,
    decision_source: str = "scan",
    policy_mode: str | None = None,
    client_id: str | None = None,
    session_id: str | None = None,
    agent_id: str | None = None,
    reasons: list[dict[str, object]] | None = None,
    drift_report: dict[str, Any] | None = None,
    groq_decision: GroqSecurityDecision | None = None,
) -> EnforcedVerdict:
    groq_telemetry = _extract_groq_telemetry(groq_decision)

    # If Groq produced a harder verdict, escalate; never downgrade.
    final_verdict: VerdictType = verdict
    if groq_decision is not None:
        final_verdict = _max_verdict(verdict, groq_decision.verdict)
        if final_verdict != verdict:
            groq_reason: dict[str, object] = {
                "source": "ai",
                "label": "Groq security brain escalation",
                "details": groq_decision.summary,
                "score": min(groq_decision.risk_score / 100.0, 1.0),
            }
            reasons = list(reasons or []) + [groq_reason]

    return EnforcedVerdict(
        action_type=action_type,
        target=target,
        content=content,
        verdict=final_verdict,
        summary=summary,
        risk_score=risk_score,
        should_halt=final_verdict in ("block", "quarantine"),
        should_warn=final_verdict in ("warn", "quarantine"),
        scan_id=scan_id,
        matched_patterns=list(matched_patterns or []),
        categories=list(categories or []),
        decision_source=decision_source,
        policy_mode=policy_mode,
        client_id=client_id,
        session_id=session_id,
        agent_id=agent_id,
        reasons=list(reasons or []),
        drift_report=drift_report,
        groq_verdict=groq_telemetry["groq_verdict"],
        groq_risk_score=groq_telemetry["groq_risk_score"],
        groq_confidence=groq_telemetry["groq_confidence"],
        groq_latency_ms=groq_telemetry["groq_latency_ms"],
        groq_model_name=groq_telemetry["groq_model_name"],
        groq_signals=groq_telemetry["groq_signals"],
        groq_summary=groq_telemetry["groq_summary"],
        groq_decided_at=groq_telemetry["groq_decided_at"],
        enforced_at=_utc_now(),
    )
