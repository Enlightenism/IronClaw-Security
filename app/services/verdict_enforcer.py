from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal, TypedDict

from app.services.guard_security_brain import GuardSecurityDecision

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
    # Guard telemetry
    guard_verdict: str | None
    guard_risk_score: int | None
    guard_confidence: float | None
    guard_latency_ms: float | None
    guard_model_name: str | None
    guard_signals: list[str]
    guard_summary: str | None
    guard_decided_at: str | None
    # Enforcer stamp
    enforced_at: str


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _verdict_rank(verdict: str) -> int:
    return {"allow": 1, "warn": 2, "quarantine": 3, "block": 4}.get(verdict, 0)


def _max_verdict(a: str, b: str) -> VerdictType:
    return a if _verdict_rank(a) >= _verdict_rank(b) else b  # type: ignore[return-value]


def _extract_guard_telemetry(
    decision: GuardSecurityDecision | None,
) -> dict[str, Any]:
    if decision is None:
        return {
            "guard_verdict": None,
            "guard_risk_score": None,
            "guard_confidence": None,
            "guard_latency_ms": None,
            "guard_model_name": None,
            "guard_signals": [],
            "guard_summary": None,
            "guard_decided_at": None,
        }
    return {
        "guard_verdict": decision.verdict,
        "guard_risk_score": decision.risk_score,
        "guard_confidence": getattr(decision, "confidence", None),
        "guard_latency_ms": getattr(decision, "latency_ms", None),
        "guard_model_name": decision.model_name,
        "guard_signals": list(decision.signals),
        "guard_summary": decision.summary,
        "guard_decided_at": decision.decided_at,
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
    guard_decision: GuardSecurityDecision | None = None,
) -> EnforcedVerdict:
    guard_telemetry = _extract_guard_telemetry(guard_decision)

    # If the local guard produced a harder verdict, escalate; never downgrade.
    final_verdict: VerdictType = verdict
    if guard_decision is not None:
        final_verdict = _max_verdict(verdict, guard_decision.verdict)
        if final_verdict != verdict:
            guard_reason: dict[str, object] = {
                "source": "ai",
                "label": "Guard security brain escalation",
                "details": guard_decision.summary,
                "score": min(guard_decision.risk_score / 100.0, 1.0),
            }
            reasons = list(reasons or []) + [guard_reason]

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
        guard_verdict=guard_telemetry["guard_verdict"],
        guard_risk_score=guard_telemetry["guard_risk_score"],
        guard_confidence=guard_telemetry["guard_confidence"],
        guard_latency_ms=guard_telemetry["guard_latency_ms"],
        guard_model_name=guard_telemetry["guard_model_name"],
        guard_signals=guard_telemetry["guard_signals"],
        guard_summary=guard_telemetry["guard_summary"],
        guard_decided_at=guard_telemetry["guard_decided_at"],
        enforced_at=_utc_now(),
    )
