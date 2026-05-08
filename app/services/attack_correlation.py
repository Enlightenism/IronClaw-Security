from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

CorrelationVerdict = Literal["allow", "warn", "quarantine", "block"]

_VERDICT_ESCALATION_WEIGHT: dict[str, int] = {
    "block": 30,
    "quarantine": 20,
    "warn": 10,
    "allow": 0,
}

_RISK_SCORE_WEIGHT: list[tuple[int, int]] = [
    (90, 25),
    (70, 15),
    (40, 5),
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize(value: str | None) -> str | None:
    text = (value or "").strip()
    return text or None


def _verdict_from_score(score: int) -> CorrelationVerdict:
    if score >= 85:
        return "block"
    if score >= 60:
        return "quarantine"
    if score >= 30:
        return "warn"
    return "allow"


def _risk_weight(risk_score: int) -> int:
    for threshold, weight in _RISK_SCORE_WEIGHT:
        if risk_score >= threshold:
            return weight
    return 0


@dataclass(slots=True)
class CorrelationEvent:
    event_id: str
    timestamp: str
    action_type: str
    target: str
    verdict: CorrelationVerdict
    risk_score: int
    client_id: str | None = None
    session_id: str | None = None
    trace_id: str | None = None
    request_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "action_type": self.action_type,
            "target": self.target,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "client_id": self.client_id,
            "session_id": self.session_id,
            "trace_id": self.trace_id,
            "request_id": self.request_id,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class CorrelationSummary:
    checked_at: str
    verdict: CorrelationVerdict
    escalation_score: int
    total_events: int
    high_risk_events: int
    repeated_targets: list[str] = field(default_factory=list)
    repeated_action_types: list[str] = field(default_factory=list)
    repeated_sessions: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    events: list[CorrelationEvent] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "checked_at": self.checked_at,
            "verdict": self.verdict,
            "escalation_score": self.escalation_score,
            "total_events": self.total_events,
            "high_risk_events": self.high_risk_events,
            "repeated_targets": list(self.repeated_targets),
            "repeated_action_types": list(self.repeated_action_types),
            "repeated_sessions": list(self.repeated_sessions),
            "reasons": list(self.reasons),
            "events": [event.to_dict() for event in self.events],
        }


def build_correlation_event(
    *,
    event_id: str,
    action_type: str,
    target: str,
    verdict: CorrelationVerdict,
    risk_score: int,
    client_id: str | None = None,
    session_id: str | None = None,
    trace_id: str | None = None,
    request_id: str | None = None,
    timestamp: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> CorrelationEvent:
    normalized_event_id = _normalize(event_id)
    normalized_action_type = _normalize(action_type)
    normalized_target = _normalize(target)

    if not normalized_event_id:
        raise ValueError("event_id is required")
    if not normalized_action_type:
        raise ValueError("action_type is required")
    if not normalized_target:
        raise ValueError("target is required")

    bounded_risk_score = max(0, min(int(risk_score), 100))

    return CorrelationEvent(
        event_id=normalized_event_id,
        timestamp=timestamp or _utc_now(),
        action_type=normalized_action_type,
        target=normalized_target,
        verdict=verdict,
        risk_score=bounded_risk_score,
        client_id=_normalize(client_id),
        session_id=_normalize(session_id),
        trace_id=_normalize(trace_id),
        request_id=_normalize(request_id),
        metadata=dict(metadata or {}),
    )


def correlate_attack_events(
    events: list[CorrelationEvent],
) -> CorrelationSummary:
    checked_at = _utc_now()
    total_events = len(events)

    if not events:
        return CorrelationSummary(
            checked_at=checked_at,
            verdict="allow",
            escalation_score=0,
            total_events=0,
            high_risk_events=0,
            reasons=["No events provided for correlation."],
            events=[],
        )

    high_risk_events = sum(1 for event in events if event.risk_score >= 70)

    target_counts: Counter[str] = Counter(event.target for event in events)
    action_counts: Counter[str] = Counter(event.action_type for event in events)
    session_counts: Counter[str] = Counter(
        event.session_id for event in events if event.session_id
    )

    reasons: list[str] = []
    escalation_score = 0

    for event in events:
        escalation_score += _VERDICT_ESCALATION_WEIGHT.get(event.verdict, 0)
        escalation_score += _risk_weight(event.risk_score)

    repeated_targets = sorted(t for t, c in target_counts.items() if c > 1)
    repeated_action_types = sorted(a for a, c in action_counts.items() if c > 1)
    repeated_sessions = sorted(s for s, c in session_counts.items() if c > 1)

    if high_risk_events:
        reasons.append(f"Detected {high_risk_events} high-risk events in the sequence.")
    if repeated_targets:
        reasons.append("Detected repeated targeting across protected resources.")
        escalation_score += 15
    if repeated_action_types:
        reasons.append("Detected repeated action-type patterns across the event stream.")
        escalation_score += 10
    if repeated_sessions:
        reasons.append(
            f"Detected {len(repeated_sessions)} session(s) with repeated correlated events."
        )
        escalation_score += 12
    if total_events >= 5:
        reasons.append("Detected sustained multi-event activity requiring escalation.")
        escalation_score += 10

    escalation_score = min(escalation_score, 100)
    verdict = _verdict_from_score(escalation_score)

    if not reasons:
        reasons.append("No correlated escalation patterns were detected.")

    return CorrelationSummary(
        checked_at=checked_at,
        verdict=verdict,
        escalation_score=escalation_score,
        total_events=total_events,
        high_risk_events=high_risk_events,
        repeated_targets=repeated_targets,
        repeated_action_types=repeated_action_types,
        repeated_sessions=repeated_sessions,
        reasons=reasons,
        events=list(events),
    )


def summarize_correlation_summary(summary: CorrelationSummary) -> dict[str, Any]:
    return {
        "checked_at": summary.checked_at,
        "verdict": summary.verdict,
        "escalation_score": summary.escalation_score,
        "total_events": summary.total_events,
        "high_risk_events": summary.high_risk_events,
        "repeated_target_count": len(summary.repeated_targets),
        "repeated_action_type_count": len(summary.repeated_action_types),
        "repeated_session_count": len(summary.repeated_sessions),
        "reason_count": len(summary.reasons),
    }