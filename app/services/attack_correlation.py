from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

CorrelationVerdict = Literal["allow", "warn", "quarantine", "block"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize(value: str | None) -> str | None:
    text = (value or "").strip()
    return text or None


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
        metadata=dict(metadata or {}),
    )


def correlate_attack_events(
    events: list[CorrelationEvent],
) -> CorrelationSummary:
    checked_at = _utc_now()
    total_events = len(events)
    high_risk_events = sum(1 for event in events if event.risk_score >= 70)

    target_counts: dict[str, int] = {}
    action_counts: dict[str, int] = {}
    reasons: list[str] = []
    escalation_score = 0

    for event in events:
        target_counts[event.target] = target_counts.get(event.target, 0) + 1
        action_counts[event.action_type] = action_counts.get(event.action_type, 0) + 1

        if event.verdict == "block":
            escalation_score += 30
        elif event.verdict == "quarantine":
            escalation_score += 20
        elif event.verdict == "warn":
            escalation_score += 10

        if event.risk_score >= 90:
            escalation_score += 25
        elif event.risk_score >= 70:
            escalation_score += 15
        elif event.risk_score >= 40:
            escalation_score += 5

    repeated_targets = sorted(
        [target for target, count in target_counts.items() if count > 1]
    )
    repeated_action_types = sorted(
        [action_type for action_type, count in action_counts.items() if count > 1]
    )

    if high_risk_events:
        reasons.append(f"Detected {high_risk_events} high-risk events in the sequence.")
    if repeated_targets:
        reasons.append("Detected repeated targeting across protected resources.")
        escalation_score += 15
    if repeated_action_types:
        reasons.append("Detected repeated action-type patterns across the event stream.")
        escalation_score += 10
    if total_events >= 5:
        reasons.append("Detected sustained multi-event activity requiring escalation.")
        escalation_score += 10

    escalation_score = min(escalation_score, 100)

    if escalation_score >= 85:
        verdict: CorrelationVerdict = "block"
    elif escalation_score >= 60:
        verdict = "quarantine"
    elif escalation_score >= 30:
        verdict = "warn"
    else:
        verdict = "allow"

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
        "reason_count": len(summary.reasons),
    }