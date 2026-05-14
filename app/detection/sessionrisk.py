from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

VERDICT_RANK = {
    "allow": 1,
    "monitor": 2,
    "review": 3,
    "block": 4,
}

SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(slots=True)
class SessionEvent:
    source: str
    verdict: str
    severity: str
    score: float
    timestamp: str
    detail: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class SessionRiskFactor:
    name: str
    weight: float
    evidence: str
    category: str


@dataclass(slots=True)
class SessionRiskResult:
    session_id: str
    verdict: str
    severity: str
    score: float
    confidence: float
    event_count: int
    factors: list[SessionRiskFactor]
    reasons: list[str]
    escalated: bool
    first_seen_at: str | None
    last_seen_at: str | None
    analyzed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def as_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "verdict": self.verdict,
            "severity": self.severity,
            "score": self.score,
            "confidence": self.confidence,
            "event_count": self.event_count,
            "factors": [
                {
                    "name": factor.name,
                    "weight": factor.weight,
                    "evidence": factor.evidence,
                    "category": factor.category,
                }
                for factor in self.factors
            ],
            "reasons": list(self.reasons),
            "escalated": self.escalated,
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
            "analyzed_at": self.analyzed_at,
        }


class SessionRiskAnalyzer:
    def analyze(
        self,
        *,
        session_id: str,
        events: list[SessionEvent | dict[str, Any]],
        active_review: bool = False,
        recent_window_minutes: int = 30,
    ) -> SessionRiskResult:
        normalized_events = [self._normalize_event(event) for event in events]
        normalized_events.sort(key=lambda item: item.timestamp)

        factors: list[SessionRiskFactor] = []
        if not normalized_events:
            return SessionRiskResult(
                session_id=session_id,
                verdict="allow",
                severity="low",
                score=0.0,
                confidence=0.42,
                event_count=0,
                factors=[],
                reasons=["No session events were available for risk aggregation."],
                escalated=False,
                first_seen_at=None,
                last_seen_at=None,
            )

        factors.extend(self._score_verdict_pressure(normalized_events))
        factors.extend(self._score_severity_pressure(normalized_events))
        factors.extend(self._score_repeat_hits(normalized_events))
        factors.extend(self._score_burst_activity(normalized_events, recent_window_minutes=recent_window_minutes))
        factors.extend(self._score_multi_source_activity(normalized_events))
        factors.extend(self._score_recentness(normalized_events, recent_window_minutes=recent_window_minutes))

        if active_review:
            factors.append(
                SessionRiskFactor(
                    name="active_review_queue",
                    weight=0.16,
                    evidence="Session is already attached to an active human or policy review workflow.",
                    category="workflow",
                ),
            )

        factors = self._dedupe_factors(factors)
        score = self._resolve_score(normalized_events, factors)
        verdict = self._resolve_verdict(normalized_events, score, active_review=active_review)
        severity = self._resolve_severity(normalized_events, score)
        confidence = self._resolve_confidence(normalized_events, factors, active_review=active_review)
        reasons = self._build_reasons(
            normalized_events,
            factors,
            verdict=verdict,
            severity=severity,
            active_review=active_review,
        )

        return SessionRiskResult(
            session_id=session_id,
            verdict=verdict,
            severity=severity,
            score=score,
            confidence=confidence,
            event_count=len(normalized_events),
            factors=factors,
            reasons=reasons,
            escalated=verdict in {"review", "block"},
            first_seen_at=normalized_events[0].timestamp,
            last_seen_at=normalized_events[-1].timestamp,
        )

    def _normalize_event(self, event: SessionEvent | dict[str, Any]) -> SessionEvent:
        if isinstance(event, SessionEvent):
            return event

        return SessionEvent(
            source=str(event.get("source", "unknown")),
            verdict=str(event.get("verdict", "allow")),
            severity=str(event.get("severity", "low")),
            score=float(event.get("score", 0.0)),
            timestamp=self._normalize_timestamp(event.get("timestamp")),
            detail=event.get("detail"),
            metadata=dict(event.get("metadata", {}) or {}),
        )

    def _normalize_timestamp(self, value: Any) -> str:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=UTC)
            return value.astimezone(UTC).isoformat()

        if isinstance(value, str) and value.strip():
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed.astimezone(UTC).isoformat()

        return datetime.now(UTC).isoformat()

    def _score_verdict_pressure(self, events: list[SessionEvent]) -> list[SessionRiskFactor]:
        factors: list[SessionRiskFactor] = []
        review_count = sum(1 for event in events if event.verdict == "review")
        block_count = sum(1 for event in events if event.verdict == "block")
        monitor_count = sum(1 for event in events if event.verdict == "monitor")

        if monitor_count:
            factors.append(
                SessionRiskFactor(
                    name="monitor_verdicts",
                    weight=min(0.20, monitor_count * 0.05),
                    evidence=f"Session accumulated {monitor_count} monitor verdict event(s).",
                    category="verdict",
                ),
            )
        if review_count:
            factors.append(
                SessionRiskFactor(
                    name="review_verdicts",
                    weight=min(0.36, review_count * 0.12),
                    evidence=f"Session accumulated {review_count} review verdict event(s).",
                    category="verdict",
                ),
            )
        if block_count:
            factors.append(
                SessionRiskFactor(
                    name="block_verdicts",
                    weight=min(0.55, block_count * 0.22),
                    evidence=f"Session accumulated {block_count} block verdict event(s).",
                    category="verdict",
                ),
            )

        return factors

    def _score_severity_pressure(self, events: list[SessionEvent]) -> list[SessionRiskFactor]:
        factors: list[SessionRiskFactor] = []
        high_events = [event for event in events if event.severity in {"high", "critical"}]
        critical_events = [event for event in events if event.severity == "critical"]

        if high_events:
            factors.append(
                SessionRiskFactor(
                    name="high_severity_presence",
                    weight=min(0.30, len(high_events) * 0.08),
                    evidence=f"{len(high_events)} event(s) were marked high or critical severity.",
                    category="severity",
                ),
            )
        if critical_events:
            factors.append(
                SessionRiskFactor(
                    name="critical_severity_presence",
                    weight=min(0.44, len(critical_events) * 0.16),
                    evidence=f"{len(critical_events)} event(s) were marked critical severity.",
                    category="severity",
                ),
            )

        return factors

    def _score_repeat_hits(self, events: list[SessionEvent]) -> list[SessionRiskFactor]:
        factors: list[SessionRiskFactor] = []
        source_counts: dict[str, int] = {}
        for event in events:
            source_counts[event.source] = source_counts.get(event.source, 0) + 1

        repeat_sources = {source: count for source, count in source_counts.items() if count >= 3}
        if repeat_sources:
            details = ", ".join(f"{source}:{count}" for source, count in sorted(repeat_sources.items()))
            factors.append(
                SessionRiskFactor(
                    name="repeat_detector_hits",
                    weight=min(0.24, sum(repeat_sources.values()) * 0.03),
                    evidence=f"Repeated activity across detectors: {details}.",
                    category="pattern",
                ),
            )

        return factors

    def _score_burst_activity(
        self,
        events: list[SessionEvent],
        *,
        recent_window_minutes: int,
    ) -> list[SessionRiskFactor]:
        factors: list[SessionRiskFactor] = []
        parsed_times = [datetime.fromisoformat(event.timestamp) for event in events]
        if not parsed_times:
            return factors

        window = timedelta(minutes=recent_window_minutes)
        max_hits = 0
        for index, anchor in enumerate(parsed_times):
            hits = 0
            for candidate in parsed_times[index:]:
                if candidate - anchor <= window:
                    hits += 1
            max_hits = max(max_hits, hits)

        if max_hits >= 4:
            factors.append(
                SessionRiskFactor(
                    name="burst_activity",
                    weight=min(0.22, max_hits * 0.04),
                    evidence=f"Session produced {max_hits} events within a {recent_window_minutes}-minute window.",
                    category="tempo",
                ),
            )

        return factors

    def _score_multi_source_activity(self, events: list[SessionEvent]) -> list[SessionRiskFactor]:
        factors: list[SessionRiskFactor] = []
        unique_sources = {event.source for event in events}
        if len(unique_sources) >= 3:
            factors.append(
                SessionRiskFactor(
                    name="multi_source_correlation",
                    weight=min(0.18, len(unique_sources) * 0.04),
                    evidence=f"Risk surfaced across {len(unique_sources)} independent sources.",
                    category="correlation",
                ),
            )
        return factors

    def _score_recentness(
        self,
        events: list[SessionEvent],
        *,
        recent_window_minutes: int,
    ) -> list[SessionRiskFactor]:
        factors: list[SessionRiskFactor] = []
        last_seen = datetime.fromisoformat(events[-1].timestamp)
        age = datetime.now(UTC) - last_seen

        if age <= timedelta(minutes=recent_window_minutes):
            factors.append(
                SessionRiskFactor(
                    name="recent_risk_activity",
                    weight=0.10,
                    evidence=f"Latest risky event was observed within the past {recent_window_minutes} minutes.",
                    category="tempo",
                ),
            )

        return factors

    def _resolve_score(self, events: list[SessionEvent], factors: list[SessionRiskFactor]) -> float:
        event_pressure = 0.0
        for event in events:
            verdict_weight = {
                "allow": 0.00,
                "monitor": 0.05,
                "review": 0.12,
                "block": 0.24,
            }.get(event.verdict, 0.0)
            severity_weight = {
                "low": 0.00,
                "medium": 0.04,
                "high": 0.08,
                "critical": 0.14,
            }.get(event.severity, 0.0)
            event_pressure += min(event.score, 1.0) * 0.20 + verdict_weight + severity_weight

        factor_pressure = sum(factor.weight for factor in factors)
        total = min(event_pressure + factor_pressure, 1.0)
        return round(total, 4)

    def _resolve_verdict(self, events: list[SessionEvent], score: float, *, active_review: bool) -> str:
        strongest_verdict = max((VERDICT_RANK.get(event.verdict, 1) for event in events), default=1)

        if strongest_verdict >= VERDICT_RANK["block"] and score >= 0.68:
            return "block"
        if active_review or score >= 0.46 or strongest_verdict >= VERDICT_RANK["review"]:
            return "review"
        if score >= 0.18 or strongest_verdict >= VERDICT_RANK["monitor"]:
            return "monitor"
        return "allow"

    def _resolve_severity(self, events: list[SessionEvent], score: float) -> str:
        strongest_severity = max((SEVERITY_RANK.get(event.severity, 1) for event in events), default=1)

        if strongest_severity >= SEVERITY_RANK["critical"] or score >= 0.82:
            return "critical"
        if strongest_severity >= SEVERITY_RANK["high"] or score >= 0.54:
            return "high"
        if strongest_severity >= SEVERITY_RANK["medium"] or score >= 0.24:
            return "medium"
        return "low"

    def _resolve_confidence(
        self,
        events: list[SessionEvent],
        factors: list[SessionRiskFactor],
        *,
        active_review: bool,
    ) -> float:
        base = 0.40
        base += min(len(events) * 0.04, 0.24)
        base += min(len(factors) * 0.05, 0.20)
        if active_review:
            base += 0.08
        return round(min(base, 0.99), 4)

    def _build_reasons(
        self,
        events: list[SessionEvent],
        factors: list[SessionRiskFactor],
        *,
        verdict: str,
        severity: str,
        active_review: bool,
    ) -> list[str]:
        reasons = [
            f"Session risk resolved to {verdict} with {severity} severity across {len(events)} event(s).",
        ]

        if active_review:
            reasons.append("Session is already connected to an active review workflow.")

        for factor in sorted(factors, key=lambda item: item.weight, reverse=True)[:6]:
            reasons.append(f"{factor.name}: {factor.evidence}")

        strongest_event = max(events, key=lambda event: (event.score, VERDICT_RANK.get(event.verdict, 1)))
        reasons.append(
            f"Strongest single event came from {strongest_event.source} with verdict {strongest_event.verdict} and score {strongest_event.score:.4f}.",
        )

        return reasons

    def _dedupe_factors(self, factors: list[SessionRiskFactor]) -> list[SessionRiskFactor]:
        deduped: list[SessionRiskFactor] = []
        seen: set[tuple[str, str, str]] = set()
        for factor in factors:
            key = (factor.name, factor.category, factor.evidence)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(factor)
        return deduped


def build_session_risk_analyzer() -> SessionRiskAnalyzer:
    return SessionRiskAnalyzer()


__all__ = [
    "SessionEvent",
    "SessionRiskAnalyzer",
    "SessionRiskFactor",
    "SessionRiskResult",
    "build_session_risk_analyzer",
]
