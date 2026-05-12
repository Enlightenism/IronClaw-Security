from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SessionRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SessionRiskSignalKind(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    MALWARE_DETONATION = "malware_detonation"
    DATA_EXFIL = "data_exfiltration"
    POLICY_VIOLATION = "policy_violation"
    TOOL_ABUSE = "tool_abuse"
    RATE_LIMIT_EVASION = "rate_limit_evasion"
    HOSTILE_CONTEXT = "hostile_context"
    INTEGRATION_MISUSE = "integration_misuse"
    OTHER = "other"


class SessionRiskSignal(BaseModel):
    """
    Normalized risk signal attached to a runtime session.

    This is deliberately narrower than the full threat-intel signal shape and is
    focused on per-session posture. The attack-correlation engine can consume
    these as CorrelatedSignal entries.
    """

    signal_id: str = Field(..., description="Unique identifier for this risk signal")
    session_id: str = Field(..., description="Runtime session the signal belongs to")
    kind: SessionRiskSignalKind = Field(..., description="Type of risk indicator")
    severity: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description="Raw severity on a 0–10 scale before aggregation",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Detector confidence in [0,1]",
    )
    source: str = Field(
        ...,
        description="Source subsystem (promptguard, malware, secrets, runtime, etc.)",
    )
    tags: set[str] = Field(
        default_factory=set,
        description="Additional context tags (integration, environment, model id, etc.)",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Detector-specific metadata kept for enrichment and UX",
    )


class SessionRiskSnapshot(BaseModel):
    """
    Aggregated, explainable risk snapshot for a single runtime session.

    This is what higher layers (policy engine, remediation gate, review queue)
    should consume when deciding allow/warn/quarantine behavior.
    """

    session_id: str
    risk_score: float = Field(..., ge=0.0, le=10.0)
    level: SessionRiskLevel
    dominant_kinds: list[SessionRiskSignalKind] = Field(
        default_factory=list,
        description="Most influential signal kinds contributing to the score",
    )
    contributing_signal_ids: list[str] = Field(
        default_factory=list,
        description="Signals that materially impacted the score",
    )
    recommended_action: str = Field(
        ...,
        description="High-level recommendation (allow, warn, step_up, quarantine, block)",
    )
    reasons: list[str] = Field(
        default_factory=list,
        description="Human-readable explanations suitable for UI and audit logs",
    )


@dataclass(frozen=True)
class _SessionRiskConfig:
    """
    Tunable scoring configuration.

    This is intentionally conservative; thresholds can be tightened by policy.
    """

    min_medium_score: float = 3.0
    min_high_score: float = 6.0
    min_critical_score: float = 8.5

    prompt_injection_weight: float = 1.4
    malware_weight: float = 1.6
    data_exfil_weight: float = 1.6
    policy_violation_weight: float = 1.2
    tool_abuse_weight: float = 1.1
    hostile_context_weight: float = 1.1
    rate_limit_weight: float = 1.0
    integration_misuse_weight: float = 1.0
    other_weight: float = 0.8

    max_score: float = 10.0


class SessionRiskScoringService:
    """
    Stateless session risk scoring engine.

    Responsibilities:
    - Normalize and aggregate granular risk signals into a single session-level score.
    - Classify the session into risk levels (low/medium/high/critical).
    - Provide recommended actions that can feed into remediation gate / response coordinator.
    - Preserve enough explanation for UI and auditability.

    The caller is responsible for:
    - Persisting SessionRiskSnapshot into the session store.
    - Emitting security events and wiring into review queue / incident linkage.
    """

    def __init__(self, config: _SessionRiskConfig | None = None) -> None:
        self._config = config or _SessionRiskConfig()

    def score_session(
        self,
        session_id: str,
        signals: Sequence[SessionRiskSignal],
    ) -> SessionRiskSnapshot:
        relevant_signals = [s for s in signals if s.session_id == session_id]
        if not relevant_signals:
            # Explicit "no risk" snapshot to keep downstream code simple.
            return SessionRiskSnapshot(
                session_id=session_id,
                risk_score=0.0,
                level=SessionRiskLevel.LOW,
                dominant_kinds=[],
                contributing_signal_ids=[],
                recommended_action="allow",
                reasons=["No risk signals observed for this session."],
            )

        weighted_scores: list[float] = []
        contributing_ids: list[str] = []
        kind_contributions: dict[SessionRiskSignalKind, float] = {}
        reasons: list[str] = []

        for signal in relevant_signals:
            weight = self._weight_for_kind(signal.kind)
            contribution = signal.severity * signal.confidence * weight
            if contribution <= 0:
                continue

            weighted_scores.append(contribution)
            contributing_ids.append(signal.signal_id)
            kind_contributions[signal.kind] = kind_contributions.get(signal.kind, 0.0) + contribution

            reasons.append(
                f"{signal.kind.value.replace('_', ' ')} signal from {signal.source} "
                f"(severity={signal.severity:.1f}, confidence={signal.confidence:.2f}, weight={weight:.2f})"
            )

        if not weighted_scores:
            return SessionRiskSnapshot(
                session_id=session_id,
                risk_score=0.0,
                level=SessionRiskLevel.LOW,
                dominant_kinds=[],
                contributing_signal_ids=[],
                recommended_action="allow",
                reasons=["Risk signals present but all had zero effective contribution."],
            )

        # Aggregate using mean of contributions, then clamp to [0, max_score].
        aggregate = sum(weighted_scores) / max(1.0, len(weighted_scores))
        aggregate = max(0.0, min(self._config.max_score, aggregate))

        level = self._level_for_score(aggregate)
        recommended_action = self._action_for_level(level, relevant_signals)

        dominant_kinds = sorted(
            kind_contributions.keys(),
            key=lambda k: kind_contributions[k],
            reverse=True,
        )

        return SessionRiskSnapshot(
            session_id=session_id,
            risk_score=aggregate,
            level=level,
            dominant_kinds=dominant_kinds,
            contributing_signal_ids=contributing_ids,
            recommended_action=recommended_action,
            reasons=reasons,
        )

    def score_all(
        self,
        signals_by_session: Mapping[str, Sequence[SessionRiskSignal]],
    ) -> list[SessionRiskSnapshot]:
        """
        Convenience method used by batch pipelines to score multiple sessions at once.
        """
        snapshots: list[SessionRiskSnapshot] = []
        for session_id, signals in signals_by_session.items():
            snapshots.append(self.score_session(session_id, signals))
        return snapshots

    def _weight_for_kind(self, kind: SessionRiskSignalKind) -> float:
        if kind == SessionRiskSignalKind.PROMPT_INJECTION:
            return self._config.prompt_injection_weight
        if kind == SessionRiskSignalKind.MALWARE_DETONATION:
            return self._config.malware_weight
        if kind == SessionRiskSignalKind.DATA_EXFIL:
            return self._config.data_exfil_weight
        if kind == SessionRiskSignalKind.POLICY_VIOLATION:
            return self._config.policy_violation_weight
        if kind == SessionRiskSignalKind.TOOL_ABUSE:
            return self._config.tool_abuse_weight
        if kind == SessionRiskSignalKind.HOSTILE_CONTEXT:
            return self._config.hostile_context_weight
        if kind == SessionRiskSignalKind.RATE_LIMIT_EVASION:
            return self._config.rate_limit_weight
        if kind == SessionRiskSignalKind.INTEGRATION_MISUSE:
            return self._config.integration_misuse_weight
        return self._config.other_weight

    def _level_for_score(self, score: float) -> SessionRiskLevel:
        if score >= self._config.min_critical_score:
            return SessionRiskLevel.CRITICAL
        if score >= self._config.min_high_score:
            return SessionRiskLevel.HIGH
        if score >= self._config.min_medium_score:
            return SessionRiskLevel.MEDIUM
        return SessionRiskLevel.LOW

    def _action_for_level(
        self,
        level: SessionRiskLevel,
        signals: Sequence[SessionRiskSignal],
    ) -> str:
        """
        Map risk level into a coarse recommended action.

        This is intentionally generic; policy engine and remediation gate can apply
        stricter decisions based on environment, integration, or tenant settings.
        """
        has_malware = any(s.kind == SessionRiskSignalKind.MALWARE_DETONATION for s in signals)
        has_data_exfil = any(s.kind == SessionRiskSignalKind.DATA_EXFIL for s in signals)
        has_prompt_injection = any(s.kind == SessionRiskSignalKind.PROMPT_INJECTION for s in signals)

        if level is SessionRiskLevel.CRITICAL:
            if has_malware or has_data_exfil:
                return "quarantine_and_block"
            if has_prompt_injection:
                return "quarantine_and_require_review"
            return "quarantine"

        if level is SessionRiskLevel.HIGH:
            if has_prompt_injection or has_malware or has_data_exfil:
                return "step_up_and_queue_review"
            return "step_up_authentication"

        if level is SessionRiskLevel.MEDIUM:
            return "warn_and_monitor"

        return "allow"