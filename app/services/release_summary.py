from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional


@dataclass(frozen=True)
class ReleaseSummaryInput:
    integration_id: str
    compatibility_state: str
    telemetry_state: str
    lifecycle_state: str
    rollout_recommendation: str
    readiness_level: str
    risk_score: float
    ready: bool
    reasons: List[str] = field(default_factory=list)
    next_actions: List[str] = field(default_factory=list)
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ReleaseSummary:
    integration_id: str
    release_status: str
    compatibility_state: str
    telemetry_state: str
    lifecycle_state: str
    rollout_recommendation: str
    readiness_level: str
    risk_score: float
    ready: bool
    reasons: List[str] = field(default_factory=list)
    next_actions: List[str] = field(default_factory=list)
    generated_at: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return _normalize_value(asdict(self))


def build_release_summary(
    summary_input: ReleaseSummaryInput,
) -> ReleaseSummary:
    generated_at = datetime.now(timezone.utc).isoformat()
    release_status = _derive_release_status(summary_input)

    return ReleaseSummary(
        integration_id=summary_input.integration_id,
        release_status=release_status,
        compatibility_state=summary_input.compatibility_state,
        telemetry_state=summary_input.telemetry_state,
        lifecycle_state=summary_input.lifecycle_state,
        rollout_recommendation=summary_input.rollout_recommendation,
        readiness_level=summary_input.readiness_level,
        risk_score=_clamp(summary_input.risk_score, 0.0, 100.0),
        ready=summary_input.ready,
        reasons=_deduplicate(summary_input.reasons),
        next_actions=_deduplicate(summary_input.next_actions),
        generated_at=generated_at,
        metadata=dict(_normalize_value(dict(summary_input.metadata))),
    )


def summarize_release_summary(
    release_summary: ReleaseSummary,
) -> Dict[str, Any]:
    return release_summary.to_dict()


def build_release_summary_from_parts(
    *,
    integration_id: str,
    rollout_decision: Any,
    readiness_result: Any,
    compatibility_state: str,
    telemetry_state: str,
    lifecycle_state: str,
    metadata: Optional[Mapping[str, Any]] = None,
) -> ReleaseSummary:
    rollout_recommendation = _read_attr(
        rollout_decision,
        "recommendation",
        default="unknown",
    )
    if hasattr(rollout_recommendation, "value"):
        rollout_recommendation = rollout_recommendation.value

    readiness_level = _read_attr(
        readiness_result,
        "level",
        default="unknown",
    )
    if hasattr(readiness_level, "value"):
        readiness_level = readiness_level.value

    risk_score = float(
        _read_attr(
            readiness_result,
            "score",
            default=_read_attr(rollout_decision, "score", default=0.0),
        )
    )
    ready = bool(_read_attr(readiness_result, "ready", default=False))

    reasons = _coerce_string_list(_read_attr(rollout_decision, "reasons", default=[]))
    readiness_findings = _read_attr(readiness_result, "findings", default=[])
    reasons.extend(_extract_finding_messages(readiness_findings))

    next_actions = _coerce_string_list(
        _read_attr(readiness_result, "next_actions", default=[])
    )
    next_actions.extend(
        _coerce_string_list(_read_attr(rollout_decision, "required_actions", default=[]))
    )

    return build_release_summary(
        ReleaseSummaryInput(
            integration_id=integration_id,
            compatibility_state=compatibility_state,
            telemetry_state=telemetry_state,
            lifecycle_state=lifecycle_state,
            rollout_recommendation=str(rollout_recommendation),
            readiness_level=str(readiness_level),
            risk_score=risk_score,
            ready=ready,
            reasons=reasons,
            next_actions=next_actions,
            metadata=metadata or {},
        )
    )


def _derive_release_status(summary_input: ReleaseSummaryInput) -> str:
    if summary_input.readiness_level == "fail":
        return "blocked"

    if summary_input.rollout_recommendation == "hold":
        return "blocked"

    if summary_input.rollout_recommendation == "rollback_ready":
        return "rollback_ready"

    if summary_input.rollout_recommendation == "limited_rollout":
        return "limited_rollout"

    if summary_input.ready and summary_input.readiness_level == "pass":
        return "approved"

    if summary_input.readiness_level == "warn":
        return "review_required"

    return "pending"


def _extract_finding_messages(findings: Iterable[Any]) -> List[str]:
    messages: List[str] = []
    for finding in findings:
        message = _read_attr(finding, "message", default=None)
        if message:
            messages.append(str(message))
    return messages


def _coerce_string_list(values: Iterable[Any]) -> List[str]:
    result: List[str] = []
    for value in values:
        if value is None:
            continue
        result.append(str(value))
    return result


def _read_attr(obj: Any, name: str, default: Any = None) -> Any:
    if obj is None:
        return default
    return getattr(obj, name, default)


def _deduplicate(values: Iterable[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))


def _normalize_value(value: Any) -> Any:
    if is_dataclass(value):
        return _normalize_value(asdict(value))
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _normalize_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize_value(item) for item in value]
    if hasattr(value, "value"):
        return value.value
    return value