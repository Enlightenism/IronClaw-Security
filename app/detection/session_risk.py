from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Mapping

from app.detection.artifact_analyzer import analyze_artifact
from app.detection.download_analyzer import analyze_download
from app.detection.prompt_injection_analyzer import analyze_prompt_injection
from app.detection.output_sanitizer import sanitize_output


@dataclass(slots=True)
class SessionRiskAssessment:
    session_id: str
    client_id: str
    risk_score: int
    verdict: str
    confidence: str
    reason: str
    component_scores: dict[str, int] = field(default_factory=dict)
    matched_patterns: list[str] = field(default_factory=list)
    failed_checks: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _get_value(payload: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in payload:
            return payload[key]
    return None


def _derive_verdict(score: int) -> tuple[str, str]:
    if score >= 80:
        return "quarantine", "high"
    if score >= 40:
        return "warn", "medium"
    return "allow", "low"


def assess_session_risk(payload: Mapping[str, Any]) -> SessionRiskAssessment:
    session_id = str(_get_value(payload, "session_id") or "")
    client_id = str(_get_value(payload, "client_id", "actor_id") or "")

    prompt_result = analyze_prompt_injection(payload)
    download_result = analyze_download(payload)
    artifact_result = analyze_artifact(payload)
    output_result = sanitize_output(payload)

    base_risk = _safe_int(_get_value(payload, "risk_score", "score"), 0)

    component_scores = {
        "base": base_risk,
        "prompt_injection": prompt_result.risk_score,
        "download": download_result.risk_score,
        "artifact": artifact_result.risk_score,
        "output": output_result.risk_score,
    }

    weighted_score = min(
        100,
        base_risk
        + int(prompt_result.risk_score * 0.35)
        + int(download_result.risk_score * 0.20)
        + int(artifact_result.risk_score * 0.20)
        + int(output_result.risk_score * 0.25),
    )

    verdict, confidence = _derive_verdict(weighted_score)

    matched_patterns = [
        *prompt_result.matched_patterns,
        *download_result.matched_patterns,
        *artifact_result.matched_patterns,
        *output_result.redacted_items,
    ]

    failed_checks = [
        *prompt_result.failed_checks,
        *download_result.failed_checks,
        *artifact_result.failed_checks,
        *output_result.failed_checks,
    ]

    reason = (
        prompt_result.reason
        if prompt_result.detected
        else download_result.reason
        if download_result.detected
        else artifact_result.reason
        if artifact_result.detected
        else output_result.reason
    )

    return SessionRiskAssessment(
        session_id=session_id,
        client_id=client_id,
        risk_score=weighted_score,
        verdict=verdict,
        confidence=confidence,
        reason=reason,
        component_scores=component_scores,
        matched_patterns=matched_patterns,
        failed_checks=failed_checks,
        metadata={"source": "session_risk"},
    )


def summarize_session_risk(payload: Mapping[str, Any]) -> dict[str, Any]:
    return assess_session_risk(payload).to_dict()


__all__ = [
    "SessionRiskAssessment",
    "assess_session_risk",
    "summarize_session_risk",
]