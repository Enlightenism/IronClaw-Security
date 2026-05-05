from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

GroqSecurityVerdict = Literal["allow", "warn", "quarantine", "block"]
GroqMode = Literal["disabled", "assist", "enforce"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_text(value: str | None) -> str:
    return (value or "").strip()


def _contains_any(haystack: str, needles: list[str]) -> bool:
    lowered = haystack.lower()
    return any(needle in lowered for needle in needles)


@dataclass(slots=True)
class GroqSecurityRequest:
    action_type: str
    target: str
    content: str = ""
    client_id: str | None = None
    session_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "target": self.target,
            "content": self.content,
            "client_id": self.client_id,
            "session_id": self.session_id,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class GroqSecurityDecision:
    mode: GroqMode
    verdict: GroqSecurityVerdict
    risk_score: int
    summary: str
    reasoning: list[str] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)
    model_name: str = "groq-security-brain-local"
    decided_at: str = field(default_factory=_utc_now)
    request: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "summary": self.summary,
            "reasoning": list(self.reasoning),
            "signals": list(self.signals),
            "model_name": self.model_name,
            "decided_at": self.decided_at,
            "request": dict(self.request),
            "metadata": dict(self.metadata),
        }


def build_groq_security_request(
    *,
    action_type: str,
    target: str,
    content: str = "",
    client_id: str | None = None,
    session_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> GroqSecurityRequest:
    normalized_action_type = _normalize_text(action_type)
    normalized_target = _normalize_text(target)

    if not normalized_action_type:
        raise ValueError("action_type is required")
    if not normalized_target:
        raise ValueError("target is required")

    return GroqSecurityRequest(
        action_type=normalized_action_type,
        target=normalized_target,
        content=content or "",
        client_id=_normalize_text(client_id) or None,
        session_id=_normalize_text(session_id) or None,
        metadata=dict(metadata or {}),
    )


def evaluate_groq_security_request(
    request: GroqSecurityRequest,
    *,
    mode: GroqMode = "assist",
    model_name: str = "groq-security-brain-local",
    extra_metadata: dict[str, Any] | None = None,
) -> GroqSecurityDecision:
    content = f"{request.action_type} {request.target} {request.content}".lower()
    reasoning: list[str] = []
    signals: list[str] = []
    risk_score = 0

    critical_patterns = [
        "system prompt",
        "ignore previous",
        "override instructions",
        "exfiltrate",
        "steal credential",
        "export secret",
        "rm -rf",
        "powershell -enc",
    ]
    high_patterns = [
        "ssh key",
        "api key",
        "token",
        "password",
        "sudo",
        "curl http",
        "wget http",
        "invoke-webrequest",
    ]
    medium_patterns = [
        "base64",
        "hidden prompt",
        "bypass",
        "disable guard",
        "upload file",
        "external write",
    ]

    if _contains_any(content, critical_patterns):
        risk_score = max(risk_score, 95)
        signals.append("critical-pattern-match")
        reasoning.append("Critical attack language matched known high-severity indicators.")

    if _contains_any(content, high_patterns):
        risk_score = max(risk_score, 75)
        signals.append("high-pattern-match")
        reasoning.append("High-risk execution or secret-access indicators were detected.")

    if _contains_any(content, medium_patterns):
        risk_score = max(risk_score, 45)
        signals.append("medium-pattern-match")
        reasoning.append("Suspicious evasion or externalization language was detected.")

    if request.action_type in {"shellcommand", "toolcall"}:
        risk_score += 10
        signals.append("sensitive-action-type")
        reasoning.append("Requested action type is inherently higher risk.")

    if request.target.lower().startswith(("http://", "https://")):
        risk_score += 5
        signals.append("network-target")
        reasoning.append("Remote target access increases exfiltration and pivot risk.")

    risk_score = min(risk_score, 100)

    if mode == "disabled":
        verdict: GroqSecurityVerdict = "allow"
        summary = "Groq security brain is disabled."
        reasoning = ["Groq evaluation was skipped because the mode is disabled."]
    elif risk_score >= 90:
        verdict = "block"
        summary = "Groq security brain recommends blocking the request."
    elif risk_score >= 70:
        verdict = "quarantine"
        summary = "Groq security brain recommends quarantining the request."
    elif risk_score >= 40:
        verdict = "warn"
        summary = "Groq security brain recommends warning on the request."
    else:
        verdict = "allow"
        summary = "Groq security brain found no material risk indicators."

    metadata = dict(extra_metadata or {})
    metadata["evaluated_with_keywords"] = True

    return GroqSecurityDecision(
        mode=mode,
        verdict=verdict,
        risk_score=risk_score,
        summary=summary,
        reasoning=reasoning,
        signals=signals,
        model_name=model_name,
        request=request.to_dict(),
        metadata=metadata,
    )


def summarize_groq_security_decision(
    decision: GroqSecurityDecision,
) -> dict[str, Any]:
    return {
        "mode": decision.mode,
        "verdict": decision.verdict,
        "risk_score": decision.risk_score,
        "signal_count": len(decision.signals),
        "reason_count": len(decision.reasoning),
        "model_name": decision.model_name,
        "decided_at": decision.decided_at,
    }