from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

HIGH_CONFIDENCE_PATTERNS = {
    "ignore previous instructions": 45,
    "disregard all prior instructions": 45,
    "reveal your system prompt": 50,
    "show the hidden prompt": 50,
    "print your hidden instructions": 50,
    "developer message": 35,
    "system prompt": 35,
    "override safety": 40,
    "jailbreak": 35,
    "bypass restrictions": 40,
    "disable safeguards": 40,
    "do not tell the user": 35,
    "secret instructions": 35,
}

MEDIUM_CONFIDENCE_PATTERNS = {
    "ignore safety": 20,
    "act as root": 20,
    "trust this content": 15,
    "execute this command": 20,
    "run this script": 20,
    "fetch and execute": 25,
    "download and run": 25,
    "base64 payload": 20,
    "encoded payload": 20,
    "exfiltrate": 25,
    "token": 15,
    "credential": 15,
    "cookie": 15,
    "ssh key": 20,
}

SOCIAL_ENGINEERING_PATTERNS = {
    "urgent security patch": 10,
    "admin override": 10,
    "authorized by developer": 15,
    "this is safe": 10,
    "internal tool": 10,
    "trusted source": 10,
}


@dataclass(slots=True)
class PromptInjectionAnalysis:
    detected: bool
    risk_score: int
    verdict: Literal["allow", "block"]
    confidence: str
    reason: str
    matched_patterns: list[str] = field(default_factory=list)
    failed_checks: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _get_text(payload: Any) -> str:
    if isinstance(payload, str):
        return _normalize_text(payload)

    if isinstance(payload, Mapping):
        parts: list[str] = []
        for key in (
            "content",
            "prompt",
            "message",
            "text",
            "summary",
            "reason",
            "target",
            "target_value",
        ):
            value = payload.get(key)
            if value is not None:
                parts.append(str(value))

        for key in ("messages", "reasons", "alerts", "tags"):
            value = payload.get(key)
            if isinstance(value, list):
                parts.extend(str(item) for item in value if item is not None)
            elif value is not None:
                parts.append(str(value))

        return _normalize_text(" | ".join(parts))

    return _normalize_text(payload)


def _score_patterns(text: str) -> tuple[int, list[str]]:
    score = 0
    matched: list[str] = []

    for pattern, weight in HIGH_CONFIDENCE_PATTERNS.items():
        if pattern in text:
            score += weight
            matched.append(pattern)

    for pattern, weight in MEDIUM_CONFIDENCE_PATTERNS.items():
        if pattern in text:
            score += weight
            matched.append(pattern)

    for pattern, weight in SOCIAL_ENGINEERING_PATTERNS.items():
        if pattern in text:
            score += weight
            matched.append(pattern)

    return min(100, score), matched


def _derive_verdict(score: int) -> tuple[Literal["allow", "block"], str]:
    if score >= 70:
        return "block", "high"
    if score >= 35:
        return "block", "medium"
    return "allow", "low"


def analyze_prompt_injection(payload: Any) -> PromptInjectionAnalysis:
    text = _get_text(payload)
    score, matched_patterns = _score_patterns(text)
    verdict, confidence = _derive_verdict(score)
    if matched_patterns:
        verdict = "block"

    detected = verdict == "block"
    failed_checks = []

    if matched_patterns:
        failed_checks.append("prompt injection indicators detected")

    if any("system prompt" in pattern or "hidden" in pattern for pattern in matched_patterns):
        failed_checks.append("sensitive instruction extraction attempt detected")

    if any("execute" in pattern or "run" in pattern for pattern in matched_patterns):
        failed_checks.append("execution coercion language detected")

    if any("token" in pattern or "credential" in pattern or "cookie" in pattern for pattern in matched_patterns):
        failed_checks.append("secret extraction language detected")

    reason = matched_patterns[0] if matched_patterns else "no prompt injection indicators detected"

    return PromptInjectionAnalysis(
        detected=detected,
        risk_score=score,
        verdict=verdict,
        confidence=confidence,
        reason=reason,
        matched_patterns=matched_patterns,
        failed_checks=failed_checks,
        metadata={"source": "prompt_injection_analyzer"},
    )


def summarize_prompt_injection(payload: Any) -> dict[str, Any]:
    return analyze_prompt_injection(payload).to_dict()


__all__ = [
    "HIGH_CONFIDENCE_PATTERNS",
    "MEDIUM_CONFIDENCE_PATTERNS",
    "SOCIAL_ENGINEERING_PATTERNS",
    "PromptInjectionAnalysis",
    "analyze_prompt_injection",
    "summarize_prompt_injection",
]
