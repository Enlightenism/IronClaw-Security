from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.groq_security_brain import GroqSecurityVerdict
from app.ui.groq.prompt_guard_policy import (
    PromptGuardAction,
    PromptGuardCategory,
    build_prompt_guard_policy_view,
)


router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-prompt-guard-simulator"],
)


SimulatorRiskLevel = Literal["low", "medium", "high", "critical"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class PromptGuardMatch:
    rule_id: str
    rule_name: str
    category: PromptGuardCategory
    action: PromptGuardAction
    score: int
    matched_patterns: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category,
            "action": self.action,
            "score": self.score,
            "matched_patterns": list(self.matched_patterns),
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class PromptGuardSimulation:
    prompt: str
    normalized_prompt: str
    verdict: GroqSecurityVerdict
    risk_score: int
    risk_level: SimulatorRiskLevel
    matches: list[PromptGuardMatch]
    safe_excerpt: str
    generated_at: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "prompt": self.prompt,
            "normalized_prompt": self.normalized_prompt,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "matches": [match.to_dict() for match in self.matches],
            "safe_excerpt": self.safe_excerpt,
            "generated_at": self.generated_at,
            "metadata": dict(self.metadata),
        }


class PromptGuardSimulationRequest(BaseModel):
    prompt: str = Field(..., description="Prompt to simulate against the Groq prompt guard policy.")


class PromptGuardMatchView(BaseModel):
    rule_id: str
    rule_name: str
    category: PromptGuardCategory
    action: PromptGuardAction
    score: int
    matched_patterns: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PromptGuardSimulationResponse(BaseModel):
    prompt: str
    normalized_prompt: str
    verdict: GroqSecurityVerdict
    risk_score: int
    risk_level: SimulatorRiskLevel
    matches: list[PromptGuardMatchView]
    safe_excerpt: str
    generated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


def _normalize_prompt(prompt: str) -> str:
    return " ".join(prompt.strip().lower().split())


def _safe_excerpt(prompt: str, max_len: int = 160) -> str:
    excerpt = " ".join(prompt.strip().split())
    if len(excerpt) <= max_len:
        return excerpt
    return excerpt[: max_len - 3] + "..."


def _risk_level_from_score(score: int) -> SimulatorRiskLevel:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _verdict_from_score(
    *,
    score: int,
    quarantine_score: int,
    block_score: int,
    warn_score: int,
) -> GroqSecurityVerdict:
    if score >= quarantine_score:
        return "quarantine"
    if score >= block_score:
        return "block"
    if score >= warn_score:
        return "warn"
    return "allow"


def _simulate_prompt(prompt: str) -> PromptGuardSimulation:
    policy = build_prompt_guard_policy_view()
    normalized = _normalize_prompt(prompt)

    matches: list[PromptGuardMatch] = []

    for rule in policy.rules:
        if not rule.enabled:
            continue

        matched_patterns = [
            pattern
            for pattern in rule.match_patterns
            if pattern.lower() in normalized
        ]
        if not matched_patterns:
            continue

        score = min(100, rule.severity_weight + (len(matched_patterns) - 1) * 4)

        matches.append(
            PromptGuardMatch(
                rule_id=rule.id,
                rule_name=rule.name,
                category=rule.category,
                action=rule.default_action,
                score=score,
                matched_patterns=matched_patterns,
                metadata={
                    "pattern_match_count": len(matched_patterns),
                },
            )
        )

    risk_score = max((match.score for match in matches), default=0)

    verdict = _verdict_from_score(
        score=risk_score,
        quarantine_score=policy.thresholds.quarantine_score,
        block_score=policy.thresholds.block_score,
        warn_score=policy.thresholds.warn_score,
    )
    risk_level = _risk_level_from_score(risk_score)

    return PromptGuardSimulation(
        prompt=prompt,
        normalized_prompt=normalized,
        verdict=verdict,
        risk_score=risk_score,
        risk_level=risk_level,
        matches=matches,
        safe_excerpt=_safe_excerpt(prompt),
        generated_at=_utc_now(),
        metadata={
            "policy_mode": policy.mode,
            "policy_health": policy.health,
            "thresholds": policy.thresholds.to_dict(),
            "match_count": len(matches),
        },
    )


@router.post("/prompt-guard/simulate", response_model=PromptGuardSimulationResponse)
def simulate_prompt_guard(
    payload: PromptGuardSimulationRequest,
) -> PromptGuardSimulationResponse:
    simulation = _simulate_prompt(payload.prompt)
    data = simulation.to_dict()

    return PromptGuardSimulationResponse(
        prompt=data["prompt"],
        normalized_prompt=data["normalized_prompt"],
        verdict=data["verdict"],
        risk_score=data["risk_score"],
        risk_level=data["risk_level"],
        matches=[PromptGuardMatchView(**match) for match in data["matches"]],
        safe_excerpt=data["safe_excerpt"],
        generated_at=data["generated_at"],
        metadata=data["metadata"],
    )