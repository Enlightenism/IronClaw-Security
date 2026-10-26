from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.guard_security_brain import GuardSecurityVerdict
from app.ui.guard.prompt_guard_policy import build_prompt_guard_policy_view
from app.ui.guard.prompt_guard_simulator import (
    _normalize_prompt,
    _risk_level_from_score,
    _safe_excerpt,
    _simulate_prompt,
)

router = APIRouter(
    prefix="/ui/guard",
    tags=["guard-prompt-guard-explain"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class PromptGuardExplanation:
    prompt: str
    safe_excerpt: str
    normalized_prompt: str
    verdict: GuardSecurityVerdict
    risk_score: int
    risk_level: str
    matched_rules: list[dict[str, Any]]
    explanation: str
    operator_guidance: list[str]
    generated_at: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "prompt": self.prompt,
            "safe_excerpt": self.safe_excerpt,
            "normalized_prompt": self.normalized_prompt,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "matched_rules": list(self.matched_rules),
            "explanation": self.explanation,
            "operator_guidance": list(self.operator_guidance),
            "generated_at": self.generated_at,
            "metadata": dict(self.metadata),
        }


class PromptGuardExplainRequest(BaseModel):
    prompt: str = Field(..., description="Prompt to explain using the prompt guard policy.")


class PromptGuardExplanationResponse(BaseModel):
    prompt: str
    safe_excerpt: str
    normalized_prompt: str
    verdict: GuardSecurityVerdict
    risk_score: int
    risk_level: str
    matched_rules: list[dict[str, Any]] = Field(default_factory=list)
    explanation: str
    operator_guidance: list[str] = Field(default_factory=list)
    generated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


def _build_explanation_text(
    *,
    verdict: GuardSecurityVerdict,
    risk_score: int,
    matched_rule_names: list[str],
) -> str:
    if not matched_rule_names:
        return f"The prompt did not trigger any active prompt guard rules, so the system returned a {verdict} verdict with a risk score of {risk_score}."

    joined_rules = ", ".join(matched_rule_names)
    return f"The system returned a {verdict} verdict with a risk score of {risk_score} because the prompt matched active guard rules: {joined_rules}."


def _build_operator_guidance(
    *,
    verdict: GuardSecurityVerdict,
    risk_score: int,
    matched_rule_names: list[str],
) -> list[str]:
    guidance: list[str] = []

    if matched_rule_names:
        guidance.append("Review the matched rule set and confirm the prompt intent is represented correctly.")
    else:
        guidance.append("No active rule matched; review manually if the prompt still looks suspicious.")

    if verdict in ("block", "quarantine"):
        guidance.append("Keep enforcement in place unless a documented exception or allowlist entry justifies release.")
        guidance.append("If this is a legitimate workflow, route it to the review queue before changing policy.")
    elif verdict == "warn":
        guidance.append("Monitor for repeated attempts and escalate to review if the same pattern appears again.")
    else:
        guidance.append("Allow the prompt, but continue passive monitoring for repeated low-risk patterns.")

    if risk_score >= 85:
        guidance.append("Treat this as critical-risk behavior and preserve an audit trail for investigation.")

    return guidance


def build_prompt_guard_explanation(prompt: str) -> PromptGuardExplanation:
    simulation = _simulate_prompt(prompt)
    policy = build_prompt_guard_policy_view()

    matched_rules: list[dict[str, Any]] = []
    matched_rule_names: list[str] = []

    for match in simulation.matches:
        matched_rule_names.append(match.rule_name)
        matched_rules.append(
            {
                "rule_id": match.rule_id,
                "rule_name": match.rule_name,
                "category": match.category,
                "action": match.action,
                "score": match.score,
                "matched_patterns": list(match.matched_patterns),
            },
        )

    explanation = _build_explanation_text(
        verdict=simulation.verdict,
        risk_score=simulation.risk_score,
        matched_rule_names=matched_rule_names,
    )
    operator_guidance = _build_operator_guidance(
        verdict=simulation.verdict,
        risk_score=simulation.risk_score,
        matched_rule_names=matched_rule_names,
    )

    return PromptGuardExplanation(
        prompt=prompt,
        safe_excerpt=_safe_excerpt(prompt),
        normalized_prompt=_normalize_prompt(prompt),
        verdict=simulation.verdict,
        risk_score=simulation.risk_score,
        risk_level=_risk_level_from_score(simulation.risk_score),
        matched_rules=matched_rules,
        explanation=explanation,
        operator_guidance=operator_guidance,
        generated_at=_utc_now(),
        metadata={
            "policy_mode": policy.mode,
            "policy_health": policy.health,
            "enabled_rule_count": sum(1 for rule in policy.rules if rule.enabled),
            "matched_rule_count": len(matched_rules),
        },
    )


@router.post("/prompt-guard/explain", response_model=PromptGuardExplanationResponse)
def explain_prompt_guard_decision(
    payload: PromptGuardExplainRequest,
) -> PromptGuardExplanationResponse:
    explanation = build_prompt_guard_explanation(payload.prompt)
    data = explanation.to_dict()

    return PromptGuardExplanationResponse(
        prompt=data["prompt"],
        safe_excerpt=data["safe_excerpt"],
        normalized_prompt=data["normalized_prompt"],
        verdict=data["verdict"],
        risk_score=data["risk_score"],
        risk_level=data["risk_level"],
        matched_rules=data["matched_rules"],
        explanation=data["explanation"],
        operator_guidance=data["operator_guidance"],
        generated_at=data["generated_at"],
        metadata=data["metadata"],
    )
