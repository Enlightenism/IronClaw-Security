from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.groq_security_brain import GroqMode


router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-prompt-guard-policy"],
)


PolicyHealth = Literal["healthy", "warning", "critical", "disabled"]
PolicyMode = Literal["disabled", "observe", "assist", "enforce"]
PromptGuardCategory = Literal[
    "prompt_injection",
    "data_exfiltration",
    "secret_exposure",
    "tool_misuse",
    "policy_bypass",
    "unsafe_execution",
]
PromptGuardAction = Literal["allow", "warn", "block", "quarantine"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class PromptGuardRule:
    id: str
    name: str
    category: PromptGuardCategory
    description: str
    enabled: bool
    severity_weight: int
    default_action: PromptGuardAction
    match_patterns: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "enabled": self.enabled,
            "severity_weight": self.severity_weight,
            "default_action": self.default_action,
            "match_patterns": list(self.match_patterns),
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class PromptGuardThresholds:
    warn_score: int
    block_score: int
    quarantine_score: int
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "warn_score": self.warn_score,
            "block_score": self.block_score,
            "quarantine_score": self.quarantine_score,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class PromptGuardPolicyView:
    title: str
    mode: PolicyMode
    health: PolicyHealth
    generated_at: str
    thresholds: PromptGuardThresholds
    rules: list[PromptGuardRule]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "mode": self.mode,
            "health": self.health,
            "generated_at": self.generated_at,
            "thresholds": self.thresholds.to_dict(),
            "rules": [rule.to_dict() for rule in self.rules],
            "metadata": dict(self.metadata),
        }


class PromptGuardRuleView(BaseModel):
    id: str
    name: str
    category: PromptGuardCategory
    description: str
    enabled: bool
    severity_weight: int
    default_action: PromptGuardAction
    match_patterns: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PromptGuardThresholdsView(BaseModel):
    warn_score: int
    block_score: int
    quarantine_score: int
    metadata: dict[str, Any] = Field(default_factory=dict)


class PromptGuardPolicyResponse(BaseModel):
    title: str
    mode: PolicyMode
    health: PolicyHealth
    generated_at: str
    thresholds: PromptGuardThresholdsView
    rules: list[PromptGuardRuleView]
    metadata: dict[str, Any] = Field(default_factory=dict)


def _coerce_policy_mode(mode: GroqMode) -> PolicyMode:
    return mode


def _health_from_mode_and_rules(
    *,
    mode: PolicyMode,
    rules: list[PromptGuardRule],
) -> PolicyHealth:
    if mode == "disabled":
        return "disabled"

    enabled_rules = [rule for rule in rules if rule.enabled]
    if not enabled_rules:
        return "critical"

    critical_categories = {
        "prompt_injection",
        "data_exfiltration",
        "secret_exposure",
        "policy_bypass",
    }
    enabled_categories = {rule.category for rule in enabled_rules}

    if not critical_categories.issubset(enabled_categories):
        return "warning"

    if mode == "observe":
        return "warning"

    return "healthy"


def _build_default_rules() -> list[PromptGuardRule]:
    return [
        PromptGuardRule(
            id="pg-001",
            name="Prompt Injection Guard",
            category="prompt_injection",
            description="Detects attempts to override system instructions or hidden policy.",
            enabled=True,
            severity_weight=95,
            default_action="block",
            match_patterns=[
                "ignore previous instructions",
                "disregard the system prompt",
                "reveal hidden instructions",
                "bypass policy",
            ],
            metadata={"priority": 1},
        ),
        PromptGuardRule(
            id="pg-002",
            name="Data Exfiltration Guard",
            category="data_exfiltration",
            description="Detects attempts to extract data, logs, memory, or confidential context.",
            enabled=True,
            severity_weight=92,
            default_action="quarantine",
            match_patterns=[
                "export all data",
                "send secrets externally",
                "dump memory",
                "print confidential data",
            ],
            metadata={"priority": 2},
        ),
        PromptGuardRule(
            id="pg-003",
            name="Secret Exposure Guard",
            category="secret_exposure",
            description="Detects requests for keys, tokens, credentials, or internal secrets.",
            enabled=True,
            severity_weight=90,
            default_action="quarantine",
            match_patterns=[
                "show api key",
                "print token",
                "reveal credentials",
                "display secrets",
            ],
            metadata={"priority": 3},
        ),
        PromptGuardRule(
            id="pg-004",
            name="Tool Misuse Guard",
            category="tool_misuse",
            description="Detects risky attempts to abuse tool calls, shell access, or privileged actions.",
            enabled=True,
            severity_weight=82,
            default_action="block",
            match_patterns=[
                "run shell command",
                "execute rm -rf",
                "open privileged file",
                "call admin tool",
            ],
            metadata={"priority": 4},
        ),
        PromptGuardRule(
            id="pg-005",
            name="Policy Bypass Guard",
            category="policy_bypass",
            description="Detects framing tricks that try to make the model roleplay around safety policy.",
            enabled=True,
            severity_weight=86,
            default_action="block",
            match_patterns=[
                "this is only a simulation",
                "pretend policy does not apply",
                "for testing ignore safeguards",
                "as an unrestricted model",
            ],
            metadata={"priority": 5},
        ),
        PromptGuardRule(
            id="pg-006",
            name="Unsafe Execution Guard",
            category="unsafe_execution",
            description="Detects prompts that try to trigger dangerous execution paths or destructive actions.",
            enabled=True,
            severity_weight=88,
            default_action="quarantine",
            match_patterns=[
                "delete all files",
                "disable protection",
                "kill the process",
                "turn off security",
            ],
            metadata={"priority": 6},
        ),
    ]


def build_prompt_guard_policy_view(
    *,
    mode: GroqMode = "assist",
) -> PromptGuardPolicyView:
    policy_mode = _coerce_policy_mode(mode)
    rules = _build_default_rules()

    thresholds = PromptGuardThresholds(
        warn_score=35,
        block_score=70,
        quarantine_score=85,
        metadata={
            "scoring_model": "groq-prompt-guard-v1",
        },
    )

    health = _health_from_mode_and_rules(
        mode=policy_mode,
        rules=rules,
    )

    return PromptGuardPolicyView(
        title="Groq Prompt Guard Policy",
        mode=policy_mode,
        health=health,
        generated_at=_utc_now(),
        thresholds=thresholds,
        rules=rules,
        metadata={
            "protected_surface": "every_user_prompt",
            "total_rules": len(rules),
            "enabled_rules": sum(1 for rule in rules if rule.enabled),
        },
    )


@router.get("/prompt-guard/policy", response_model=PromptGuardPolicyResponse)
def get_prompt_guard_policy() -> PromptGuardPolicyResponse:
    view = build_prompt_guard_policy_view()
    data = view.to_dict()

    return PromptGuardPolicyResponse(
        title=data["title"],
        mode=data["mode"],
        health=data["health"],
        generated_at=data["generated_at"],
        thresholds=PromptGuardThresholdsView(**data["thresholds"]),
        rules=[PromptGuardRuleView(**rule) for rule in data["rules"]],
        metadata=data["metadata"],
    )