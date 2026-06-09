from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PolicyEnforcementMode(str, Enum):
    """How the policy engine handles a matched rule."""

    block = "block"
    warn = "warn"
    quarantine = "quarantine"
    allow = "allow"
    audit = "audit"


class PolicyScope(str, Enum):
    """Which layer of the request pipeline this policy targets."""

    prompt = "prompt"
    tool_call = "tool_call"
    execution = "execution"
    response = "response"
    global_ = "global"


class PolicySeverity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class PolicyRule(BaseModel):
    """A single enforceable rule within a policy."""

    rule_id: str = Field(..., description="Unique rule identifier")
    name: str = Field(..., description="Human-readable rule name")
    description: str | None = None
    scope: PolicyScope = PolicyScope.global_
    severity: PolicySeverity = PolicySeverity.medium
    enforcement_mode: PolicyEnforcementMode = PolicyEnforcementMode.block
    pattern: str | None = Field(None, description="Regex or keyword pattern this rule matches against")
    categories: list[str] = Field(default_factory=list)
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyRuleSet(BaseModel):
    """Named, versioned collection of PolicyRules."""

    ruleset_id: str
    name: str
    version: str = "1.0.0"
    rules: list[PolicyRule] = Field(default_factory=list)
    created_at: datetime | None = None
    updated_at: datetime | None = None
    is_active: bool = True


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class PolicyCreateRequest(BaseModel):
    """Payload to create or replace the active policy ruleset."""

    name: str
    version: str = "1.0.0"
    rules: list[PolicyRule] = Field(default_factory=list)
    heuristic_threshold: int = Field(50, ge=0, le=100, description="Heuristic risk score trigger threshold (0-100)")
    unicode_normalization_enabled: bool = True
    enforcement_mode: PolicyEnforcementMode = PolicyEnforcementMode.block
    scope: PolicyScope = PolicyScope.global_
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyUpdateRequest(BaseModel):
    """Partial update to the active policy; all fields optional."""

    name: str | None = None
    version: str | None = None
    rules: list[PolicyRule] | None = None
    heuristic_threshold: int | None = Field(None, ge=0, le=100)
    unicode_normalization_enabled: bool | None = None
    enforcement_mode: PolicyEnforcementMode | None = None
    scope: PolicyScope | None = None
    metadata: dict[str, Any] | None = None


class PolicyEvaluationResult(BaseModel):
    """Result returned when a payload is evaluated against the active policy."""

    verdict: PolicyEnforcementMode
    matched_rules: list[str] = Field(default_factory=list, description="rule_ids that matched")
    severity: PolicySeverity = PolicySeverity.info
    risk_score: int = Field(0, ge=0, le=100)
    reasoning: str | None = None
    categories: list[str] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)
    policy_version: str | None = None


# ---------------------------------------------------------------------------
# Status schema (consumed by /policy/status endpoint)
# ---------------------------------------------------------------------------


class PolicyStatus(BaseModel):
    """Current runtime state of the policy engine."""

    heuristic_threshold: int = Field(..., ge=0, le=100)
    heuristic_threshold_env: str | None = None
    severity_counts: dict[str, int] = Field(default_factory=dict)
    category_counts: dict[str, int] = Field(default_factory=dict)
    unicode_normalization_enabled: bool
    rule_count: int = 0
    policy_loaded_from_db: bool = False
    enforcement_mode: PolicyEnforcementMode = PolicyEnforcementMode.block
    active_ruleset_id: str | None = None
    active_ruleset_version: str | None = None
    scope: PolicyScope = PolicyScope.global_
    last_evaluated_at: datetime | None = None
    last_policy_updated_at: datetime | None = None
    enabled_rules: int = 0
    disabled_rules: int = 0
    tags_index: list[str] = Field(default_factory=list, description="Union of all tags across active rules")
