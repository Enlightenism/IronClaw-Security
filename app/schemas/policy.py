from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

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

    model_config = ConfigDict(from_attributes=True)

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


class PolicyRuleCreate(BaseModel):
    """Payload for creating a new PolicyRule (rule_id is server-assigned)."""

    model_config = ConfigDict(from_attributes=True)

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


class PolicyRuleMatch(BaseModel):
    """Details of a single rule that matched during policy evaluation."""

    model_config = ConfigDict(from_attributes=True)

    rule_id: str
    name: str
    severity: PolicySeverity
    enforcement_mode: PolicyEnforcementMode
    pattern: str | None = None
    categories: list[str] = Field(default_factory=list)
    matched_text: str | None = Field(None, description="Excerpt that triggered the match")
    tags: list[str] = Field(default_factory=list)


class PolicyRuleSet(BaseModel):
    """Named, versioned collection of PolicyRules."""

    model_config = ConfigDict(from_attributes=True)

    ruleset_id: str
    name: str
    version: str = "1.0.0"
    rules: list[PolicyRule] = Field(default_factory=list)
    created_at: datetime | None = None
    updated_at: datetime | None = None
    is_active: bool = True


# ---------------------------------------------------------------------------
# PolicySet aliases (canonical names used by service/router layer)
# ---------------------------------------------------------------------------

PolicySet = PolicyRuleSet


class PolicySetCreate(BaseModel):
    """Payload to create a new PolicySet (server assigns ruleset_id)."""

    model_config = ConfigDict(from_attributes=True)

    name: str
    version: str = "1.0.0"
    rules: list[PolicyRule] = Field(default_factory=list)
    is_active: bool = True


class PolicySetUpdate(BaseModel):
    """Partial update to an existing PolicySet; all fields optional."""

    model_config = ConfigDict(from_attributes=True)

    name: str | None = None
    version: str | None = None
    rules: list[PolicyRule] | None = None
    is_active: bool | None = None


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class PolicyCreateRequest(BaseModel):
    """Payload to create or replace the active policy ruleset."""

    model_config = ConfigDict(from_attributes=True)

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

    model_config = ConfigDict(from_attributes=True)

    name: str | None = None
    version: str | None = None
    rules: list[PolicyRule] | None = None
    heuristic_threshold: int | None = Field(None, ge=0, le=100)
    unicode_normalization_enabled: bool | None = None
    enforcement_mode: PolicyEnforcementMode | None = None
    scope: PolicyScope | None = None
    metadata: dict[str, Any] | None = None


class PolicyVerdict(BaseModel):
    """Structured verdict emitted after policy evaluation of a single payload."""

    model_config = ConfigDict(from_attributes=True)

    verdict: PolicyEnforcementMode
    matched_rules: list[PolicyRuleMatch] = Field(default_factory=list)
    severity: PolicySeverity = PolicySeverity.info
    risk_score: int = Field(0, ge=0, le=100)
    reasoning: str | None = None
    categories: list[str] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    policy_version: str | None = None


class PolicyEvaluationResult(BaseModel):
    """Result returned when a payload is evaluated against the active policy.

    Kept for backwards compatibility. New consumers should use PolicyVerdict.
    """

    model_config = ConfigDict(from_attributes=True)

    verdict: PolicyEnforcementMode
    matched_rules: list[str] = Field(default_factory=list, description="rule_ids that matched")
    severity: PolicySeverity = PolicySeverity.info
    risk_score: int = Field(0, ge=0, le=100)
    reasoning: str | None = None
    categories: list[str] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    policy_version: str | None = None


# ---------------------------------------------------------------------------
# Status schema (consumed by /policy/status endpoint)
# ---------------------------------------------------------------------------


class PolicyStatus(BaseModel):
    """Current runtime state of the policy engine."""

    model_config = ConfigDict(from_attributes=True)

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
    tags_index: list[str] = Field(
        default_factory=list,
        description="Union of all tags across active rules",
    )
