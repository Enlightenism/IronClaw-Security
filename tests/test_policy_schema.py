"""
Unit tests for app/schemas/policy.py

Covers:
- PolicyRule field validation (invalid severity, enforcement_mode, missing rule_id)
- PolicyCreateRequest heuristic_threshold bounds (ge=0, le=100)
- PolicyStatus default field population
- PolicyEvaluationResult evaluated_at auto-population
- Enum round-trip serialization for all three enums
"""

from __future__ import annotations

from datetime import datetime

from pydantic import ValidationError
import pytest

from app.schemas.policy import (
    PolicyCreateRequest,
    PolicyEnforcementMode,
    PolicyEvaluationResult,
    PolicyRule,
    PolicyScope,
    PolicySeverity,
    PolicyStatus,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _valid_rule(**overrides) -> dict:
    base: dict = {
        "rule_id": "rule-001",
        "name": "Test Rule",
        "pattern": None,
    }
    base.update(overrides)
    return base


def _minimal_status(**overrides) -> dict:
    base: dict = {
        "heuristic_threshold": 50,
        "unicode_normalization_enabled": True,
    }
    base.update(overrides)
    return base


def _minimal_result(**overrides) -> dict:
    base: dict = {
        "verdict": PolicyEnforcementMode.block,
        "risk_score": 0,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# PolicyRule — field validation
# ---------------------------------------------------------------------------


class TestPolicyRuleValidation:

    def test_valid_rule_minimal(self):
        rule = PolicyRule(**_valid_rule())
        assert rule.rule_id == "rule-001"
        assert rule.name == "Test Rule"
        assert rule.severity == PolicySeverity.medium
        assert rule.enforcement_mode == PolicyEnforcementMode.block
        assert rule.enabled is True

    def test_missing_rule_id_raises(self):
        with pytest.raises(ValidationError) as exc_info:
            PolicyRule(name="No ID Rule", pattern=None)
        errors = exc_info.value.errors()
        fields = {e["loc"][0] for e in errors}
        assert "rule_id" in fields

    def test_missing_name_raises(self):
        with pytest.raises(ValidationError) as exc_info:
            PolicyRule(rule_id="rule-002", pattern=None)
        errors = exc_info.value.errors()
        fields = {e["loc"][0] for e in errors}
        assert "name" in fields

    def test_invalid_severity_raises(self):
        with pytest.raises(ValidationError):
            PolicyRule(**_valid_rule(severity="extreme"))

    def test_invalid_enforcement_mode_raises(self):
        with pytest.raises(ValidationError):
            PolicyRule(**_valid_rule(enforcement_mode="destroy"))

    def test_invalid_scope_raises(self):
        with pytest.raises(ValidationError):
            PolicyRule(**_valid_rule(scope="universe"))

    def test_all_valid_severities_accepted(self):
        for sev in PolicySeverity:
            rule = PolicyRule(**_valid_rule(severity=sev.value))
            assert rule.severity == sev

    def test_all_valid_enforcement_modes_accepted(self):
        for mode in PolicyEnforcementMode:
            rule = PolicyRule(**_valid_rule(enforcement_mode=mode.value))
            assert rule.enforcement_mode == mode

    def test_optional_fields_default_correctly(self):
        rule = PolicyRule(**_valid_rule())
        assert rule.description is None
        assert rule.pattern is None
        assert rule.categories == []
        assert rule.tags == []
        assert rule.metadata == {}
        assert rule.scope == PolicyScope.global_

    def test_rule_with_all_fields(self):
        rule = PolicyRule(
            rule_id="rule-full",
            name="Full Rule",
            description="A complete rule",
            scope=PolicyScope.prompt,
            severity=PolicySeverity.critical,
            enforcement_mode=PolicyEnforcementMode.quarantine,
            pattern=r"(ignore|override)\s+instructions",
            categories=["prompt_injection"],
            enabled=False,
            tags=["high-risk"],
            metadata={"source": "ironclaw"},
        )
        assert rule.rule_id == "rule-full"
        assert rule.scope == PolicyScope.prompt
        assert rule.severity == PolicySeverity.critical
        assert rule.enforcement_mode == PolicyEnforcementMode.quarantine
        assert rule.enabled is False
        assert rule.categories == ["prompt_injection"]
        assert rule.tags == ["high-risk"]


# ---------------------------------------------------------------------------
# PolicyCreateRequest — threshold bounds
# ---------------------------------------------------------------------------


class TestPolicyCreateRequestThreshold:

    def test_default_threshold(self):
        req = PolicyCreateRequest(name="Default Policy")
        assert req.heuristic_threshold == 50

    def test_threshold_boundary_zero(self):
        req = PolicyCreateRequest(name="Zero Threshold", heuristic_threshold=0)
        assert req.heuristic_threshold == 0

    def test_threshold_boundary_one_hundred(self):
        req = PolicyCreateRequest(name="Max Threshold", heuristic_threshold=100)
        assert req.heuristic_threshold == 100

    def test_threshold_midrange(self):
        req = PolicyCreateRequest(name="Mid Threshold", heuristic_threshold=75)
        assert req.heuristic_threshold == 75

    def test_threshold_below_zero_raises(self):
        with pytest.raises(ValidationError) as exc_info:
            PolicyCreateRequest(name="Bad Low", heuristic_threshold=-1)
        errors = exc_info.value.errors()
        fields = {e["loc"][0] for e in errors}
        assert "heuristic_threshold" in fields

    def test_threshold_above_one_hundred_raises(self):
        with pytest.raises(ValidationError) as exc_info:
            PolicyCreateRequest(name="Bad High", heuristic_threshold=101)
        errors = exc_info.value.errors()
        fields = {e["loc"][0] for e in errors}
        assert "heuristic_threshold" in fields

    def test_default_enforcement_mode(self):
        req = PolicyCreateRequest(name="Defaults")
        assert req.enforcement_mode == PolicyEnforcementMode.block

    def test_default_scope(self):
        req = PolicyCreateRequest(name="Defaults")
        assert req.scope == PolicyScope.global_

    def test_default_unicode_normalization(self):
        req = PolicyCreateRequest(name="Defaults")
        assert req.unicode_normalization_enabled is True

    def test_rules_default_empty(self):
        req = PolicyCreateRequest(name="No Rules")
        assert req.rules == []

    def test_metadata_default_empty(self):
        req = PolicyCreateRequest(name="No Meta")
        assert req.metadata == {}


# ---------------------------------------------------------------------------
# PolicyStatus — default field population
# ---------------------------------------------------------------------------


class TestPolicyStatusDefaults:

    def test_required_fields_only(self):
        status = PolicyStatus(**_minimal_status())
        assert status.heuristic_threshold == 50
        assert status.unicode_normalization_enabled is True
        assert status.rule_count == 0
        assert status.policy_loaded_from_db is False
        assert status.enforcement_mode == PolicyEnforcementMode.block
        assert status.scope == PolicyScope.global_
        assert status.enabled_rules == 0
        assert status.disabled_rules == 0
        assert status.tags_index == []
        assert status.severity_counts == {}
        assert status.category_counts == {}
        assert status.active_ruleset_id is None
        assert status.active_ruleset_version is None
        assert status.last_evaluated_at is None
        assert status.last_policy_updated_at is None
        assert status.heuristic_threshold_env is None

    def test_status_threshold_boundary_zero(self):
        status = PolicyStatus(**_minimal_status(heuristic_threshold=0, unicode_normalization_enabled=False))
        assert status.heuristic_threshold == 0

    def test_status_threshold_boundary_one_hundred(self):
        status = PolicyStatus(**_minimal_status(heuristic_threshold=100))
        assert status.heuristic_threshold == 100

    def test_status_threshold_below_zero_raises(self):
        with pytest.raises(ValidationError):
            PolicyStatus(**_minimal_status(heuristic_threshold=-1))

    def test_status_threshold_above_one_hundred_raises(self):
        with pytest.raises(ValidationError):
            PolicyStatus(**_minimal_status(heuristic_threshold=101))

    def test_full_status_population(self):
        now = datetime.utcnow()
        status = PolicyStatus(
            heuristic_threshold=80,
            unicode_normalization_enabled=True,
            rule_count=5,
            policy_loaded_from_db=True,
            enforcement_mode=PolicyEnforcementMode.warn,
            active_ruleset_id="rs-001",
            active_ruleset_version="2.1.0",
            scope=PolicyScope.prompt,
            last_evaluated_at=now,
            last_policy_updated_at=now,
            enabled_rules=4,
            disabled_rules=1,
            tags_index=["pii", "injection"],
            severity_counts={"critical": 2, "high": 3},
            category_counts={"prompt_injection": 2},
            heuristic_threshold_env="IRONCLAW_THRESHOLD",
        )
        assert status.rule_count == 5
        assert status.policy_loaded_from_db is True
        assert status.enforcement_mode == PolicyEnforcementMode.warn
        assert status.active_ruleset_id == "rs-001"
        assert status.scope == PolicyScope.prompt
        assert status.enabled_rules == 4
        assert status.disabled_rules == 1
        assert "pii" in status.tags_index
        assert status.heuristic_threshold_env == "IRONCLAW_THRESHOLD"


# ---------------------------------------------------------------------------
# PolicyEvaluationResult — evaluated_at auto-population
# ---------------------------------------------------------------------------


class TestPolicyEvaluationResultAutoPopulation:

    def test_evaluated_at_auto_populated(self):
        before = datetime.utcnow()
        result = PolicyEvaluationResult(**_minimal_result())
        after = datetime.utcnow()
        assert isinstance(result.evaluated_at, datetime)
        assert before <= result.evaluated_at <= after

    def test_evaluated_at_can_be_overridden(self):
        fixed = datetime(2025, 1, 1, 12, 0, 0)
        result = PolicyEvaluationResult(**_minimal_result(verdict=PolicyEnforcementMode.allow, evaluated_at=fixed))
        assert result.evaluated_at == fixed

    def test_default_severity_is_info(self):
        result = PolicyEvaluationResult(**_minimal_result(verdict=PolicyEnforcementMode.warn))
        assert result.severity == PolicySeverity.info

    def test_default_risk_score_is_zero(self):
        result = PolicyEvaluationResult(**_minimal_result(verdict=PolicyEnforcementMode.quarantine))
        assert result.risk_score == 0

    def test_risk_score_boundary_zero(self):
        result = PolicyEvaluationResult(**_minimal_result(risk_score=0))
        assert result.risk_score == 0

    def test_risk_score_boundary_one_hundred(self):
        result = PolicyEvaluationResult(**_minimal_result(risk_score=100))
        assert result.risk_score == 100

    def test_risk_score_below_zero_raises(self):
        with pytest.raises(ValidationError):
            PolicyEvaluationResult(**_minimal_result(risk_score=-1))

    def test_risk_score_above_one_hundred_raises(self):
        with pytest.raises(ValidationError):
            PolicyEvaluationResult(**_minimal_result(risk_score=101))

    def test_default_collections_empty(self):
        result = PolicyEvaluationResult(**_minimal_result(verdict=PolicyEnforcementMode.audit))
        assert result.matched_rules == []
        assert result.categories == []
        assert result.reasoning is None
        assert result.policy_version is None

    def test_full_result_population(self):
        now = datetime.utcnow()
        result = PolicyEvaluationResult(
            verdict=PolicyEnforcementMode.block,
            risk_score=95,
            matched_rules=["rule-001", "rule-002"],
            severity=PolicySeverity.critical,
            reasoning="Prompt injection pattern matched.",
            categories=["prompt_injection"],
            evaluated_at=now,
            policy_version="3.0.0",
        )
        assert result.verdict == PolicyEnforcementMode.block
        assert "rule-001" in result.matched_rules
        assert result.severity == PolicySeverity.critical
        assert result.risk_score == 95
        assert result.policy_version == "3.0.0"


# ---------------------------------------------------------------------------
# Enum round-trip serialization
# ---------------------------------------------------------------------------


class TestEnumRoundTrip:

    def test_enforcement_mode_round_trip(self):
        for member in PolicyEnforcementMode:
            assert PolicyEnforcementMode(member.value) == member
            assert member.value == member

    def test_scope_round_trip(self):
        for member in PolicyScope:
            assert PolicyScope(member.value) == member
            assert member.value == member

    def test_severity_round_trip(self):
        for member in PolicySeverity:
            assert PolicySeverity(member.value) == member
            assert member.value == member

    def test_enforcement_mode_values(self):
        values = {m.value for m in PolicyEnforcementMode}
        assert values == {"block", "warn", "quarantine", "allow", "audit"}

    def test_scope_values(self):
        values = {m.value for m in PolicyScope}
        assert values == {"prompt", "tool_call", "execution", "response", "global"}

    def test_severity_values(self):
        values = {m.value for m in PolicySeverity}
        assert values == {"critical", "high", "medium", "low", "info"}

    def test_enforcement_mode_serializes_as_string(self):
        rule = PolicyRule(**_valid_rule(enforcement_mode="warn"))
        data = rule.model_dump()
        assert data["enforcement_mode"] == "warn"

    def test_severity_serializes_as_string(self):
        rule = PolicyRule(**_valid_rule(severity="high"))
        data = rule.model_dump()
        assert data["severity"] == "high"

    def test_scope_serializes_as_string(self):
        rule = PolicyRule(**_valid_rule(scope="prompt"))
        data = rule.model_dump()
        assert data["scope"] == "prompt"

    def test_policy_create_request_enum_serialization(self):
        req = PolicyCreateRequest(
            name="Enum Test",
            enforcement_mode=PolicyEnforcementMode.quarantine,
            scope=PolicyScope.tool_call,
        )
        data = req.model_dump()
        assert data["enforcement_mode"] == "quarantine"
        assert data["scope"] == "tool_call"

    def test_evaluation_result_enum_serialization(self):
        result = PolicyEvaluationResult(**_minimal_result(verdict=PolicyEnforcementMode.audit, severity=PolicySeverity.low))
        data = result.model_dump()
        assert data["verdict"] == "audit"
        assert data["severity"] == "low"

    def test_policy_status_enum_serialization(self):
        status = PolicyStatus(
            **_minimal_status(
                heuristic_threshold=25,
                unicode_normalization_enabled=False,
                enforcement_mode=PolicyEnforcementMode.allow,
                scope=PolicyScope.execution,
            )
        )
        data = status.model_dump()
        assert data["enforcement_mode"] == "allow"
        assert data["scope"] == "execution"
