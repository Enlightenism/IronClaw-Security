from __future__ import annotations

from datetime import UTC

from pydantic import ValidationError
import pytest

from app.schemas.policy import (
    PolicyCreateRequest,
    PolicyEnforcementMode,
    PolicyEvaluationResult,
    PolicyRule,
    PolicyRuleCreate,
    PolicyRuleMatch,
    PolicyRuleSet,
    PolicyScope,
    PolicySet,
    PolicySetCreate,
    PolicySetUpdate,
    PolicySeverity,
    PolicyStatus,
    PolicyUpdateRequest,
    PolicyVerdict,
)

# ---------------------------------------------------------------------------
# Enums — complete value coverage
# ---------------------------------------------------------------------------


def test_policy_enforcement_mode_values():
    assert set(PolicyEnforcementMode) == {
        PolicyEnforcementMode.block,
        PolicyEnforcementMode.warn,
        PolicyEnforcementMode.quarantine,
        PolicyEnforcementMode.allow,
        PolicyEnforcementMode.audit,
    }


@pytest.mark.parametrize("value", ["block", "warn", "quarantine", "allow", "audit"])
def test_policy_enforcement_mode_from_string(value):
    assert PolicyEnforcementMode(value).value == value


def test_policy_enforcement_mode_invalid():
    with pytest.raises(ValueError):
        PolicyEnforcementMode("pass")


def test_policy_scope_values():
    assert set(PolicyScope) == {
        PolicyScope.prompt,
        PolicyScope.tool_call,
        PolicyScope.execution,
        PolicyScope.response,
        PolicyScope.global_,
    }


@pytest.mark.parametrize("value", ["prompt", "tool_call", "execution", "response", "global"])
def test_policy_scope_from_string(value):
    assert PolicyScope(value).value == value


def test_policy_scope_invalid():
    with pytest.raises(ValueError):
        PolicyScope("network")


def test_policy_severity_values():
    assert set(PolicySeverity) == {
        PolicySeverity.critical,
        PolicySeverity.high,
        PolicySeverity.medium,
        PolicySeverity.low,
        PolicySeverity.info,
    }


@pytest.mark.parametrize("value", ["critical", "high", "medium", "low", "info"])
def test_policy_severity_from_string(value):
    assert PolicySeverity(value).value == value


def test_policy_severity_invalid():
    with pytest.raises(ValueError):
        PolicySeverity("fatal")


# ---------------------------------------------------------------------------
# PolicyRule — required fields and defaults
# ---------------------------------------------------------------------------

_BASE_RULE = dict(rule_id="rule-001", name="Test Rule")


def test_policy_rule_required_fields():
    rule = PolicyRule(**_BASE_RULE)
    assert rule.rule_id == "rule-001"
    assert rule.name == "Test Rule"


def test_policy_rule_defaults():
    rule = PolicyRule(**_BASE_RULE)
    assert rule.description is None
    assert rule.scope == PolicyScope.global_
    assert rule.severity == PolicySeverity.medium
    assert rule.enforcement_mode == PolicyEnforcementMode.block
    assert rule.pattern is None
    assert rule.categories == []
    assert rule.enabled is True
    assert rule.tags == []
    assert rule.metadata == {}


def test_policy_rule_missing_rule_id_rejected():
    with pytest.raises(ValidationError):
        PolicyRule(name="No ID Rule")


def test_policy_rule_missing_name_rejected():
    with pytest.raises(ValidationError):
        PolicyRule(rule_id="rule-002")


def test_policy_rule_full_construction():
    rule = PolicyRule(
        rule_id="rule-003",
        name="Full Rule",
        description="Blocks injection",
        scope=PolicyScope.prompt,
        severity=PolicySeverity.critical,
        enforcement_mode=PolicyEnforcementMode.block,
        pattern=r"ignore previous instructions",
        categories=["injection"],
        enabled=False,
        tags=["high-risk"],
        metadata={"source": "ironclaw"},
    )
    assert rule.scope == PolicyScope.prompt
    assert rule.severity == PolicySeverity.critical
    assert rule.enabled is False
    assert rule.tags == ["high-risk"]


def test_policy_rule_orm_compat():
    assert PolicyRule.model_config.get("from_attributes") is True


# ---------------------------------------------------------------------------
# PolicyRuleCreate — no rule_id field
# ---------------------------------------------------------------------------


def test_policy_rule_create_no_rule_id():
    create = PolicyRuleCreate(name="New Rule")
    assert not hasattr(create, "rule_id") or "rule_id" not in create.model_fields
    assert create.name == "New Rule"


def test_policy_rule_create_defaults():
    create = PolicyRuleCreate(name="New Rule")
    assert create.scope == PolicyScope.global_
    assert create.severity == PolicySeverity.medium
    assert create.enforcement_mode == PolicyEnforcementMode.block
    assert create.pattern is None
    assert create.categories == []
    assert create.enabled is True
    assert create.tags == []
    assert create.metadata == {}


def test_policy_rule_create_missing_name_rejected():
    with pytest.raises(ValidationError):
        PolicyRuleCreate()


def test_policy_rule_create_orm_compat():
    assert PolicyRuleCreate.model_config.get("from_attributes") is True


# ---------------------------------------------------------------------------
# PolicyRuleMatch — shape validation
# ---------------------------------------------------------------------------

_BASE_MATCH = dict(
    rule_id="rule-001",
    name="Injection Rule",
    severity=PolicySeverity.high,
    enforcement_mode=PolicyEnforcementMode.block,
)


def test_policy_rule_match_required_fields():
    match = PolicyRuleMatch(**_BASE_MATCH)
    assert match.rule_id == "rule-001"
    assert match.name == "Injection Rule"
    assert match.severity == PolicySeverity.high
    assert match.enforcement_mode == PolicyEnforcementMode.block


def test_policy_rule_match_defaults():
    match = PolicyRuleMatch(**_BASE_MATCH)
    assert match.pattern is None
    assert match.categories == []
    assert match.matched_text is None
    assert match.tags == []


def test_policy_rule_match_with_matched_text():
    match = PolicyRuleMatch(**{**_BASE_MATCH, "matched_text": "ignore previous"})
    assert match.matched_text == "ignore previous"


def test_policy_rule_match_missing_severity_rejected():
    with pytest.raises(ValidationError):
        PolicyRuleMatch(rule_id="r1", name="x", enforcement_mode=PolicyEnforcementMode.block)


def test_policy_rule_match_missing_enforcement_mode_rejected():
    with pytest.raises(ValidationError):
        PolicyRuleMatch(rule_id="r1", name="x", severity=PolicySeverity.high)


def test_policy_rule_match_orm_compat():
    assert PolicyRuleMatch.model_config.get("from_attributes") is True


# ---------------------------------------------------------------------------
# PolicySet is alias of PolicyRuleSet
# ---------------------------------------------------------------------------


def test_policy_set_is_alias_of_policy_ruleset():
    assert PolicySet is PolicyRuleSet


def test_policy_set_alias_instantiates_correctly():
    ps = PolicySet(ruleset_id="rs-001", name="Default Set")
    assert isinstance(ps, PolicyRuleSet)
    assert ps.ruleset_id == "rs-001"
    assert ps.name == "Default Set"
    assert ps.version == "1.0.0"
    assert ps.rules == []
    assert ps.is_active is True
    assert ps.created_at is None
    assert ps.updated_at is None


# ---------------------------------------------------------------------------
# PolicySetCreate — field contracts
# ---------------------------------------------------------------------------


def test_policy_set_create_minimal():
    create = PolicySetCreate(name="My Set")
    assert create.name == "My Set"
    assert create.version == "1.0.0"
    assert create.rules == []
    assert create.is_active is True


def test_policy_set_create_with_rules():
    rule = PolicyRule(**_BASE_RULE)
    create = PolicySetCreate(name="Set With Rules", rules=[rule])
    assert len(create.rules) == 1
    assert create.rules[0].rule_id == "rule-001"


def test_policy_set_create_missing_name_rejected():
    with pytest.raises(ValidationError):
        PolicySetCreate()


def test_policy_set_create_orm_compat():
    assert PolicySetCreate.model_config.get("from_attributes") is True


# ---------------------------------------------------------------------------
# PolicySetUpdate — all fields optional
# ---------------------------------------------------------------------------


def test_policy_set_update_all_none():
    update = PolicySetUpdate()
    assert update.name is None
    assert update.version is None
    assert update.rules is None
    assert update.is_active is None


def test_policy_set_update_partial():
    update = PolicySetUpdate(name="Updated Name", is_active=False)
    assert update.name == "Updated Name"
    assert update.is_active is False
    assert update.version is None
    assert update.rules is None


def test_policy_set_update_with_rules():
    rule = PolicyRule(**_BASE_RULE)
    update = PolicySetUpdate(rules=[rule])
    assert len(update.rules) == 1


def test_policy_set_update_orm_compat():
    assert PolicySetUpdate.model_config.get("from_attributes") is True


# ---------------------------------------------------------------------------
# PolicyVerdict — risk_score bounds + auto-timestamp with timezone
# ---------------------------------------------------------------------------

_BASE_VERDICT = dict(verdict=PolicyEnforcementMode.allow)


def test_policy_verdict_minimal():
    v = PolicyVerdict(**_BASE_VERDICT)
    assert v.verdict == PolicyEnforcementMode.allow
    assert v.risk_score == 0
    assert v.severity == PolicySeverity.info
    assert v.matched_rules == []
    assert v.categories == []
    assert v.reasoning is None
    assert v.policy_version is None


def test_policy_verdict_auto_timestamp_is_timezone_aware():
    v = PolicyVerdict(**_BASE_VERDICT)
    assert v.evaluated_at.tzinfo is not None
    assert v.evaluated_at.tzinfo == UTC


def test_policy_verdict_explicit_timestamp_preserved():
    from datetime import datetime

    ts = datetime(2026, 6, 16, 10, 0, 0, tzinfo=UTC)
    v = PolicyVerdict(**{**_BASE_VERDICT, "evaluated_at": ts})
    assert v.evaluated_at == ts


def test_policy_verdict_risk_score_zero():
    v = PolicyVerdict(**{**_BASE_VERDICT, "risk_score": 0})
    assert v.risk_score == 0


def test_policy_verdict_risk_score_max():
    v = PolicyVerdict(**{**_BASE_VERDICT, "risk_score": 100})
    assert v.risk_score == 100


def test_policy_verdict_risk_score_below_zero_rejected():
    with pytest.raises(ValidationError):
        PolicyVerdict(**{**_BASE_VERDICT, "risk_score": -1})


def test_policy_verdict_risk_score_above_100_rejected():
    with pytest.raises(ValidationError):
        PolicyVerdict(**{**_BASE_VERDICT, "risk_score": 101})


@pytest.mark.parametrize("mode", list(PolicyEnforcementMode))
def test_policy_verdict_all_enforcement_modes(mode):
    v = PolicyVerdict(verdict=mode)
    assert v.verdict == mode


def test_policy_verdict_with_matched_rules():
    match = PolicyRuleMatch(**_BASE_MATCH)
    v = PolicyVerdict(verdict=PolicyEnforcementMode.block, matched_rules=[match])
    assert len(v.matched_rules) == 1
    assert v.matched_rules[0].rule_id == "rule-001"


def test_policy_verdict_orm_compat():
    assert PolicyVerdict.model_config.get("from_attributes") is True


# ---------------------------------------------------------------------------
# PolicyEvaluationResult — backwards compatibility
# ---------------------------------------------------------------------------

_BASE_EVAL = dict(verdict=PolicyEnforcementMode.warn)


def test_policy_evaluation_result_minimal():
    r = PolicyEvaluationResult(**_BASE_EVAL)
    assert r.verdict == PolicyEnforcementMode.warn
    assert r.matched_rules == []
    assert r.severity == PolicySeverity.info
    assert r.risk_score == 0
    assert r.reasoning is None
    assert r.categories == []
    assert r.policy_version is None


def test_policy_evaluation_result_matched_rules_are_strings():
    r = PolicyEvaluationResult(
        verdict=PolicyEnforcementMode.block,
        matched_rules=["rule-001", "rule-002"],
    )
    assert r.matched_rules == ["rule-001", "rule-002"]
    assert all(isinstance(rid, str) for rid in r.matched_rules)


def test_policy_evaluation_result_auto_timestamp_timezone_aware():
    r = PolicyEvaluationResult(**_BASE_EVAL)
    assert r.evaluated_at.tzinfo is not None


def test_policy_evaluation_result_risk_score_bounds():
    r = PolicyEvaluationResult(**{**_BASE_EVAL, "risk_score": 75})
    assert r.risk_score == 75


def test_policy_evaluation_result_risk_score_below_zero_rejected():
    with pytest.raises(ValidationError):
        PolicyEvaluationResult(**{**_BASE_EVAL, "risk_score": -1})


def test_policy_evaluation_result_risk_score_above_100_rejected():
    with pytest.raises(ValidationError):
        PolicyEvaluationResult(**{**_BASE_EVAL, "risk_score": 101})


def test_policy_evaluation_result_orm_compat():
    assert PolicyEvaluationResult.model_config.get("from_attributes") is True


# ---------------------------------------------------------------------------
# PolicyCreateRequest — threshold bounds + defaults
# ---------------------------------------------------------------------------


def test_policy_create_request_minimal():
    req = PolicyCreateRequest(name="Prod Policy")
    assert req.name == "Prod Policy"
    assert req.version == "1.0.0"
    assert req.heuristic_threshold == 50
    assert req.unicode_normalization_enabled is True
    assert req.enforcement_mode == PolicyEnforcementMode.block
    assert req.scope == PolicyScope.global_
    assert req.rules == []
    assert req.metadata == {}


def test_policy_create_request_threshold_zero():
    req = PolicyCreateRequest(name="Zero Threshold", heuristic_threshold=0)
    assert req.heuristic_threshold == 0


def test_policy_create_request_threshold_max():
    req = PolicyCreateRequest(name="Max Threshold", heuristic_threshold=100)
    assert req.heuristic_threshold == 100


def test_policy_create_request_threshold_below_zero_rejected():
    with pytest.raises(ValidationError):
        PolicyCreateRequest(name="Bad", heuristic_threshold=-1)


def test_policy_create_request_threshold_above_100_rejected():
    with pytest.raises(ValidationError):
        PolicyCreateRequest(name="Bad", heuristic_threshold=101)


def test_policy_create_request_missing_name_rejected():
    with pytest.raises(ValidationError):
        PolicyCreateRequest()


def test_policy_create_request_orm_compat():
    assert PolicyCreateRequest.model_config.get("from_attributes") is True


# ---------------------------------------------------------------------------
# PolicyUpdateRequest — all fields optional + threshold bounds
# ---------------------------------------------------------------------------


def test_policy_update_request_all_none():
    req = PolicyUpdateRequest()
    assert req.name is None
    assert req.version is None
    assert req.rules is None
    assert req.heuristic_threshold is None
    assert req.unicode_normalization_enabled is None
    assert req.enforcement_mode is None
    assert req.scope is None
    assert req.metadata is None


def test_policy_update_request_partial():
    req = PolicyUpdateRequest(name="Updated", enforcement_mode=PolicyEnforcementMode.warn)
    assert req.name == "Updated"
    assert req.enforcement_mode == PolicyEnforcementMode.warn
    assert req.heuristic_threshold is None


def test_policy_update_request_threshold_bounds():
    req = PolicyUpdateRequest(heuristic_threshold=75)
    assert req.heuristic_threshold == 75


def test_policy_update_request_threshold_below_zero_rejected():
    with pytest.raises(ValidationError):
        PolicyUpdateRequest(heuristic_threshold=-1)


def test_policy_update_request_threshold_above_100_rejected():
    with pytest.raises(ValidationError):
        PolicyUpdateRequest(heuristic_threshold=101)


def test_policy_update_request_orm_compat():
    assert PolicyUpdateRequest.model_config.get("from_attributes") is True


# ---------------------------------------------------------------------------
# PolicyStatus — field contracts
# ---------------------------------------------------------------------------


_BASE_STATUS = dict(
    heuristic_threshold=50,
    unicode_normalization_enabled=True,
)


def test_policy_status_minimal():
    s = PolicyStatus(**_BASE_STATUS)
    assert s.heuristic_threshold == 50
    assert s.unicode_normalization_enabled is True
    assert s.rule_count == 0
    assert s.policy_loaded_from_db is False
    assert s.enforcement_mode == PolicyEnforcementMode.block
    assert s.scope == PolicyScope.global_
    assert s.enabled_rules == 0
    assert s.disabled_rules == 0
    assert s.tags_index == []
    assert s.severity_counts == {}
    assert s.category_counts == {}
    assert s.active_ruleset_id is None
    assert s.active_ruleset_version is None
    assert s.last_evaluated_at is None
    assert s.last_policy_updated_at is None


def test_policy_status_threshold_zero():
    s = PolicyStatus(heuristic_threshold=0, unicode_normalization_enabled=False)
    assert s.heuristic_threshold == 0


def test_policy_status_threshold_max():
    s = PolicyStatus(heuristic_threshold=100, unicode_normalization_enabled=True)
    assert s.heuristic_threshold == 100


def test_policy_status_threshold_below_zero_rejected():
    with pytest.raises(ValidationError):
        PolicyStatus(heuristic_threshold=-1, unicode_normalization_enabled=True)


def test_policy_status_threshold_above_100_rejected():
    with pytest.raises(ValidationError):
        PolicyStatus(heuristic_threshold=101, unicode_normalization_enabled=True)


def test_policy_status_missing_threshold_rejected():
    with pytest.raises(ValidationError):
        PolicyStatus(unicode_normalization_enabled=True)


def test_policy_status_missing_unicode_flag_rejected():
    with pytest.raises(ValidationError):
        PolicyStatus(heuristic_threshold=50)


def test_policy_status_full_construction():
    from datetime import datetime

    now = datetime.now(UTC)
    s = PolicyStatus(
        heuristic_threshold=75,
        heuristic_threshold_env="IRONCLAW_HEURISTIC_THRESHOLD",
        unicode_normalization_enabled=True,
        rule_count=10,
        policy_loaded_from_db=True,
        enforcement_mode=PolicyEnforcementMode.quarantine,
        active_ruleset_id="rs-001",
        active_ruleset_version="2.0.0",
        scope=PolicyScope.prompt,
        last_evaluated_at=now,
        last_policy_updated_at=now,
        enabled_rules=9,
        disabled_rules=1,
        tags_index=["injection", "exfil"],
        severity_counts={"critical": 2, "high": 3},
        category_counts={"injection": 5},
    )
    assert s.rule_count == 10
    assert s.policy_loaded_from_db is True
    assert s.enforcement_mode == PolicyEnforcementMode.quarantine
    assert s.active_ruleset_id == "rs-001"
    assert s.scope == PolicyScope.prompt
    assert s.enabled_rules == 9
    assert s.disabled_rules == 1
    assert "injection" in s.tags_index
    assert s.severity_counts["critical"] == 2


def test_policy_status_orm_compat():
    assert PolicyStatus.model_config.get("from_attributes") is True
