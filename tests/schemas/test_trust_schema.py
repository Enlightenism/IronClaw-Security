from __future__ import annotations

from datetime import UTC, datetime

from pydantic import ValidationError
import pytest

from app.schemas.trust import (
    TrustAccessControlsSchema,
    TrustAccessCountsSchema,
    TrustAccessSummaryResponse,
    TrustDecayConfig,
    TrustDecayStrategy,
    TrustEvent,
    TrustEventCreate,
    TrustEventListResponse,
    TrustEventResponse,
    TrustEventType,
    TrustOutcome,
    TrustProfile,
    TrustProfileCreate,
    TrustProfileListResponse,
    TrustProfileResponse,
    TrustProfileUpdate,
    TrustQueryParams,
    TrustScore,
    TrustTier,
    _score_to_tier,
)

# ---------------------------------------------------------------------------
# TrustEventType — complete group coverage
# ---------------------------------------------------------------------------


def test_trust_event_type_positive_group():
    expected = {
        TrustEventType.ACTION_APPROVED,
        TrustEventType.ACTION_COMPLETED_CLEANLY,
        TrustEventType.SCAN_PASSED,
        TrustEventType.POLICY_COMPLIANT,
        TrustEventType.REVIEW_APPROVED,
        TrustEventType.AUTH_SUCCESS,
        TrustEventType.AGENT_REGISTERED,
        TrustEventType.SESSION_CLEAN,
    }
    actual = {
        e
        for e in TrustEventType
        if e.value
        in {
            "action.approved",
            "action.completed_cleanly",
            "scan.passed",
            "policy.compliant",
            "review.approved",
            "auth.success",
            "agent.registered",
            "session.clean",
        }
    }
    assert actual == expected


def test_trust_event_type_negative_group():
    expected = {
        TrustEventType.PROMPT_INJECTION_DETECTED,
        TrustEventType.TOOL_CALL_BLOCKED,
        TrustEventType.TOOL_CALL_QUARANTINED,
        TrustEventType.ACTION_BLOCKED,
        TrustEventType.ACTION_QUARANTINED,
        TrustEventType.ACTION_FAILED,
        TrustEventType.POLICY_VIOLATION,
        TrustEventType.SCAN_BLOCKED,
        TrustEventType.SCAN_QUARANTINED,
        TrustEventType.DATA_LEAKAGE_DETECTED,
        TrustEventType.DATA_EXPORT_BLOCKED,
        TrustEventType.AUTH_FAILURE,
        TrustEventType.AUTH_RATE_LIMITED,
        TrustEventType.REVIEW_REJECTED,
        TrustEventType.ANOMALY_DETECTED,
        TrustEventType.THREAT_DETECTED,
        TrustEventType.ATTACK_SEQUENCE_IDENTIFIED,
    }
    actual = {
        e
        for e in TrustEventType
        if e.value
        in {
            "prompt.injection_detected",
            "tool_call.blocked",
            "tool_call.quarantined",
            "action.blocked",
            "action.quarantined",
            "action.failed",
            "policy.violation",
            "scan.blocked",
            "scan.quarantined",
            "data.leakage_detected",
            "data.export_blocked",
            "auth.failure",
            "auth.rate_limited",
            "review.rejected",
            "anomaly.detected",
            "threat.detected",
            "attack.sequence_identified",
        }
    }
    assert actual == expected


def test_trust_event_type_control_group():
    expected = {
        TrustEventType.PROFILE_LOCKED,
        TrustEventType.PROFILE_UNLOCKED,
        TrustEventType.PROFILE_RESET,
        TrustEventType.TRUST_RESTORED,
        TrustEventType.TRUST_MANUALLY_ADJUSTED,
        TrustEventType.DECAY_APPLIED,
        TrustEventType.SESSION_ENDED,
    }
    actual = {e for e in TrustEventType if e.value.startswith("profile.") or e.value.startswith("trust.") or e.value.startswith("decay.") or e.value == "session.ended"}
    assert actual == expected


def test_trust_event_type_meta_group():
    assert TrustEventType.UNKNOWN == TrustEventType("unknown")


def test_trust_event_type_invalid():
    with pytest.raises(ValueError):
        TrustEventType("not.a.real.event")


@pytest.mark.parametrize("member", list(TrustEventType))
def test_trust_event_type_all_round_trip(member):
    assert TrustEventType(member.value) == member


# ---------------------------------------------------------------------------
# TrustTier — complete coverage
# ---------------------------------------------------------------------------


def test_trust_tier_values():
    assert set(TrustTier) == {
        TrustTier.CRITICAL,
        TrustTier.LOW,
        TrustTier.MODERATE,
        TrustTier.HIGH,
        TrustTier.FULL,
    }


@pytest.mark.parametrize("value", ["critical", "low", "moderate", "high", "full"])
def test_trust_tier_from_string(value):
    assert TrustTier(value).value == value


def test_trust_tier_invalid():
    with pytest.raises(ValueError):
        TrustTier("extreme")


# ---------------------------------------------------------------------------
# TrustOutcome — complete coverage
# ---------------------------------------------------------------------------


def test_trust_outcome_values():
    assert set(TrustOutcome) == {
        TrustOutcome.INCREASED,
        TrustOutcome.DECREASED,
        TrustOutcome.LOCKED,
        TrustOutcome.UNLOCKED,
        TrustOutcome.RESET,
        TrustOutcome.UNCHANGED,
        TrustOutcome.DECAYED,
    }


@pytest.mark.parametrize(
    "value",
    ["increased", "decreased", "locked", "unlocked", "reset", "unchanged", "decayed"],
)
def test_trust_outcome_from_string(value):
    assert TrustOutcome(value).value == value


def test_trust_outcome_invalid():
    with pytest.raises(ValueError):
        TrustOutcome("blocked")


# ---------------------------------------------------------------------------
# TrustDecayStrategy — complete coverage
# ---------------------------------------------------------------------------


def test_trust_decay_strategy_values():
    assert set(TrustDecayStrategy) == {
        TrustDecayStrategy.LINEAR,
        TrustDecayStrategy.EXPONENTIAL,
        TrustDecayStrategy.STEP,
        TrustDecayStrategy.NONE,
    }


@pytest.mark.parametrize("value", ["linear", "exponential", "step", "none"])
def test_trust_decay_strategy_from_string(value):
    assert TrustDecayStrategy(value).value == value


def test_trust_decay_strategy_invalid():
    with pytest.raises(ValueError):
        TrustDecayStrategy("gradient")


# ---------------------------------------------------------------------------
# _score_to_tier — boundary tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "score,expected_tier",
    [
        (0, TrustTier.CRITICAL),
        (19, TrustTier.CRITICAL),
        (20, TrustTier.LOW),
        (39, TrustTier.LOW),
        (40, TrustTier.MODERATE),
        (59, TrustTier.MODERATE),
        (60, TrustTier.HIGH),
        (79, TrustTier.HIGH),
        (80, TrustTier.FULL),
        (100, TrustTier.FULL),
    ],
)
def test_score_to_tier_boundaries(score, expected_tier):
    assert _score_to_tier(score) == expected_tier


# ---------------------------------------------------------------------------
# TrustScore — required fields, tier auto-derivation, defaults
# ---------------------------------------------------------------------------

_BASE_SCORE = dict(agent_id="agent-001", score=75)


def test_trust_score_minimal():
    s = TrustScore(**_BASE_SCORE)
    assert s.agent_id == "agent-001"
    assert s.score == 75


def test_trust_score_tier_derived_from_score():
    s = TrustScore(agent_id="agent-001", score=75)
    assert s.tier == TrustTier.HIGH


def test_trust_score_tier_derived_critical():
    s = TrustScore(agent_id="agent-001", score=10)
    assert s.tier == TrustTier.CRITICAL


def test_trust_score_tier_derived_low():
    s = TrustScore(agent_id="agent-001", score=25)
    assert s.tier == TrustTier.LOW


def test_trust_score_tier_derived_moderate():
    s = TrustScore(agent_id="agent-001", score=50)
    assert s.tier == TrustTier.MODERATE


def test_trust_score_tier_derived_full():
    s = TrustScore(agent_id="agent-001", score=100)
    assert s.tier == TrustTier.FULL


def test_trust_score_previous_score_default_none():
    s = TrustScore(**_BASE_SCORE)
    assert s.previous_score is None


def test_trust_score_delta_default_none():
    s = TrustScore(**_BASE_SCORE)
    assert s.delta is None


def test_trust_score_evaluated_at_defaults_utc():
    s = TrustScore(**_BASE_SCORE)
    assert s.evaluated_at is not None
    assert s.evaluated_at.tzinfo is not None


def test_trust_score_missing_agent_id_rejected():
    with pytest.raises(ValidationError):
        TrustScore(score=75)


def test_trust_score_missing_score_rejected():
    with pytest.raises(ValidationError):
        TrustScore(agent_id="agent-001")


def test_trust_score_score_below_zero_rejected():
    with pytest.raises(ValidationError):
        TrustScore(agent_id="agent-001", score=-1)


def test_trust_score_score_above_100_rejected():
    with pytest.raises(ValidationError):
        TrustScore(agent_id="agent-001", score=101)


def test_trust_score_score_boundaries_accepted():
    s_min = TrustScore(agent_id="agent-001", score=0)
    s_max = TrustScore(agent_id="agent-001", score=100)
    assert s_min.score == 0
    assert s_max.score == 100


def test_trust_score_full_construction():
    ts = datetime(2026, 6, 16, 10, 0, 0, tzinfo=UTC)
    s = TrustScore(
        agent_id="agent-001",
        score=65,
        previous_score=80,
        delta=-15,
        evaluated_at=ts,
    )
    assert s.tier == TrustTier.HIGH
    assert s.previous_score == 80
    assert s.delta == -15
    assert s.evaluated_at == ts


# ---------------------------------------------------------------------------
# TrustDecayConfig — field validation
# ---------------------------------------------------------------------------


def test_trust_decay_config_defaults():
    c = TrustDecayConfig()
    assert c.agent_id is None
    assert c.strategy == TrustDecayStrategy.LINEAR
    assert c.decay_rate == 1.0
    assert c.decay_interval_hours == 24.0
    assert c.min_score_floor == 0
    assert c.exponential_base == 0.99
    assert c.enabled is True
    assert c.metadata == {}


def test_trust_decay_config_negative_decay_rate_rejected():
    with pytest.raises(ValidationError):
        TrustDecayConfig(decay_rate=-0.1)


def test_trust_decay_config_zero_decay_rate_accepted():
    c = TrustDecayConfig(decay_rate=0.0)
    assert c.decay_rate == 0.0


def test_trust_decay_config_decay_rate_above_100_rejected():
    with pytest.raises(ValidationError):
        TrustDecayConfig(decay_rate=100.1)


def test_trust_decay_config_decay_interval_hours_zero_rejected():
    with pytest.raises(ValidationError):
        TrustDecayConfig(decay_interval_hours=0.0)


def test_trust_decay_config_decay_interval_hours_negative_rejected():
    with pytest.raises(ValidationError):
        TrustDecayConfig(decay_interval_hours=-1.0)


def test_trust_decay_config_decay_interval_hours_positive_accepted():
    c = TrustDecayConfig(decay_interval_hours=12.0)
    assert c.decay_interval_hours == 12.0


def test_trust_decay_config_exponential_base_zero_rejected():
    with pytest.raises(ValidationError):
        TrustDecayConfig(exponential_base=0.0)


def test_trust_decay_config_exponential_base_above_one_rejected():
    with pytest.raises(ValidationError):
        TrustDecayConfig(exponential_base=1.01)


def test_trust_decay_config_exponential_base_one_accepted():
    c = TrustDecayConfig(exponential_base=1.0)
    assert c.exponential_base == 1.0


def test_trust_decay_config_min_score_floor_below_zero_rejected():
    with pytest.raises(ValidationError):
        TrustDecayConfig(min_score_floor=-1)


def test_trust_decay_config_min_score_floor_above_100_rejected():
    with pytest.raises(ValidationError):
        TrustDecayConfig(min_score_floor=101)


def test_trust_decay_config_min_score_floor_boundaries_accepted():
    c_min = TrustDecayConfig(min_score_floor=0)
    c_max = TrustDecayConfig(min_score_floor=100)
    assert c_min.min_score_floor == 0
    assert c_max.min_score_floor == 100


def test_trust_decay_config_all_strategies_accepted():
    for strategy in TrustDecayStrategy:
        c = TrustDecayConfig(strategy=strategy)
        assert c.strategy == strategy


def test_trust_decay_config_full_construction():
    c = TrustDecayConfig(
        agent_id="agent-001",
        strategy=TrustDecayStrategy.EXPONENTIAL,
        decay_rate=2.5,
        decay_interval_hours=6.0,
        min_score_floor=10,
        exponential_base=0.95,
        enabled=False,
        metadata={"source": "policy-engine"},
    )
    assert c.agent_id == "agent-001"
    assert c.strategy == TrustDecayStrategy.EXPONENTIAL
    assert c.decay_rate == 2.5
    assert c.min_score_floor == 10
    assert c.enabled is False
    assert c.metadata["source"] == "policy-engine"


# ---------------------------------------------------------------------------
# TrustEventCreate — required-field enforcement and bounds
# ---------------------------------------------------------------------------

_BASE_EVENT_CREATE = dict(
    agent_id="agent-001",
    event_type=TrustEventType.ANOMALY_DETECTED,
    score_delta=-10,
    outcome=TrustOutcome.DECREASED,
)


def test_trust_event_create_minimal():
    ev = TrustEventCreate(**_BASE_EVENT_CREATE)
    assert ev.agent_id == "agent-001"
    assert ev.event_type == TrustEventType.ANOMALY_DETECTED
    assert ev.score_delta == -10
    assert ev.outcome == TrustOutcome.DECREASED


def test_trust_event_create_missing_agent_id_rejected():
    payload = {k: v for k, v in _BASE_EVENT_CREATE.items() if k != "agent_id"}
    with pytest.raises(ValidationError):
        TrustEventCreate(**payload)


def test_trust_event_create_missing_event_type_rejected():
    payload = {k: v for k, v in _BASE_EVENT_CREATE.items() if k != "event_type"}
    with pytest.raises(ValidationError):
        TrustEventCreate(**payload)


def test_trust_event_create_missing_score_delta_rejected():
    payload = {k: v for k, v in _BASE_EVENT_CREATE.items() if k != "score_delta"}
    with pytest.raises(ValidationError):
        TrustEventCreate(**payload)


def test_trust_event_create_missing_outcome_rejected():
    payload = {k: v for k, v in _BASE_EVENT_CREATE.items() if k != "outcome"}
    with pytest.raises(ValidationError):
        TrustEventCreate(**payload)


def test_trust_event_create_empty_agent_id_rejected():
    with pytest.raises(ValidationError):
        TrustEventCreate(**{**_BASE_EVENT_CREATE, "agent_id": ""})


def test_trust_event_create_agent_id_too_long_rejected():
    with pytest.raises(ValidationError):
        TrustEventCreate(**{**_BASE_EVENT_CREATE, "agent_id": "x" * 513})


def test_trust_event_create_agent_id_max_boundary_accepted():
    ev = TrustEventCreate(**{**_BASE_EVENT_CREATE, "agent_id": "x" * 512})
    assert len(ev.agent_id) == 512


def test_trust_event_create_score_delta_min_boundary():
    ev = TrustEventCreate(**{**_BASE_EVENT_CREATE, "score_delta": -100})
    assert ev.score_delta == -100


def test_trust_event_create_score_delta_max_boundary():
    ev = TrustEventCreate(**{**_BASE_EVENT_CREATE, "score_delta": 100})
    assert ev.score_delta == 100


def test_trust_event_create_score_delta_below_min_rejected():
    with pytest.raises(ValidationError):
        TrustEventCreate(**{**_BASE_EVENT_CREATE, "score_delta": -101})


def test_trust_event_create_score_delta_above_max_rejected():
    with pytest.raises(ValidationError):
        TrustEventCreate(**{**_BASE_EVENT_CREATE, "score_delta": 101})


def test_trust_event_create_zero_delta_accepted():
    ev = TrustEventCreate(**{**_BASE_EVENT_CREATE, "score_delta": 0, "outcome": TrustOutcome.UNCHANGED})
    assert ev.score_delta == 0


def test_trust_event_create_defaults():
    ev = TrustEventCreate(**_BASE_EVENT_CREATE)
    assert ev.triggered_by is None
    assert ev.triggered_by_type is None
    assert ev.org_id is None
    assert ev.session_id is None
    assert ev.request_id is None
    assert ev.actor is None
    assert ev.reasoning is None
    assert ev.categories == []
    assert ev.tags == []
    assert ev.metadata == {}
    assert ev.created_at is None


def test_trust_event_create_reasoning_too_long_rejected():
    with pytest.raises(ValidationError):
        TrustEventCreate(**{**_BASE_EVENT_CREATE, "reasoning": "x" * 2049})


def test_trust_event_create_reasoning_max_boundary_accepted():
    ev = TrustEventCreate(**{**_BASE_EVENT_CREATE, "reasoning": "x" * 2048})
    assert len(ev.reasoning) == 2048


def test_trust_event_create_full_construction():
    ts = datetime(2026, 6, 16, 10, 0, 0, tzinfo=UTC)
    ev = TrustEventCreate(
        agent_id="agent-xyz",
        event_type=TrustEventType.PROMPT_INJECTION_DETECTED,
        score_delta=-25,
        outcome=TrustOutcome.DECREASED,
        triggered_by="scan-001",
        triggered_by_type="scan",
        org_id="org-001",
        session_id="sess-001",
        request_id="req-001",
        actor="user-abc",
        reasoning="Injection pattern matched critical signature",
        categories=["injection", "critical"],
        tags=["claude", "mcp"],
        metadata={"pattern": "ignore previous instructions"},
        created_at=ts,
    )
    assert ev.score_delta == -25
    assert ev.triggered_by == "scan-001"
    assert ev.categories == ["injection", "critical"]
    assert ev.metadata["pattern"] == "ignore previous instructions"
    assert ev.created_at == ts


@pytest.mark.parametrize("event_type", list(TrustEventType))
def test_trust_event_create_all_event_types_accepted(event_type):
    ev = TrustEventCreate(**{**_BASE_EVENT_CREATE, "event_type": event_type})
    assert ev.event_type == event_type


@pytest.mark.parametrize("outcome", list(TrustOutcome))
def test_trust_event_create_all_outcomes_accepted(outcome):
    ev = TrustEventCreate(**{**_BASE_EVENT_CREATE, "outcome": outcome})
    assert ev.outcome == outcome


# ---------------------------------------------------------------------------
# TrustEvent — read model full round-trip via model_dump
# ---------------------------------------------------------------------------

_BASE_EVENT = dict(
    event_id="tevt-001",
    agent_id="agent-001",
    event_type=TrustEventType.ANOMALY_DETECTED,
    score_before=80,
    score_after=70,
    score_delta=-10,
    outcome=TrustOutcome.DECREASED,
)


def test_trust_event_minimal():
    ev = TrustEvent(**_BASE_EVENT)
    assert ev.event_id == "tevt-001"
    assert ev.agent_id == "agent-001"
    assert ev.score_before == 80
    assert ev.score_after == 70
    assert ev.score_delta == -10
    assert ev.outcome == TrustOutcome.DECREASED


def test_trust_event_defaults():
    ev = TrustEvent(**_BASE_EVENT)
    assert ev.triggered_by is None
    assert ev.triggered_by_type is None
    assert ev.org_id is None
    assert ev.session_id is None
    assert ev.request_id is None
    assert ev.actor is None
    assert ev.reasoning is None
    assert ev.categories == []
    assert ev.tags == []
    assert ev.metadata == {}


def test_trust_event_created_at_defaults_utc():
    ev = TrustEvent(**_BASE_EVENT)
    assert ev.created_at is not None
    assert ev.created_at.tzinfo is not None


def test_trust_event_missing_event_id_rejected():
    payload = {k: v for k, v in _BASE_EVENT.items() if k != "event_id"}
    with pytest.raises(ValidationError):
        TrustEvent(**payload)


def test_trust_event_missing_agent_id_rejected():
    payload = {k: v for k, v in _BASE_EVENT.items() if k != "agent_id"}
    with pytest.raises(ValidationError):
        TrustEvent(**payload)


def test_trust_event_missing_score_before_rejected():
    payload = {k: v for k, v in _BASE_EVENT.items() if k != "score_before"}
    with pytest.raises(ValidationError):
        TrustEvent(**payload)


def test_trust_event_missing_score_after_rejected():
    payload = {k: v for k, v in _BASE_EVENT.items() if k != "score_after"}
    with pytest.raises(ValidationError):
        TrustEvent(**payload)


def test_trust_event_full_round_trip():
    ts = datetime(2026, 6, 16, 10, 0, 0, tzinfo=UTC)
    ev = TrustEvent(
        event_id="tevt-999",
        agent_id="agent-xyz",
        event_type=TrustEventType.THREAT_DETECTED,
        score_before=60,
        score_after=35,
        score_delta=-25,
        outcome=TrustOutcome.DECREASED,
        triggered_by="scan-001",
        triggered_by_type="scan",
        org_id="org-001",
        session_id="sess-001",
        request_id="req-001",
        actor="ironclaw-guard",
        reasoning="Threat signature matched",
        categories=["threat", "high-risk"],
        tags=["mcp", "claude"],
        metadata={"score": 0.97},
        created_at=ts,
    )
    dumped = ev.model_dump()
    restored = TrustEvent(**dumped)
    assert restored.event_id == "tevt-999"
    assert restored.event_type == TrustEventType.THREAT_DETECTED
    assert restored.score_before == 60
    assert restored.score_after == 35
    assert restored.score_delta == -25
    assert restored.outcome == TrustOutcome.DECREASED
    assert restored.categories == ["threat", "high-risk"]
    assert restored.metadata["score"] == 0.97
    assert restored.created_at == ts


def test_trust_event_serializes_to_dict():
    ev = TrustEvent(**_BASE_EVENT)
    d = ev.model_dump()
    assert "event_id" in d
    assert "agent_id" in d
    assert "score_before" in d
    assert "score_after" in d
    assert "score_delta" in d
    assert "outcome" in d
    assert "metadata" in d
    assert "created_at" in d
    assert d["categories"] == []
    assert d["tags"] == []


# ---------------------------------------------------------------------------
# TrustProfile — auto-derivation, defaults, bounds
# ---------------------------------------------------------------------------

_BASE_PROFILE = dict(agent_id="agent-001")


def test_trust_profile_minimal():
    p = TrustProfile(**_BASE_PROFILE)
    assert p.agent_id == "agent-001"
    assert p.trust_score == 100


def test_trust_profile_trust_tier_derived_from_trust_score():
    p = TrustProfile(agent_id="agent-001", trust_score=100)
    assert p.trust_tier == TrustTier.FULL


def test_trust_profile_trust_tier_critical():
    p = TrustProfile(agent_id="agent-001", trust_score=5)
    assert p.trust_tier == TrustTier.CRITICAL


def test_trust_profile_trust_tier_low():
    p = TrustProfile(agent_id="agent-001", trust_score=30)
    assert p.trust_tier == TrustTier.LOW


def test_trust_profile_trust_tier_moderate():
    p = TrustProfile(agent_id="agent-001", trust_score=50)
    assert p.trust_tier == TrustTier.MODERATE


def test_trust_profile_trust_tier_high():
    p = TrustProfile(agent_id="agent-001", trust_score=70)
    assert p.trust_tier == TrustTier.HIGH


def test_trust_profile_profile_locked_default_false():
    p = TrustProfile(**_BASE_PROFILE)
    assert p.profile_locked is False


def test_trust_profile_anomaly_count_default_zero():
    p = TrustProfile(**_BASE_PROFILE)
    assert p.anomaly_count == 0


def test_trust_profile_last_anomaly_at_default_none():
    p = TrustProfile(**_BASE_PROFILE)
    assert p.last_anomaly_at is None


def test_trust_profile_trust_score_below_zero_rejected():
    with pytest.raises(ValidationError):
        TrustProfile(agent_id="agent-001", trust_score=-1)


def test_trust_profile_trust_score_above_100_rejected():
    with pytest.raises(ValidationError):
        TrustProfile(agent_id="agent-001", trust_score=101)


def test_trust_profile_trust_score_boundaries_accepted():
    p_min = TrustProfile(agent_id="agent-001", trust_score=0)
    p_max = TrustProfile(agent_id="agent-001", trust_score=100)
    assert p_min.trust_score == 0
    assert p_max.trust_score == 100


def test_trust_profile_missing_agent_id_rejected():
    with pytest.raises(ValidationError):
        TrustProfile()


def test_trust_profile_empty_agent_id_rejected():
    with pytest.raises(ValidationError):
        TrustProfile(agent_id="")


def test_trust_profile_agent_id_too_long_rejected():
    with pytest.raises(ValidationError):
        TrustProfile(agent_id="x" * 513)


def test_trust_profile_anomaly_count_below_zero_rejected():
    with pytest.raises(ValidationError):
        TrustProfile(agent_id="agent-001", anomaly_count=-1)


def test_trust_profile_total_actions_below_zero_rejected():
    with pytest.raises(ValidationError):
        TrustProfile(agent_id="agent-001", total_actions=-1)


def test_trust_profile_total_blocked_actions_below_zero_rejected():
    with pytest.raises(ValidationError):
        TrustProfile(agent_id="agent-001", total_blocked_actions=-1)


def test_trust_profile_created_at_defaults_utc():
    p = TrustProfile(**_BASE_PROFILE)
    assert p.created_at is not None
    assert p.created_at.tzinfo is not None


def test_trust_profile_full_construction():
    ts = datetime(2026, 6, 16, 10, 0, 0, tzinfo=UTC)
    decay = TrustDecayConfig(strategy=TrustDecayStrategy.EXPONENTIAL, decay_rate=2.0)
    p = TrustProfile(
        agent_id="agent-xyz",
        trust_score=35,
        anomaly_count=7,
        last_anomaly_at=ts,
        profile_locked=True,
        locked_at=ts,
        locked_reason="Critical threat detected",
        lock_expires_at=None,
        org_id="org-001",
        session_id="sess-001",
        consecutive_clean_actions=0,
        total_actions=50,
        total_blocked_actions=7,
        decay_config=decay,
        categories=["high-risk"],
        tags=["mcp"],
        metadata={"env": "production"},
        created_at=ts,
    )
    assert p.trust_tier == TrustTier.LOW
    assert p.anomaly_count == 7
    assert p.profile_locked is True
    assert p.locked_reason == "Critical threat detected"
    assert p.total_blocked_actions == 7
    assert p.decay_config.strategy == TrustDecayStrategy.EXPONENTIAL
    assert p.metadata["env"] == "production"


# ---------------------------------------------------------------------------
# TrustProfileCreate — field enforcement
# ---------------------------------------------------------------------------


def test_trust_profile_create_minimal():
    pc = TrustProfileCreate(agent_id="agent-001")
    assert pc.agent_id == "agent-001"
    assert pc.initial_score == 100


def test_trust_profile_create_missing_agent_id_rejected():
    with pytest.raises(ValidationError):
        TrustProfileCreate()


def test_trust_profile_create_initial_score_below_zero_rejected():
    with pytest.raises(ValidationError):
        TrustProfileCreate(agent_id="agent-001", initial_score=-1)


def test_trust_profile_create_initial_score_above_100_rejected():
    with pytest.raises(ValidationError):
        TrustProfileCreate(agent_id="agent-001", initial_score=101)


def test_trust_profile_create_initial_score_boundaries_accepted():
    pc_min = TrustProfileCreate(agent_id="agent-001", initial_score=0)
    pc_max = TrustProfileCreate(agent_id="agent-001", initial_score=100)
    assert pc_min.initial_score == 0
    assert pc_max.initial_score == 100


def test_trust_profile_create_defaults():
    pc = TrustProfileCreate(agent_id="agent-001")
    assert pc.org_id is None
    assert pc.session_id is None
    assert pc.decay_config is None
    assert pc.categories == []
    assert pc.tags == []
    assert pc.metadata == {}


# ---------------------------------------------------------------------------
# TrustProfileUpdate — field enforcement
# ---------------------------------------------------------------------------


def test_trust_profile_update_all_optional():
    pu = TrustProfileUpdate()
    assert pu.trust_score is None
    assert pu.profile_locked is None
    assert pu.locked_reason is None
    assert pu.lock_expires_at is None
    assert pu.org_id is None
    assert pu.session_id is None
    assert pu.decay_config is None
    assert pu.categories is None
    assert pu.tags is None
    assert pu.metadata is None


def test_trust_profile_update_trust_score_below_zero_rejected():
    with pytest.raises(ValidationError):
        TrustProfileUpdate(trust_score=-1)


def test_trust_profile_update_trust_score_above_100_rejected():
    with pytest.raises(ValidationError):
        TrustProfileUpdate(trust_score=101)


def test_trust_profile_update_trust_score_boundaries_accepted():
    pu_min = TrustProfileUpdate(trust_score=0)
    pu_max = TrustProfileUpdate(trust_score=100)
    assert pu_min.trust_score == 0
    assert pu_max.trust_score == 100


def test_trust_profile_update_partial_fields():
    pu = TrustProfileUpdate(
        profile_locked=True,
        locked_reason="Manual lock",
        tags=["quarantine"],
    )
    assert pu.profile_locked is True
    assert pu.locked_reason == "Manual lock"
    assert pu.tags == ["quarantine"]
    assert pu.trust_score is None


# ---------------------------------------------------------------------------
# TrustQueryParams — limit/offset/score bounds
# ---------------------------------------------------------------------------


def test_trust_query_params_defaults():
    q = TrustQueryParams()
    assert q.limit == 100
    assert q.offset == 0
    assert q.agent_id is None
    assert q.org_id is None
    assert q.session_id is None
    assert q.trust_tier is None
    assert q.profile_locked is None
    assert q.event_type is None
    assert q.outcome is None
    assert q.trust_score_min is None
    assert q.trust_score_max is None
    assert q.anomaly_count_min is None
    assert q.since is None
    assert q.until is None


def test_trust_query_params_limit_min():
    q = TrustQueryParams(limit=1)
    assert q.limit == 1


def test_trust_query_params_limit_max():
    q = TrustQueryParams(limit=1000)
    assert q.limit == 1000


def test_trust_query_params_limit_below_min_rejected():
    with pytest.raises(ValidationError):
        TrustQueryParams(limit=0)


def test_trust_query_params_limit_above_max_rejected():
    with pytest.raises(ValidationError):
        TrustQueryParams(limit=1001)


def test_trust_query_params_offset_zero():
    q = TrustQueryParams(offset=0)
    assert q.offset == 0


def test_trust_query_params_offset_positive():
    q = TrustQueryParams(offset=50)
    assert q.offset == 50


def test_trust_query_params_offset_negative_rejected():
    with pytest.raises(ValidationError):
        TrustQueryParams(offset=-1)


def test_trust_query_params_trust_score_min_below_zero_rejected():
    with pytest.raises(ValidationError):
        TrustQueryParams(trust_score_min=-1)


def test_trust_query_params_trust_score_min_above_100_rejected():
    with pytest.raises(ValidationError):
        TrustQueryParams(trust_score_min=101)


def test_trust_query_params_trust_score_max_below_zero_rejected():
    with pytest.raises(ValidationError):
        TrustQueryParams(trust_score_max=-1)


def test_trust_query_params_trust_score_max_above_100_rejected():
    with pytest.raises(ValidationError):
        TrustQueryParams(trust_score_max=101)


def test_trust_query_params_trust_score_boundaries_accepted():
    q = TrustQueryParams(trust_score_min=0, trust_score_max=100)
    assert q.trust_score_min == 0
    assert q.trust_score_max == 100


def test_trust_query_params_anomaly_count_min_below_zero_rejected():
    with pytest.raises(ValidationError):
        TrustQueryParams(anomaly_count_min=-1)


def test_trust_query_params_anomaly_count_min_zero_accepted():
    q = TrustQueryParams(anomaly_count_min=0)
    assert q.anomaly_count_min == 0


def test_trust_query_params_full_filter():
    since = datetime(2026, 1, 1, tzinfo=UTC)
    until = datetime(2026, 6, 16, tzinfo=UTC)
    q = TrustQueryParams(
        agent_id="agent-001",
        org_id="org-001",
        session_id="sess-001",
        trust_tier=TrustTier.CRITICAL,
        profile_locked=True,
        event_type=TrustEventType.THREAT_DETECTED,
        outcome=TrustOutcome.LOCKED,
        trust_score_min=0,
        trust_score_max=19,
        anomaly_count_min=3,
        since=since,
        until=until,
        limit=25,
        offset=10,
    )
    assert q.trust_tier == TrustTier.CRITICAL
    assert q.profile_locked is True
    assert q.trust_score_max == 19
    assert q.anomaly_count_min == 3
    assert q.limit == 25
    assert q.offset == 10


@pytest.mark.parametrize("tier", list(TrustTier))
def test_trust_query_params_all_tiers(tier):
    q = TrustQueryParams(trust_tier=tier)
    assert q.trust_tier == tier


@pytest.mark.parametrize("outcome", list(TrustOutcome))
def test_trust_query_params_all_outcomes(outcome):
    q = TrustQueryParams(outcome=outcome)
    assert q.outcome == outcome


# ---------------------------------------------------------------------------
# TrustProfileListResponse — pagination shape
# ---------------------------------------------------------------------------


def test_trust_profile_list_response_empty():
    r = TrustProfileListResponse(count=0)
    assert r.count == 0
    assert r.total is None
    assert r.items == []


def test_trust_profile_list_response_with_items():
    p = TrustProfile(agent_id="agent-001", trust_score=80)
    r = TrustProfileListResponse(count=1, total=1, items=[p])
    assert r.count == 1
    assert r.total == 1
    assert len(r.items) == 1
    assert r.items[0].agent_id == "agent-001"


def test_trust_profile_list_response_count_below_zero_rejected():
    with pytest.raises(ValidationError):
        TrustProfileListResponse(count=-1)


def test_trust_profile_list_response_missing_count_rejected():
    with pytest.raises(ValidationError):
        TrustProfileListResponse()


def test_trust_profile_list_response_total_optional():
    r = TrustProfileListResponse(count=5)
    assert r.total is None


# ---------------------------------------------------------------------------
# TrustEventListResponse — pagination shape
# ---------------------------------------------------------------------------


def test_trust_event_list_response_empty():
    r = TrustEventListResponse(count=0)
    assert r.count == 0
    assert r.total is None
    assert r.items == []


def test_trust_event_list_response_with_items():
    ev = TrustEvent(**_BASE_EVENT)
    r = TrustEventListResponse(count=1, total=1, items=[ev])
    assert r.count == 1
    assert len(r.items) == 1
    assert r.items[0].event_id == "tevt-001"


def test_trust_event_list_response_count_below_zero_rejected():
    with pytest.raises(ValidationError):
        TrustEventListResponse(count=-1)


def test_trust_event_list_response_missing_count_rejected():
    with pytest.raises(ValidationError):
        TrustEventListResponse()


# ---------------------------------------------------------------------------
# TrustProfileResponse — ok/error shape
# ---------------------------------------------------------------------------


def test_trust_profile_response_success():
    p = TrustProfile(agent_id="agent-001", trust_score=90)
    r = TrustProfileResponse(ok=True, agent_id="agent-001", profile=p)
    assert r.ok is True
    assert r.agent_id == "agent-001"
    assert r.profile.trust_score == 90
    assert r.error is None


def test_trust_profile_response_failure():
    r = TrustProfileResponse(ok=False, error="Agent profile not found")
    assert r.ok is False
    assert r.agent_id is None
    assert r.profile is None
    assert r.error == "Agent profile not found"


def test_trust_profile_response_missing_ok_rejected():
    with pytest.raises(ValidationError):
        TrustProfileResponse()


def test_trust_profile_response_defaults():
    r = TrustProfileResponse(ok=True)
    assert r.agent_id is None
    assert r.profile is None
    assert r.error is None


# ---------------------------------------------------------------------------
# TrustEventResponse — ok/error shape
# ---------------------------------------------------------------------------


def test_trust_event_response_success():
    r = TrustEventResponse(
        ok=True,
        event_id="tevt-001",
        score_after=70,
        tier_after=TrustTier.HIGH,
        profile_locked=False,
    )
    assert r.ok is True
    assert r.event_id == "tevt-001"
    assert r.score_after == 70
    assert r.tier_after == TrustTier.HIGH
    assert r.profile_locked is False
    assert r.error is None


def test_trust_event_response_lock_triggered():
    r = TrustEventResponse(
        ok=True,
        event_id="tevt-002",
        score_after=5,
        tier_after=TrustTier.CRITICAL,
        profile_locked=True,
    )
    assert r.profile_locked is True
    assert r.tier_after == TrustTier.CRITICAL


def test_trust_event_response_failure():
    r = TrustEventResponse(ok=False, error="Score delta out of range")
    assert r.ok is False
    assert r.event_id is None
    assert r.score_after is None
    assert r.tier_after is None
    assert r.profile_locked is None
    assert r.error == "Score delta out of range"


def test_trust_event_response_missing_ok_rejected():
    with pytest.raises(ValidationError):
        TrustEventResponse()


def test_trust_event_response_score_after_below_zero_rejected():
    with pytest.raises(ValidationError):
        TrustEventResponse(ok=True, score_after=-1)


def test_trust_event_response_score_after_above_100_rejected():
    with pytest.raises(ValidationError):
        TrustEventResponse(ok=True, score_after=101)


def test_trust_event_response_all_tiers_accepted():
    for tier in TrustTier:
        r = TrustEventResponse(ok=True, tier_after=tier)
        assert r.tier_after == tier


# ---------------------------------------------------------------------------
# TrustAccessCountsSchema — defaults and full construction
# ---------------------------------------------------------------------------


def test_trust_access_counts_defaults():
    c = TrustAccessCountsSchema()
    assert c.totalprofiles == 0
    assert c.lockedprofiles == 0
    assert c.criticaltiertprofiles == 0
    assert c.lowtiertprofiles == 0
    assert c.totaltrustevents == 0
    assert c.trustdegradations == 0
    assert c.trustrestorations == 0
    assert c.latesteventat == "Not yet recorded"


def test_trust_access_counts_full():
    c = TrustAccessCountsSchema(
        totalprofiles=100,
        lockedprofiles=5,
        criticaltiertprofiles=3,
        lowtiertprofiles=12,
        totaltrustevents=500,
        trustdegradations=80,
        trustrestorations=20,
        latesteventat="2026-06-16T10:00:00Z",
    )
    assert c.totalprofiles == 100
    assert c.lockedprofiles == 5
    assert c.trustdegradations == 80
    assert c.latesteventat == "2026-06-16T10:00:00Z"


# ---------------------------------------------------------------------------
# TrustAccessControlsSchema — defaults and full construction
# ---------------------------------------------------------------------------


def test_trust_access_controls_defaults():
    c = TrustAccessControlsSchema()
    assert c.decayconfigured is False
    assert c.lockenforcementenabled is False
    assert c.anomalythresholdset is False
    assert c.sessioncorrelationenabled is False
    assert c.auditintegrationenabled is False
    assert c.manualadjustmentcontrolled is False


def test_trust_access_controls_all_enabled():
    c = TrustAccessControlsSchema(
        decayconfigured=True,
        lockenforcementenabled=True,
        anomalythresholdset=True,
        sessioncorrelationenabled=True,
        auditintegrationenabled=True,
        manualadjustmentcontrolled=True,
    )
    assert all(
        [
            c.decayconfigured,
            c.lockenforcementenabled,
            c.anomalythresholdset,
            c.sessioncorrelationenabled,
            c.auditintegrationenabled,
            c.manualadjustmentcontrolled,
        ]
    )


# ---------------------------------------------------------------------------
# TrustAccessSummaryResponse — required-field enforcement
# ---------------------------------------------------------------------------

_BASE_SUMMARY = dict(
    pageid="trust-001",
    title="Trust Access Summary",
    path="/trust",
    summary="Access summary for trust layer",
    generatedat="2026-06-16T10:00:00Z",
)


def test_trust_access_summary_response_minimal():
    r = TrustAccessSummaryResponse(**_BASE_SUMMARY)
    assert r.pageid == "trust-001"
    assert r.title == "Trust Access Summary"
    assert r.path == "/trust"
    assert r.accessavailable is False
    assert r.trustvisibilityenabled is False
    assert r.recenteventsready is False
    assert r.decayconfigured is False
    assert r.recentevents == []
    assert r.metadata == {}
    assert isinstance(r.counts, TrustAccessCountsSchema)
    assert isinstance(r.controls, TrustAccessControlsSchema)


def test_trust_access_summary_response_required_fields_enforced():
    for missing_field in ["pageid", "title", "path", "summary", "generatedat"]:
        payload = {k: v for k, v in _BASE_SUMMARY.items() if k != missing_field}
        with pytest.raises(ValidationError):
            TrustAccessSummaryResponse(**payload)


def test_trust_access_summary_response_full():
    counts = TrustAccessCountsSchema(
        totalprofiles=50,
        lockedprofiles=2,
        criticaltiertprofiles=2,
        trustdegradations=10,
    )
    controls = TrustAccessControlsSchema(
        decayconfigured=True,
        lockenforcementenabled=True,
        auditintegrationenabled=True,
    )
    r = TrustAccessSummaryResponse(
        **_BASE_SUMMARY,
        accessavailable=True,
        trustvisibilityenabled=True,
        recenteventsready=True,
        decayconfigured=True,
        counts=counts,
        controls=controls,
        recentevents=[{"event_id": "tevt-001", "event_type": "anomaly.detected"}],
        metadata={"env": "production"},
    )
    assert r.accessavailable is True
    assert r.trustvisibilityenabled is True
    assert r.decayconfigured is True
    assert r.counts.totalprofiles == 50
    assert r.counts.lockedprofiles == 2
    assert r.controls.lockenforcementenabled is True
    assert len(r.recentevents) == 1
    assert r.metadata["env"] == "production"


def test_trust_access_summary_response_defaults_nested_schemas():
    r = TrustAccessSummaryResponse(**_BASE_SUMMARY)
    assert r.counts.totalprofiles == 0
    assert r.counts.latesteventat == "Not yet recorded"
    assert r.controls.decayconfigured is False
    assert r.controls.lockenforcementenabled is False
