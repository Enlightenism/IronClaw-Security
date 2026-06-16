from __future__ import annotations

from datetime import UTC, datetime

from pydantic import ValidationError
import pytest

from app.schemas.audit import (
    AuditAccessControlsSchema,
    AuditAccessCountsSchema,
    AuditAccessSummaryResponse,
    AuditEvent,
    AuditEventCreate,
    AuditEventResponse,
    AuditEventType,
    AuditListResponse,
    AuditOutcome,
    AuditQueryParams,
    AuditSeverity,
    AuditTargetType,
)

# ---------------------------------------------------------------------------
# AuditEventType — complete group coverage
# ---------------------------------------------------------------------------


def test_audit_event_type_prompt_group():
    expected = {
        AuditEventType.PROMPT_RECEIVED,
        AuditEventType.PROMPT_SCANNED,
        AuditEventType.PROMPT_INJECTION_DETECTED,
        AuditEventType.PROMPT_BLOCKED,
        AuditEventType.PROMPT_ALLOWED,
        AuditEventType.PROMPT_QUARANTINED,
        AuditEventType.PROMPT_FLAGGED,
        AuditEventType.PROMPT_REDACTED,
    }
    actual = {e for e in AuditEventType if e.value.startswith("prompt.")}
    assert actual == expected


def test_audit_event_type_tool_call_group():
    expected = {
        AuditEventType.TOOL_CALL_RECEIVED,
        AuditEventType.TOOL_CALL_EVALUATED,
        AuditEventType.TOOL_CALL_ALLOWED,
        AuditEventType.TOOL_CALL_BLOCKED,
        AuditEventType.TOOL_CALL_QUARANTINED,
        AuditEventType.TOOL_CALL_SANDBOXED,
        AuditEventType.TOOL_CALL_FAILED,
    }
    actual = {e for e in AuditEventType if e.value.startswith("tool_call.")}
    assert actual == expected


def test_audit_event_type_action_group():
    expected = {
        AuditEventType.ACTION_SUBMITTED,
        AuditEventType.ACTION_DECISION_MADE,
        AuditEventType.ACTION_EXECUTED,
        AuditEventType.ACTION_BLOCKED,
        AuditEventType.ACTION_QUARANTINED,
        AuditEventType.ACTION_FAILED,
        AuditEventType.ACTION_SANDBOXED,
        AuditEventType.ACTION_REVIEWED,
        AuditEventType.ACTION_REVIEW_APPROVED,
        AuditEventType.ACTION_REVIEW_REJECTED,
    }
    actual = {e for e in AuditEventType if e.value.startswith("action.")}
    assert actual == expected


def test_audit_event_type_policy_group():
    expected = {
        AuditEventType.POLICY_EVALUATED,
        AuditEventType.POLICY_VIOLATION,
        AuditEventType.POLICY_CREATED,
        AuditEventType.POLICY_UPDATED,
        AuditEventType.POLICY_DELETED,
    }
    actual = {e for e in AuditEventType if e.value.startswith("policy.")}
    assert actual == expected


def test_audit_event_type_agent_group():
    expected = {
        AuditEventType.AGENT_SESSION_STARTED,
        AuditEventType.AGENT_SESSION_ENDED,
        AuditEventType.AGENT_TRUST_DEGRADED,
        AuditEventType.AGENT_TRUST_RESTORED,
        AuditEventType.AGENT_PROFILE_CREATED,
        AuditEventType.AGENT_PROFILE_UPDATED,
    }
    actual = {e for e in AuditEventType if e.value.startswith("agent.")}
    assert actual == expected


def test_audit_event_type_auth_group():
    expected = {
        AuditEventType.AUTH_SUCCESS,
        AuditEventType.AUTH_FAILURE,
        AuditEventType.AUTH_TOKEN_REVOKED,
        AuditEventType.AUTH_RATE_LIMITED,
        AuditEventType.AUTH_PERMISSION_DENIED,
    }
    actual = {e for e in AuditEventType if e.value.startswith("auth.")}
    assert actual == expected


def test_audit_event_type_data_group():
    expected = {
        AuditEventType.DATA_ACCESS,
        AuditEventType.DATA_EXPORT_ATTEMPTED,
        AuditEventType.DATA_EXPORT_BLOCKED,
        AuditEventType.DATA_REDACTED,
        AuditEventType.DATA_LEAKAGE_DETECTED,
    }
    actual = {e for e in AuditEventType if e.value.startswith("data.")}
    assert actual == expected


def test_audit_event_type_threat_group():
    expected = {
        AuditEventType.THREAT_DETECTED,
        AuditEventType.THREAT_CORRELATED,
        AuditEventType.ATTACK_SEQUENCE_IDENTIFIED,
        AuditEventType.IOC_MATCHED,
    }
    actual = {e for e in AuditEventType if e.value.startswith("threat.") or e.value.startswith("attack.") or e.value.startswith("ioc.")}
    assert actual == expected


def test_audit_event_type_review_group():
    expected = {
        AuditEventType.REVIEW_ITEM_CREATED,
        AuditEventType.REVIEW_DECISION_MADE,
        AuditEventType.REVIEW_ESCALATED,
        AuditEventType.REVIEW_APPROVED,
        AuditEventType.REVIEW_REJECTED,
    }
    actual = {e for e in AuditEventType if e.value.startswith("review.")}
    assert actual == expected


def test_audit_event_type_config_group():
    expected = {
        AuditEventType.CONFIG_CHANGED,
        AuditEventType.USER_CREATED,
        AuditEventType.USER_UPDATED,
        AuditEventType.USER_DELETED,
        AuditEventType.ROLE_ASSIGNED,
        AuditEventType.ROLE_REVOKED,
        AuditEventType.API_KEY_ISSUED,
        AuditEventType.API_KEY_REVOKED,
    }
    actual = {e for e in AuditEventType if e.value.startswith("config.") or e.value.startswith("user.") or e.value.startswith("role.") or e.value.startswith("api_key.")}
    assert actual == expected


def test_audit_event_type_system_group():
    expected = {
        AuditEventType.SYSTEM_STARTUP,
        AuditEventType.SYSTEM_SHUTDOWN,
        AuditEventType.SYSTEM_ERROR,
        AuditEventType.SYSTEM_HEALTH_CHECK,
    }
    actual = {e for e in AuditEventType if e.value.startswith("system.")}
    assert actual == expected


def test_audit_event_type_audit_meta_group():
    expected = {
        AuditEventType.AUDIT_EXPORT_REQUESTED,
        AuditEventType.AUDIT_LOG_CLEARED,
    }
    actual = {e for e in AuditEventType if e.value.startswith("audit.")}
    assert actual == expected


def test_audit_event_type_unknown_member():
    assert AuditEventType.UNKNOWN == AuditEventType("unknown")


def test_audit_event_type_invalid():
    with pytest.raises(ValueError):
        AuditEventType("not.a.real.event")


@pytest.mark.parametrize("member", list(AuditEventType))
def test_audit_event_type_all_round_trip(member):
    assert AuditEventType(member.value) == member


# ---------------------------------------------------------------------------
# AuditOutcome — complete coverage
# ---------------------------------------------------------------------------


def test_audit_outcome_values():
    assert set(AuditOutcome) == {
        AuditOutcome.SUCCESS,
        AuditOutcome.FAILURE,
        AuditOutcome.BLOCKED,
        AuditOutcome.ALLOWED,
        AuditOutcome.QUARANTINED,
        AuditOutcome.WARNED,
        AuditOutcome.PENDING,
        AuditOutcome.ERROR,
        AuditOutcome.UNKNOWN,
    }


@pytest.mark.parametrize(
    "value",
    ["success", "failure", "blocked", "allowed", "quarantined", "warned", "pending", "error", "unknown"],
)
def test_audit_outcome_from_string(value):
    assert AuditOutcome(value).value == value


def test_audit_outcome_invalid():
    with pytest.raises(ValueError):
        AuditOutcome("pass")


# ---------------------------------------------------------------------------
# AuditSeverity — complete coverage
# ---------------------------------------------------------------------------


def test_audit_severity_values():
    assert set(AuditSeverity) == {
        AuditSeverity.INFO,
        AuditSeverity.LOW,
        AuditSeverity.MEDIUM,
        AuditSeverity.HIGH,
        AuditSeverity.CRITICAL,
    }


@pytest.mark.parametrize("value", ["info", "low", "medium", "high", "critical"])
def test_audit_severity_from_string(value):
    assert AuditSeverity(value).value == value


def test_audit_severity_invalid():
    with pytest.raises(ValueError):
        AuditSeverity("fatal")


# ---------------------------------------------------------------------------
# AuditTargetType — complete coverage
# ---------------------------------------------------------------------------


def test_audit_target_type_values():
    assert set(AuditTargetType) == {
        AuditTargetType.PROMPT,
        AuditTargetType.TOOL_CALL,
        AuditTargetType.ACTION,
        AuditTargetType.POLICY,
        AuditTargetType.POLICY_RULE,
        AuditTargetType.AGENT,
        AuditTargetType.SESSION,
        AuditTargetType.USER,
        AuditTargetType.API_KEY,
        AuditTargetType.SCAN,
        AuditTargetType.REVIEW_ITEM,
        AuditTargetType.DATA_RECORD,
        AuditTargetType.CONFIG,
        AuditTargetType.SYSTEM,
        AuditTargetType.UNKNOWN,
    }


@pytest.mark.parametrize("member", list(AuditTargetType))
def test_audit_target_type_all_round_trip(member):
    assert AuditTargetType(member.value) == member


def test_audit_target_type_invalid():
    with pytest.raises(ValueError):
        AuditTargetType("not_a_type")


# ---------------------------------------------------------------------------
# AuditEventCreate — required-field enforcement
# ---------------------------------------------------------------------------

_BASE_CREATE = dict(
    event_type=AuditEventType.PROMPT_SCANNED,
    actor="agent-001",
    target_type=AuditTargetType.PROMPT,
    action="Scanned prompt for injection patterns",
    outcome=AuditOutcome.ALLOWED,
)


def test_audit_event_create_minimal():
    ev = AuditEventCreate(**_BASE_CREATE)
    assert ev.event_type == AuditEventType.PROMPT_SCANNED
    assert ev.actor == "agent-001"
    assert ev.target_type == AuditTargetType.PROMPT
    assert ev.action == "Scanned prompt for injection patterns"
    assert ev.outcome == AuditOutcome.ALLOWED


def test_audit_event_create_missing_actor_rejected():
    payload = {k: v for k, v in _BASE_CREATE.items() if k != "actor"}
    with pytest.raises(ValidationError):
        AuditEventCreate(**payload)


def test_audit_event_create_missing_action_rejected():
    payload = {k: v for k, v in _BASE_CREATE.items() if k != "action"}
    with pytest.raises(ValidationError):
        AuditEventCreate(**payload)


def test_audit_event_create_missing_event_type_rejected():
    payload = {k: v for k, v in _BASE_CREATE.items() if k != "event_type"}
    with pytest.raises(ValidationError):
        AuditEventCreate(**payload)


def test_audit_event_create_missing_target_type_rejected():
    payload = {k: v for k, v in _BASE_CREATE.items() if k != "target_type"}
    with pytest.raises(ValidationError):
        AuditEventCreate(**payload)


def test_audit_event_create_missing_outcome_rejected():
    payload = {k: v for k, v in _BASE_CREATE.items() if k != "outcome"}
    with pytest.raises(ValidationError):
        AuditEventCreate(**payload)


def test_audit_event_create_empty_actor_rejected():
    with pytest.raises(ValidationError):
        AuditEventCreate(**{**_BASE_CREATE, "actor": ""})


def test_audit_event_create_actor_too_long_rejected():
    with pytest.raises(ValidationError):
        AuditEventCreate(**{**_BASE_CREATE, "actor": "x" * 513})


def test_audit_event_create_empty_action_rejected():
    with pytest.raises(ValidationError):
        AuditEventCreate(**{**_BASE_CREATE, "action": ""})


def test_audit_event_create_action_too_long_rejected():
    with pytest.raises(ValidationError):
        AuditEventCreate(**{**_BASE_CREATE, "action": "x" * 1025})


def test_audit_event_create_actor_max_boundary_accepted():
    ev = AuditEventCreate(**{**_BASE_CREATE, "actor": "x" * 512})
    assert len(ev.actor) == 512


def test_audit_event_create_action_max_boundary_accepted():
    ev = AuditEventCreate(**{**_BASE_CREATE, "action": "x" * 1024})
    assert len(ev.action) == 1024


def test_audit_event_create_defaults():
    ev = AuditEventCreate(**_BASE_CREATE)
    assert ev.severity == AuditSeverity.INFO
    assert ev.risk_score == 0
    assert ev.categories == []
    assert ev.tags == []
    assert ev.metadata == {}
    assert ev.target_id is None
    assert ev.org_id is None
    assert ev.session_id is None
    assert ev.request_id is None
    assert ev.ip_address is None
    assert ev.user_agent is None
    assert ev.reasoning is None
    assert ev.actor_type is None
    assert ev.created_at is None


def test_audit_event_create_full_construction():
    ev = AuditEventCreate(
        event_type=AuditEventType.PROMPT_INJECTION_DETECTED,
        actor="user-abc",
        actor_type="user",
        target_type=AuditTargetType.PROMPT,
        target_id="prompt-xyz",
        action="Injection pattern detected in user prompt",
        outcome=AuditOutcome.BLOCKED,
        severity=AuditSeverity.CRITICAL,
        org_id="org-001",
        session_id="sess-001",
        request_id="req-001",
        ip_address="10.0.0.1",
        user_agent="ironclaw/1.0",
        risk_score=95,
        categories=["injection", "high-risk"],
        tags=["claude", "mcp"],
        reasoning="Pattern matched known prompt injection signature",
        metadata={"pattern": "ignore previous instructions", "score": 0.99},
        created_at=datetime(2026, 6, 16, 10, 0, 0, tzinfo=UTC),
    )
    assert ev.event_type == AuditEventType.PROMPT_INJECTION_DETECTED
    assert ev.outcome == AuditOutcome.BLOCKED
    assert ev.severity == AuditSeverity.CRITICAL
    assert ev.risk_score == 95
    assert "injection" in ev.categories
    assert ev.metadata["score"] == 0.99


def test_audit_event_create_invalid_event_type_rejected():
    with pytest.raises(ValidationError):
        AuditEventCreate(**{**_BASE_CREATE, "event_type": "not.valid"})


def test_audit_event_create_invalid_outcome_rejected():
    with pytest.raises(ValidationError):
        AuditEventCreate(**{**_BASE_CREATE, "outcome": "pass"})


def test_audit_event_create_risk_score_below_min_rejected():
    with pytest.raises(ValidationError):
        AuditEventCreate(**{**_BASE_CREATE, "risk_score": -1})


def test_audit_event_create_risk_score_above_max_rejected():
    with pytest.raises(ValidationError):
        AuditEventCreate(**{**_BASE_CREATE, "risk_score": 101})


def test_audit_event_create_risk_score_boundaries_accepted():
    ev_min = AuditEventCreate(**{**_BASE_CREATE, "risk_score": 0})
    ev_max = AuditEventCreate(**{**_BASE_CREATE, "risk_score": 100})
    assert ev_min.risk_score == 0
    assert ev_max.risk_score == 100


@pytest.mark.parametrize("event_type", list(AuditEventType))
def test_audit_event_create_all_event_types_accepted(event_type):
    ev = AuditEventCreate(**{**_BASE_CREATE, "event_type": event_type})
    assert ev.event_type == event_type


@pytest.mark.parametrize("outcome", list(AuditOutcome))
def test_audit_event_create_all_outcomes_accepted(outcome):
    ev = AuditEventCreate(**{**_BASE_CREATE, "outcome": outcome})
    assert ev.outcome == outcome


@pytest.mark.parametrize("severity", list(AuditSeverity))
def test_audit_event_create_all_severities_accepted(severity):
    ev = AuditEventCreate(**{**_BASE_CREATE, "severity": severity})
    assert ev.severity == severity


@pytest.mark.parametrize("target_type", list(AuditTargetType))
def test_audit_event_create_all_target_types_accepted(target_type):
    ev = AuditEventCreate(**{**_BASE_CREATE, "target_type": target_type})
    assert ev.target_type == target_type


# ---------------------------------------------------------------------------
# AuditQueryParams — limit/offset/risk_score bounds
# ---------------------------------------------------------------------------


def test_audit_query_params_defaults():
    q = AuditQueryParams()
    assert q.limit == 100
    assert q.offset == 0
    assert q.event_type is None
    assert q.actor is None
    assert q.actor_type is None
    assert q.target_type is None
    assert q.target_id is None
    assert q.outcome is None
    assert q.severity is None
    assert q.org_id is None
    assert q.session_id is None
    assert q.risk_score_min is None
    assert q.risk_score_max is None
    assert q.since is None
    assert q.until is None


def test_audit_query_params_limit_min():
    q = AuditQueryParams(limit=1)
    assert q.limit == 1


def test_audit_query_params_limit_max():
    q = AuditQueryParams(limit=1000)
    assert q.limit == 1000


def test_audit_query_params_limit_below_min_rejected():
    with pytest.raises(ValidationError):
        AuditQueryParams(limit=0)


def test_audit_query_params_limit_above_max_rejected():
    with pytest.raises(ValidationError):
        AuditQueryParams(limit=1001)


def test_audit_query_params_offset_zero():
    q = AuditQueryParams(offset=0)
    assert q.offset == 0


def test_audit_query_params_offset_positive():
    q = AuditQueryParams(offset=50)
    assert q.offset == 50


def test_audit_query_params_offset_negative_rejected():
    with pytest.raises(ValidationError):
        AuditQueryParams(offset=-1)


def test_audit_query_params_risk_score_min_boundary():
    q = AuditQueryParams(risk_score_min=0)
    assert q.risk_score_min == 0


def test_audit_query_params_risk_score_max_boundary():
    q = AuditQueryParams(risk_score_max=100)
    assert q.risk_score_max == 100


def test_audit_query_params_risk_score_min_below_zero_rejected():
    with pytest.raises(ValidationError):
        AuditQueryParams(risk_score_min=-1)


def test_audit_query_params_risk_score_min_above_100_rejected():
    with pytest.raises(ValidationError):
        AuditQueryParams(risk_score_min=101)


def test_audit_query_params_risk_score_max_below_zero_rejected():
    with pytest.raises(ValidationError):
        AuditQueryParams(risk_score_max=-1)


def test_audit_query_params_risk_score_max_above_100_rejected():
    with pytest.raises(ValidationError):
        AuditQueryParams(risk_score_max=101)


def test_audit_query_params_full_filter():
    since = datetime(2026, 1, 1, tzinfo=UTC)
    until = datetime(2026, 6, 16, tzinfo=UTC)
    q = AuditQueryParams(
        event_type=AuditEventType.PROMPT_INJECTION_DETECTED,
        actor="agent-001",
        actor_type="agent",
        target_type=AuditTargetType.PROMPT,
        target_id="prompt-xyz",
        outcome=AuditOutcome.BLOCKED,
        severity=AuditSeverity.CRITICAL,
        org_id="org-001",
        session_id="sess-001",
        risk_score_min=50,
        risk_score_max=100,
        since=since,
        until=until,
        limit=25,
        offset=10,
    )
    assert q.event_type == AuditEventType.PROMPT_INJECTION_DETECTED
    assert q.outcome == AuditOutcome.BLOCKED
    assert q.severity == AuditSeverity.CRITICAL
    assert q.risk_score_min == 50
    assert q.risk_score_max == 100
    assert q.since == since
    assert q.until == until
    assert q.limit == 25
    assert q.offset == 10


@pytest.mark.parametrize("outcome", list(AuditOutcome))
def test_audit_query_params_all_outcomes(outcome):
    q = AuditQueryParams(outcome=outcome)
    assert q.outcome == outcome


@pytest.mark.parametrize("severity", list(AuditSeverity))
def test_audit_query_params_all_severities(severity):
    q = AuditQueryParams(severity=severity)
    assert q.severity == severity


# ---------------------------------------------------------------------------
# AuditEvent — read model full round-trip via model_dump
# ---------------------------------------------------------------------------

_BASE_EVENT = dict(
    event_id="evt-001",
    event_type=AuditEventType.PROMPT_SCANNED,
    actor="agent-001",
    target_type=AuditTargetType.PROMPT,
    action="Scanned prompt for injection patterns",
    outcome=AuditOutcome.ALLOWED,
)


def test_audit_event_minimal():
    ev = AuditEvent(**_BASE_EVENT)
    assert ev.event_id == "evt-001"
    assert ev.event_type == AuditEventType.PROMPT_SCANNED
    assert ev.actor == "agent-001"
    assert ev.target_type == AuditTargetType.PROMPT
    assert ev.action == "Scanned prompt for injection patterns"
    assert ev.outcome == AuditOutcome.ALLOWED


def test_audit_event_defaults():
    ev = AuditEvent(**_BASE_EVENT)
    assert ev.severity == AuditSeverity.INFO
    assert ev.risk_score == 0
    assert ev.categories == []
    assert ev.tags == []
    assert ev.metadata == {}
    assert ev.target_id is None
    assert ev.org_id is None
    assert ev.session_id is None
    assert ev.request_id is None
    assert ev.ip_address is None
    assert ev.user_agent is None
    assert ev.reasoning is None
    assert ev.actor_type is None


def test_audit_event_created_at_defaults_to_utc_now():
    ev = AuditEvent(**_BASE_EVENT)
    assert ev.created_at is not None
    assert ev.created_at.tzinfo is not None


def test_audit_event_missing_event_id_rejected():
    payload = {k: v for k, v in _BASE_EVENT.items() if k != "event_id"}
    with pytest.raises(ValidationError):
        AuditEvent(**payload)


def test_audit_event_missing_actor_rejected():
    payload = {k: v for k, v in _BASE_EVENT.items() if k != "actor"}
    with pytest.raises(ValidationError):
        AuditEvent(**payload)


def test_audit_event_missing_target_type_rejected():
    payload = {k: v for k, v in _BASE_EVENT.items() if k != "target_type"}
    with pytest.raises(ValidationError):
        AuditEvent(**payload)


def test_audit_event_missing_action_rejected():
    payload = {k: v for k, v in _BASE_EVENT.items() if k != "action"}
    with pytest.raises(ValidationError):
        AuditEvent(**payload)


def test_audit_event_missing_outcome_rejected():
    payload = {k: v for k, v in _BASE_EVENT.items() if k != "outcome"}
    with pytest.raises(ValidationError):
        AuditEvent(**payload)


def test_audit_event_full_round_trip():
    ts = datetime(2026, 6, 16, 10, 0, 0, tzinfo=UTC)
    ev = AuditEvent(
        event_id="evt-999",
        event_type=AuditEventType.PROMPT_INJECTION_DETECTED,
        actor="user-abc",
        actor_type="user",
        target_type=AuditTargetType.PROMPT,
        target_id="prompt-xyz",
        action="Injection pattern detected in user prompt",
        outcome=AuditOutcome.BLOCKED,
        severity=AuditSeverity.CRITICAL,
        org_id="org-001",
        session_id="sess-001",
        request_id="req-001",
        ip_address="10.0.0.1",
        user_agent="ironclaw/1.0",
        risk_score=95,
        categories=["injection", "high-risk"],
        tags=["claude", "mcp"],
        reasoning="Pattern matched known prompt injection signature",
        metadata={"pattern": "ignore previous instructions", "score": 0.99},
        created_at=ts,
    )
    dumped = ev.model_dump()
    restored = AuditEvent(**dumped)
    assert restored.event_id == "evt-999"
    assert restored.event_type == AuditEventType.PROMPT_INJECTION_DETECTED
    assert restored.outcome == AuditOutcome.BLOCKED
    assert restored.severity == AuditSeverity.CRITICAL
    assert restored.risk_score == 95
    assert restored.categories == ["injection", "high-risk"]
    assert restored.tags == ["claude", "mcp"]
    assert restored.metadata["score"] == 0.99
    assert restored.created_at == ts


def test_audit_event_serializes_to_dict():
    ev = AuditEvent(**_BASE_EVENT)
    d = ev.model_dump()
    assert "event_id" in d
    assert "actor" in d
    assert "target_type" in d
    assert "action" in d
    assert "outcome" in d
    assert "metadata" in d
    assert "created_at" in d
    assert d["categories"] == []
    assert d["tags"] == []
    assert d["metadata"] == {}


def test_audit_event_risk_score_below_min_rejected():
    with pytest.raises(ValidationError):
        AuditEvent(**{**_BASE_EVENT, "risk_score": -1})


def test_audit_event_risk_score_above_max_rejected():
    with pytest.raises(ValidationError):
        AuditEvent(**{**_BASE_EVENT, "risk_score": 101})


def test_audit_event_risk_score_boundaries_accepted():
    ev_min = AuditEvent(**{**_BASE_EVENT, "risk_score": 0})
    ev_max = AuditEvent(**{**_BASE_EVENT, "risk_score": 100})
    assert ev_min.risk_score == 0
    assert ev_max.risk_score == 100


# ---------------------------------------------------------------------------
# AuditListResponse — pagination shape
# ---------------------------------------------------------------------------


def test_audit_list_response_empty():
    r = AuditListResponse(count=0)
    assert r.count == 0
    assert r.total is None
    assert r.items == []


def test_audit_list_response_with_items():
    ev = AuditEvent(**_BASE_EVENT)
    r = AuditListResponse(count=1, total=1, items=[ev])
    assert r.count == 1
    assert r.total == 1
    assert len(r.items) == 1
    assert r.items[0].event_id == "evt-001"


def test_audit_list_response_count_below_zero_rejected():
    with pytest.raises(ValidationError):
        AuditListResponse(count=-1)


def test_audit_list_response_missing_count_rejected():
    with pytest.raises(ValidationError):
        AuditListResponse()


def test_audit_list_response_multiple_items():
    ev1 = AuditEvent(**{**_BASE_EVENT, "event_id": "evt-001"})
    ev2 = AuditEvent(**{**_BASE_EVENT, "event_id": "evt-002", "outcome": AuditOutcome.BLOCKED})
    r = AuditListResponse(count=2, total=2, items=[ev1, ev2])
    assert r.count == 2
    assert r.items[1].outcome == AuditOutcome.BLOCKED


def test_audit_list_response_total_is_optional():
    r = AuditListResponse(count=5)
    assert r.total is None


# ---------------------------------------------------------------------------
# AuditEventResponse — ok/error shape
# ---------------------------------------------------------------------------


def test_audit_event_response_success():
    r = AuditEventResponse(ok=True, event_id="evt-001")
    assert r.ok is True
    assert r.event_id == "evt-001"
    assert r.error is None


def test_audit_event_response_failure():
    r = AuditEventResponse(ok=False, error="Event not found")
    assert r.ok is False
    assert r.event_id is None
    assert r.error == "Event not found"


def test_audit_event_response_missing_ok_rejected():
    with pytest.raises(ValidationError):
        AuditEventResponse()


def test_audit_event_response_defaults():
    r = AuditEventResponse(ok=True)
    assert r.event_id is None
    assert r.error is None


# ---------------------------------------------------------------------------
# AuditAccessCountsSchema — defaults and full construction
# ---------------------------------------------------------------------------


def test_audit_access_counts_defaults():
    c = AuditAccessCountsSchema()
    assert c.totalevents == 0
    assert c.allowedactions == 0
    assert c.blockedactions == 0
    assert c.quarantinedactions == 0
    assert c.policyviolations == 0
    assert c.authfailures == 0
    assert c.criticalevents == 0
    assert c.latesteventat == "Not yet recorded"


def test_audit_access_counts_full():
    c = AuditAccessCountsSchema(
        totalevents=500,
        allowedactions=400,
        blockedactions=60,
        quarantinedactions=20,
        policyviolations=15,
        authfailures=5,
        criticalevents=10,
        latesteventat="2026-06-16T10:00:00Z",
    )
    assert c.totalevents == 500
    assert c.blockedactions == 60
    assert c.criticalevents == 10
    assert c.latesteventat == "2026-06-16T10:00:00Z"


# ---------------------------------------------------------------------------
# AuditAccessControlsSchema — defaults and full construction
# ---------------------------------------------------------------------------


def test_audit_access_controls_defaults():
    c = AuditAccessControlsSchema()
    assert c.retentiontracked is False
    assert c.actorattributionrequired is False
    assert c.sessioncorrelationenabled is False
    assert c.requestcorrelationenabled is False
    assert c.exportcontrolled is False
    assert c.tamperdetectionenabled is False


def test_audit_access_controls_all_enabled():
    c = AuditAccessControlsSchema(
        retentiontracked=True,
        actorattributionrequired=True,
        sessioncorrelationenabled=True,
        requestcorrelationenabled=True,
        exportcontrolled=True,
        tamperdetectionenabled=True,
    )
    assert all(
        [
            c.retentiontracked,
            c.actorattributionrequired,
            c.sessioncorrelationenabled,
            c.requestcorrelationenabled,
            c.exportcontrolled,
            c.tamperdetectionenabled,
        ]
    )


# ---------------------------------------------------------------------------
# AuditAccessSummaryResponse — required-field enforcement
# ---------------------------------------------------------------------------

_BASE_SUMMARY = dict(
    pageid="audit-001",
    title="Audit Access Summary",
    path="/audit",
    summary="Access summary for audit layer",
    generatedat="2026-06-16T10:00:00Z",
)


def test_audit_access_summary_response_minimal():
    r = AuditAccessSummaryResponse(**_BASE_SUMMARY)
    assert r.pageid == "audit-001"
    assert r.title == "Audit Access Summary"
    assert r.path == "/audit"
    assert r.accessavailable is False
    assert r.auditvisibilityenabled is False
    assert r.recenteventsready is False
    assert r.exportcontrolled is False
    assert r.recentevents == []
    assert r.metadata == {}
    assert isinstance(r.counts, AuditAccessCountsSchema)
    assert isinstance(r.controls, AuditAccessControlsSchema)


def test_audit_access_summary_response_required_fields_enforced():
    for missing_field in ["pageid", "title", "path", "summary", "generatedat"]:
        payload = {k: v for k, v in _BASE_SUMMARY.items() if k != missing_field}
        with pytest.raises(ValidationError):
            AuditAccessSummaryResponse(**payload)


def test_audit_access_summary_response_full():
    counts = AuditAccessCountsSchema(totalevents=200, blockedactions=40, criticalevents=5)
    controls = AuditAccessControlsSchema(
        retentiontracked=True,
        tamperdetectionenabled=True,
    )
    r = AuditAccessSummaryResponse(
        **_BASE_SUMMARY,
        accessavailable=True,
        auditvisibilityenabled=True,
        recenteventsready=True,
        exportcontrolled=True,
        counts=counts,
        controls=controls,
        recentevents=[{"event_id": "evt-001", "event_type": "prompt.scanned"}],
        metadata={"env": "production", "version": "1.0"},
    )
    assert r.accessavailable is True
    assert r.auditvisibilityenabled is True
    assert r.counts.totalevents == 200
    assert r.counts.criticalevents == 5
    assert r.controls.tamperdetectionenabled is True
    assert len(r.recentevents) == 1
    assert r.metadata["env"] == "production"


def test_audit_access_summary_response_defaults_nested_schemas():
    r = AuditAccessSummaryResponse(**_BASE_SUMMARY)
    assert r.counts.totalevents == 0
    assert r.counts.latesteventat == "Not yet recorded"
    assert r.controls.retentiontracked is False
    assert r.controls.tamperdetectionenabled is False
