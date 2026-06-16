from __future__ import annotations

from app.orchestrator.security_audit_log import (
    initialize_security_audit_log,
    record_policy_decision,
)
from app.schemas.audit import (
    AuditEventCreate,
    AuditEventType,
    AuditOutcome,
    AuditSeverity,
    AuditTargetType,
)
from app.services.audit_log_service import (
    get_audit_event_as_schema,
    get_audit_log,
    list_audit_events,
    list_audit_events_as_schema,
    list_audit_events_for_actor,
    list_audit_events_for_request,
    list_audit_events_for_session,
    list_audit_events_for_session_as_schema,
    list_audit_events_for_trace,
    reset_audit_log,
    set_audit_log,
)


def setup_function() -> None:
    reset_audit_log()


def _seed_audit_events() -> None:
    audit_log = initialize_security_audit_log("output/security-events.jsonl")

    audit_log = record_policy_decision(
        audit_log,
        actor_id="audit-actor-001",
        action_type="http_fetch",
        target="https://example.com/a",
        verdict="allow",
        risk_score=0,
        reason="Seeded allow event.",
        session_id="audit-session-001",
        file_path="app/api/action_execute.py",
        metadata={
            "request_id": "req-audit-001",
            "trace_id": "trace-audit-001",
            "source": "test_seed",
        },
    )

    audit_log = record_policy_decision(
        audit_log,
        actor_id="audit-actor-002",
        action_type="tool_call",
        target="shell",
        verdict="quarantine",
        risk_score=85,
        reason="Seeded quarantine event.",
        session_id="audit-session-002",
        file_path="app/orchestrator/secure_runtime_pipeline.py",
        metadata={
            "request_id": "req-audit-002",
            "trace_id": "trace-audit-002",
            "source": "test_seed",
        },
    )

    set_audit_log(audit_log)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------


def test_get_audit_log_returns_instance() -> None:
    log = get_audit_log()
    assert log is not None


def test_set_audit_log_installs_instance() -> None:
    new_log = initialize_security_audit_log("output/security-events.jsonl")
    result = set_audit_log(new_log)
    assert result is new_log
    assert get_audit_log() is new_log


def test_reset_audit_log_clears_events() -> None:
    _seed_audit_events()
    reset_audit_log()
    events = list_audit_events()
    assert events == []


# ---------------------------------------------------------------------------
# Legacy dict API
# ---------------------------------------------------------------------------


def test_list_audit_events_returns_recent_events() -> None:
    _seed_audit_events()
    events = list_audit_events()
    assert len(events) == 2
    assert events[0]["actor_id"] == "audit-actor-002"
    assert events[1]["actor_id"] == "audit-actor-001"


def test_list_audit_events_honors_limit() -> None:
    _seed_audit_events()
    events = list_audit_events(limit=1)
    assert len(events) == 1
    assert events[0]["actor_id"] == "audit-actor-002"


def test_list_audit_events_limit_none_returns_all() -> None:
    _seed_audit_events()
    events = list_audit_events(limit=None)
    assert len(events) == 2


def test_list_audit_events_for_session() -> None:
    _seed_audit_events()
    events = list_audit_events_for_session("audit-session-001")
    assert len(events) == 1
    assert events[0]["session_id"] == "audit-session-001"
    assert events[0]["actor_id"] == "audit-actor-001"


def test_list_audit_events_for_actor() -> None:
    _seed_audit_events()
    events = list_audit_events_for_actor("audit-actor-002")
    assert len(events) == 1
    assert events[0]["actor_id"] == "audit-actor-002"
    assert events[0]["verdict"] == "quarantine"


def test_list_audit_events_for_request() -> None:
    _seed_audit_events()
    events = list_audit_events_for_request("req-audit-002")
    assert len(events) == 1
    assert events[0]["request_id"] == "req-audit-002"
    assert events[0]["trace_id"] == "trace-audit-002"


def test_list_audit_events_for_trace() -> None:
    _seed_audit_events()
    events = list_audit_events_for_trace("trace-audit-001")
    assert len(events) == 1
    assert events[0]["trace_id"] == "trace-audit-001"
    assert events[0]["request_id"] == "req-audit-001"


# ---------------------------------------------------------------------------
# Schema-bridge API
# ---------------------------------------------------------------------------


def test_list_audit_events_as_schema_returns_audit_event_create() -> None:
    _seed_audit_events()
    results = list_audit_events_as_schema()
    assert len(results) == 2
    for item in results:
        assert isinstance(item, AuditEventCreate)


def test_list_audit_events_as_schema_newest_first() -> None:
    _seed_audit_events()
    results = list_audit_events_as_schema()
    assert results[0].actor == "audit-actor-002"
    assert results[1].actor == "audit-actor-001"


def test_list_audit_events_as_schema_honors_limit() -> None:
    _seed_audit_events()
    results = list_audit_events_as_schema(limit=1)
    assert len(results) == 1
    assert results[0].actor == "audit-actor-002"


def test_list_audit_events_as_schema_quarantine_maps_correctly() -> None:
    _seed_audit_events()
    results = list_audit_events_as_schema()
    quarantine_event = results[0]
    assert quarantine_event.outcome == AuditOutcome.QUARANTINED
    assert quarantine_event.event_type == AuditEventType.ACTION_QUARANTINED
    assert quarantine_event.severity == AuditSeverity.CRITICAL
    assert quarantine_event.risk_score == 85
    assert quarantine_event.target_type == AuditTargetType.TOOL_CALL


def test_list_audit_events_as_schema_allow_maps_correctly() -> None:
    _seed_audit_events()
    results = list_audit_events_as_schema()
    allow_event = results[1]
    assert allow_event.outcome == AuditOutcome.ALLOWED
    assert allow_event.event_type == AuditEventType.ACTION_EXECUTED
    assert allow_event.severity == AuditSeverity.INFO
    assert allow_event.risk_score == 0


def test_list_audit_events_for_session_as_schema() -> None:
    _seed_audit_events()
    results = list_audit_events_for_session_as_schema("audit-session-002")
    assert len(results) == 1
    assert isinstance(results[0], AuditEventCreate)
    assert results[0].session_id == "audit-session-002"
    assert results[0].outcome == AuditOutcome.QUARANTINED


def test_list_audit_events_for_session_as_schema_no_match_returns_empty() -> None:
    _seed_audit_events()
    results = list_audit_events_for_session_as_schema("no-such-session")
    assert results == []


def test_get_audit_event_as_schema_returns_none_for_unknown_id() -> None:
    _seed_audit_events()
    result = get_audit_event_as_schema("nonexistent-event-id")
    assert result is None


def test_get_audit_event_as_schema_returns_event_for_known_id() -> None:
    _seed_audit_events()
    all_events = list_audit_events(limit=None)
    event_id = all_events[0].get("event_id")
    if event_id:
        result = get_audit_event_as_schema(event_id)
        assert isinstance(result, AuditEventCreate)
