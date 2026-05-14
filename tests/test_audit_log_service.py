from __future__ import annotations

from app.orchestrator.security_audit_log import (
    initialize_security_audit_log,
    record_policy_decision,
)
from app.services.audit_log_service import (
    list_audit_events,
    list_audit_events_for_actor,
    list_audit_events_for_request,
    list_audit_events_for_session,
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


def test_list_audit_events_returns_recent_events():
    _seed_audit_events()

    events = list_audit_events()

    assert len(events) == 2
    assert events[0]["actor_id"] == "audit-actor-002"
    assert events[1]["actor_id"] == "audit-actor-001"


def test_list_audit_events_honors_limit():
    _seed_audit_events()

    events = list_audit_events(limit=1)

    assert len(events) == 1
    assert events[0]["actor_id"] == "audit-actor-002"


def test_list_audit_events_for_session():
    _seed_audit_events()

    events = list_audit_events_for_session("audit-session-001")

    assert len(events) == 1
    assert events[0]["session_id"] == "audit-session-001"
    assert events[0]["actor_id"] == "audit-actor-001"


def test_list_audit_events_for_actor():
    _seed_audit_events()

    events = list_audit_events_for_actor("audit-actor-002")

    assert len(events) == 1
    assert events[0]["actor_id"] == "audit-actor-002"
    assert events[0]["verdict"] == "quarantine"


def test_list_audit_events_for_request():
    _seed_audit_events()

    events = list_audit_events_for_request("req-audit-002")

    assert len(events) == 1
    assert events[0]["request_id"] == "req-audit-002"
    assert events[0]["trace_id"] == "trace-audit-002"


def test_list_audit_events_for_trace():
    _seed_audit_events()

    events = list_audit_events_for_trace("trace-audit-001")

    assert len(events) == 1
    assert events[0]["trace_id"] == "trace-audit-001"
    assert events[0]["request_id"] == "req-audit-001"
