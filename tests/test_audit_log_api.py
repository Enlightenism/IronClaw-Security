from __future__ import annotations

from fastapi.testclient import TestClient

from app.dependencies.action_execute import reset_action_execute_pipeline
from app.main import app
from app.orchestrator.security_audit_log import (
    initialize_security_audit_log,
    record_policy_decision,
)
from app.services.audit_log_service import reset_audit_log, set_audit_log
from app.services.review_queue_service import reset_review_queue

client = TestClient(app)


def setup_function() -> None:
    reset_audit_log()
    reset_review_queue()
    reset_action_execute_pipeline()


def _seed_audit_event(
    *,
    actor_id: str,
    session_id: str,
    verdict: str = "allow",
    request_id: str = "req-test-001",
    trace_id: str = "trace-test-001",
    target: str = "https://example.com",
    action_type: str = "http_fetch",
    risk_score: int = 0,
) -> None:
    audit_log = initialize_security_audit_log("output/security-events.jsonl")
    audit_log = record_policy_decision(
        audit_log,
        actor_id=actor_id,
        action_type=action_type,
        target=target,
        verdict=verdict,
        risk_score=risk_score,
        reason="Seeded audit event for API testing.",
        session_id=session_id,
        file_path="app/api/action_execute.py",
        metadata={
            "actor_id": actor_id,
            "session_id": session_id,
            "request_id": request_id,
            "trace_id": trace_id,
            "source": "test_seed",
        },
    )
    set_audit_log(audit_log)


def test_audit_events_endpoint_returns_recent_events():
    _seed_audit_event(
        actor_id="audit-client-001",
        session_id="audit-session-001",
        request_id="req-audit-001",
        trace_id="trace-audit-001",
    )

    response = client.get(
        "/guard/audit/events",
        headers={"x-api-key": "test-api-key"},
    )
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["actor_id"] == "audit-client-001"
    assert data[0]["session_id"] == "audit-session-001"
    assert data[0]["request_id"] == "req-audit-001"
    assert data[0]["trace_id"] == "trace-audit-001"


def test_audit_events_endpoint_honors_limit():
    _seed_audit_event(
        actor_id="audit-client-001",
        session_id="audit-session-001",
        request_id="req-audit-001",
        trace_id="trace-audit-001",
    )
    _seed_audit_event(
        actor_id="audit-client-002",
        session_id="audit-session-002",
        request_id="req-audit-002",
        trace_id="trace-audit-002",
    )

    response = client.get(
        "/guard/audit/events?limit=1",
        headers={"x-api-key": "test-api-key"},
    )
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["actor_id"] == "audit-client-002"


def test_audit_events_can_be_filtered_by_session():
    _seed_audit_event(
        actor_id="audit-client-002",
        session_id="audit-session-002",
        request_id="req-audit-002",
        trace_id="trace-audit-002",
        target="https://example.com/a",
    )
    _seed_audit_event(
        actor_id="audit-client-003",
        session_id="audit-session-003",
        request_id="req-audit-003",
        trace_id="trace-audit-003",
        target="https://example.com/b",
    )

    response = client.get(
        "/guard/audit/events/by-session/audit-session-002",
        headers={"x-api-key": "test-api-key"},
    )
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["session_id"] == "audit-session-002"
    assert data[0]["actor_id"] == "audit-client-002"


def test_audit_events_by_session_honors_limit():
    _seed_audit_event(
        actor_id="audit-client-010",
        session_id="audit-session-shared",
        request_id="req-audit-010",
        trace_id="trace-audit-010",
    )
    _seed_audit_event(
        actor_id="audit-client-011",
        session_id="audit-session-shared",
        request_id="req-audit-011",
        trace_id="trace-audit-011",
    )

    response = client.get(
        "/guard/audit/events/by-session/audit-session-shared?limit=1",
        headers={"x-api-key": "test-api-key"},
    )
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["session_id"] == "audit-session-shared"
    assert data[0]["actor_id"] == "audit-client-011"


def test_audit_events_can_be_filtered_by_actor():
    _seed_audit_event(
        actor_id="audit-actor-001",
        session_id="audit-session-actor-001",
        request_id="req-audit-actor-001",
        trace_id="trace-audit-actor-001",
        target="https://example.com/actor",
        risk_score=1,
    )

    response = client.get(
        "/guard/audit/events/by-actor/audit-actor-001",
        headers={"x-api-key": "test-api-key"},
    )
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["actor_id"] == "audit-actor-001"
    assert data[0]["session_id"] == "audit-session-actor-001"


def test_audit_events_by_actor_honors_limit():
    _seed_audit_event(
        actor_id="audit-actor-shared",
        session_id="audit-session-020",
        request_id="req-audit-020",
        trace_id="trace-audit-020",
    )
    _seed_audit_event(
        actor_id="audit-actor-shared",
        session_id="audit-session-021",
        request_id="req-audit-021",
        trace_id="trace-audit-021",
    )

    response = client.get(
        "/guard/audit/events/by-actor/audit-actor-shared?limit=1",
        headers={"x-api-key": "test-api-key"},
    )
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["actor_id"] == "audit-actor-shared"
    assert data[0]["session_id"] == "audit-session-021"


def test_audit_events_can_be_filtered_by_request():
    _seed_audit_event(
        actor_id="audit-client-004",
        session_id="audit-session-004",
        request_id="req-audit-004",
        trace_id="trace-audit-004",
        target="shell",
        action_type="tool_call",
        verdict="quarantine",
        risk_score=85,
    )

    response = client.get(
        "/guard/audit/events/by-request/req-audit-004",
        headers={"x-api-key": "test-api-key"},
    )
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["request_id"] == "req-audit-004"
    assert data[0]["trace_id"] == "trace-audit-004"
    assert data[0]["verdict"] == "quarantine"


def test_audit_events_can_be_filtered_by_trace():
    _seed_audit_event(
        actor_id="audit-client-005",
        session_id="audit-session-005",
        request_id="req-audit-005",
        trace_id="trace-audit-005",
    )

    response = client.get(
        "/guard/audit/events/by-trace/trace-audit-005",
        headers={"x-api-key": "test-api-key"},
    )
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["trace_id"] == "trace-audit-005"
    assert data[0]["request_id"] == "req-audit-005"


def test_audit_events_allows_access_with_api_key():
    response = client.get(
        "/guard/audit/events",
        headers={"x-api-key": "test-api-key"},
    )

    assert response.status_code == 200


def test_audit_events_by_session_allows_access_with_api_key():
    response = client.get(
        "/guard/audit/events/by-session/audit-session-001",
        headers={"x-api-key": "test-api-key"},
    )

    assert response.status_code == 200


def test_audit_events_rejects_invalid_limit():
    response = client.get(
        "/guard/audit/events?limit=0",
        headers={"x-api-key": "test-api-key"},
    )

    assert response.status_code == 422


def test_audit_events_by_session_rejects_invalid_limit():
    response = client.get(
        "/guard/audit/events/by-session/audit-session-001?limit=1001",
        headers={"x-api-key": "test-api-key"},
    )

    assert response.status_code == 422