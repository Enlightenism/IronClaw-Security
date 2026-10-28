from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient
import pytest

from app.api import history as history_api
from app.orchestrator.security_audit_log import (
    initialize_security_audit_log,
    record_policy_decision,
)
from app.services import history as history_service
from app.services.audit_log_service import set_audit_log


def _seed_history_event(
    *,
    actor_id: str = "history-actor-001",
    session_id: str = "history-session-001",
    request_id: str = "req-history-001",
    trace_id: str = "trace-history-001",
    target: str = "https://example.com/history",
    action_type: str = "http_fetch",
    verdict: str = "allow",
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
        reason="Seeded history event for API testing.",
        session_id=session_id,
        file_path="app/api/action_execute.py",
        metadata={
            "actor_id": actor_id,
            "session_id": session_id,
            "request_id": request_id,
            "trace_id": trace_id,
            "source": "test_seed_history",
        },
    )
    set_audit_log(audit_log)


def test_history_endpoint_returns_recent_events(test_client: TestClient) -> None:
    _seed_history_event(
        actor_id="history-actor-001",
        session_id="history-session-001",
        request_id="req-history-001",
        trace_id="trace-history-001",
    )

    response = test_client.get("/history/events")
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert len(data) >= 1

    first = data[0]
    assert first["actor_id"] == "history-actor-001"
    assert first["session_id"] == "history-session-001"
    assert first["request_id"] == "req-history-001"
    assert first["trace_id"] == "trace-history-001"


def test_history_endpoint_honors_limit(test_client: TestClient) -> None:
    _seed_history_event(
        actor_id="history-actor-001",
        session_id="history-session-001",
        request_id="req-history-001",
        trace_id="trace-history-001",
    )
    _seed_history_event(
        actor_id="history-actor-002",
        session_id="history-session-002",
        request_id="req-history-002",
        trace_id="trace-history-002",
    )

    response = test_client.get("/history/events?limit=1")
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["actor_id"] == "history-actor-002"


def test_history_events_can_be_filtered_by_session(test_client: TestClient) -> None:
    _seed_history_event(
        actor_id="history-actor-010",
        session_id="history-session-010",
        request_id="req-history-010",
        trace_id="trace-history-010",
    )
    _seed_history_event(
        actor_id="history-actor-011",
        session_id="history-session-011",
        request_id="req-history-011",
        trace_id="trace-history-011",
    )

    response = test_client.get("/history/events/by-session/history-session-011")
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert len(data) >= 1
    assert all(item["session_id"] == "history-session-011" for item in data)


def test_history_events_can_be_filtered_by_actor(test_client: TestClient) -> None:
    _seed_history_event(
        actor_id="history-actor-filter",
        session_id="history-session-020",
        request_id="req-history-020",
        trace_id="trace-history-020",
    )
    _seed_history_event(
        actor_id="history-actor-filter",
        session_id="history-session-021",
        request_id="req-history-021",
        trace_id="trace-history-021",
    )

    response = test_client.get("/history/events/by-actor/history-actor-filter")
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert len(data) >= 1
    assert all(item["actor_id"] == "history-actor-filter" for item in data)


def test_history_events_allows_access_with_api_key(test_client: TestClient) -> None:
    response = test_client.get("/history/events")
    assert response.status_code == 200


def test_history_events_rejects_invalid_limit(test_client: TestClient) -> None:
    response = test_client.get("/history/events?limit=0")
    assert response.status_code == 422


@pytest.mark.parametrize("verdict", ["block", "quarantine"])
def test_scan_history_defaults_block_records_to_pending_and_untrusted(
    verdict: str,
) -> None:
    item = history_service._normalize_record(
        {"scan_id": "scan-review-001", "verdict": verdict},
    )

    assert item["review_status"] == "pending"
    assert item["untrusted"] is True


@pytest.mark.parametrize("verdict", ["block", "quarantine"])
def test_review_scan_record_keeps_block_after_approval(
    monkeypatch: pytest.MonkeyPatch,
    verdict: str,
) -> None:
    item = {
        "scan_id": "scan-review-002",
        "verdict": verdict,
        "summary": "A suspicious pattern was detected.",
        "target_type": "text",
        "target_value": "suspicious input",
        "risk_score": 90,
        "matched_patterns": ["suspicious-pattern"],
        "review_status": "pending",
        "untrusted": True,
    }
    recorded_updates: dict[str, object] = {}

    monkeypatch.setattr(history_api, "get_scan_by_id", lambda _: item)

    def update_scan_by_id(
        _scan_id: str,
        updates: dict[str, Any],
    ) -> dict[str, Any]:
        recorded_updates.update(updates)
        return {**item, **updates}

    monkeypatch.setattr(history_api, "update_scan_by_id", update_scan_by_id)
    result = history_api.review_scan_record(
        "scan-review-002",
        history_api.ReviewRequest(action="approve"),
    )

    assert recorded_updates["verdict"] == "block"
    assert recorded_updates["untrusted"] is True
    assert result.verdict == "block"
    assert result.review_status == "approved"
    assert result.untrusted is True


@pytest.mark.parametrize("verdict", ["block", "quarantine"])
def test_history_service_review_accepts_block_and_legacy_quarantine(
    monkeypatch: pytest.MonkeyPatch,
    verdict: str,
) -> None:
    item = {
        "scan_id": "scan-review-003",
        "verdict": verdict,
        "summary": "A suspicious pattern was detected.",
    }
    recorded_updates: dict[str, object] = {}

    monkeypatch.setattr(history_service, "get_scan_by_id", lambda _: item)

    def update_scan_by_id(
        _scan_id: str,
        updates: dict[str, Any],
    ) -> dict[str, Any]:
        recorded_updates.update(updates)
        return {**item, **updates}

    monkeypatch.setattr(history_service, "update_scan_by_id", update_scan_by_id)
    result = history_service.review_scan("scan-review-003", "approve")
    assert result is not None
    result = history_service.apply_review_action(result, "approve")

    assert recorded_updates["verdict"] == "block"
    assert result["verdict"] == "block"
    assert result["review_status"] == "approved"
    assert result["untrusted"] is True
