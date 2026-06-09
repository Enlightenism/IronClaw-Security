from __future__ import annotations

from fastapi.testclient import TestClient


def _assert_client_error(response, expected_statuses: set[int]) -> None:
    assert response.status_code in expected_statuses, f"Expected one of {sorted(expected_statuses)}, got {response.status_code}: {response.text}"


def test_history_detail_unknown_id_returns_client_error(test_client: TestClient) -> None:
    response = test_client.get("/history/does-not-exist")
    _assert_client_error(response, {404, 422})


def test_review_detail_unknown_id_returns_client_error(test_client: TestClient) -> None:
    response = test_client.get("/guard/reviews/does-not-exist")
    _assert_client_error(response, {404, 422})


def test_review_approve_unknown_id_returns_client_error(test_client: TestClient) -> None:
    response = test_client.post("/guard/reviews/does-not-exist/approve")
    _assert_client_error(response, {404, 422})


def test_review_reject_unknown_id_returns_client_error(test_client: TestClient) -> None:
    response = test_client.post("/guard/reviews/does-not-exist/reject")
    _assert_client_error(response, {404, 422})


def test_history_events_by_session_unknown_id_is_stable(test_client: TestClient) -> None:
    response = test_client.get("/history/events/by-session/does-not-exist")
    _assert_client_error(response, {200, 404, 422})


def test_history_events_by_actor_unknown_id_is_stable(test_client: TestClient) -> None:
    response = test_client.get("/history/events/by-actor/does-not-exist")
    _assert_client_error(response, {200, 404, 422})


def test_guard_audit_by_session_unknown_id_is_stable(test_client: TestClient) -> None:
    response = test_client.get("/guard/audit/events/by-session/does-not-exist")
    _assert_client_error(response, {200, 404, 422})


def test_guard_audit_by_actor_unknown_id_is_stable(test_client: TestClient) -> None:
    response = test_client.get("/guard/audit/events/by-actor/does-not-exist")
    _assert_client_error(response, {200, 404, 422})


def test_guard_audit_by_request_unknown_id_is_stable(test_client: TestClient) -> None:
    response = test_client.get("/guard/audit/events/by-request/does-not-exist")
    _assert_client_error(response, {200, 404, 422})


def test_guard_audit_by_trace_unknown_id_is_stable(test_client: TestClient) -> None:
    response = test_client.get("/guard/audit/events/by-trace/does-not-exist")
    _assert_client_error(response, {200, 404, 422})
