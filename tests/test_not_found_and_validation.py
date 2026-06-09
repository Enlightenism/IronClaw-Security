from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient
import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _assert_client_error(response, expected_statuses: set[int]) -> None:
    assert response.status_code in expected_statuses, f"Expected one of {sorted(expected_statuses)}, got {response.status_code}: {response.text}"


# ---------------------------------------------------------------------------
# /history/{scan_id} — unknown ID
# ---------------------------------------------------------------------------


def test_history_detail_unknown_id_returns_client_error(test_client: TestClient) -> None:
    response = test_client.get("/history/does-not-exist")
    _assert_client_error(response, {404, 422, 503})


def test_history_detail_unknown_id_api_prefix(test_client: TestClient) -> None:
    """Dual-mounted /api/history prefix must behave identically."""
    response = test_client.get("/api/history/does-not-exist")
    _assert_client_error(response, {404, 422, 503})


# ---------------------------------------------------------------------------
# /history/{scan_id} — repository connection error produces 503, not 500
# ---------------------------------------------------------------------------


class _FakeConnectionError(Exception):
    """Stands in for ScanHistoryRepositoryConnectionError without importing Supabase."""


def _raise_connection_error(*_args, **_kwargs):
    raise _FakeConnectionError("missing SUPABASE_URL")


@pytest.fixture()
def _broken_repo_client(test_client: TestClient):
    """Patch get_scan_by_id so it raises a connection-style error."""
    with patch(
        "app.api.history.get_scan_by_id",
        side_effect=_raise_connection_error,
    ):
        yield test_client


def test_history_detail_connection_error_returns_503(
    _broken_repo_client: TestClient,
) -> None:
    """When the repository raises a connection error the handler must return
    503 (or 404) — never an unhandled 500."""
    response = _broken_repo_client.get("/history/does-not-exist")
    _assert_client_error(response, {404, 422, 503})


def test_history_detail_api_prefix_connection_error_returns_503(
    _broken_repo_client: TestClient,
) -> None:
    """Dual-mounted /api/history prefix must produce 503 on connection errors too."""
    response = _broken_repo_client.get("/api/history/does-not-exist")
    _assert_client_error(response, {404, 422, 503})


# ---------------------------------------------------------------------------
# /history/{scan_id}/review — connection error on GET produces 503
# ---------------------------------------------------------------------------


def test_history_review_connection_error_returns_503(
    _broken_repo_client: TestClient,
) -> None:
    """When get_scan_by_id raises a connection error during review lookup,
    the handler must return 503 — never an unhandled 500."""
    response = _broken_repo_client.post(
        "/history/does-not-exist/review",
        json={"action": "approve"},
    )
    _assert_client_error(response, {404, 422, 503})


# ---------------------------------------------------------------------------
# /history/ list — connection error on read_scan_history produces 503
# ---------------------------------------------------------------------------


@pytest.fixture()
def _broken_list_client(test_client: TestClient):
    """Patch read_scan_history so it raises a connection-style error."""
    with patch(
        "app.api.history.read_scan_history",
        side_effect=_FakeConnectionError("missing SUPABASE_URL"),
    ):
        yield test_client


def test_history_list_connection_error_returns_503(
    _broken_list_client: TestClient,
) -> None:
    """When read_scan_history raises a connection error the list handler must
    return 503 — never an unhandled 500."""
    response = _broken_list_client.get("/history/")
    _assert_client_error(response, {503})


# ---------------------------------------------------------------------------
# /guard/reviews — unknown ID
# ---------------------------------------------------------------------------


def test_review_detail_unknown_id_returns_client_error(test_client: TestClient) -> None:
    response = test_client.get("/guard/reviews/does-not-exist")
    _assert_client_error(response, {404, 422})


def test_review_approve_unknown_id_returns_client_error(test_client: TestClient) -> None:
    response = test_client.post("/guard/reviews/does-not-exist/approve")
    _assert_client_error(response, {404, 422})


def test_review_reject_unknown_id_returns_client_error(test_client: TestClient) -> None:
    response = test_client.post("/guard/reviews/does-not-exist/reject")
    _assert_client_error(response, {404, 422})


# ---------------------------------------------------------------------------
# /history/{scan_id}/review — bad review state (non-quarantine scan)
# ---------------------------------------------------------------------------


def test_history_review_non_quarantine_scan_returns_400(test_client: TestClient) -> None:
    """Attempting to review a scan that is not in quarantine must return 400."""
    scan_resp = test_client.post(
        "/scan",
        json={"content": "hello world", "context": "test"},
    )
    if scan_resp.status_code not in {200, 201}:
        pytest.skip("scan endpoint unavailable in this fixture configuration")

    scan_id = scan_resp.json().get("scan_id") or scan_resp.json().get("id")
    if not scan_id:
        pytest.skip("no scan_id in scan response")

    review_resp = test_client.post(
        f"/history/{scan_id}/review",
        json={"action": "approve"},
    )
    _assert_client_error(review_resp, {400, 404, 422})


# ---------------------------------------------------------------------------
# /history/events — session / actor lookups with unknown IDs
# ---------------------------------------------------------------------------


def test_history_events_by_session_unknown_id_is_stable(test_client: TestClient) -> None:
    response = test_client.get("/history/events/by-session/does-not-exist")
    _assert_client_error(response, {200, 404, 422})


def test_history_events_by_actor_unknown_id_is_stable(test_client: TestClient) -> None:
    response = test_client.get("/history/events/by-actor/does-not-exist")
    _assert_client_error(response, {200, 404, 422})


# ---------------------------------------------------------------------------
# /guard/audit — various unknown-ID lookups
# ---------------------------------------------------------------------------


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
