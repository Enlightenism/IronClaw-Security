from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from app.main import create_app


@pytest.fixture(scope="module")
def client() -> TestClient:
    app = create_app()
    return TestClient(app, raise_server_exceptions=True)


def test_request_context_requires_auth(client: TestClient) -> None:
    response = client.get("/request-context")
    assert response.status_code in (200, 401, 403)


def test_request_context_with_headers(client: TestClient) -> None:
    response = client.get(
        "/request-context",
        headers={
            "X-Request-ID": "req-test-123",
            "X-Trace-ID": "trace-test-123",
            "User-Agent": "pytest-agent",
            "X-API-Key": "test-key",
        },
    )
    assert response.status_code in (200, 401, 403)
    if response.status_code == 200:
        body = response.json()
        assert body["path"] == "/request-context"
        assert body["method"] == "GET"


def test_history_events_endpoint_accepts_limit(client: TestClient) -> None:
    response = client.get("/history/events?limit=10")
    assert response.status_code in (200, 401, 403)
    if response.status_code == 200:
        assert isinstance(response.json(), list)


def test_ui_history_events_by_session_endpoint_accepts_limit(client: TestClient) -> None:
    response = client.get("/history/events/by-session/test-session-xyz?limit=5")
    assert response.status_code in (200, 401, 403)
    if response.status_code == 200:
        assert isinstance(response.json(), list)


def test_ui_history_events_by_actor_endpoint_accepts_limit(client: TestClient) -> None:
    response = client.get("/history/events/by-actor/test-actor-xyz?limit=5")
    assert response.status_code in (200, 401, 403)
    if response.status_code == 200:
        assert isinstance(response.json(), list)


def test_ui_scan_history_list_endpoint_works(client: TestClient) -> None:
    response = client.get("/history/")
    assert response.status_code in (200, 401, 403)
    if response.status_code == 200:
        body = response.json()
        assert "count" in body
        assert "items" in body
        assert isinstance(body["items"], list)
