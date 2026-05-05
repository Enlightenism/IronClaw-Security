from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.history import router as history_router
from app.api.request_context import router as request_context_router


app = FastAPI()
app.include_router(history_router, prefix="/history")
app.include_router(request_context_router)
client = TestClient(app)


def test_request_context_returns_basic_metadata() -> None:
    response = client.get(
        "/request-context",
        headers={
            "X-Request-ID": "req-test-123",
            "X-Trace-ID": "trace-test-123",
            "User-Agent": "pytest-agent",
        },
    )

    assert response.status_code == 200
    body = response.json()

    assert body["path"] == "/request-context"
    assert body["method"] == "GET"
    assert body["headers"]["x-request-id"] == "req-test-123"
    assert body["headers"]["x-trace-id"] == "trace-test-123"
    assert body["headers"]["user-agent"] == "pytest-agent"


def test_history_events_endpoint_accepts_limit() -> None:
    response = client.get("/history/events?limit=10")
    assert response.status_code in {200, 401, 403}
    if response.status_code == 200:
        assert isinstance(response.json(), list)


def test_history_events_by_session_endpoint_accepts_limit() -> None:
    response = client.get("/history/events/by-session/test-session-xyz?limit=5")
    assert response.status_code in {200, 401, 403}
    if response.status_code == 200:
        assert isinstance(response.json(), list)


def test_history_events_by_actor_endpoint_accepts_limit() -> None:
    response = client.get("/history/events/by-actor/test-actor-xyz?limit=5")
    assert response.status_code in {200, 401, 403}
    if response.status_code == 200:
        assert isinstance(response.json(), list)


def test_scan_history_list_endpoint_works() -> None:
    response = client.get("/history/")
    assert response.status_code in {200, 401, 403}
    if response.status_code == 200:
        body = response.json()
        assert "count" in body
        assert "items" in body
        assert isinstance(body["items"], list)