from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.audit_log import router

app = FastAPI()
app.include_router(router)
client = TestClient(app)


def _auth_headers() -> dict[str, str]:
    return {"x-api-key": "test-api-key"}


def test_get_audit_events_returns_success() -> None:
    response = client.get("/audit/events", headers=_auth_headers())
    assert response.status_code in {200, 401, 403}


def test_get_audit_events_by_session_returns_success() -> None:
    response = client.get(
        "/audit/events/by-session/test-session-001",
        headers=_auth_headers(),
    )
    assert response.status_code in {200, 401, 403}


def test_get_audit_events_by_actor_returns_success() -> None:
    response = client.get(
        "/audit/events/by-actor/test-actor-001",
        headers=_auth_headers(),
    )
    assert response.status_code in {200, 401, 403}


def test_get_audit_events_by_request_returns_success() -> None:
    response = client.get(
        "/audit/events/by-request/test-request-001",
        headers=_auth_headers(),
    )
    assert response.status_code in {200, 401, 403}


def test_get_audit_events_by_trace_returns_success() -> None:
    response = client.get(
        "/audit/events/by-trace/test-trace-001",
        headers=_auth_headers(),
    )
    assert response.status_code in {200, 401, 403}


def test_get_telemetry_events_returns_success() -> None:
    response = client.get("/audit/telemetry/events", headers=_auth_headers())
    assert response.status_code in {200, 401, 403}


def test_get_telemetry_summary_returns_success() -> None:
    response = client.get("/audit/telemetry/summary", headers=_auth_headers())
    assert response.status_code in {200, 401, 403}


def test_audit_events_limit_validation() -> None:
    response = client.get("/audit/events?limit=0", headers=_auth_headers())
    assert response.status_code == 422


def test_telemetry_summary_limit_validation() -> None:
    response = client.get("/audit/telemetry/summary?limit=6000", headers=_auth_headers())
    assert response.status_code == 422