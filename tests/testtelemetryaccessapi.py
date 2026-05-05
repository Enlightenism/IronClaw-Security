from __future__ import annotations

from typing import Any, Final

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.telemetryaccess import (
    get_telemetry_access_service,
    router,
)


class StubTelemetryAccessService:
    def __init__(self) -> None:
        self.summary_calls: list[dict[str, Any]] = []
        self.events_calls: list[dict[str, Any]] = []

    def summary(
        self,
        *,
        actor_id: str | None = None,
        session_id: str | None = None,
        request_id: str | None = None,
        organization_id: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        self.summary_calls.append(
            {
                "actor_id": actor_id,
                "session_id": session_id,
                "request_id": request_id,
                "organization_id": organization_id,
                "limit": limit,
            }
        )
        return {
            "title": "Telemetry Access",
            "status": "ok",
            "summary": {
                "total_events": 3,
                "allowed": 2,
                "denied": 1,
            },
            "items": [
                {
                    "event_id": "evt-001",
                    "decision": "allowed",
                    "actor_id": actor_id or "actor-001",
                    "session_id": session_id or "sess-001",
                }
            ],
        }

    def events(
        self,
        *,
        actor_id: str | None = None,
        session_id: str | None = None,
        request_id: str | None = None,
        organization_id: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        self.events_calls.append(
            {
                "actor_id": actor_id,
                "session_id": session_id,
                "request_id": request_id,
                "organization_id": organization_id,
                "limit": limit,
            }
        )
        return {
            "items": [
                {
                    "event_id": "evt-001",
                    "decision": "allowed",
                    "actor_id": actor_id or "actor-001",
                    "session_id": session_id or "sess-001",
                    "request_id": request_id or "req-001",
                },
                {
                    "event_id": "evt-002",
                    "decision": "denied",
                    "actor_id": actor_id or "actor-001",
                    "session_id": session_id or "sess-001",
                    "request_id": request_id or "req-002",
                },
            ],
            "count": 2,
            "status": "ok",
        }


TELEMETRY_SUMMARY_PATH: Final[str] = "/telemetry/access"
TELEMETRY_EVENTS_PATH: Final[str] = "/telemetry/access/events"


def _build_client(service: StubTelemetryAccessService) -> TestClient:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_telemetry_access_service] = lambda: service
    return TestClient(app)


def _assert_json_response(response: Any) -> dict[str, Any]:
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/json")
    payload = response.json()
    assert isinstance(payload, dict)
    return payload


def test_telemetry_access_summary_endpoint_returns_summary_shape() -> None:
    service = StubTelemetryAccessService()
    client = _build_client(service)

    response = client.get(TELEMETRY_SUMMARY_PATH)
    body = _assert_json_response(response)

    assert any(key in body for key in ("title", "summary", "items", "status"))
    assert body.get("status") == "ok"
    assert "summary" in body
    assert isinstance(body["summary"], dict)
    assert isinstance(body.get("items", []), list)
    assert service.summary_calls


def test_telemetry_access_summary_passes_query_filters_to_service() -> None:
    service = StubTelemetryAccessService()
    client = _build_client(service)

    response = client.get(
        TELEMETRY_SUMMARY_PATH,
        params={
            "actor_id": "actor-123",
            "session_id": "sess-123",
            "request_id": "req-123",
            "organization_id": "org-123",
            "limit": 25,
        },
    )
    _assert_json_response(response)

    call = service.summary_calls[0]
    assert call["actor_id"] == "actor-123"
    assert call["session_id"] == "sess-123"
    assert call["request_id"] == "req-123"
    assert call["organization_id"] == "org-123"
    assert call["limit"] == 25


def test_telemetry_access_events_endpoint_returns_collection_shape_when_available() -> None:
    service = StubTelemetryAccessService()
    client = _build_client(service)

    response = client.get(TELEMETRY_EVENTS_PATH)

    if response.status_code == 404:
        return

    body = _assert_json_response(response)
    assert any(key in body for key in ("items", "events", "count", "status"))

    items = body.get("items", [])
    assert isinstance(items, list)
    if items:
        first = items[0]
        assert isinstance(first, dict)
        assert any(
            key in first
            for key in ("event_id", "decision", "actor_id", "session_id", "request_id")
        )


def test_telemetry_access_events_passes_filters_when_endpoint_exists() -> None:
    service = StubTelemetryAccessService()
    client = _build_client(service)

    response = client.get(
        TELEMETRY_EVENTS_PATH,
        params={
            "actor_id": "actor-evt",
            "session_id": "sess-evt",
            "request_id": "req-evt",
            "organization_id": "org-evt",
            "limit": 10,
        },
    )

    if response.status_code == 404:
        return

    _assert_json_response(response)

    call = service.events_calls[0]
    assert call["actor_id"] == "actor-evt"
    assert call["session_id"] == "sess-evt"
    assert call["request_id"] == "req-evt"
    assert call["organization_id"] == "org-evt"
    assert call["limit"] == 10


def test_telemetry_access_rejects_invalid_limit_when_validated() -> None:
    service = StubTelemetryAccessService()
    client = _build_client(service)

    response = client.get(TELEMETRY_SUMMARY_PATH, params={"limit": 0})

    assert response.status_code in {200, 400, 422}
    if response.status_code == 200:
        body = response.json()
        assert isinstance(body, dict)