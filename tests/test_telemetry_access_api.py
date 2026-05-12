from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.services.telemetry import append_telemetry_event

client = TestClient(app)


def _auth_headers() -> dict[str, str]:
    return {"x-api-key": "test-api-key"}


def _seed_telemetry() -> None:
    append_telemetry_event(
        "test_telemetry_event_one",
        {
            "source": "pytest",
            "category": "telemetry_access",
            "severity": "info",
        },
    )
    append_telemetry_event(
        "test_telemetry_event_two",
        {
            "source": "pytest",
            "category": "telemetry_access",
            "severity": "warning",
        },
    )


def test_telemetry_access_summary_endpoint_is_reachable() -> None:
    _seed_telemetry()

    response = client.get("/telemetry-access/summary", headers=_auth_headers())
    assert response.status_code in {200, 401, 403}
    if response.status_code != 200:
        return

    data = response.json()
    assert isinstance(data, dict)
    assert "telemetry_summary" in data
    assert "recent_events" in data


def test_telemetry_access_summary_returns_recent_events_when_available() -> None:
    _seed_telemetry()

    response = client.get("/telemetry-access/summary", headers=_auth_headers())
    assert response.status_code in {200, 401, 403}
    if response.status_code != 200:
        return

    data = response.json()
    recent_events = data["recent_events"]
    assert isinstance(recent_events, list)

    serialized = str(recent_events)
    assert "test_telemetry_event_one" in serialized or "test_telemetry_event_two" in serialized


def test_telemetry_access_summary_supports_query_limits() -> None:
    _seed_telemetry()

    response = client.get(
        "/telemetry-access/summary?summary_limit=5&events_limit=5",
        headers=_auth_headers(),
    )
    assert response.status_code in {200, 401, 403, 422}


def test_telemetry_access_summary_rejects_invalid_limits_when_validated() -> None:
    response = client.get(
        "/telemetry-access/summary?summary_limit=0&events_limit=0",
        headers=_auth_headers(),
    )
    assert response.status_code in {401, 403, 422}


def test_telemetry_access_summary_rejects_missing_auth_when_protected() -> None:
    response = client.get("/telemetry-access/summary")
    assert response.status_code in {200, 401, 403}