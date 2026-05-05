from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_admin_incident_triage_route_is_registered() -> None:
    response = client.get("/admin/incident-triage")
    assert response.status_code == 200


def test_admin_incident_triage_returns_json_object() -> None:
    response = client.get("/admin/incident-triage")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)


def test_admin_incident_triage_contains_basic_shape() -> None:
    response = client.get("/admin/incident-triage")

    assert response.status_code == 200

    data = response.json()
    assert data
    assert any(
        key in data
        for key in (
            "title",
            "incidents",
            "triage",
            "queue",
            "items",
            "summary",
            "status",
        )
    )