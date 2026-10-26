from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_guard_ui_dashboard_route_is_registered() -> None:
    response = client.get("/ui/guard/prompt-guard/dashboard-index")
    assert response.status_code == 200


def test_guard_ui_dashboard_returns_json_object() -> None:
    response = client.get("/ui/guard/prompt-guard/dashboard-index")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)


def test_guard_ui_dashboard_contains_basic_shape() -> None:
    response = client.get("/ui/guard/prompt-guard/dashboard-index")

    assert response.status_code == 200

    data = response.json()
    assert {"generated_at", "dashboard", "sections", "metadata"} <= data.keys()
