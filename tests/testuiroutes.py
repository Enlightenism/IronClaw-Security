from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_ui_routes_route_is_registered() -> None:
    response = client.get("/ui/routes")
    assert response.status_code == 200


def test_ui_routes_returns_json_object() -> None:
    response = client.get("/ui/routes")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)


def test_ui_routes_contains_basic_shape() -> None:
    response = client.get("/ui/routes")

    assert response.status_code == 200

    data = response.json()
    assert data
    assert any(
        key in data
        for key in (
            "title",
            "routes",
            "items",
            "sections",
            "summary",
            "status",
        )
    )