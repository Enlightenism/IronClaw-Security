from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_ui_manifest_route_is_registered() -> None:
    response = client.get("/ui/manifest")
    assert response.status_code == 200


def test_ui_manifest_returns_json_object() -> None:
    response = client.get("/ui/manifest")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)


def test_ui_manifest_contains_basic_shape() -> None:
    response = client.get("/ui/manifest")

    assert response.status_code == 200

    data = response.json()
    assert data
    assert any(
        key in data
        for key in (
            "status",
            "service",
            "timestamp",
            "totalroutes",
            "routes",
            "metadata",
        )
    )


def test_ui_manifest_routes_have_basic_shape() -> None:
    response = client.get("/ui/manifest")

    assert response.status_code == 200

    data = response.json()
    routes = data.get("routes", [])

    assert isinstance(routes, list)
    assert routes

    for route in routes:
        assert isinstance(route, dict)
        assert "prefix" in route
        assert isinstance(route["prefix"], str)
        assert route["prefix"].startswith("/")


def test_ui_manifest_contains_core_entries() -> None:
    response = client.get("/ui/manifest")

    assert response.status_code == 200

    data = response.json()
    routes = data.get("routes", [])

    assert any(route.get("prefix") == "/ui/manifest" for route in routes)
    assert any(route.get("prefix") == "/ui/routes" for route in routes)
    assert any(route.get("prefix") == "/ui/pages" for route in routes)