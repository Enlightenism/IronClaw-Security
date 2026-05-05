from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_marketing_layout_route_is_registered() -> None:
    response = client.get("/marketing/layout")
    assert response.status_code == 200


def test_marketing_layout_returns_json_object() -> None:
    response = client.get("/marketing/layout")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)


def test_marketing_layout_contains_expected_sections() -> None:
    response = client.get("/marketing/layout")
    assert response.status_code == 200

    data = response.json()
    assert data

    # flexible but meaningful contract
    assert any(k in data for k in ("header", "hero", "footer", "sections"))
    # allow a nav linkage without requiring a specific shape
    assert any(k in data for k in ("nav", "nav_key", "navigation_ref"))