from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_marketing_home_route_is_registered() -> None:
    response = client.get("/marketing/home")
    assert response.status_code == 200


def test_marketing_home_returns_json_object() -> None:
    response = client.get("/marketing/home")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)


def test_marketing_home_contains_core_fields() -> None:
    response = client.get("/marketing/home")
    assert response.status_code == 200

    data = response.json()
    assert data

    assert any(k in data for k in ("title", "hero", "headline"))
    assert any(k in data for k in ("sections", "blocks", "content", "layout"))