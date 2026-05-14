from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_marketing_platform_route_is_registered() -> None:
    response = client.get("/marketing/platform")
    assert response.status_code == 200


def test_marketing_platform_returns_json_object() -> None:
    response = client.get("/marketing/platform")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)


def test_marketing_platform_contains_core_fields() -> None:
    response = client.get("/marketing/platform")
    assert response.status_code == 200

    data = response.json()
    assert data

    # flexible but meaningful contract
    assert any(k in data for k in ("title", "headline", "hero"))
    assert any(k in data for k in ("sections", "blocks", "capabilities", "features"))
