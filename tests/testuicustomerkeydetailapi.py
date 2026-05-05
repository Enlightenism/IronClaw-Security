from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_ui_customer_key_detail_route_is_registered() -> None:
    response = client.get("/ui/customer-key-detail")
    assert response.status_code == 200


def test_ui_customer_key_detail_returns_json_object() -> None:
    response = client.get("/ui/customer-key-detail")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)


def test_ui_customer_key_detail_contains_core_fields() -> None:
    response = client.get("/ui/customer-key-detail")
    assert response.status_code == 200

    data = response.json()
    assert data

    assert any(k in data for k in ("title", "headline", "summary", "page_title"))
    assert any(
        k in data
        for k in ("key", "detail", "item", "record", "metadata", "customer_key")
    )
    assert any(
        k in data
        for k in ("status", "actions", "sections", "audit", "policies", "details")
    )