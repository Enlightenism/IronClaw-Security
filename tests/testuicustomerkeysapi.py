from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_ui_customer_keys_route_is_registered() -> None:
    response = client.get("/ui/customer-keys")
    assert response.status_code == 200


def test_ui_customer_keys_returns_json_object() -> None:
    response = client.get("/ui/customer-keys")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)


def test_ui_customer_keys_contains_core_fields() -> None:
    response = client.get("/ui/customer-keys")
    assert response.status_code == 200

    data = response.json()
    assert data

    assert any(k in data for k in ("title", "headline", "summary", "page_title"))
    assert any(k in data for k in ("keys", "items", "rows", "records", "customers", "entries"))
    assert any(k in data for k in ("actions", "filters", "status", "sections", "policies", "columns"))
