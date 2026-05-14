from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_ui_organizations_route_is_registered() -> None:
    response = client.get("/ui/organizations")
    assert response.status_code == 200


def test_ui_organizations_returns_json_object() -> None:
    response = client.get("/ui/organizations")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)


def test_ui_organizations_contains_core_fields() -> None:
    response = client.get("/ui/organizations")
    assert response.status_code == 200

    data = response.json()
    assert data

    assert any(k in data for k in ("title", "headline", "summary", "page_title"))
    assert any(k in data for k in ("organizations", "items", "rows", "records", "tenants", "accounts"))
    assert any(k in data for k in ("filters", "sections", "actions", "columns", "table", "pagination"))
