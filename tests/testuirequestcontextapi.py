from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_ui_request_context_route_is_registered() -> None:
    response = client.get("/ui/request-context")
    assert response.status_code == 200


def test_ui_request_context_returns_json_object() -> None:
    response = client.get("/ui/request-context")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)


def test_ui_request_context_contains_core_fields() -> None:
    response = client.get("/ui/request-context")
    assert response.status_code == 200

    data = response.json()
    assert data

    assert any(k in data for k in ("title", "headline", "summary", "page_title"))
    assert any(k in data for k in ("request", "context", "session", "metadata", "inputs"))
    assert any(k in data for k in ("risk", "signals", "policy", "actions", "decision", "trace"))
