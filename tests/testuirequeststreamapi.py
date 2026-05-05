from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_ui_request_stream_route_is_registered() -> None:
    response = client.get("/ui/request-stream")
    assert response.status_code == 200


def test_ui_request_stream_returns_json_object() -> None:
    response = client.get("/ui/request-stream")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)


def test_ui_request_stream_contains_core_fields() -> None:
    response = client.get("/ui/request-stream")
    assert response.status_code == 200

    data = response.json()
    assert data

    assert any(k in data for k in ("title", "headline", "summary", "dashboard_title"))
    assert any(
        k in data
        for k in ("items", "events", "requests", "entries", "stream")
    )
    assert any(
        k in data
        for k in ("filters", "timeline", "sections", "tabs", "actions")
    )