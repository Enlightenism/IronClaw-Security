from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_ui_session_risk_route_is_registered() -> None:
    response = client.get("/ui/session-risk")
    assert response.status_code == 200


def test_ui_session_risk_returns_json_object() -> None:
    response = client.get("/ui/session-risk")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    payload = response.json()
    assert isinstance(payload, dict)


def test_ui_session_risk_contains_core_fields() -> None:
    response = client.get("/ui/session-risk")
    assert response.status_code == 200

    payload = response.json()
    assert payload

    assert any(key in payload for key in ("title", "headline", "page_title", "summary"))
    assert any(
        key in payload
        for key in ("session", "sessions", "risk", "risk_summary", "assessment")
    )
    assert any(
        key in payload
        for key in ("score", "level", "signals", "factors", "recommendations", "actions")
    )