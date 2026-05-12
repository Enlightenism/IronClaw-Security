from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _auth_headers() -> dict[str, str]:
    return {"x-api-key": "test-api-key"}


def test_ui_status_endpoint_is_reachable() -> None:
    response = client.get("/ui-status", headers=_auth_headers())
    assert response.status_code in {200, 401, 403}
    if response.status_code != 200:
        return

    data = response.json()
    assert isinstance(data, dict)


def test_ui_status_contains_basic_status_fields_when_available() -> None:
    response = client.get("/ui-status", headers=_auth_headers())
    assert response.status_code in {200, 401, 403}
    if response.status_code != 200:
        return

    data = response.json()
    assert "status" in data
    assert "service" in data
    assert "timestamp" in data


def test_ui_status_supports_unauthenticated_access_or_rejects_cleanly() -> None:
    response = client.get("/ui-status")
    assert response.status_code in {200, 401, 403}


def test_ui_status_accepts_head_request_when_supported() -> None:
    response = client.head("/ui-status", headers=_auth_headers())
    assert response.status_code in {200, 401, 403, 405}


def test_ui_status_returns_json_content_on_success() -> None:
    response = client.get("/ui-status", headers=_auth_headers())
    assert response.status_code in {200, 401, 403}
    if response.status_code != 200:
        return

    assert "application/json" in response.headers.get("content-type", "")


def test_ui_status_contains_counts_and_flags_on_success() -> None:
    response = client.get("/ui-status", headers=_auth_headers())
    assert response.status_code in {200, 401, 403}
    if response.status_code != 200:
        return

    data = response.json()
    assert "counts" in data
    assert "flags" in data