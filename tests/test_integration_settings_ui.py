from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.auth import API_KEY_HEADER_NAME
from app.main import create_app


def _client() -> TestClient:
    return TestClient(create_app())


def _auth_headers() -> dict[str, str]:
    return {API_KEY_HEADER_NAME: "test-api-key"}


def test_ui_integration_settings_page_returns_success() -> None:
    client = _client()

    response = client.get("/ui/integrations/settings", headers=_auth_headers())

    assert response.status_code == 200
    payload = response.json()

    assert isinstance(payload, dict)
    assert "providers" in payload
    assert isinstance(payload["providers"], list)
    assert payload["providers"], "providers list should not be empty"

    first_item = payload["providers"][0]
    for key in (
        "name",
        "enabled",
        "mode",
        "endpoint",
    ):
        assert key in first_item


def test_ui_integration_settings_items_are_unique_by_name() -> None:
    client = _client()

    response = client.get("/ui/integrations/settings", headers=_auth_headers())

    assert response.status_code == 200
    payload = response.json()

    assert "providers" in payload
    assert isinstance(payload["providers"], list)

    names = [item["name"] for item in payload["providers"]]
    assert len(names) == len(set(names))
