from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.auth import API_KEY_HEADER_NAME
from app.main import create_app


def _client() -> TestClient:
    return TestClient(create_app())


def _auth_headers() -> dict[str, str]:
    return {API_KEY_HEADER_NAME: "test-api-key"}


def test_integration_settings_page_returns_success():
    client = _client()

    response = client.get("/ui/integrations/settings")

    assert response.status_code == 200
    payload = response.json()

    assert "generatedat" in payload
    assert "providers" in payload
    assert isinstance(payload["providers"], list)


def test_integration_settings_page_exposes_expected_top_level_fields():
    client = _client()

    response = client.get("/ui/integrations/settings", headers=_auth_headers())

    assert response.status_code == 200
    payload = response.json()

    for key in (
        "generatedat",
        "defaultguardmode",
        "bidirectionalsyncenabled",
        "providers",
    ):
        assert key in payload

    assert isinstance(payload["bidirectionalsyncenabled"], bool)
    assert isinstance(payload["providers"], list)
    assert len(payload["providers"]) >= 1


def test_integration_settings_contains_known_integrations():
    client = _client()

    response = client.get("/ui/integrations/settings", headers=_auth_headers())

    assert response.status_code == 200
    payload = response.json()

    names = {item["name"] for item in payload["providers"]}
    assert {"OpenClaw", "Claude Code", "Cursor", "Goose", "Gemini CLI", "GitHub Copilot", "Security Guardian"} <= names


def test_integration_settings_uses_canonical_install_key_family_labels():
    client = _client()

    response = client.get("/ui/integrations/settings", headers=_auth_headers())

    assert response.status_code == 200
    payload = response.json()

    programs = {item["installkeyprogram"] for item in payload["providers"] if item.get("installkeyprogram")}
    assert {"openclaw", "claude_code", "cursor", "goose", "gemini_cli", "copilot", "security_guardian"} <= programs

    names = {item["name"] for item in payload["providers"]}
    assert "GitHub Copilot" in names
    assert "Security Guardian" in names

    family_names = {item["installkeyfamily"] for item in payload["settings"] if item.get("installkeyfamily")}
    assert {"openclaw", "claude_code", "cursor", "goose", "gemini_cli", "copilot", "security_guardian"} <= family_names


def test_integration_settings_items_expose_expected_fields():
    client = _client()

    response = client.get("/ui/integrations/settings", headers=_auth_headers())

    assert response.status_code == 200
    payload = response.json()

    first_item = payload["providers"][0]

    for key in (
        "name",
        "enabled",
        "mode",
        "endpoint",
    ):
        assert key in first_item


def test_integration_settings_items_are_unique_by_name():
    client = _client()

    response = client.get("/ui/integrations/settings", headers=_auth_headers())

    assert response.status_code == 200
    payload = response.json()

    names = [item["name"] for item in payload["providers"]]
    assert len(names) == len(set(names))
