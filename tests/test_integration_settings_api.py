from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.auth import API_KEY_HEADER_NAME
from app.core.install_key_formats import InstallKeyFormatRegistry
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
    assert {"OpenClaw", "Claude Code", "Cursor", "Goose", "Gemini CLI", "GitHub Copilot", "Hermes", "Security Guardian"} <= names


def test_integration_settings_uses_canonical_install_key_family_labels():
    client = _client()

    response = client.get("/ui/integrations/settings", headers=_auth_headers())

    assert response.status_code == 200
    payload = response.json()

    programs = {item["installkeyprogram"] for item in payload["providers"] if item.get("installkeyprogram")}
    assert {"openclaw", "claude_code", "cursor", "goose", "gemini_cli", "copilot", "hermes", "security_guardian"} <= programs

    names = {item["name"] for item in payload["providers"]}
    assert "GitHub Copilot" in names
    assert "Hermes" in names
    assert "Security Guardian" in names

    family_names = {item["installkeyfamily"] for item in payload["settings"] if item.get("installkeyfamily")}
    assert {"openclaw", "claude_code", "cursor", "goose", "gemini_cli", "copilot", "hermes", "security_guardian"} <= family_names


def test_integration_settings_summary_tracks_canonical_install_key_matrix():
    client = _client()

    response = client.get("/ui/integrations/settings", headers=_auth_headers())

    assert response.status_code == 200
    payload = response.json()

    expected_programs = set(InstallKeyFormatRegistry.list_programs())
    assert {item["installkeyprogram"] for item in payload["settings"] if item.get("installkeyprogram")} == expected_programs
    assert payload["summary"]["totalintegrations"] == len(expected_programs)
    assert payload["summary"]["configurableintegrations"] == len(expected_programs)
    assert payload["summary"]["verifiedintegrations"] == len(expected_programs)
    assert payload["summary"]["activeintegrations"] == len(expected_programs)
    assert payload["summary"]["pendingintegrations"] == 0


def test_integration_settings_metadata_includes_hermes_and_modern_programs():
    client = _client()

    response = client.get("/ui/integrations/settings", headers=_auth_headers())

    assert response.status_code == 200
    payload = response.json()

    providers_by_name = {item["name"]: item for item in payload["providers"]}
    for name, program, family, prefix in (
        ("Hermes", "hermes", "hermes", "ic_install_hermes_"),
        ("GitHub Copilot", "copilot", "copilot", "ic_install_copilot_"),
        ("Gemini CLI", "gemini_cli", "gemini_cli", "ic_install_gemini_cli_"),
    ):
        item = providers_by_name[name]
        assert item["installkeyprogram"] == program
        assert item["installkeyfamily"] == family
        assert item["installkeyprefix"] == prefix
        assert item["installkeyaliases"]

    hermes = providers_by_name["Hermes"]
    assert "hermes-agent" in hermes["installkeyaliases"]
    assert "hermes" in hermes["installkeyaliases"]


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
