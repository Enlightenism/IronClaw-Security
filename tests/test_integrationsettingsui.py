from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app


def test_ui_integration_settings_route_returns_expected_shape() -> None:
    client = TestClient(create_app())

    response = client.get("/ui/integrations/settings")

    assert response.status_code == 200
    payload = response.json()

    assert isinstance(payload["generatedat"], str)
    assert payload["defaultguardmode"] == "strict"
    assert payload["bidirectionalsyncenabled"] is False

    providers = payload["providers"]
    assert isinstance(providers, list)
    assert len(providers) >= 3

    names = {provider["name"] for provider in providers}
    assert {"OpenClaw", "Claude Code"} <= names
    assert "Standalone IronClaw" not in names

    for provider in providers:
        assert isinstance(provider["name"], str)
        assert isinstance(provider["enabled"], bool)
        assert isinstance(provider["mode"], str)
        assert "notes" in provider
        assert isinstance(provider["notes"], list)
