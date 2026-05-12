from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_ui_integration_settings_api_returns_settings_page_contract() -> None:
    response = client.get("/ui/integrations/settings")

    assert response.status_code == 200
    payload = response.json()

    assert payload["pageid"] == "ui-integrations-settings"
    assert payload["title"] == "Integration Settings"
    assert payload["section"] == "platform"
    assert payload["status"] == "ok"
    assert payload["service"] == "IronClaw-Security"
    assert isinstance(payload["generatedat"], str)

    summary = payload["summary"]
    assert isinstance(summary, dict)
    assert set(summary) >= {
        "totalintegrations",
        "configurableintegrations",
        "verifiedintegrations",
        "pendingintegrations",
    }

    actions = payload["actions"]
    assert actions["integrationsroute"] == "/ui/integrations"
    assert actions["catalogroute"] == "/integrations/installers"
    assert actions["verificationroute"] == "/integrations/verifiers"

    settings = payload["settings"]
    assert isinstance(settings, list)
    assert len(settings) >= 1

    item = settings[0]
    assert set(item) >= {
        "integrationid",
        "displayname",
        "platform",
        "status",
        "verified",
        "verifiedat",
        "settingsroute",
        "verificationroute",
        "manifestroute",
        "adaptermodule",
        "configurable",
        "configurationstate",
        "tags",
        "metadata",
    }
    assert isinstance(item["integrationid"], str)
    assert isinstance(item["displayname"], str)
    assert isinstance(item["platform"], str)
    assert isinstance(item["status"], str)
    assert isinstance(item["verified"], bool)
    assert item["verifiedat"] is None or isinstance(item["verifiedat"], str)
    assert item["settingsroute"] is None or isinstance(item["settingsroute"], str)
    assert item["verificationroute"] is None or isinstance(item["verificationroute"], str)
    assert item["manifestroute"] is None or isinstance(item["manifestroute"], str)
    assert isinstance(item["adaptermodule"], str)
    assert isinstance(item["configurable"], bool)
    assert item["configurationstate"] in {"configured", "pending", "unavailable"}
    assert isinstance(item["tags"], list)
    assert isinstance(item["metadata"], dict)


def test_ui_integration_settings_api_summary_matches_settings_collection() -> None:
    response = client.get("/ui/integrations/settings")

    assert response.status_code == 200
    payload = response.json()

    settings = payload["settings"]
    summary = payload["summary"]

    configurable_count = sum(1 for item in settings if item["configurable"])
    verified_count = sum(1 for item in settings if item["verified"])
    pending_count = sum(1 for item in settings if not item["verified"])

    assert summary["totalintegrations"] == len(settings)
    assert summary["configurableintegrations"] == configurable_count
    assert summary["verifiedintegrations"] == verified_count
    assert summary["pendingintegrations"] == pending_count


def test_ui_integration_settings_api_is_registered_in_openapi() -> None:
    schema = app.openapi()
    assert "/ui/integrations/settings" in schema["paths"]

    operation = schema["paths"]["/ui/integrations/settings"]["get"]
    assert "ui-integrations" in operation["tags"]
    assert operation["operationId"] == "read_ui_integration_settings_ui_integrations_settings_get"