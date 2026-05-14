from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_integrations_settings_route_is_registered() -> None:
    response = client.get("/ui/integrations/settings")
    assert response.status_code == 200


def test_integrations_settings_returns_json_response() -> None:
    response = client.get("/ui/integrations/settings")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")


def test_integrations_settings_returns_expected_page_metadata() -> None:
    response = client.get("/ui/integrations/settings")

    payload = response.json()
    assert payload["pageid"] == "ui-integrations-settings"
    assert payload["title"] == "Integration Settings"
    assert payload["section"] == "platform"
    assert payload["status"] == "ok"
    assert payload["service"] == "IronClaw-Security"
    assert isinstance(payload["generatedat"], str)


def test_integrations_settings_returns_expected_summary_and_actions() -> None:
    response = client.get("/ui/integrations/settings")

    payload = response.json()
    summary = payload["summary"]
    actions = payload["actions"]

    assert set(summary) >= {
        "totalintegrations",
        "configurableintegrations",
        "verifiedintegrations",
        "pendingintegrations",
    }
    assert isinstance(summary["totalintegrations"], int)
    assert isinstance(summary["configurableintegrations"], int)
    assert isinstance(summary["verifiedintegrations"], int)
    assert isinstance(summary["pendingintegrations"], int)

    assert actions == {
        "integrationsroute": "/ui/integrations",
        "catalogroute": "/integrations/installers",
        "verificationroute": "/integrations/verifiers",
    }


def test_integrations_settings_returns_settings_collection() -> None:
    response = client.get("/ui/integrations/settings")

    payload = response.json()
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


def test_integrations_settings_summary_matches_settings_collection() -> None:
    response = client.get("/ui/integrations/settings")

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
