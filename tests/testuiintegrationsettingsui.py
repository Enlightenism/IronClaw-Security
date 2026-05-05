from __future__ import annotations

from app.ui.integrationsettings import (
    build_ui_integration_settings_page,
    get_ui_integration_settings_page,
)


def test_build_ui_integration_settings_page_returns_expected_contract() -> None:
    payload = build_ui_integration_settings_page()

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
    assert actions == {
        "integrationsroute": "/ui/integrations",
        "catalogroute": "/integrations/installers",
        "verificationroute": "/integrations/verifiers",
    }

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


def test_build_ui_integration_settings_page_summary_matches_collection() -> None:
    payload = build_ui_integration_settings_page()

    settings = payload["settings"]
    summary = payload["summary"]

    configurable_count = sum(1 for item in settings if item["configurable"])
    verified_count = sum(1 for item in settings if item["verified"])
    pending_count = sum(1 for item in settings if not item["verified"])

    assert summary["totalintegrations"] == len(settings)
    assert summary["configurableintegrations"] == configurable_count
    assert summary["verifiedintegrations"] == verified_count
    assert summary["pendingintegrations"] == pending_count


def test_get_ui_integration_settings_page_returns_builder_payload() -> None:
    payload = get_ui_integration_settings_page()

    assert payload["pageid"] == "ui-integrations-settings"
    assert isinstance(payload["settings"], list)
    assert isinstance(payload["summary"], dict)