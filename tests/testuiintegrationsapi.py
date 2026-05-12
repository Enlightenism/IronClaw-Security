from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_ui_integrations_route_is_registered() -> None:
    response = client.get("/ui/integrations")
    assert response.status_code == 200


def test_ui_integrations_returns_json_object() -> None:
    response = client.get("/ui/integrations")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)


def test_ui_integrations_contains_expected_page_contract() -> None:
    response = client.get("/ui/integrations")
    assert response.status_code == 200

    data = response.json()

    assert data.get("pageid") == "ui-integrations"
    assert data.get("title") == "Integrations"
    assert data.get("section") == "platform"
    assert data.get("status") == "ok"
    assert data.get("service") == "IronClaw-Security"
    assert "generatedat" in data


def test_ui_integrations_contains_summary_actions_and_integrations() -> None:
    response = client.get("/ui/integrations")
    assert response.status_code == 200

    data = response.json()

    summary = data.get("summary")
    actions = data.get("actions")
    integrations = data.get("integrations")

    assert isinstance(summary, dict)
    assert isinstance(actions, dict)
    assert isinstance(integrations, list)

    assert "totalintegrations" in summary
    assert "installedintegrations" in summary
    assert "readyintegrations" in summary
    assert "degradedintegrations" in summary

    assert actions.get("catalogroute") == "/integrations/installers"
    assert actions.get("verificationroute") == "/integrations/verifiers"
    assert actions.get("settingsroute") == "/ui/integrations/settings"


def test_ui_integrations_entries_expose_expected_shape() -> None:
    response = client.get("/ui/integrations")
    assert response.status_code == 200

    data = response.json()
    integrations = data.get("integrations")

    assert isinstance(integrations, list)
    assert integrations, "expected at least one integration entry"

    entry = integrations[0]
    assert isinstance(entry, dict)

    expected_keys = {
        "integrationid",
        "platform",
        "displayname",
        "status",
        "installed",
        "installedat",
        "verified",
        "verifiedat",
        "settingsroute",
        "manifestroute",
        "verificationroute",
        "adaptermodule",
        "capabilities",
        "installerpreview",
        "verifierpreview",
        "health",
    }
    missing_keys = expected_keys - set(entry)
    assert not missing_keys, f"missing integration keys: {sorted(missing_keys)}"


def test_ui_integrations_entries_echo_preview_shapes() -> None:
    response = client.get("/ui/integrations")
    assert response.status_code == 200

    data = response.json()
    entry = data["integrations"][0]

    installerpreview = entry.get("installerpreview")
    verifierpreview = entry.get("verifierpreview")

    assert isinstance(installerpreview, dict)
    assert installerpreview.get("status")
    assert "installed" in installerpreview
    assert "summary" in installerpreview
    assert isinstance(installerpreview.get("steps"), list)

    assert isinstance(verifierpreview, dict)
    assert verifierpreview.get("status")
    assert "verified" in verifierpreview
    assert "strict" in verifierpreview
    assert "summary" in verifierpreview
    assert isinstance(verifierpreview.get("checks"), list)
    assert isinstance(verifierpreview.get("missingcapabilities"), list)