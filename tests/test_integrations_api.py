from __future__ import annotations

from fastapi.testclient import TestClient


def test_integrations_list_returns_registry_items(test_client: TestClient) -> None:
    response = test_client.get("/integrations")

    assert response.status_code == 200
    payload = response.json()

    assert payload["total"] >= 3
    assert isinstance(payload["items"], list)
    assert any(item["slug"] == "claude-code" for item in payload["items"])
    assert any(item["slug"] == "openclaw" for item in payload["items"])
    assert any(item["slug"] == "generic-agent" for item in payload["items"])


def test_integrations_summary_returns_expected_shape(test_client: TestClient) -> None:
    response = test_client.get("/integrations/summary")

    assert response.status_code == 200
    payload = response.json()

    assert payload["total_integrations"] >= 3
    assert "platforms" in payload
    assert "capabilities" in payload
    assert "one_command_ready_targets" in payload
    assert "claude-code" in payload["one_command_ready_targets"]


def test_integrations_detail_returns_known_integration(test_client: TestClient) -> None:
    response = test_client.get("/integrations/integration-claude-code")

    assert response.status_code == 200
    payload = response.json()

    assert payload["integration_id"] == "integration-claude-code"
    assert payload["slug"] == "claude-code"
    assert payload["platform"] == "claude-code"
    assert payload["integration_type"] == "adapter"


def test_integrations_detail_returns_404_for_unknown_id(test_client: TestClient) -> None:
    response = test_client.get("/integrations/integration-does-not-exist")

    assert response.status_code == 404
    payload = response.json()

    assert any(key in payload for key in ("detail", "message", "error"))


def test_integrations_list_can_filter_by_platform(test_client: TestClient) -> None:
    response = test_client.get("/integrations", params={"platform": "openclaw"})

    assert response.status_code == 200
    payload = response.json()

    assert payload["total"] == 1
    assert payload["items"][0]["slug"] == "openclaw"


def test_integrations_list_can_filter_by_capability(test_client: TestClient) -> None:
    response = test_client.get("/integrations", params={"capability": "guard_assist"})

    assert response.status_code == 200
    payload = response.json()

    assert payload["total"] >= 1
    assert all(any(capability["name"] == "guard_assist" and capability["enabled"] is True for capability in item["capabilities"]) for item in payload["items"])
