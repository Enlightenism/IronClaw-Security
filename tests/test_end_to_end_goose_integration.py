from __future__ import annotations

from fastapi.testclient import TestClient

from app.api.integrations import router as integrations_router
from app.main import create_app
from app.services.integration_registry import (
    get_integration,
    initialize_integration_registry,
)


def _client() -> TestClient:
    app = create_app()
    app.include_router(integrations_router)
    return TestClient(app)


def _assert_canonical_runtime_metadata(payload: dict, *, platform: str, adapter_name: str) -> None:
    assert payload["platform"] == platform
    assert payload["adapter_name"] == adapter_name
    assert payload["metadata"]["runtime"] == platform
    assert payload["metadata"]["guard_mode"] == "strict"


def test_goose_route_reinforces_canonical_runtime_contract(monkeypatch):
    registry = initialize_integration_registry()
    record = get_integration(registry, "integration-goose")
    from app.adapters.generic_agent_adapter import GenericAgentAdapter

    drifted_adapter = GenericAgentAdapter(
        record=record,
        metadata={"runtime": "hermes", "guard_mode": "loose"},
    )
    monkeypatch.setattr("app.routes.integrations.goose._build_adapter", lambda: drifted_adapter)

    client = _client()
    handshake = client.post(
        "/integrations/goose/handshake",
        headers={"X-API-Key": "test-api-key"},
        json={
            "client_id": "goose-client",
            "protocol_version": "1.0.0",
            "session_id": "goose-session-42",
            "metadata": {"environment": "test"},
        },
    )

    assert handshake.status_code == 200, handshake.text
    payload = handshake.json()
    _assert_canonical_runtime_metadata(payload, platform="goose", adapter_name="ironclaw-goose")


def test_goose_route_contract_handshake_manifest_and_secret_scan_gate():
    client = _client()

    handshake = client.post(
        "/integrations/goose/handshake",
        headers={"X-API-Key": "test-api-key"},
        json={
            "client_id": "goose-client",
            "protocol_version": "1.0.0",
            "session_id": "goose-session-42",
            "metadata": {"environment": "test"},
        },
    )
    assert handshake.status_code == 200, handshake.text
    handshake_payload = handshake.json()
    assert handshake_payload["status"] == "ok"
    _assert_canonical_runtime_metadata(handshake_payload, platform="goose", adapter_name="ironclaw-goose")
    assert any(cap["name"] == "secret-scan" for cap in handshake_payload["capabilities"])
    assert handshake_payload["metadata"]["session_id"] == "goose-session-42"

    manifest = client.get("/integrations/goose/manifest", headers={"X-API-Key": "test-api-key"})
    assert manifest.status_code == 200, manifest.text
    manifest_payload = manifest.json()
    assert manifest_payload["platform"] == "goose"
    assert manifest_payload["adapter_name"] == "ironclaw-goose"
    assert "tool_plan" in manifest_payload["supported_action_types"]
    assert any(cap["name"] == "audit-trail" for cap in manifest_payload["capabilities"])

    evaluate = client.post(
        "/integrations/goose/evaluate",
        headers={"X-API-Key": "test-api-key"},
        json={
            "action_type": "shell_command",
            "target": "bash",
            "content": "AKIA1234567890EXAMPLE secret token",
            "client_id": "goose-client",
            "session_id": "goose-session-42",
            "risk_score": 35,
            "metadata": {"tenant": "alpha"},
        },
    )
    assert evaluate.status_code == 200, evaluate.text
    evaluate_payload = evaluate.json()
    assert evaluate_payload["verdict"] == "block"
    assert evaluate_payload["should_block"] is True
    assert evaluate_payload["should_quarantine"] is True
    assert evaluate_payload["secret_scan"]["scanned"] is True
    assert evaluate_payload["secret_scan"]["findings"]
    assert evaluate_payload["audit_trail"]["secret_scan_triggered"] is True
    assert evaluate_payload["audit_trail"]["metadata"]["tenant"] == "alpha"
