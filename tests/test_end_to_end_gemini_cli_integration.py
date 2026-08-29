from __future__ import annotations

from fastapi.testclient import TestClient

from app.api.integrations import router as integrations_router
from app.main import create_app


def _client() -> TestClient:
    app = create_app()
    app.include_router(integrations_router)
    return TestClient(app)


def test_gemini_cli_route_contract_handshake_manifest_and_secret_scan_gate():
    client = _client()

    handshake = client.post(
        "/integrations/gemini-cli/handshake",
        headers={"X-API-Key": "test-api-key"},
        json={
            "client_id": "gemini-client",
            "protocol_version": "1.0.0",
            "session_id": "gemini-session-42",
            "metadata": {"environment": "test"},
        },
    )
    assert handshake.status_code == 200, handshake.text
    handshake_payload = handshake.json()
    assert handshake_payload["status"] == "ok"
    assert handshake_payload["platform"] == "gemini-cli"
    assert handshake_payload["adapter_name"] == "ironclaw-gemini-cli"
    assert any(cap["name"] == "secret-scan" for cap in handshake_payload["capabilities"])
    assert handshake_payload["metadata"]["session_id"] == "gemini-session-42"

    manifest = client.get(
        "/integrations/gemini-cli/manifest",
        headers={"X-API-Key": "test-api-key"},
    )
    assert manifest.status_code == 200, manifest.text
    manifest_payload = manifest.json()
    assert manifest_payload["platform"] == "gemini-cli"
    assert manifest_payload["adapter_name"] == "ironclaw-gemini-cli"
    assert "workflow_step" in manifest_payload["supported_action_types"]
    assert any(cap["name"] == "audit-trail" for cap in manifest_payload["capabilities"])

    evaluate = client.post(
        "/integrations/gemini-cli/evaluate",
        headers={"X-API-Key": "test-api-key"},
        json={
            "action_type": "command",
            "target": "bash",
            "content": "export AWS_ACCESS_KEY_ID=AKIA1234567890EXAMPLE",
            "client_id": "gemini-client",
            "session_id": "gemini-session-42",
            "risk_score": 30,
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
