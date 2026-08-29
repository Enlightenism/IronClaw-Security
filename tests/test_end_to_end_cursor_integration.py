from __future__ import annotations

from fastapi.testclient import TestClient

from app.api.integrations import router as integrations_router
from app.main import create_app


def _client() -> TestClient:
    app = create_app()
    app.include_router(integrations_router)
    return TestClient(app)


def test_cursor_route_contract_handshake_manifest_evaluate_and_policy_decision():
    client = _client()

    handshake = client.post(
        "/integrations/cursor/handshake",
        headers={"X-API-Key": "test-api-key"},
        json={
            "client_id": "cursor-client",
            "protocol_version": "1.0.0",
            "session_id": "cursor-session-42",
            "metadata": {"environment": "test"},
        },
    )
    assert handshake.status_code == 200, handshake.text
    handshake_payload = handshake.json()
    assert handshake_payload["status"] == "ok"
    assert handshake_payload["platform"] == "cursor"
    assert handshake_payload["adapter_name"] == "ironclaw-cursor"
    assert any(cap["name"] == "secret-scan" for cap in handshake_payload["capabilities"])

    manifest = client.get("/integrations/cursor/manifest", headers={"X-API-Key": "test-api-key"})
    assert manifest.status_code == 200, manifest.text
    manifest_payload = manifest.json()
    assert manifest_payload["platform"] == "cursor"
    assert manifest_payload["adapter_name"] == "ironclaw-cursor"
    assert "file_edit" in manifest_payload["supported_action_types"]
    assert any(cap["name"] == "audit-trail" for cap in manifest_payload["capabilities"])

    evaluate = client.post(
        "/integrations/cursor/evaluate",
        headers={"X-API-Key": "test-api-key"},
        json={
            "action_type": "shell_command",
            "target": "bash",
            "content": "AKIA1234567890EXAMPLE secret token",
            "client_id": "cursor-client",
            "session_id": "cursor-session-42",
            "risk_score": 40,
            "metadata": {"tenant": "alpha"},
        },
    )
    assert evaluate.status_code == 200, evaluate.text
    evaluate_payload = evaluate.json()
    assert evaluate_payload["verdict"] == "block"
    assert evaluate_payload["should_block"] is True
    assert evaluate_payload["secret_scan"]["scanned"] is True
    assert evaluate_payload["audit_trail"]["secret_scan_triggered"] is True

    policy_decision = client.post(
        "/integrations/cursor/policy-decision",
        headers={"X-API-Key": "test-api-key"},
        json={
            "action_type": "tool_call",
            "target": "http://example.internal/api",
            "content": "fetch internal admin service status",
            "client_id": "cursor-client",
            "session_id": "cursor-session-42",
            "risk_score": 30,
            "metadata": {"tenant": "alpha"},
        },
    )
    assert policy_decision.status_code == 200, policy_decision.text
    decision_payload = policy_decision.json()
    assert decision_payload["platform"] == "cursor"
    assert "verdict" in decision_payload
    assert "matched_rules" in decision_payload
    assert "audit_trail" in decision_payload
