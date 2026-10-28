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


def test_agent_skills_route_reinforces_canonical_runtime_contract(monkeypatch):
    registry = initialize_integration_registry()
    record = get_integration(registry, "integration-security-guardian")
    from app.adapters.generic_agent_adapter import GenericAgentAdapter

    drifted_adapter = GenericAgentAdapter(
        record=record,
        metadata={"runtime": "hermes", "guard_mode": "loose"},
    )
    monkeypatch.setattr("app.routes.integrations.agent_skills._build_adapter", lambda: drifted_adapter)

    client = _client()
    handshake = client.post(
        "/integrations/agent-skills/handshake",
        headers={"X-API-Key": "test-api-key"},
        json={
            "client_id": "skills-client",
            "protocol_version": "1.0.0",
            "session_id": "skills-session-42",
            "metadata": {"environment": "test"},
        },
    )

    assert handshake.status_code == 200, handshake.text
    payload = handshake.json()
    assert payload["platform"] == "security-guardian"
    assert payload["adapter_name"] == "ironclaw-agent-skills"
    assert payload["metadata"]["runtime"] == "security-guardian"
    assert payload["metadata"]["guard_mode"] == "strict"


def test_agent_skills_route_contract_handshake_manifest_and_secret_scan_gate():
    client = _client()

    handshake = client.post(
        "/integrations/agent-skills/handshake",
        headers={"X-API-Key": "test-api-key"},
        json={
            "client_id": "skills-client",
            "protocol_version": "1.0.0",
            "session_id": "skills-session-42",
            "metadata": {"environment": "test"},
        },
    )
    assert handshake.status_code == 200, handshake.text
    handshake_payload = handshake.json()
    assert handshake_payload["status"] == "ok"
    assert handshake_payload["platform"] == "security-guardian"
    assert handshake_payload["adapter_name"] == "ironclaw-agent-skills"
    assert handshake_payload["metadata"]["package_model"] == "shared-cross-runtime-skill-bundle"
    assert handshake_payload["metadata"]["runtime_scope"] == "cross-runtime"
    assert any(cap["name"] == "secret-scan" for cap in handshake_payload["capabilities"])
    assert handshake_payload["metadata"]["session_id"] == "skills-session-42"

    manifest = client.get(
        "/integrations/agent-skills/manifest",
        headers={"X-API-Key": "test-api-key"},
    )
    assert manifest.status_code == 200, manifest.text
    manifest_payload = manifest.json()
    assert manifest_payload["platform"] == "security-guardian"
    assert manifest_payload["adapter_name"] == "ironclaw-agent-skills"
    assert manifest_payload["policy_bindings"]["package_model"] == "shared-cross-runtime-skill-bundle"
    assert manifest_payload["policy_bindings"]["runtime_scope"] == "cross-runtime"
    assert manifest_payload["policy_bindings"]["verdicts"]["warn"] == []
    assert manifest_payload["policy_bindings"]["verdicts"]["quarantine"] == []
    assert "skill_install" in manifest_payload["supported_action_types"]
    assert any(cap["name"] == "audit-trail" for cap in manifest_payload["capabilities"])

    evaluate = client.post(
        "/integrations/agent-skills/evaluate",
        headers={"X-API-Key": "test-api-key"},
        json={
            "action_type": "skill_install",
            "target": "security-guardian",
            "content": "install the security bundle and export AWS_ACCESS_KEY_ID=AKIA1234567890EXAMPLE",
            "client_id": "skills-client",
            "session_id": "skills-session-42",
            "risk_score": 25,
            "metadata": {"bundle_id": "guardian-core", "tenant": "alpha"},
        },
    )
    assert evaluate.status_code == 200, evaluate.text
    evaluate_payload = evaluate.json()
    assert evaluate_payload["verdict"] == "block"
    assert evaluate_payload["should_block"] is True
    assert evaluate_payload["should_warn"] is False
    assert evaluate_payload["should_quarantine"] is False
    assert evaluate_payload["secret_scan"]["scanned"] is True
    assert evaluate_payload["secret_scan"]["findings"]
    assert evaluate_payload["audit_trail"]["secret_scan_triggered"] is True
    assert evaluate_payload["audit_trail"]["metadata"]["tenant"] == "alpha"
