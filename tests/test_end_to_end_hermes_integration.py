from __future__ import annotations

from fastapi.testclient import TestClient

from app.api.integrations import router as integrations_router
from app.core.auth import AuthContext, get_auth_context
from app.core.install_keys import get_install_key_registry
from app.main import create_app
from app.services.integration_registry import get_integration, initialize_integration_registry


def _client() -> TestClient:
    app = create_app()
    app.include_router(integrations_router)
    return TestClient(app)


def test_hermes_end_to_end_paid_flow_and_contract() -> None:
    registry = initialize_integration_registry()
    assert get_integration(registry, "integration-hermes") is not None

    key_registry = get_install_key_registry()
    owner_key = "hermes-owner@ironclaw.test"
    subscription_id = "sub_hermes_paid_flow"

    record = key_registry.generate_install_key(
        owner_key=owner_key,
        subscription_id=subscription_id,
        program="hermes",
        label="Hermes End-to-End",
        purchase_reference="ref_hermes_paid_flow",
        checkout_session_id="cs_hermes_paid_flow",
    )
    assert record.program == "hermes"
    assert record.raw_key.startswith("ic_install_hermes_")
    assert record.payment_status == "paid"
    assert record.entitlements_status == "active"
    assert record.issued_after_payment is True

    client = _client()

    self_status = client.get(
        "/install-key-events/self",
        headers={"X-API-Key": "test-api-key", "X-Install-Key": record.raw_key},
    )
    assert self_status.status_code == 200, self_status.text
    self_payload = self_status.json()
    assert self_payload["owner_key"] == owner_key
    assert self_payload["has_active_entitlement"] is True
    hermes_slot = next(item for item in self_payload["keys"] if item["program"] == "hermes")
    assert hermes_slot["status"] == "active"
    assert hermes_slot["masked_key"] == record.masked_key

    handshake = client.post(
        "/integrations/hermes/handshake",
        headers={"X-API-Key": "test-api-key"},
        json={
            "client_id": "hermes-client",
            "protocol_version": "1.0.0",
            "session_id": "hermes-session-42",
            "metadata": {"environment": "test"},
        },
    )
    assert handshake.status_code == 200, handshake.text
    handshake_payload = handshake.json()
    assert handshake_payload["status"] == "ok"
    assert handshake_payload["platform"] == "hermes"
    assert handshake_payload["adapter_name"] == "ironclaw-hermes"
    assert handshake_payload["metadata"]["runtime"] == "hermes"
    assert handshake_payload["metadata"]["guard_mode"] == "strict"

    manifest = client.get("/integrations/hermes/manifest", headers={"X-API-Key": "test-api-key"})
    assert manifest.status_code == 200, manifest.text
    manifest_payload = manifest.json()
    assert manifest_payload["platform"] == "hermes"
    assert manifest_payload["adapter_name"] == "ironclaw-hermes"
    assert manifest_payload["policy_bindings"]["verdicts"]["warn"] == []
    assert manifest_payload["policy_bindings"]["verdicts"]["quarantine"] == []
    assert "workflow_step" in manifest_payload["supported_action_types"]
    assert any(cap["name"] == "secret-scan" for cap in manifest_payload["capabilities"])

    evaluate = client.post(
        "/integrations/hermes/evaluate",
        headers={"X-API-Key": "test-api-key"},
        json={
            "action_type": "shell_command",
            "target": "bash",
            "content": "AKIA1234567890EXAMPLE secret token",
            "client_id": "hermes-client",
            "session_id": "hermes-session-42",
            "risk_score": 40,
            "metadata": {"tenant": "alpha"},
        },
    )
    assert evaluate.status_code == 200, evaluate.text
    evaluate_payload = evaluate.json()
    assert evaluate_payload["verdict"] == "block"
    assert evaluate_payload["should_block"] is True
    assert evaluate_payload["should_warn"] is False
    assert evaluate_payload["should_quarantine"] is False
    assert evaluate_payload["should_review"] is True
    assert evaluate_payload["secret_scan"]["scanned"] is True
    assert evaluate_payload["audit_trail"]["secret_scan_triggered"] is True

    dashboard_auth = AuthContext(
        api_key="test-api-key",
        principal_type="customer",
        principal_id=owner_key,
        session_id=None,
        org_id=None,
        permissions=("customer:read", "customer:write"),
        roles=("customer_admin",),
        authenticated=True,
        auth_source="test",
        auth_method="test",
        metadata={"owner_key": owner_key},
    )
    client.app.dependency_overrides[get_auth_context] = lambda: dashboard_auth
    try:
        dashboard = client.get(
            "/dashboard/overview",
            params={"owner_key": owner_key},
            headers={"X-API-Key": "test-api-key"},
        )
    finally:
        client.app.dependency_overrides.pop(get_auth_context, None)
    assert dashboard.status_code == 200, dashboard.text
    dashboard_payload = dashboard.json()
    hermes_card = next(item for item in dashboard_payload["install_keys"] if item["program"] == "hermes")
    assert hermes_card["status"] == "active"
    assert hermes_card["payment_status"] == "paid"
    assert hermes_card["masked_key"] == record.masked_key


def test_hermes_install_key_paid_gate_rejects_unpaid_state() -> None:
    key_registry = get_install_key_registry()
    owner_key = "hermes-unpaid-owner@ironclaw.test"
    record = key_registry.generate_install_key(
        owner_key=owner_key,
        subscription_id="sub_hermes_unpaid_gate",
        program="hermes",
        label="Hermes Gate",
        purchase_reference="ref_hermes_unpaid_gate",
        checkout_session_id="cs_hermes_unpaid_gate",
    )
    record.payment_status = "unpaid"
    record.entitlements_status = "not_active"
    record.issued_after_payment = False
    key_registry._records_by_id[record.key_id] = record

    client = _client()
    response = client.get(
        "/install-key-events/self",
        headers={"X-API-Key": "test-api-key", "X-Install-Key": record.raw_key},
    )
    assert response.status_code == 401, response.text
    assert response.json()["detail"] == "Invalid or inactive install key"
