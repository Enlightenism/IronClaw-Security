from __future__ import annotations

from fastapi.testclient import TestClient

from app.api.integrations import router as integrations_router
from app.core.install_keys import get_install_key_registry
from app.main import create_app
from app.routes.install_keys import router as install_keys_router
from app.services.integration_registry import get_integration, initialize_integration_registry


def _client() -> TestClient:
    app = create_app()
    app.include_router(install_keys_router)
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
    )
    assert record.program == "hermes"
    assert record.raw_key.startswith("ic_install_hermes_")
    assert record.payment_status == "paid"
    assert record.entitlements_status == "active"
    assert record.issued_after_payment is True

    client = _client()

    activate = client.post(
        "/install-keys/activate",
        headers={"X-API-Key": "test-api-key", "X-Owner-Key": owner_key},
        json={"raw_key": record.raw_key},
    )
    assert activate.status_code == 200, activate.text
    activate_payload = activate.json()
    assert activate_payload["program"] == "hermes"
    assert activate_payload["valid"] is True
    assert activate_payload["active"] is True

    my_keys = client.get(
        "/install-keys/my-keys",
        headers={"X-API-Key": "test-api-key", "X-Owner-Key": owner_key},
    )
    assert my_keys.status_code == 200, my_keys.text
    my_keys_payload = my_keys.json()
    hermes_slot = next(item for item in my_keys_payload["keys"] if item["program"] == "hermes")
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
    assert evaluate_payload["secret_scan"]["scanned"] is True
    assert evaluate_payload["audit_trail"]["secret_scan_triggered"] is True

    dashboard = client.get(
        "/dashboard/overview",
        params={"owner_key": owner_key},
        headers={"X-API-Key": "test-api-key"},
    )
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
    )
    record.payment_status = "unpaid"
    record.entitlements_status = "not_active"
    record.issued_after_payment = False
    key_registry._records_by_id[record.key_id] = record

    client = _client()
    response = client.post(
        "/install-keys/activate",
        headers={"X-API-Key": "test-api-key", "X-Owner-Key": owner_key},
        json={"raw_key": record.raw_key},
    )
    assert response.status_code == 401, response.text
    assert response.json()["detail"] == "Invalid or inactive install key."
