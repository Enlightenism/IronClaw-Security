from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

import app.routes.customerkeys as customerkeys_module
from app.routes.customerkeys import CustomerKeyRegistry, CustomerKeyUpdateRequest, router


@pytest.fixture()
def app() -> FastAPI:
    application = FastAPI()
    application.include_router(router)
    return application


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture(autouse=True)
def reset_registry() -> None:
    customerkeys_module._registry = CustomerKeyRegistry()


def _payload(
    *,
    customer_id: str = "cust-001",
    owner_key: str = "owner-001",
    org_id: str = "org-01",
    display_name: str = "Acme Customer",
    scopes: list[str] | None = None,
    metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "customer_id": customer_id,
        "owner_key": owner_key,
        "org_id": org_id,
        "display_name": display_name,
        "scopes": scopes or ["read", "write"],
        "metadata": metadata or {"tier": "pro", "region": "us-east"},
    }


def test_create_customer_key_returns_mapping_record(client: TestClient) -> None:
    response = client.post("/customer-keys", json=_payload())

    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "IronClaw-Security"
    assert body["key"]["customer_id"] == "cust-001"
    assert body["key"]["owner_key"] == "owner-001"
    assert body["key"]["org_id"] == "org-01"
    assert body["key"]["display_name"] == "Acme Customer"
    assert body["key"]["scopes"] == ["read", "write"]
    assert body["key"]["active"] is True
    assert body["key"]["metadata"] == {"tier": "pro", "region": "us-east"}
    assert body["key"]["key_id"].startswith("cust_")


def test_create_customer_key_uses_customer_id_when_display_name_blank(client: TestClient) -> None:
    response = client.post("/customer-keys", json=_payload(display_name=""))

    assert response.status_code == 201
    assert response.json()["key"]["display_name"] == "cust-001"


def test_create_customer_key_rejects_missing_customer_id(client: TestClient) -> None:
    response = client.post(
        "/customer-keys",
        json={
            "owner_key": "owner-001",
            "display_name": "Missing customer",
        },
    )

    assert response.status_code == 422


def test_create_customer_key_rejects_missing_owner_key(client: TestClient) -> None:
    response = client.post(
        "/customer-keys",
        json={
            "customer_id": "cust-002",
            "display_name": "Missing owner",
        },
    )

    assert response.status_code == 422


def test_create_customer_key_rejects_install_token_material(client: TestClient) -> None:
    response = client.post(
        "/customer-keys",
        json={
            "customer_id": "cust-secret",
            "owner_key": "owner-secret",
            "display_name": "Secret Payload",
            "metadata": {"raw_key": "ic_install_openclaw_secret_123", "tier": "pro"},
        },
    )

    assert response.status_code == 422
    assert "install-token" in response.json()["detail"]


def test_list_customer_keys_returns_filtered_entries(client: TestClient) -> None:
    client.post("/customer-keys", json=_payload(customer_id="cust-001", owner_key="owner-001", org_id="org-01"))
    client.post("/customer-keys", json=_payload(customer_id="cust-002", owner_key="owner-001", org_id="org-01"))
    client.post("/customer-keys", json=_payload(customer_id="cust-003", owner_key="owner-002", org_id="org-02"))

    all_response = client.get("/customer-keys")
    owner_response = client.get("/customer-keys", params={"owner_key": "owner-001"})
    active_response = client.get("/customer-keys", params={"active_only": True, "org_id": "org-01"})

    assert all_response.status_code == 200
    assert all_response.json()["total"] == 3
    assert owner_response.status_code == 200
    assert owner_response.json()["total"] == 2
    assert active_response.status_code == 200
    assert active_response.json()["total"] == 2


def test_get_customer_key_returns_existing_record(client: TestClient) -> None:
    create_response = client.post("/customer-keys", json=_payload(customer_id="cust-tenant-1", owner_key="owner-tenant"))
    key_id = create_response.json()["key"]["key_id"]

    response = client.get(f"/customer-keys/{key_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["key_id"] == key_id
    assert body["customer_id"] == "cust-tenant-1"
    assert body["owner_key"] == "owner-tenant"
    assert body["active"] is True


def test_get_customer_key_returns_404_for_unknown_key(client: TestClient) -> None:
    response = client.get("/customer-keys/does-not-exist")

    assert response.status_code == 404
    assert response.json()["detail"] == "Customer key mapping not found"


def test_update_customer_key_updates_metadata_and_scopes(client: TestClient) -> None:
    create_response = client.post("/customer-keys", json=_payload(customer_id="cust-update", owner_key="owner-update"))
    key_id = create_response.json()["key"]["key_id"]

    response = client.patch(
        f"/customer-keys/{key_id}",
        json={
            "display_name": "Updated Customer",
            "org_id": "org-updated",
            "active": False,
            "scopes": ["read", "admin"],
            "metadata": {"tier": "enterprise", "sso": True},
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["display_name"] == "Updated Customer"
    assert body["org_id"] == "org-updated"
    assert body["active"] is False
    assert body["scopes"] == ["read", "admin"]
    assert body["metadata"] == {"tier": "enterprise", "sso": True}

    fetch = client.get(f"/customer-keys/{key_id}")
    assert fetch.json()["active"] is False


def test_update_customer_key_returns_404_for_unknown_key(client: TestClient) -> None:
    response = client.patch(
        "/customer-keys/ghost-key",
        json={"display_name": "Ghost"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Customer key mapping not found"


def test_revoke_customer_key_marks_record_inactive(client: TestClient) -> None:
    create_response = client.post("/customer-keys", json=_payload(customer_id="cust-revoke", owner_key="owner-revoke"))
    key_id = create_response.json()["key"]["key_id"]

    response = client.post(f"/customer-keys/{key_id}/revoke")

    assert response.status_code == 200
    body = response.json()
    assert body["key_id"] == key_id
    assert body["active"] is False

    fetch = client.get(f"/customer-keys/{key_id}")
    assert fetch.json()["active"] is False


def test_revoke_customer_key_returns_404_for_unknown_key(client: TestClient) -> None:
    response = client.post("/customer-keys/ghost-key/revoke")

    assert response.status_code == 404
    assert response.json()["detail"] == "Customer key mapping not found"


def test_registry_exposes_customer_mapping_lookup() -> None:
    registry = CustomerKeyRegistry()
    first = registry.create(
        customerkeys_module.CustomerKeyCreateRequest(
            customer_id="cust-registry",
            owner_key="owner-registry",
            org_id="org-registry",
            display_name="Registry Customer",
            scopes=["read"],
            metadata={"team": "security"},
        )
    )
    second = registry.create(
        customerkeys_module.CustomerKeyCreateRequest(
            customer_id="cust-registry",
            owner_key="owner-registry",
            org_id="org-registry",
            display_name="Second Customer",
            scopes=["write"],
            metadata={"team": "ops"},
        )
    )

    records = registry.get_by_customer("cust-registry")
    assert {record.key_id for record in records} == {first.key_id, second.key_id}


def test_update_request_model_accepts_optional_fields() -> None:
    payload = CustomerKeyUpdateRequest(
        display_name="Updated",
        org_id="new-org",
        active=False,
        scopes=["admin"],
        metadata={"status": "paused"},
    )

    assert payload.display_name == "Updated"
    assert payload.org_id == "new-org"
    assert payload.active is False
    assert payload.scopes == ["admin"]
    assert payload.metadata == {"status": "paused"}
