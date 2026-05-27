from __future__ import annotations

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.billing import PACKAGE_CATALOG
from app.api.routes.billing import router as billing_router
from app.core.auth import API_KEY_HEADER_NAME


def _build_app() -> FastAPI:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        auth_required=True,
        api_key="test-secret-key",
        admin_api_key=None,
    )
    app.include_router(billing_router)
    return app


def test_billing_registry_returns_200() -> None:
    client = TestClient(_build_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )
    assert response.status_code == 200


def test_billing_registry_envelope_shape() -> None:
    client = TestClient(_build_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "IronClaw-Security"
    assert "timestamp" in data
    assert isinstance(data["timestamp"], str)
    assert len(data["timestamp"]) > 0


def test_billing_registry_packages_list_is_populated() -> None:
    client = TestClient(_build_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )
    data = response.json()
    packages = data["packages"]
    assert isinstance(packages, list)
    assert len(packages) == len(PACKAGE_CATALOG)


def test_billing_registry_package_item_shape() -> None:
    client = TestClient(_build_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )
    data = response.json()
    for pkg in data["packages"]:
        assert "package_id" in pkg
        assert "name" in pkg
        assert "price_usd" in pkg
        assert "included_units" in pkg
        assert "description" in pkg
        assert isinstance(pkg["package_id"], str)
        assert isinstance(pkg["name"], str)
        assert isinstance(pkg["price_usd"], float)
        assert isinstance(pkg["included_units"], int)
        assert isinstance(pkg["description"], str)
        assert pkg["price_usd"] > 0
        assert pkg["included_units"] > 0


def test_billing_registry_known_package_ids_present() -> None:
    client = TestClient(_build_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )
    data = response.json()
    returned_ids = {pkg["package_id"] for pkg in data["packages"]}
    for expected_id in PACKAGE_CATALOG:
        assert expected_id in returned_ids


def test_billing_registry_unit_policy_present() -> None:
    client = TestClient(_build_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )
    data = response.json()
    assert "unit_policy" in data
    unit_policy = data["unit_policy"]
    assert isinstance(unit_policy, dict)


def test_billing_registry_unit_policy_shape() -> None:
    client = TestClient(_build_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )
    data = response.json()
    unit_policy = data["unit_policy"]
    assert "unit_definition" in unit_policy
    assert "delivery_model" in unit_policy
    assert "buyer_positioning" in unit_policy
    assert "protection_layers" in unit_policy
    assert "market_context" in unit_policy
    assert isinstance(unit_policy["unit_definition"], str)
    assert isinstance(unit_policy["delivery_model"], str)
    assert isinstance(unit_policy["buyer_positioning"], str)
    assert isinstance(unit_policy["protection_layers"], list)
    assert isinstance(unit_policy["market_context"], list)
    assert len(unit_policy["protection_layers"]) > 0
    assert len(unit_policy["market_context"]) > 0


def test_billing_registry_protection_layer_item_shape() -> None:
    client = TestClient(_build_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )
    data = response.json()
    for layer in data["unit_policy"]["protection_layers"]:
        assert "title" in layer
        assert "detail" in layer
        assert isinstance(layer["title"], str)
        assert isinstance(layer["detail"], str)
        assert len(layer["title"]) > 0
        assert len(layer["detail"]) > 0


def test_billing_registry_requires_no_body() -> None:
    client = TestClient(_build_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )
    assert response.status_code == 200


def test_billing_registry_content_type_is_json() -> None:
    client = TestClient(_build_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )
    assert "application/json" in response.headers.get("content-type", "")
