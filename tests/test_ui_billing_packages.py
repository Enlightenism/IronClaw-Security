from __future__ import annotations

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.billing import PACKAGE_CATALOG
from app.api.routes.billing import router as billing_router
from app.core.auth import API_KEY_HEADER_NAME


def _build_packages_app() -> FastAPI:
    application = FastAPI()
    application.state.settings = SimpleNamespace(
        auth_required=True,
        api_key="test-secret-key",
        admin_api_key=None,
    )
    application.include_router(billing_router)
    return application


def test_list_billing_packages_returns_200() -> None:
    client = TestClient(_build_packages_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )
    assert response.status_code == 200


def test_list_billing_packages_response_envelope() -> None:
    client = TestClient(_build_packages_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "IronClaw-Security"
    assert "timestamp" in data


def test_list_billing_packages_returns_list() -> None:
    client = TestClient(_build_packages_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )
    data = response.json()
    assert isinstance(data["packages"], list)
    assert len(data["packages"]) == len(PACKAGE_CATALOG)


def test_list_billing_packages_item_shape() -> None:
    client = TestClient(_build_packages_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )
    packages = response.json()["packages"]
    for pkg in packages:
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


def test_list_billing_packages_known_package_ids_present() -> None:
    client = TestClient(_build_packages_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )
    package_ids = {pkg["package_id"] for pkg in response.json()["packages"]}
    for expected_id in PACKAGE_CATALOG:
        assert expected_id in package_ids


def test_list_billing_packages_unit_policy_present() -> None:
    client = TestClient(_build_packages_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )
    data = response.json()
    assert "unit_policy" in data
    policy = data["unit_policy"]
    assert "unit_definition" in policy
    assert "delivery_model" in policy
    assert "protection_layers" in policy
    assert isinstance(policy["protection_layers"], list)
    assert len(policy["protection_layers"]) > 0


def test_list_billing_packages_protection_layer_shape() -> None:
    client = TestClient(_build_packages_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )
    layers = response.json()["unit_policy"]["protection_layers"]
    for layer in layers:
        assert "title" in layer
        assert "detail" in layer
        assert isinstance(layer["title"], str)
        assert isinstance(layer["detail"], str)


def test_list_billing_packages_no_auth_raises() -> None:
    client = TestClient(_build_packages_app(), raise_server_exceptions=True)
    import pytest

    from app.core.errors import AppError

    with pytest.raises(AppError) as exc_info:
        client.get("/billing/packages")
    assert exc_info.value.status_code == 401
