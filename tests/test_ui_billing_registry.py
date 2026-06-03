from __future__ import annotations

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.billing import PACKAGE_CATALOG
from app.api.routes.billing import router as billing_router
from app.core.auth import API_KEY_HEADER_NAME
from app.core.errors import register_exception_handlers

_EXPECTED_CATALOG: dict[str, dict] = {
    "single-user": {
        "name": "Single User",
        "price_usd": 20.0,
        "included_units": 10_000,
    },
    "team-security": {
        "name": "Team Security",
        "price_usd": 90.0,
        "included_units": 50_000,
    },
    "enterprise-security": {
        "name": "Enterprise Security",
        "price_usd": 150.0,
        "included_units": 100_000,
    },
}


def _build_app() -> FastAPI:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        auth_required=True,
        api_key="test-secret-key",
        admin_api_key=None,
    )
    register_exception_handlers(app)
    app.include_router(billing_router)
    return app


def _get_packages(client: TestClient) -> list[dict]:
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: "test-secret-key"},
    )
    assert response.status_code == 200
    return response.json()["packages"]


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


def test_billing_registry_exactly_three_packages() -> None:
    client = TestClient(_build_app())
    packages = _get_packages(client)
    assert len(packages) == 3, f"Expected exactly 3 packages, got {len(packages)}"


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


def test_billing_registry_catalog_values_single_user() -> None:
    client = TestClient(_build_app())
    packages = _get_packages(client)
    pkg_map = {p["package_id"]: p for p in packages}
    assert "single-user" in pkg_map, "single-user package missing from response"
    pkg = pkg_map["single-user"]
    assert pkg["name"] == "Single User", f"Expected 'Single User', got {pkg['name']!r}"
    assert pkg["price_usd"] == 20.0, f"Expected price_usd=20.0, got {pkg['price_usd']}"
    assert pkg["included_units"] == 10_000, f"Expected included_units=10000, got {pkg['included_units']}"


def test_billing_registry_catalog_values_team_security() -> None:
    client = TestClient(_build_app())
    packages = _get_packages(client)
    pkg_map = {p["package_id"]: p for p in packages}
    assert "team-security" in pkg_map, "team-security package missing from response"
    pkg = pkg_map["team-security"]
    assert pkg["name"] == "Team Security", f"Expected 'Team Security', got {pkg['name']!r}"
    assert pkg["price_usd"] == 90.0, f"Expected price_usd=90.0, got {pkg['price_usd']}"
    assert pkg["included_units"] == 50_000, f"Expected included_units=50000, got {pkg['included_units']}"


def test_billing_registry_catalog_values_enterprise_security() -> None:
    client = TestClient(_build_app())
    packages = _get_packages(client)
    pkg_map = {p["package_id"]: p for p in packages}
    assert "enterprise-security" in pkg_map, "enterprise-security package missing from response"
    pkg = pkg_map["enterprise-security"]
    assert pkg["name"] == "Enterprise Security", f"Expected 'Enterprise Security', got {pkg['name']!r}"
    assert pkg["price_usd"] == 150.0, f"Expected price_usd=150.0, got {pkg['price_usd']}"
    assert pkg["included_units"] == 100_000, f"Expected included_units=100000, got {pkg['included_units']}"


def test_billing_registry_all_catalog_values_match_expected() -> None:
    client = TestClient(_build_app())
    packages = _get_packages(client)
    pkg_map = {p["package_id"]: p for p in packages}
    for package_id, expected in _EXPECTED_CATALOG.items():
        assert package_id in pkg_map, f"Package {package_id!r} missing from response"
        pkg = pkg_map[package_id]
        assert pkg["name"] == expected["name"], f"{package_id}: expected name={expected['name']!r}, got {pkg['name']!r}"
        assert pkg["price_usd"] == expected["price_usd"], f"{package_id}: expected price_usd={expected['price_usd']}, got {pkg['price_usd']}"
        assert pkg["included_units"] == expected["included_units"], f"{package_id}: expected included_units={expected['included_units']}, got {pkg['included_units']}"


def test_billing_registry_no_extra_package_ids_beyond_catalog() -> None:
    client = TestClient(_build_app())
    packages = _get_packages(client)
    returned_ids = {p["package_id"] for p in packages}
    catalog_ids = set(PACKAGE_CATALOG.keys())
    extra = returned_ids - catalog_ids
    assert not extra, f"Response contains package IDs not in catalog: {extra}"


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


def test_billing_registry_unauthorized_without_api_key() -> None:
    client = TestClient(_build_app(), raise_server_exceptions=False)
    response = client.get("/billing/packages")
    assert response.status_code == 401


def test_billing_registry_unauthorized_with_wrong_api_key() -> None:
    client = TestClient(_build_app(), raise_server_exceptions=False)
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: "wrong-key"},
    )
    assert response.status_code == 401
