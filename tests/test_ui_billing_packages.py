from __future__ import annotations

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.billing import PACKAGE_CATALOG
from app.api.routes.billing import router as billing_router
from app.core.auth import API_KEY_HEADER_NAME
from app.core.errors import register_exception_handlers

# ---------------------------------------------------------------------------
# Canonical value-pinning table — single source of truth for this test module.
# Mirrors PACKAGE_CATALOG in app/api/routes/billing.py exactly.
# ---------------------------------------------------------------------------


_EXPECTED_CATALOG: dict[str, dict] = {
    "pkg_5000": {
        "name": "Starter",
        "price_usd": 20.0,
        "included_units": 5_000,
    },
    "pkg_25000": {
        "name": "Team",
        "price_usd": 90.0,
        "included_units": 25_000,
    },
    "pkg_60000": {
        "name": "Enterprise",
        "price_usd": 180.0,
        "included_units": 60_000,
    },
}


_API_KEY = "test-secret-key"


# ---------------------------------------------------------------------------
# App factory + helpers
# ---------------------------------------------------------------------------


def _build_packages_app() -> FastAPI:
    application = FastAPI()
    application.state.settings = SimpleNamespace(
        auth_required=True,
        api_key=_API_KEY,
        admin_api_key=None,
    )
    register_exception_handlers(application)
    application.include_router(billing_router)
    return application


def _get_packages(client: TestClient) -> list[dict]:
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: _API_KEY},
    )
    assert response.status_code == 200
    return response.json()["packages"]


def _get_pkg_map(client: TestClient) -> dict[str, dict]:
    return {pkg["package_id"]: pkg for pkg in _get_packages(client)}


# ---------------------------------------------------------------------------
# HTTP contract
# ---------------------------------------------------------------------------


def test_list_billing_packages_returns_200() -> None:
    client = TestClient(_build_packages_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: _API_KEY},
    )
    assert response.status_code == 200


def test_list_billing_packages_content_type_is_json() -> None:
    client = TestClient(_build_packages_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: _API_KEY},
    )
    assert "application/json" in response.headers.get("content-type", "")


def test_list_billing_packages_no_auth_raises_401() -> None:
    client = TestClient(_build_packages_app())
    response = client.get("/billing/packages")
    assert response.status_code == 401
    data = response.json()
    assert data.get("error") in ("missing_api_key", "authentication_required")


def test_list_billing_packages_wrong_key_raises_401() -> None:
    client = TestClient(_build_packages_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: "wrong-key"},
    )
    assert response.status_code == 401
    data = response.json()
    assert data.get("error") == "invalid_api_key"


# ---------------------------------------------------------------------------
# Envelope shape
# ---------------------------------------------------------------------------


def test_list_billing_packages_response_envelope() -> None:
    client = TestClient(_build_packages_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: _API_KEY},
    )
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "IronClaw-Security"
    assert "timestamp" in data
    assert isinstance(data["timestamp"], str)
    assert data["timestamp"].endswith("Z")
    assert len(data["timestamp"]) > 0


# ---------------------------------------------------------------------------
# Packages — structural
# ---------------------------------------------------------------------------


def test_list_billing_packages_returns_list() -> None:
    client = TestClient(_build_packages_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: _API_KEY},
    )
    data = response.json()
    assert isinstance(data["packages"], list)
    assert len(data["packages"]) == len(PACKAGE_CATALOG)


def test_list_billing_packages_exactly_three_packages() -> None:
    client = TestClient(_build_packages_app())
    packages = _get_packages(client)
    assert len(packages) == 3, f"Expected exactly 3 packages, got {len(packages)}"


def test_list_billing_packages_item_shape() -> None:
    client = TestClient(_build_packages_app())
    packages = _get_packages(client)
    for pkg in packages:
        assert "package_id" in pkg
        assert "name" in pkg
        assert "price_usd" in pkg
        assert "included_units" in pkg
        assert "description" in pkg
        assert "display_label" in pkg
        assert "token_coverage" in pkg
        assert "tokens_per_unit" in pkg
        assert isinstance(pkg["package_id"], str)
        assert isinstance(pkg["name"], str)
        assert isinstance(pkg["price_usd"], float)
        assert isinstance(pkg["included_units"], int)
        assert isinstance(pkg["description"], str)
        assert isinstance(pkg["display_label"], str)
        assert isinstance(pkg["token_coverage"], int)
        assert isinstance(pkg["tokens_per_unit"], int)
        assert pkg["price_usd"] > 0
        assert pkg["included_units"] > 0


def test_list_billing_packages_known_package_ids_present() -> None:
    client = TestClient(_build_packages_app())
    packages = _get_packages(client)
    returned_ids = {pkg["package_id"] for pkg in packages}
    for expected_id in PACKAGE_CATALOG:
        assert expected_id in returned_ids, f"Expected package_id {expected_id!r} missing from response"


def test_list_billing_packages_no_extra_package_ids_beyond_catalog() -> None:
    client = TestClient(_build_packages_app())
    packages = _get_packages(client)
    returned_ids = {pkg["package_id"] for pkg in packages}
    catalog_ids = set(PACKAGE_CATALOG.keys())
    extra = returned_ids - catalog_ids
    assert not extra, f"Response contains package IDs not in catalog: {extra}"


# ---------------------------------------------------------------------------
# Packages — value-pinning (exact name, price_usd, included_units per package ID)
# ---------------------------------------------------------------------------


def test_list_billing_packages_pkg_5000_exact_values() -> None:
    client = TestClient(_build_packages_app())
    pkg_map = _get_pkg_map(client)
    assert "pkg_5000" in pkg_map, "pkg_5000 package missing from response"
    pkg = pkg_map["pkg_5000"]
    assert pkg["name"] == "Starter", f"Expected name='Starter', got {pkg['name']!r}"
    assert pkg["price_usd"] == 20.0, f"Expected price_usd=20.0, got {pkg['price_usd']}"
    assert pkg["included_units"] == 5_000, f"Expected included_units=5000, got {pkg['included_units']}"


def test_list_billing_packages_pkg_25000_exact_values() -> None:
    client = TestClient(_build_packages_app())
    pkg_map = _get_pkg_map(client)
    assert "pkg_25000" in pkg_map, "pkg_25000 package missing from response"
    pkg = pkg_map["pkg_25000"]
    assert pkg["name"] == "Team", f"Expected name='Team', got {pkg['name']!r}"
    assert pkg["price_usd"] == 90.0, f"Expected price_usd=90.0, got {pkg['price_usd']}"
    assert pkg["included_units"] == 25_000, f"Expected included_units=25000, got {pkg['included_units']}"


def test_list_billing_packages_pkg_60000_exact_values() -> None:
    client = TestClient(_build_packages_app())
    pkg_map = _get_pkg_map(client)
    assert "pkg_60000" in pkg_map, "pkg_60000 package missing from response"
    pkg = pkg_map["pkg_60000"]
    assert pkg["name"] == "Enterprise", f"Expected name='Enterprise', got {pkg['name']!r}"
    assert pkg["price_usd"] == 180.0, f"Expected price_usd=180.0, got {pkg['price_usd']}"
    assert pkg["included_units"] == 60_000, f"Expected included_units=60000, got {pkg['included_units']}"


def test_list_billing_packages_all_catalog_values_match_expected() -> None:
    client = TestClient(_build_packages_app())
    pkg_map = _get_pkg_map(client)
    for package_id, expected in _EXPECTED_CATALOG.items():
        assert package_id in pkg_map, f"Package {package_id!r} missing from response"
        pkg = pkg_map[package_id]
        assert pkg["name"] == expected["name"], f"{package_id}: expected name={expected['name']!r}, got {pkg['name']!r}"
        assert pkg["price_usd"] == expected["price_usd"], f"{package_id}: expected price_usd={expected['price_usd']}, got {pkg['price_usd']}"
        assert pkg["included_units"] == expected["included_units"], f"{package_id}: expected included_units={expected['included_units']}, got {pkg['included_units']}"


# ---------------------------------------------------------------------------
# Unit policy — structural
# ---------------------------------------------------------------------------


def test_list_billing_packages_unit_policy_present() -> None:
    client = TestClient(_build_packages_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: _API_KEY},
    )
    data = response.json()
    assert "unit_policy" in data
    policy = data["unit_policy"]
    assert "unit_definition" in policy
    assert "token_chunk_size" in policy
    assert "delivery_model" in policy
    assert "buyer_positioning" in policy
    assert "protection_layers" in policy
    assert "market_context" in policy
    assert isinstance(policy["unit_definition"], str)
    assert isinstance(policy["token_chunk_size"], int)
    assert isinstance(policy["delivery_model"], str)
    assert isinstance(policy["buyer_positioning"], str)
    assert isinstance(policy["protection_layers"], list)
    assert isinstance(policy["market_context"], list)
    assert len(policy["protection_layers"]) > 0
    assert len(policy["market_context"]) > 0
    assert policy["token_chunk_size"] == 25_000


def test_list_billing_packages_protection_layer_shape() -> None:
    client = TestClient(_build_packages_app())
    response = client.get(
        "/billing/packages",
        headers={API_KEY_HEADER_NAME: _API_KEY},
    )
    layers = response.json()["unit_policy"]["protection_layers"]
    for layer in layers:
        assert "title" in layer
        assert "detail" in layer
        assert isinstance(layer["title"], str)
        assert isinstance(layer["detail"], str)
        assert len(layer["title"]) > 0
        assert len(layer["detail"]) > 0
