from __future__ import annotations

from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Canonical value-pinning table — single source of truth for this test module.
# Mirrors PACKAGE_CATALOG in app/api/routes/billing.py exactly.
# ---------------------------------------------------------------------------


_EXPECTED_PACKAGES: dict[str, dict] = {
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


_FEATURED_PACKAGE_ID = "pkg_25000"


# ---------------------------------------------------------------------------
# HTTP contract
# ---------------------------------------------------------------------------


def test_billing_manifest_returns_200_manifest(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert response.status_code == 200


def test_billing_manifest_content_type_is_json_manifest(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert "application/json" in response.headers.get("content-type", "")


def test_billing_manifest_response_is_object_manifest(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert isinstance(response.json(), dict)


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------


def test_billing_manifest_status_is_ok_manifest(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert response.json()["status"] == "ok"


def test_billing_manifest_service_is_ironclaw_manifest(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert response.json()["service"] == "IronClaw-Security"


def test_billing_manifest_has_timestamp(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    body = response.json()
    assert "timestamp" in body
    assert isinstance(body["timestamp"], str)
    assert body["timestamp"].endswith("Z")
    assert len(body["timestamp"]) > 0


# ---------------------------------------------------------------------------
# Pricing block — structural
# ---------------------------------------------------------------------------


def test_billing_manifest_has_pricing(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    body = response.json()
    assert "pricing" in body
    assert isinstance(body["pricing"], dict)


def test_billing_manifest_pricing_has_required_fields(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    pricing = response.json()["pricing"]
    assert "currency" in pricing
    assert "model" in pricing
    assert "packages" in pricing
    assert "kpis" in pricing
    assert "notes" in pricing


def test_billing_manifest_pricing_currency_is_usd(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert response.json()["pricing"]["currency"] == "USD"


def test_billing_manifest_pricing_model(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert response.json()["pricing"]["model"] == "prepaid-protection-units"


# ---------------------------------------------------------------------------
# Pricing packages — structural
# ---------------------------------------------------------------------------


def test_billing_manifest_pricing_packages_is_list(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert isinstance(response.json()["pricing"]["packages"], list)


def test_billing_manifest_pricing_packages_is_non_empty(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert len(response.json()["pricing"]["packages"]) > 0


def test_billing_manifest_exactly_three_packages(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    packages = response.json()["pricing"]["packages"]
    assert len(packages) == 3, f"Expected exactly 3 packages, got {len(packages)}"


def test_billing_manifest_each_package_has_required_fields(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    for i, pkg in enumerate(response.json()["pricing"]["packages"]):
        assert "package_id" in pkg, f"pricing.packages[{i}] missing package_id"
        assert "name" in pkg, f"pricing.packages[{i}] missing name"
        assert "price_usd" in pkg, f"pricing.packages[{i}] missing price_usd"
        assert "included_units" in pkg, f"pricing.packages[{i}] missing included_units"
        assert "description" in pkg, f"pricing.packages[{i}] missing description"
        assert "featured" in pkg, f"pricing.packages[{i}] missing featured"
        assert "metadata" in pkg, f"pricing.packages[{i}] missing metadata"


def test_billing_manifest_each_package_id_is_string(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    for i, pkg in enumerate(response.json()["pricing"]["packages"]):
        assert isinstance(pkg["package_id"], str), f"pricing.packages[{i}].package_id must be str"


def test_billing_manifest_each_package_price_usd_is_number(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    for i, pkg in enumerate(response.json()["pricing"]["packages"]):
        assert isinstance(pkg["price_usd"], int | float), f"pricing.packages[{i}].price_usd must be numeric"
        assert pkg["price_usd"] > 0, f"pricing.packages[{i}].price_usd must be positive"


def test_billing_manifest_each_package_included_units_is_int(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    for i, pkg in enumerate(response.json()["pricing"]["packages"]):
        assert isinstance(pkg["included_units"], int), f"pricing.packages[{i}].included_units must be int"
        assert pkg["included_units"] > 0, f"pricing.packages[{i}].included_units must be positive"


def test_billing_manifest_each_package_featured_is_bool(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    for i, pkg in enumerate(response.json()["pricing"]["packages"]):
        assert isinstance(pkg["featured"], bool), f"pricing.packages[{i}].featured must be bool"


def test_billing_manifest_exactly_one_featured_package(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    featured = [pkg for pkg in response.json()["pricing"]["packages"] if pkg["featured"]]
    assert len(featured) == 1


def test_billing_manifest_featured_package_is_team_security(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    featured = [pkg for pkg in response.json()["pricing"]["packages"] if pkg["featured"]]
    assert featured[0]["package_id"] == _FEATURED_PACKAGE_ID


# ---------------------------------------------------------------------------
# Pricing packages — exact value-pinning
# ---------------------------------------------------------------------------


def test_billing_manifest_all_expected_package_ids_present(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    returned_ids = {pkg["package_id"] for pkg in response.json()["pricing"]["packages"]}
    for package_id in _EXPECTED_PACKAGES:
        assert package_id in returned_ids, f"Expected package_id {package_id!r} missing from manifest"


def test_billing_manifest_single_user_exact_values(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    pkg_map = {pkg["package_id"]: pkg for pkg in response.json()["pricing"]["packages"]}
    assert "pkg_5000" in pkg_map, "pkg_5000 package missing"
    pkg = pkg_map["pkg_5000"]
    assert pkg["name"] == "Starter", f"Got name={pkg['name']!r}"
    assert pkg["price_usd"] == 20.0, f"Got price_usd={pkg['price_usd']}"
    assert pkg["included_units"] == 5_000, f"Got included_units={pkg['included_units']}"


def test_billing_manifest_team_security_exact_values(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    pkg_map = {pkg["package_id"]: pkg for pkg in response.json()["pricing"]["packages"]}
    assert "pkg_25000" in pkg_map, "pkg_25000 package missing"
    pkg = pkg_map["pkg_25000"]
    assert pkg["name"] == "Team", f"Got name={pkg['name']!r}"
    assert pkg["price_usd"] == 90.0, f"Got price_usd={pkg['price_usd']}"
    assert pkg["included_units"] == 25_000, f"Got included_units={pkg['included_units']}"


def test_billing_manifest_enterprise_security_exact_values(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    pkg_map = {pkg["package_id"]: pkg for pkg in response.json()["pricing"]["packages"]}
    assert "pkg_60000" in pkg_map, "pkg_60000 package missing"
    pkg = pkg_map["pkg_60000"]
    assert pkg["name"] == "Enterprise", f"Got name={pkg['name']!r}"
    assert pkg["price_usd"] == 180.0, f"Got price_usd={pkg['price_usd']}"
    assert pkg["included_units"] == 60_000, f"Got included_units={pkg['included_units']}"


def test_billing_manifest_all_catalog_values_match_expected(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    pkg_map = {pkg["package_id"]: pkg for pkg in response.json()["pricing"]["packages"]}
    for package_id, expected in _EXPECTED_PACKAGES.items():
        assert package_id in pkg_map, f"Package {package_id!r} missing from manifest"
        pkg = pkg_map[package_id]
        assert pkg["name"] == expected["name"], f"{package_id}: expected name={expected['name']!r}, got {pkg['name']!r}"
        assert pkg["price_usd"] == expected["price_usd"], f"{package_id}: expected price_usd={expected['price_usd']}, got {pkg['price_usd']}"
        assert pkg["included_units"] == expected["included_units"], f"{package_id}: expected included_units={expected['included_units']}, got {pkg['included_units']}"


# ---------------------------------------------------------------------------
# Package metadata block
# ---------------------------------------------------------------------------


def test_billing_manifest_each_package_metadata_has_price_display(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    for i, pkg in enumerate(response.json()["pricing"]["packages"]):
        meta = pkg.get("metadata", {})
        assert "price_display" in meta, f"pricing.packages[{i}].metadata missing price_display"
        assert isinstance(meta["price_display"], str)
        assert meta["price_display"].startswith("$")


def test_billing_manifest_each_package_metadata_has_units_display(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    for i, pkg in enumerate(response.json()["pricing"]["packages"]):
        meta = pkg.get("metadata", {})
        assert "units_display" in meta, f"pricing.packages[{i}].metadata missing units_display"
        assert isinstance(meta["units_display"], str)
        assert "units" in meta["units_display"]


def test_billing_manifest_each_package_metadata_has_effective_price_per_1k(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    for i, pkg in enumerate(response.json()["pricing"]["packages"]):
        meta = pkg.get("metadata", {})
        assert "effective_price_per_1k_units" in meta, f"pricing.packages[{i}].metadata missing effective_price_per_1k_units"
        assert isinstance(meta["effective_price_per_1k_units"], int | float)
        assert meta["effective_price_per_1k_units"] > 0


def test_billing_manifest_each_package_metadata_has_tokens_per_unit(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    for i, pkg in enumerate(response.json()["pricing"]["packages"]):
        meta = pkg.get("metadata", {})
        assert "tokens_per_unit" in meta, f"pricing.packages[{i}].metadata missing tokens_per_unit"
        assert meta["tokens_per_unit"] == 25_000


# ---------------------------------------------------------------------------
# KPIs
# ---------------------------------------------------------------------------


def test_billing_manifest_pricing_kpis_is_list(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert isinstance(response.json()["pricing"]["kpis"], list)


def test_billing_manifest_pricing_kpis_is_non_empty(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert len(response.json()["pricing"]["kpis"]) > 0


def test_billing_manifest_each_kpi_has_required_fields(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    for i, kpi in enumerate(response.json()["pricing"]["kpis"]):
        assert "label" in kpi, f"pricing.kpis[{i}] missing label"
        assert "value" in kpi, f"pricing.kpis[{i}] missing value"


def test_billing_manifest_each_kpi_label_is_string(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    for i, kpi in enumerate(response.json()["pricing"]["kpis"]):
        assert isinstance(kpi["label"], str), f"pricing.kpis[{i}].label must be str"


def test_billing_manifest_each_kpi_value_is_string(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    for i, kpi in enumerate(response.json()["pricing"]["kpis"]):
        assert isinstance(kpi["value"], str), f"pricing.kpis[{i}].value must be str"


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------


def test_billing_manifest_pricing_notes_is_list(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert isinstance(response.json()["pricing"]["notes"], list)


def test_billing_manifest_pricing_notes_is_non_empty(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert len(response.json()["pricing"]["notes"]) > 0


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------


def test_billing_manifest_has_actions(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    body = response.json()
    assert "actions" in body
    assert isinstance(body["actions"], list)


def test_billing_manifest_actions_is_non_empty(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert len(response.json()["actions"]) > 0


def test_billing_manifest_each_action_has_required_fields(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    for i, action in enumerate(response.json()["actions"]):
        assert "action_id" in action, f"actions[{i}] missing action_id"
        assert "label" in action, f"actions[{i}] missing label"
        assert "method" in action, f"actions[{i}] missing method"
        assert "path" in action, f"actions[{i}] missing path"
        assert "description" in action, f"actions[{i}] missing description"
        assert "requires_api_key" in action, f"actions[{i}] missing requires_api_key"


def test_billing_manifest_each_action_requires_api_key_is_bool(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    for i, action in enumerate(response.json()["actions"]):
        assert isinstance(action["requires_api_key"], bool), f"actions[{i}].requires_api_key must be bool"


def test_billing_manifest_each_action_path_starts_with_slash(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    for i, action in enumerate(response.json()["actions"]):
        assert action["path"].startswith("/"), f"actions[{i}].path must start with /"


def test_billing_manifest_known_action_ids_present(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    returned_ids = {action["action_id"] for action in response.json()["actions"]}
    for expected_id in ("list-packages", "purchase-package", "wallet-balance", "ledger-list"):
        assert expected_id in returned_ids, f"Expected action_id {expected_id!r} missing"


# ---------------------------------------------------------------------------
# Metadata block
# ---------------------------------------------------------------------------


def test_billing_manifest_has_metadata(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    body = response.json()
    assert "metadata" in body
    assert isinstance(body["metadata"], dict)


def test_billing_manifest_metadata_has_package_count(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    metadata = response.json()["metadata"]
    assert "package_count" in metadata
    assert isinstance(metadata["package_count"], int)
    assert metadata["package_count"] == 3


def test_billing_manifest_metadata_featured_package_id(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert response.json()["metadata"]["featured_package_id"] == _FEATURED_PACKAGE_ID


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


def test_billing_manifest_no_auth_required(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert response.status_code != 401
    assert response.status_code != 403
