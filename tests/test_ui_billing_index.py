from __future__ import annotations

from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Canonical value-pinning table — single source of truth for this test module.
# Mirrors UNIT_PACKAGE_CATALOG and _PRICING_FALLBACK in app/ui/billing_index.py.
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
_ORDERED_PACKAGE_IDS = ["pkg_5000", "pkg_25000", "pkg_60000"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_body(test_client: TestClient) -> dict:
    response = test_client.get("/billing-index")
    assert response.status_code == 200
    return response.json()


def _get_pkg_map(test_client: TestClient) -> dict[str, dict]:
    body = _get_body(test_client)
    return {pkg["package_id"]: pkg for pkg in body["packages"]}


# ---------------------------------------------------------------------------
# HTTP contract
# ---------------------------------------------------------------------------


def test_billing_index_returns_200(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    assert response.status_code == 200


def test_billing_index_content_type_is_json(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    assert "application/json" in response.headers.get("content-type", "")


def test_billing_index_no_auth_required(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    assert response.status_code not in (401, 403)


# ---------------------------------------------------------------------------
# Envelope shape
# ---------------------------------------------------------------------------


def test_billing_index_response_is_object(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    assert isinstance(response.json(), dict)


def test_billing_index_status_is_ok(test_client: TestClient) -> None:
    assert _get_body(test_client)["status"] == "ok"


def test_billing_index_service_is_ironclaw(test_client: TestClient) -> None:
    assert _get_body(test_client)["service"] == "IronClaw-Security"


def test_billing_index_has_timestamp(test_client: TestClient) -> None:
    body = _get_body(test_client)
    assert "timestamp" in body
    assert isinstance(body["timestamp"], str)
    assert body["timestamp"].endswith("Z")
    assert len(body["timestamp"]) > 0


# ---------------------------------------------------------------------------
# Summary block
# ---------------------------------------------------------------------------


def test_billing_index_has_summary(test_client: TestClient) -> None:
    body = _get_body(test_client)
    assert "summary" in body
    assert isinstance(body["summary"], dict)


def test_billing_index_summary_has_required_fields(test_client: TestClient) -> None:
    summary = _get_body(test_client)["summary"]
    for field in ("title", "subtitle", "featured_package_id", "package_count", "links_count", "currency", "pricing_model"):
        assert field in summary, f"summary missing field: {field!r}"


def test_billing_index_summary_title_is_string(test_client: TestClient) -> None:
    assert isinstance(_get_body(test_client)["summary"]["title"], str)


def test_billing_index_summary_currency_is_usd(test_client: TestClient) -> None:
    assert _get_body(test_client)["summary"]["currency"] == "USD"


def test_billing_index_summary_pricing_model(test_client: TestClient) -> None:
    assert _get_body(test_client)["summary"]["pricing_model"] == "prepaid-protection-units"


def test_billing_index_summary_featured_package_id(test_client: TestClient) -> None:
    assert _get_body(test_client)["summary"]["featured_package_id"] == _FEATURED_PACKAGE_ID


def test_billing_index_summary_package_count_matches_list(test_client: TestClient) -> None:
    body = _get_body(test_client)
    assert body["summary"]["package_count"] == len(body["packages"])


def test_billing_index_summary_links_count_matches_list(test_client: TestClient) -> None:
    body = _get_body(test_client)
    assert body["summary"]["links_count"] == len(body["links"])


# ---------------------------------------------------------------------------
# Packages — structural
# ---------------------------------------------------------------------------


def test_billing_index_has_packages(test_client: TestClient) -> None:
    body = _get_body(test_client)
    assert "packages" in body
    assert isinstance(body["packages"], list)


def test_billing_index_packages_is_non_empty(test_client: TestClient) -> None:
    assert len(_get_body(test_client)["packages"]) > 0


def test_billing_index_exactly_three_packages(test_client: TestClient) -> None:
    packages = _get_body(test_client)["packages"]
    assert len(packages) == 3, f"Expected exactly 3 packages, got {len(packages)}"


def test_billing_index_each_package_has_required_fields(test_client: TestClient) -> None:
    for i, pkg in enumerate(_get_body(test_client)["packages"]):
        for field in ("package_id", "name", "price_usd", "included_units", "display_label", "featured", "metadata"):
            assert field in pkg, f"packages[{i}] missing field: {field!r}"


def test_billing_index_each_package_id_is_string(test_client: TestClient) -> None:
    for i, pkg in enumerate(_get_body(test_client)["packages"]):
        assert isinstance(pkg["package_id"], str), f"packages[{i}].package_id must be str"


def test_billing_index_each_package_price_usd_is_float(test_client: TestClient) -> None:
    for i, pkg in enumerate(_get_body(test_client)["packages"]):
        assert isinstance(pkg["price_usd"], (int, float)), f"packages[{i}].price_usd must be numeric"
        assert pkg["price_usd"] > 0, f"packages[{i}].price_usd must be > 0"


def test_billing_index_each_package_included_units_is_positive_int(test_client: TestClient) -> None:
    for i, pkg in enumerate(_get_body(test_client)["packages"]):
        assert isinstance(pkg["included_units"], int), f"packages[{i}].included_units must be int"
        assert pkg["included_units"] > 0, f"packages[{i}].included_units must be > 0"


def test_billing_index_each_package_featured_is_bool(test_client: TestClient) -> None:
    for i, pkg in enumerate(_get_body(test_client)["packages"]):
        assert isinstance(pkg["featured"], bool), f"packages[{i}].featured must be bool"


def test_billing_index_each_package_metadata_is_dict(test_client: TestClient) -> None:
    for i, pkg in enumerate(_get_body(test_client)["packages"]):
        assert isinstance(pkg["metadata"], dict), f"packages[{i}].metadata must be dict"


# ---------------------------------------------------------------------------
# Packages — featured
# ---------------------------------------------------------------------------


def test_billing_index_exactly_one_featured_package(test_client: TestClient) -> None:
    featured = [pkg for pkg in _get_body(test_client)["packages"] if pkg["featured"]]
    assert len(featured) == 1, f"Expected exactly 1 featured package, got {len(featured)}"


def test_billing_index_featured_package_is_pkg_25000(test_client: TestClient) -> None:
    featured = [pkg for pkg in _get_body(test_client)["packages"] if pkg["featured"]]
    assert featured[0]["package_id"] == _FEATURED_PACKAGE_ID


# ---------------------------------------------------------------------------
# Packages — order
# ---------------------------------------------------------------------------


def test_billing_index_packages_returned_in_canonical_order(test_client: TestClient) -> None:
    ids = [pkg["package_id"] for pkg in _get_body(test_client)["packages"]]
    assert ids == _ORDERED_PACKAGE_IDS, f"Expected order {_ORDERED_PACKAGE_IDS}, got {ids}"


# ---------------------------------------------------------------------------
# Packages — value-pinning (exact price_usd and included_units per package ID)
# ---------------------------------------------------------------------------


def test_billing_index_pkg_5000_exact_values(test_client: TestClient) -> None:
    pkg_map = _get_pkg_map(test_client)
    assert "pkg_5000" in pkg_map, "pkg_5000 missing from packages"
    pkg = pkg_map["pkg_5000"]
    assert pkg["name"] == "Starter", f"Expected name='Starter', got {pkg['name']!r}"
    assert pkg["price_usd"] == 20.0, f"Expected price_usd=20.0, got {pkg['price_usd']}"
    assert pkg["included_units"] == 5_000, f"Expected included_units=5000, got {pkg['included_units']}"


def test_billing_index_pkg_25000_exact_values(test_client: TestClient) -> None:
    pkg_map = _get_pkg_map(test_client)
    assert "pkg_25000" in pkg_map, "pkg_25000 missing from packages"
    pkg = pkg_map["pkg_25000"]
    assert pkg["name"] == "Team", f"Expected name='Team', got {pkg['name']!r}"
    assert pkg["price_usd"] == 90.0, f"Expected price_usd=90.0, got {pkg['price_usd']}"
    assert pkg["included_units"] == 25_000, f"Expected included_units=25000, got {pkg['included_units']}"


def test_billing_index_pkg_60000_exact_values(test_client: TestClient) -> None:
    pkg_map = _get_pkg_map(test_client)
    assert "pkg_60000" in pkg_map, "pkg_60000 missing from packages"
    pkg = pkg_map["pkg_60000"]
    assert pkg["name"] == "Enterprise", f"Expected name='Enterprise', got {pkg['name']!r}"
    assert pkg["price_usd"] == 180.0, f"Expected price_usd=180.0, got {pkg['price_usd']}"
    assert pkg["included_units"] == 60_000, f"Expected included_units=60000, got {pkg['included_units']}"


def test_billing_index_all_catalog_values_match_expected(test_client: TestClient) -> None:
    pkg_map = _get_pkg_map(test_client)
    for package_id, expected in _EXPECTED_PACKAGES.items():
        assert package_id in pkg_map, f"Package {package_id!r} missing from response"
        pkg = pkg_map[package_id]
        assert pkg["name"] == expected["name"], f"{package_id}: expected name={expected['name']!r}, got {pkg['name']!r}"
        assert pkg["price_usd"] == expected["price_usd"], f"{package_id}: expected price_usd={expected['price_usd']}, got {pkg['price_usd']}"
        assert pkg["included_units"] == expected["included_units"], f"{package_id}: expected included_units={expected['included_units']}, got {pkg['included_units']}"


def test_billing_index_no_extra_package_ids_beyond_expected(test_client: TestClient) -> None:
    returned_ids = {pkg["package_id"] for pkg in _get_body(test_client)["packages"]}
    expected_ids = set(_EXPECTED_PACKAGES.keys())
    extra = returned_ids - expected_ids
    assert not extra, f"Response contains unexpected package IDs: {extra}"


# ---------------------------------------------------------------------------
# Packages — metadata block
# ---------------------------------------------------------------------------


def test_billing_index_each_package_metadata_has_price_display(test_client: TestClient) -> None:
    for i, pkg in enumerate(_get_body(test_client)["packages"]):
        assert "price_display" in pkg["metadata"], f"packages[{i}].metadata missing price_display"
        assert pkg["metadata"]["price_display"].startswith("$"), f"packages[{i}].metadata.price_display must start with '$'"


def test_billing_index_each_package_metadata_has_units_display(test_client: TestClient) -> None:
    for i, pkg in enumerate(_get_body(test_client)["packages"]):
        assert "units_display" in pkg["metadata"], f"packages[{i}].metadata missing units_display"
        assert "units" in pkg["metadata"]["units_display"], f"packages[{i}].metadata.units_display must contain 'units'"


def test_billing_index_each_package_metadata_has_effective_price_per_1k(test_client: TestClient) -> None:
    for i, pkg in enumerate(_get_body(test_client)["packages"]):
        assert "effective_price_per_1k_units" in pkg["metadata"], f"packages[{i}].metadata missing effective_price_per_1k_units"
        assert isinstance(pkg["metadata"]["effective_price_per_1k_units"], (int, float)), f"packages[{i}].metadata.effective_price_per_1k_units must be numeric"
        assert pkg["metadata"]["effective_price_per_1k_units"] > 0, f"packages[{i}].metadata.effective_price_per_1k_units must be > 0"


def test_billing_index_pkg_5000_effective_price_per_1k(test_client: TestClient) -> None:
    pkg = _get_pkg_map(test_client)["pkg_5000"]
    assert pkg["metadata"]["effective_price_per_1k_units"] == round((20.0 / 5_000) * 1_000, 4)


def test_billing_index_pkg_25000_effective_price_per_1k(test_client: TestClient) -> None:
    pkg = _get_pkg_map(test_client)["pkg_25000"]
    assert pkg["metadata"]["effective_price_per_1k_units"] == round((90.0 / 25_000) * 1_000, 4)


def test_billing_index_pkg_60000_effective_price_per_1k(test_client: TestClient) -> None:
    pkg = _get_pkg_map(test_client)["pkg_60000"]
    assert pkg["metadata"]["effective_price_per_1k_units"] == round((180.0 / 60_000) * 1_000, 4)


# ---------------------------------------------------------------------------
# Links — structural
# ---------------------------------------------------------------------------


def test_billing_index_has_links(test_client: TestClient) -> None:
    body = _get_body(test_client)
    assert "links" in body
    assert isinstance(body["links"], list)


def test_billing_index_links_is_non_empty(test_client: TestClient) -> None:
    assert len(_get_body(test_client)["links"]) > 0


def test_billing_index_each_link_has_required_fields(test_client: TestClient) -> None:
    for i, link in enumerate(_get_body(test_client)["links"]):
        for field in ("label", "path", "description"):
            assert field in link, f"links[{i}] missing field: {field!r}"


def test_billing_index_each_link_label_is_string(test_client: TestClient) -> None:
    for i, link in enumerate(_get_body(test_client)["links"]):
        assert isinstance(link["label"], str), f"links[{i}].label must be str"
        assert len(link["label"]) > 0, f"links[{i}].label must not be empty"


def test_billing_index_each_link_path_starts_with_slash(test_client: TestClient) -> None:
    for i, link in enumerate(_get_body(test_client)["links"]):
        assert link["path"].startswith("/"), f"links[{i}].path must start with /"


def test_billing_index_each_link_description_is_string(test_client: TestClient) -> None:
    for i, link in enumerate(_get_body(test_client)["links"]):
        assert isinstance(link["description"], str), f"links[{i}].description must be str"
        assert len(link["description"]) > 0, f"links[{i}].description must not be empty"


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------


def test_billing_index_has_notes(test_client: TestClient) -> None:
    body = _get_body(test_client)
    assert "notes" in body
    assert isinstance(body["notes"], list)


def test_billing_index_notes_is_non_empty(test_client: TestClient) -> None:
    assert len(_get_body(test_client)["notes"]) > 0


def test_billing_index_notes_all_strings(test_client: TestClient) -> None:
    for i, note in enumerate(_get_body(test_client)["notes"]):
        assert isinstance(note, str), f"notes[{i}] must be str"
        assert len(note) > 0, f"notes[{i}] must not be empty"
