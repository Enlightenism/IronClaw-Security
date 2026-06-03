from __future__ import annotations

from fastapi.testclient import TestClient

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


def _get_body(test_client: TestClient) -> dict:
    response = test_client.get("/billing-summary")
    assert response.status_code == 200
    return response.json()


def _get_package_map(test_client: TestClient) -> dict[str, dict]:
    body = _get_body(test_client)
    return {pkg["package_id"]: pkg for pkg in body["packages"]}


def test_billing_summary_returns_200(test_client: TestClient) -> None:
    response = test_client.get("/billing-summary")
    assert response.status_code == 200


def test_billing_summary_response_shape(test_client: TestClient) -> None:
    body = _get_body(test_client)

    assert body["status"] == "ok"
    assert body["service"] == "IronClaw-Security"
    assert isinstance(body["timestamp"], str)
    assert len(body["timestamp"]) > 0
    assert body["title"] == "Billing Summary"
    assert isinstance(body["subtitle"], str)
    assert len(body["subtitle"]) > 0


def test_billing_summary_kpis_present(test_client: TestClient) -> None:
    body = _get_body(test_client)

    kpis = body["kpis"]
    assert isinstance(kpis, list)
    assert len(kpis) == 3

    labels = {kpi["label"] for kpi in kpis}
    assert "Entry price" in labels
    assert "Featured package" in labels
    assert "Largest bundle" in labels

    for kpi in kpis:
        assert isinstance(kpi["label"], str)
        assert isinstance(kpi["value"], str)
        assert isinstance(kpi["metadata"], dict)


def test_billing_summary_packages_present(test_client: TestClient) -> None:
    body = _get_body(test_client)

    packages = body["packages"]
    assert isinstance(packages, list)
    assert len(packages) == 3

    package_ids = [p["package_id"] for p in packages]
    assert package_ids == _ORDERED_PACKAGE_IDS

    for pkg in packages:
        assert isinstance(pkg["package_id"], str)
        assert isinstance(pkg["name"], str)
        assert isinstance(pkg["price_usd"], float)
        assert isinstance(pkg["included_units"], int)
        assert isinstance(pkg["featured"], bool)
        assert isinstance(pkg["metadata"], dict)
        assert "price_display" in pkg["metadata"]
        assert "units_display" in pkg["metadata"]
        assert "effective_price_per_1k_units" in pkg["metadata"]
        assert "tokens_per_unit" in pkg["metadata"]


def test_billing_summary_featured_package_is_team_security(test_client: TestClient) -> None:
    body = _get_body(test_client)

    featured = [p for p in body["packages"] if p["featured"]]
    assert len(featured) == 1
    assert featured[0]["package_id"] == _FEATURED_PACKAGE_ID


def test_billing_summary_exact_catalog_values(test_client: TestClient) -> None:
    pkg_map = _get_package_map(test_client)

    for package_id, expected in _EXPECTED_PACKAGES.items():
        assert package_id in pkg_map
        pkg = pkg_map[package_id]
        assert pkg["name"] == expected["name"]
        assert pkg["price_usd"] == expected["price_usd"]
        assert pkg["included_units"] == expected["included_units"]


def test_billing_summary_pkg_5000_exact_values(test_client: TestClient) -> None:
    pkg = _get_package_map(test_client)["pkg_5000"]
    assert pkg["name"] == "Starter"
    assert pkg["price_usd"] == 20.0
    assert pkg["included_units"] == 5_000


def test_billing_summary_pkg_25000_exact_values(test_client: TestClient) -> None:
    pkg = _get_package_map(test_client)["pkg_25000"]
    assert pkg["name"] == "Team"
    assert pkg["price_usd"] == 90.0
    assert pkg["included_units"] == 25_000


def test_billing_summary_pkg_60000_exact_values(test_client: TestClient) -> None:
    pkg = _get_package_map(test_client)["pkg_60000"]
    assert pkg["name"] == "Enterprise"
    assert pkg["price_usd"] == 180.0
    assert pkg["included_units"] == 60_000


def test_billing_summary_package_metadata_values(test_client: TestClient) -> None:
    pkg_map = _get_package_map(test_client)

    assert pkg_map["pkg_5000"]["metadata"]["effective_price_per_1k_units"] == round((20.0 / 5_000) * 1_000, 4)
    assert pkg_map["pkg_25000"]["metadata"]["effective_price_per_1k_units"] == round((90.0 / 25_000) * 1_000, 4)
    assert pkg_map["pkg_60000"]["metadata"]["effective_price_per_1k_units"] == round((180.0 / 60_000) * 1_000, 4)

    for pkg in pkg_map.values():
        assert pkg["metadata"]["tokens_per_unit"] == 25_000


def test_billing_summary_links_present(test_client: TestClient) -> None:
    body = _get_body(test_client)

    links = body["links"]
    assert isinstance(links, list)
    assert len(links) == 4

    paths = {link["path"] for link in links}
    assert "/ui/billing-index" in paths
    assert "/ui/billing-manifest" in paths
    assert "/ui/billing-registry" in paths
    assert any("billing-wallet" in p for p in paths)

    for link in links:
        assert isinstance(link["label"], str)
        assert isinstance(link["path"], str)
        assert isinstance(link["description"], str)


def test_billing_summary_notes_present(test_client: TestClient) -> None:
    body = _get_body(test_client)

    notes = body["notes"]
    assert isinstance(notes, list)
    assert len(notes) >= 1
    for note in notes:
        assert isinstance(note, str)


def test_billing_summary_content_type_json(test_client: TestClient) -> None:
    response = test_client.get("/billing-summary")
    assert response.status_code == 200
    assert "application/json" in response.headers["content-type"]


def test_billing_summary_timestamp_format(test_client: TestClient) -> None:
    body = _get_body(test_client)

    timestamp = body["timestamp"]
    assert timestamp.endswith("Z")


def test_billing_summary_entry_price_kpi_value(test_client: TestClient) -> None:
    body = _get_body(test_client)

    entry_kpi = next(k for k in body["kpis"] if k["label"] == "Entry price")
    assert entry_kpi["value"] == "$20.00"
    assert entry_kpi["metadata"]["kind"] == "entry-price"


def test_billing_summary_largest_bundle_kpi_value(test_client: TestClient) -> None:
    body = _get_body(test_client)

    largest_kpi = next(k for k in body["kpis"] if k["label"] == "Largest bundle")
    assert largest_kpi["value"] == "60,000 units"
    assert largest_kpi["metadata"]["kind"] == "largest-bundle"


def test_billing_summary_featured_package_kpi_value(test_client: TestClient) -> None:
    body = _get_body(test_client)

    featured_kpi = next(k for k in body["kpis"] if k["label"] == "Featured package")
    assert featured_kpi["value"] == "Team"
