from __future__ import annotations

from fastapi.testclient import TestClient


def test_billing_summary_returns_200(test_client: TestClient) -> None:
    response = test_client.get("/billing-summary")
    assert response.status_code == 200


def test_billing_summary_response_shape(test_client: TestClient) -> None:
    response = test_client.get("/billing-summary")
    assert response.status_code == 200
    body = response.json()

    assert body["status"] == "ok"
    assert body["service"] == "IronClaw-Security"
    assert isinstance(body["timestamp"], str)
    assert len(body["timestamp"]) > 0
    assert body["title"] == "Billing Summary"
    assert isinstance(body["subtitle"], str)
    assert len(body["subtitle"]) > 0


def test_billing_summary_kpis_present(test_client: TestClient) -> None:
    response = test_client.get("/billing-summary")
    assert response.status_code == 200
    body = response.json()

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
    response = test_client.get("/billing-summary")
    assert response.status_code == 200
    body = response.json()

    packages = body["packages"]
    assert isinstance(packages, list)
    assert len(packages) == 3

    package_ids = {p["package_id"] for p in packages}
    assert "single-user" in package_ids
    assert "team-security" in package_ids
    assert "enterprise-security" in package_ids

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


def test_billing_summary_featured_package_is_team_security(test_client: TestClient) -> None:
    response = test_client.get("/billing-summary")
    assert response.status_code == 200
    body = response.json()

    featured = [p for p in body["packages"] if p["featured"]]
    assert len(featured) == 1
    assert featured[0]["package_id"] == "team-security"


def test_billing_summary_links_present(test_client: TestClient) -> None:
    response = test_client.get("/billing-summary")
    assert response.status_code == 200
    body = response.json()

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
    response = test_client.get("/billing-summary")
    assert response.status_code == 200
    body = response.json()

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
    response = test_client.get("/billing-summary")
    assert response.status_code == 200
    body = response.json()

    timestamp = body["timestamp"]
    assert timestamp.endswith("Z")


def test_billing_summary_entry_price_kpi_value(test_client: TestClient) -> None:
    response = test_client.get("/billing-summary")
    assert response.status_code == 200
    body = response.json()

    entry_kpi = next(k for k in body["kpis"] if k["label"] == "Entry price")
    assert entry_kpi["value"].startswith("$")
    assert entry_kpi["metadata"]["kind"] == "entry-price"


def test_billing_summary_largest_bundle_kpi_value(test_client: TestClient) -> None:
    response = test_client.get("/billing-summary")
    assert response.status_code == 200
    body = response.json()

    largest_kpi = next(k for k in body["kpis"] if k["label"] == "Largest bundle")
    assert "units" in largest_kpi["value"]
    assert largest_kpi["metadata"]["kind"] == "largest-bundle"
