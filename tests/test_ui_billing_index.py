from __future__ import annotations

from fastapi.testclient import TestClient


def test_billing_index_returns_200(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    assert response.status_code == 200


def test_billing_index_content_type_is_json(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    assert "application/json" in response.headers.get("content-type", "")


def test_billing_index_response_is_object(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    assert isinstance(response.json(), dict)


def test_billing_index_status_is_ok(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    assert response.json()["status"] == "ok"


def test_billing_index_service_is_ironclaw(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    assert response.json()["service"] == "IronClaw-Security"


def test_billing_index_has_timestamp(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    body = response.json()
    assert "timestamp" in body
    assert isinstance(body["timestamp"], str)
    assert len(body["timestamp"]) > 0


def test_billing_index_has_summary(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    body = response.json()
    assert "summary" in body
    assert isinstance(body["summary"], dict)


def test_billing_index_summary_has_required_fields(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    summary = response.json()["summary"]
    assert "title" in summary
    assert "subtitle" in summary
    assert "featured_package_id" in summary
    assert "package_count" in summary
    assert "currency" in summary
    assert "pricing_model" in summary


def test_billing_index_summary_title_is_string(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    assert isinstance(response.json()["summary"]["title"], str)


def test_billing_index_summary_currency_is_usd(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    assert response.json()["summary"]["currency"] == "USD"


def test_billing_index_summary_pricing_model(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    assert response.json()["summary"]["pricing_model"] == "prepaid-protection-units"


def test_billing_index_summary_featured_package_id(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    assert response.json()["summary"]["featured_package_id"] == "team-security"


def test_billing_index_has_packages(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    body = response.json()
    assert "packages" in body
    assert isinstance(body["packages"], list)


def test_billing_index_packages_is_non_empty(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    assert len(response.json()["packages"]) > 0


def test_billing_index_package_count_matches_packages_list(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    body = response.json()
    assert body["summary"]["package_count"] == len(body["packages"])


def test_billing_index_each_package_has_required_fields(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    for i, pkg in enumerate(response.json()["packages"]):
        assert "package_id" in pkg, f"packages[{i}] missing package_id"
        assert "name" in pkg, f"packages[{i}] missing name"
        assert "price_usd" in pkg, f"packages[{i}] missing price_usd"
        assert "included_units" in pkg, f"packages[{i}] missing included_units"
        assert "featured" in pkg, f"packages[{i}] missing featured"
        assert "metadata" in pkg, f"packages[{i}] missing metadata"


def test_billing_index_each_package_id_is_string(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    for i, pkg in enumerate(response.json()["packages"]):
        assert isinstance(pkg["package_id"], str), f"packages[{i}].package_id must be str"


def test_billing_index_each_package_price_usd_is_number(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    for i, pkg in enumerate(response.json()["packages"]):
        assert isinstance(pkg["price_usd"], (int, float)), f"packages[{i}].price_usd must be numeric"


def test_billing_index_each_package_included_units_is_int(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    for i, pkg in enumerate(response.json()["packages"]):
        assert isinstance(pkg["included_units"], int), f"packages[{i}].included_units must be int"


def test_billing_index_each_package_featured_is_bool(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    for i, pkg in enumerate(response.json()["packages"]):
        assert isinstance(pkg["featured"], bool), f"packages[{i}].featured must be bool"


def test_billing_index_exactly_one_featured_package(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    featured = [pkg for pkg in response.json()["packages"] if pkg["featured"]]
    assert len(featured) == 1


def test_billing_index_featured_package_is_team_security(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    featured = [pkg for pkg in response.json()["packages"] if pkg["featured"]]
    assert featured[0]["package_id"] == "team-security"


def test_billing_index_has_links(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    body = response.json()
    assert "links" in body
    assert isinstance(body["links"], list)


def test_billing_index_links_is_non_empty(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    assert len(response.json()["links"]) > 0


def test_billing_index_each_link_has_required_fields(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    for i, link in enumerate(response.json()["links"]):
        assert "label" in link, f"links[{i}] missing label"
        assert "path" in link, f"links[{i}] missing path"
        assert "description" in link, f"links[{i}] missing description"


def test_billing_index_each_link_label_is_string(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    for i, link in enumerate(response.json()["links"]):
        assert isinstance(link["label"], str), f"links[{i}].label must be str"


def test_billing_index_each_link_path_starts_with_slash(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    for i, link in enumerate(response.json()["links"]):
        assert link["path"].startswith("/"), f"links[{i}].path must start with /"


def test_billing_index_has_notes(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    body = response.json()
    assert "notes" in body
    assert isinstance(body["notes"], list)


def test_billing_index_notes_is_non_empty(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    assert len(response.json()["notes"]) > 0


def test_billing_index_no_auth_required(test_client: TestClient) -> None:
    response = test_client.get("/billing-index")
    assert response.status_code != 401
    assert response.status_code != 403
