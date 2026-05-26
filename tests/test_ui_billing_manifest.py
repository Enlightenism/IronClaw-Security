from __future__ import annotations

from fastapi.testclient import TestClient


def test_billing_manifest_returns_200(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert response.status_code == 200


def test_billing_manifest_content_type_is_json(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert "application/json" in response.headers.get("content-type", "")


def test_billing_manifest_response_is_object(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert isinstance(response.json(), dict)


def test_billing_manifest_status_is_ok(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert response.json()["status"] == "ok"


def test_billing_manifest_service_is_ironclaw(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert response.json()["service"] == "IronClaw-Security"


def test_billing_manifest_has_timestamp(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    body = response.json()
    assert "timestamp" in body
    assert isinstance(body["timestamp"], str)
    assert len(body["timestamp"]) > 0


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


def test_billing_manifest_pricing_packages_is_list(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert isinstance(response.json()["pricing"]["packages"], list)


def test_billing_manifest_pricing_packages_is_non_empty(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert len(response.json()["pricing"]["packages"]) > 0


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
        assert isinstance(pkg["price_usd"], (int, float)), f"pricing.packages[{i}].price_usd must be numeric"


def test_billing_manifest_each_package_included_units_is_int(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    for i, pkg in enumerate(response.json()["pricing"]["packages"]):
        assert isinstance(pkg["included_units"], int), f"pricing.packages[{i}].included_units must be int"


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
    assert featured[0]["package_id"] == "team-security"


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


def test_billing_manifest_pricing_notes_is_list(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert isinstance(response.json()["pricing"]["notes"], list)


def test_billing_manifest_pricing_notes_is_non_empty(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert len(response.json()["pricing"]["notes"]) > 0


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
    assert metadata["package_count"] > 0


def test_billing_manifest_metadata_featured_package_id(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert response.json()["metadata"]["featured_package_id"] == "team-security"


def test_billing_manifest_no_auth_required(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert response.status_code != 401
    assert response.status_code != 403
