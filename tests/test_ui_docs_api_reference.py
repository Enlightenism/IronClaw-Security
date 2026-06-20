from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

URL = "/ui/docs/api-reference"

_REQUIRED_TOP_LEVEL_FIELDS = (
    "generatedat",
    "version",
    "baseurl",
    "apikeyheadername",
    "totalgroupcount",
    "totalroutecount",
    "groups",
)

_KNOWN_GROUP_IDS = {
    "guard",
    "policy",
    "audit",
    "telemetry",
    "admin",
    "docs",
}

_VALID_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

_VALID_FIELD_LOCATIONS = {"body", "query", "path", "header"}

_REQUIRED_GROUP_FIELDS = (
    "groupid",
    "label",
    "description",
    "routes",
)

_REQUIRED_ROUTE_FIELDS = (
    "routeid",
    "method",
    "path",
    "description",
    "authrequired",
    "requestfields",
    "responsefields",
)

_REQUIRED_FIELD_VIEW_FIELDS = (
    "name",
    "location",
    "required",
    "description",
)


def test_get_docs_api_reference_returns_200(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200


def test_get_docs_api_reference_content_type_is_json(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert "application/json" in response.headers.get("content-type", "")


def test_get_docs_api_reference_response_is_object(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    assert isinstance(response.json(), dict)


def test_get_docs_api_reference_required_top_level_fields_present(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in _REQUIRED_TOP_LEVEL_FIELDS:
        assert field in body, f"missing top-level field: {field!r}"


def test_get_docs_api_reference_scalar_fields_are_non_empty_strings(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in ("generatedat", "version", "baseurl", "apikeyheadername"):
        assert isinstance(body[field], str), f"{field!r} must be str"
        assert body[field].strip(), f"{field!r} must not be empty"


def test_get_docs_api_reference_generatedat_is_iso8601(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    generatedat = response.json()["generatedat"]
    assert isinstance(generatedat, str)
    assert "T" in generatedat
    assert "Z" in generatedat or "+" in generatedat


def test_get_docs_api_reference_apikeyheadername_value(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    assert response.json()["apikeyheadername"] == "X-API-Key"


def test_get_docs_api_reference_version_is_gen1(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    assert response.json()["version"] == "gen1"


def test_get_docs_api_reference_groups_is_non_empty_list(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    groups = response.json()["groups"]
    assert isinstance(groups, list)
    assert len(groups) > 0


def test_get_docs_api_reference_totalgroupcount_matches_groups_length(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    assert body["totalgroupcount"] == len(body["groups"])


def test_get_docs_api_reference_totalroutecount_matches_sum_of_routes(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    computed = sum(len(g["routes"]) for g in body["groups"])
    assert body["totalroutecount"] == computed


def test_get_docs_api_reference_totalroutecount_is_positive_int(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body["totalroutecount"], int)
    assert body["totalroutecount"] > 0


def test_get_docs_api_reference_totalgroupcount_is_positive_int(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body["totalgroupcount"], int)
    assert body["totalgroupcount"] > 0


def test_get_docs_api_reference_all_known_groups_present(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    group_ids = {g["groupid"] for g in response.json()["groups"]}
    for gid in _KNOWN_GROUP_IDS:
        assert gid in group_ids, f"expected group {gid!r} not found"


def test_get_docs_api_reference_group_ids_are_unique(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    group_ids = [g["groupid"] for g in response.json()["groups"]]
    assert len(group_ids) == len(set(group_ids))


def test_get_docs_api_reference_groups_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, group in enumerate(response.json()["groups"]):
        assert isinstance(group, dict), f"groups[{i}] must be a dict"
        for field in _REQUIRED_GROUP_FIELDS:
            assert field in group, f"groups[{i}] missing field: {field!r}"
        assert isinstance(group["groupid"], str), f"groups[{i}].groupid must be str"
        assert group["groupid"].strip(), f"groups[{i}].groupid must not be empty"
        assert isinstance(group["label"], str), f"groups[{i}].label must be str"
        assert group["label"].strip(), f"groups[{i}].label must not be empty"
        assert isinstance(group["description"], str), f"groups[{i}].description must be str"
        assert group["description"].strip(), f"groups[{i}].description must not be empty"
        assert isinstance(group["routes"], list), f"groups[{i}].routes must be a list"


def test_get_docs_api_reference_all_groups_have_at_least_one_route(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, group in enumerate(response.json()["groups"]):
        assert len(group["routes"]) > 0, f"groups[{i}] ({group['groupid']!r}) has no routes"


def test_get_docs_api_reference_routes_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for gi, group in enumerate(response.json()["groups"]):
        for ri, route in enumerate(group["routes"]):
            assert isinstance(route, dict), f"groups[{gi}].routes[{ri}] must be a dict"
            for field in _REQUIRED_ROUTE_FIELDS:
                assert field in route, f"groups[{gi}].routes[{ri}] missing field: {field!r}"
            assert isinstance(route["routeid"], str)
            assert route["routeid"].strip()
            assert isinstance(route["method"], str)
            assert route["method"].strip()
            assert isinstance(route["path"], str)
            assert route["path"].strip()
            assert isinstance(route["description"], str)
            assert route["description"].strip()
            assert isinstance(route["authrequired"], bool)
            assert isinstance(route["requestfields"], list)
            assert isinstance(route["responsefields"], list)


def test_get_docs_api_reference_route_ids_are_unique_across_all_groups(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    route_ids: list[str] = []
    for group in response.json()["groups"]:
        for route in group["routes"]:
            route_ids.append(route["routeid"])
    assert len(route_ids) == len(set(route_ids))


def test_get_docs_api_reference_route_methods_are_valid_http(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for gi, group in enumerate(response.json()["groups"]):
        for ri, route in enumerate(group["routes"]):
            assert route["method"] in _VALID_HTTP_METHODS, f"groups[{gi}].routes[{ri}].method {route['method']!r} is not valid"


def test_get_docs_api_reference_route_paths_start_with_slash(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for gi, group in enumerate(response.json()["groups"]):
        for ri, route in enumerate(group["routes"]):
            assert route["path"].startswith("/"), f"groups[{gi}].routes[{ri}].path must start with '/'"


def test_get_docs_api_reference_field_views_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for gi, group in enumerate(response.json()["groups"]):
        for ri, route in enumerate(group["routes"]):
            for kind in ("requestfields", "responsefields"):
                for fi, field in enumerate(route[kind]):
                    assert isinstance(field, dict), f"groups[{gi}].routes[{ri}].{kind}[{fi}] must be a dict"
                    for required_field in _REQUIRED_FIELD_VIEW_FIELDS:
                        assert required_field in field, f"groups[{gi}].routes[{ri}].{kind}[{fi}] missing {required_field!r}"
                    assert isinstance(field["name"], str)
                    assert field["name"].strip()
                    assert isinstance(field["description"], str)
                    assert field["description"].strip()
                    assert isinstance(field["required"], bool)
                    assert field["location"] in _VALID_FIELD_LOCATIONS, f"groups[{gi}].routes[{ri}].{kind}[{fi}].location {field['location']!r} is not valid"


def test_get_docs_api_reference_guard_group_contains_guard_action(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    guard_group = next((g for g in response.json()["groups"] if g["groupid"] == "guard"), None)
    assert guard_group is not None
    route_ids = {r["routeid"] for r in guard_group["routes"]}
    assert "guard-action" in route_ids


def test_get_docs_api_reference_policy_group_contains_policy_status(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    policy_group = next((g for g in response.json()["groups"] if g["groupid"] == "policy"), None)
    assert policy_group is not None
    route_ids = {r["routeid"] for r in policy_group["routes"]}
    assert "policy-status" in route_ids


def test_get_docs_api_reference_docs_group_contains_self_referential_route(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    docs_group = next((g for g in response.json()["groups"] if g["groupid"] == "docs"), None)
    assert docs_group is not None
    route_ids = {r["routeid"] for r in docs_group["routes"]}
    assert "docs-api-reference" in route_ids


def test_get_docs_api_reference_authrequired_false_on_docs_routes(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    docs_group = next((g for g in response.json()["groups"] if g["groupid"] == "docs"), None)
    assert docs_group is not None
    for route in docs_group["routes"]:
        assert route["authrequired"] is False, f"docs route {route['routeid']!r} must have authrequired=False"


def test_get_docs_api_reference_no_auth_required(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code != 401
    assert response.status_code != 403


@pytest.mark.parametrize(
    "method",
    ["post", "put", "patch", "delete"],
)
def test_get_docs_api_reference_non_get_methods_not_allowed(
    test_client: TestClient,
    method: str,
) -> None:
    response = getattr(test_client, method)(URL)
    assert response.status_code == 405
