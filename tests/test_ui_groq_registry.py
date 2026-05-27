from __future__ import annotations

from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ROUTE = "/api/groq-registry"

_REQUIRED_RESPONSE_KEYS = {
    "status",
    "service",
    "provider",
    "timestamp",
    "total_routes",
    "routes",
    "metadata",
}

_REQUIRED_ENTRY_KEYS = {
    "name",
    "prefix",
    "tags",
    "enabled",
    "metadata",
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_groq_registry_returns_200(test_client: TestClient) -> None:
    response = test_client.get(_ROUTE)
    assert response.status_code == 200


def test_groq_registry_content_type_is_json(test_client: TestClient) -> None:
    response = test_client.get(_ROUTE)
    assert "application/json" in response.headers.get("content-type", "")


def test_groq_registry_top_level_shape(test_client: TestClient) -> None:
    data = test_client.get(_ROUTE).json()
    assert _REQUIRED_RESPONSE_KEYS.issubset(data.keys())


def test_groq_registry_status_is_ok(test_client: TestClient) -> None:
    data = test_client.get(_ROUTE).json()
    assert data["status"] == "ok"


def test_groq_registry_service_field(test_client: TestClient) -> None:
    data = test_client.get(_ROUTE).json()
    assert data["service"] == "IronClaw-Security"


def test_groq_registry_provider_is_groq(test_client: TestClient) -> None:
    data = test_client.get(_ROUTE).json()
    assert data["provider"] == "groq"


def test_groq_registry_timestamp_is_string(test_client: TestClient) -> None:
    data = test_client.get(_ROUTE).json()
    assert isinstance(data["timestamp"], str)
    assert data["timestamp"].endswith("Z")


def test_groq_registry_total_routes_is_int(test_client: TestClient) -> None:
    data = test_client.get(_ROUTE).json()
    assert isinstance(data["total_routes"], int)
    assert data["total_routes"] >= 0


def test_groq_registry_routes_is_list(test_client: TestClient) -> None:
    data = test_client.get(_ROUTE).json()
    assert isinstance(data["routes"], list)


def test_groq_registry_total_routes_matches_routes_length(
    test_client: TestClient,
) -> None:
    data = test_client.get(_ROUTE).json()
    assert data["total_routes"] == len(data["routes"])


def test_groq_registry_metadata_is_dict(test_client: TestClient) -> None:
    data = test_client.get(_ROUTE).json()
    assert isinstance(data["metadata"], dict)


def test_groq_registry_metadata_contains_expected_keys(
    test_client: TestClient,
) -> None:
    data = test_client.get(_ROUTE).json()
    meta = data["metadata"]
    assert "ui_router_registry" in meta
    assert "sorted_by" in meta
    assert meta["sorted_by"] == "prefix"


def test_groq_registry_route_entries_have_required_fields(
    test_client: TestClient,
) -> None:
    data = test_client.get(_ROUTE).json()
    for entry in data["routes"]:
        assert _REQUIRED_ENTRY_KEYS.issubset(entry.keys()), f"Entry missing keys: {entry}"


def test_groq_registry_route_entries_name_is_string(
    test_client: TestClient,
) -> None:
    data = test_client.get(_ROUTE).json()
    for entry in data["routes"]:
        assert isinstance(entry["name"], str)
        assert len(entry["name"]) > 0


def test_groq_registry_route_entries_prefix_is_string(
    test_client: TestClient,
) -> None:
    data = test_client.get(_ROUTE).json()
    for entry in data["routes"]:
        assert isinstance(entry["prefix"], str)


def test_groq_registry_route_entries_tags_is_list(
    test_client: TestClient,
) -> None:
    data = test_client.get(_ROUTE).json()
    for entry in data["routes"]:
        assert isinstance(entry["tags"], list)


def test_groq_registry_route_entries_enabled_is_bool(
    test_client: TestClient,
) -> None:
    data = test_client.get(_ROUTE).json()
    for entry in data["routes"]:
        assert isinstance(entry["enabled"], bool)


def test_groq_registry_route_entries_metadata_is_dict(
    test_client: TestClient,
) -> None:
    data = test_client.get(_ROUTE).json()
    for entry in data["routes"]:
        assert isinstance(entry["metadata"], dict)


def test_groq_registry_routes_sorted_by_prefix(test_client: TestClient) -> None:
    data = test_client.get(_ROUTE).json()
    prefixes = [entry["prefix"] for entry in data["routes"]]
    assert prefixes == sorted(prefixes)


def test_groq_registry_idempotent_across_calls(test_client: TestClient) -> None:
    r1 = test_client.get(_ROUTE).json()
    r2 = test_client.get(_ROUTE).json()
    assert r1["total_routes"] == r2["total_routes"]
    assert r1["routes"] == r2["routes"]
    assert r1["status"] == r2["status"]
