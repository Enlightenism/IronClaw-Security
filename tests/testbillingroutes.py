from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


BILLING_PATHS = (
    "/billing/index",
    "/billing/manifest",
    "/billing/packages",
    "/billing/registry",
    "/billing/summary",
)


def _get_json(path: str) -> dict[str, Any]:
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    payload = response.json()
    assert isinstance(payload, dict)
    return payload


@pytest.mark.parametrize("path", BILLING_PATHS)
def test_billing_route_is_registered(path: str) -> None:
    response = client.get(path)
    assert response.status_code == 200


@pytest.mark.parametrize("path", BILLING_PATHS)
def test_billing_routes_return_json_objects(path: str) -> None:
    payload = _get_json(path)
    assert isinstance(payload, dict)


@pytest.mark.parametrize("path", BILLING_PATHS)
def test_billing_routes_support_get_only_contract(path: str) -> None:
    response = client.post(path, json={})
    assert response.status_code in {405, 404}


def test_billing_index_route_has_stable_shape() -> None:
    payload = _get_json("/billing/index")

    assert payload
    assert any(
        key in payload
        for key in (
            "title",
            "displayname",
            "summary",
            "sections",
            "routes",
            "generatedat",
        )
    )


def test_billing_manifest_route_has_stable_shape() -> None:
    payload = _get_json("/billing/manifest")

    assert payload
    assert any(
        key in payload
        for key in (
            "manifest",
            "version",
            "generatedat",
            "packages",
            "billing",
        )
    )


def test_billing_packages_route_has_stable_shape() -> None:
    payload = _get_json("/billing/packages")

    assert payload
    assert any(
        key in payload
        for key in (
            "packages",
            "items",
            "catalog",
            "plans",
            "generatedat",
        )
    )


def test_billing_registry_route_has_stable_shape() -> None:
    payload = _get_json("/billing/registry")

    assert payload
    assert any(
        key in payload
        for key in (
            "registry",
            "entries",
            "integrations",
            "providers",
            "generatedat",
        )
    )


def test_billing_summary_route_has_stable_shape() -> None:
    payload = _get_json("/billing/summary")

    assert payload
    assert any(
        key in payload
        for key in (
            "summary",
            "balances",
            "wallet",
            "usage",
            "generatedat",
        )
    )


@pytest.mark.parametrize("path", BILLING_PATHS)
def test_billing_routes_do_not_return_empty_payloads(path: str) -> None:
    payload = _get_json(path)
    assert payload != {}


@pytest.mark.parametrize("path", BILLING_PATHS)
def test_billing_routes_are_repeatable(path: str) -> None:
    first = _get_json(path)
    second = _get_json(path)

    assert set(first.keys()) == set(second.keys())


@pytest.mark.parametrize("path", BILLING_PATHS)
def test_billing_routes_are_not_server_errors(path: str) -> None:
    response = client.get(path)
    assert response.status_code < 500


def test_billing_index_and_summary_are_distinct_documents() -> None:
    index_payload = _get_json("/billing/index")
    summary_payload = _get_json("/billing/summary")

    assert index_payload != summary_payload


def test_billing_packages_response_exposes_collection_if_present() -> None:
    payload = _get_json("/billing/packages")

    for key in ("packages", "items", "catalog", "plans"):
        if key in payload:
            assert isinstance(payload[key], (list, dict))


def test_billing_registry_response_exposes_collection_if_present() -> None:
    payload = _get_json("/billing/registry")

    for key in ("registry", "entries", "integrations", "providers"):
        if key in payload:
            assert isinstance(payload[key], (list, dict))


def test_billing_summary_response_exposes_wallet_or_usage_if_present() -> None:
    payload = _get_json("/billing/summary")

    for key in ("summary", "balances", "wallet", "usage"):
        if key in payload:
            assert isinstance(payload[key], (dict, list, str, int, float, bool))


@pytest.mark.parametrize("path", BILLING_PATHS)
def test_billing_routes_return_string_keys_only(path: str) -> None:
    payload = _get_json(path)

    for key in payload.keys():
        assert isinstance(key, str)
        assert key.strip()


@pytest.mark.parametrize("path", BILLING_PATHS)
def test_billing_routes_are_json_serialization_friendly(path: str) -> None:
    payload = _get_json(path)

    for value in payload.values():
        assert value is None or isinstance(value, (str, int, float, bool, list, dict))


def test_billing_manifest_and_packages_are_consistent_if_both_expose_packages() -> None:
    manifest = _get_json("/billing/manifest")
    packages = _get_json("/billing/packages")

    manifest_keys = {"packages", "plans", "catalog"}
    package_keys = {"packages", "plans", "catalog", "items"}

    manifest_collection_key = next((key for key in manifest_keys if key in manifest), None)
    packages_collection_key = next((key for key in package_keys if key in packages), None)

    if manifest_collection_key and packages_collection_key:
        assert isinstance(manifest[manifest_collection_key], (list, dict))
        assert isinstance(packages[packages_collection_key], (list, dict))