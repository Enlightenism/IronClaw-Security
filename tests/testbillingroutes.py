from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.api.routes.billing import router as billing_router
from app.core.auth import API_KEY_HEADER_NAME

_API_KEY = "test-secret-key"


def _build_billing_test_app() -> FastAPI:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        auth_required=True,
        api_key=_API_KEY,
        admin_api_key=None,
    )
    app.include_router(billing_router)
    return app


client = TestClient(_build_billing_test_app())

_HEADERS = {API_KEY_HEADER_NAME: _API_KEY}

BILLING_PATHS = (
    "/billing/packages",
    "/billing/ledger",
)


def _get_json(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    response = client.get(path, params=params, headers=_HEADERS)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    payload = response.json()
    assert isinstance(payload, dict)
    return payload


@pytest.mark.parametrize("path", BILLING_PATHS)
def test_billing_route_is_registered(path: str) -> None:
    response = client.get(path, headers=_HEADERS)
    assert response.status_code == 200


@pytest.mark.parametrize("path", BILLING_PATHS)
def test_billing_routes_return_json_objects(path: str) -> None:
    payload = _get_json(path)
    assert isinstance(payload, dict)


@pytest.mark.parametrize("path", BILLING_PATHS)
def test_billing_routes_support_get_only_contract(path: str) -> None:
    response = client.post(path, json={}, headers=_HEADERS)
    assert response.status_code in {405, 404}


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
            "status",
        )
    )


def test_billing_ledger_route_has_stable_shape() -> None:
    payload = _get_json("/billing/ledger")

    assert payload
    assert any(
        key in payload
        for key in (
            "entries",
            "limit",
            "owner_key",
            "status",
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
    response = client.get(path, headers=_HEADERS)
    assert response.status_code < 500


def test_billing_packages_and_ledger_are_distinct_documents() -> None:
    packages_payload = _get_json("/billing/packages")
    ledger_payload = _get_json("/billing/ledger")

    assert packages_payload != ledger_payload


def test_billing_packages_response_exposes_collection_if_present() -> None:
    payload = _get_json("/billing/packages")

    for key in ("packages", "items", "catalog", "plans"):
        if key in payload:
            assert isinstance(payload[key], list | dict)


def test_billing_ledger_response_exposes_entries_if_present() -> None:
    payload = _get_json("/billing/ledger")

    for key in ("entries",):
        if key in payload:
            assert isinstance(payload[key], list | dict)


def test_billing_ledger_response_exposes_limit_if_present() -> None:
    payload = _get_json("/billing/ledger")

    if "limit" in payload:
        assert isinstance(payload["limit"], int)


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
        assert value is None or isinstance(value, str | int | float | bool | list | dict)


def test_billing_packages_response_has_consistent_structure() -> None:
    first = _get_json("/billing/packages")
    second = _get_json("/billing/packages")

    assert set(first.keys()) == set(second.keys())

    if "packages" in first and "packages" in second:
        assert isinstance(first["packages"], list)
        assert isinstance(second["packages"], list)
