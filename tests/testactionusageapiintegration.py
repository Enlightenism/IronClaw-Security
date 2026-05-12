from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


USAGE_API_PATHS = (
    "/action/usage",
    "/usage",
    "/billing/summary",
)


def _safe_get(path: str) -> Any:
    response = client.get(path)
    if response.status_code == 404:
        pytest.skip(f"route not registered: {path}")
    assert response.status_code < 500
    return response


def _json_object_from(path: str) -> dict[str, Any]:
    response = _safe_get(path)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    payload = response.json()
    assert isinstance(payload, dict)
    return payload


def test_usage_api_has_at_least_one_registered_route() -> None:
    statuses = []
    for path in USAGE_API_PATHS:
        response = client.get(path)
        statuses.append(response.status_code)

    assert 200 in statuses


@pytest.mark.parametrize("path", USAGE_API_PATHS)
def test_usage_api_routes_do_not_error_when_present(path: str) -> None:
    response = client.get(path)

    if response.status_code == 404:
        pytest.skip(f"route not registered: {path}")

    assert response.status_code == 200


@pytest.mark.parametrize("path", USAGE_API_PATHS)
def test_usage_api_routes_return_json_objects_when_present(path: str) -> None:
    response = client.get(path)

    if response.status_code == 404:
        pytest.skip(f"route not registered: {path}")

    assert response.headers["content-type"].startswith("application/json")
    assert isinstance(response.json(), dict)


@pytest.mark.parametrize("path", USAGE_API_PATHS)
def test_usage_api_routes_support_read_contract_only_when_present(path: str) -> None:
    response = client.post(path, json={"owner_id": "owner-001"})

    if response.status_code == 404:
        pytest.skip(f"route not registered: {path}")

    assert response.status_code in {200, 201, 202, 405, 422}


@pytest.mark.parametrize("path", USAGE_API_PATHS)
def test_usage_api_payload_contains_usage_related_fields_when_present(path: str) -> None:
    response = client.get(path)

    if response.status_code == 404:
        pytest.skip(f"route not registered: {path}")

    payload = response.json()
    assert isinstance(payload, dict)
    assert any(
        key in payload
        for key in (
            "usage",
            "summary",
            "ownerid",
            "owner_id",
            "units",
            "remaining",
            "quota",
            "events",
            "records",
            "generatedat",
        )
    )


@pytest.mark.parametrize("path", USAGE_API_PATHS)
def test_usage_api_payload_values_are_json_friendly_when_present(path: str) -> None:
    response = client.get(path)

    if response.status_code == 404:
        pytest.skip(f"route not registered: {path}")

    payload = response.json()
    assert isinstance(payload, dict)

    for key, value in payload.items():
        assert isinstance(key, str)
        assert value is None or isinstance(value, (str, int, float, bool, list, dict))


@pytest.mark.parametrize("path", USAGE_API_PATHS)
def test_usage_api_route_is_repeatable_when_present(path: str) -> None:
    first = client.get(path)
    second = client.get(path)

    if first.status_code == 404 or second.status_code == 404:
        pytest.skip(f"route not registered: {path}")

    assert first.status_code == 200
    assert second.status_code == 200
    assert set(first.json().keys()) == set(second.json().keys())


def test_usage_api_primary_route_or_fallback_exposes_metering_shape() -> None:
    for path in USAGE_API_PATHS:
        response = client.get(path)
        if response.status_code == 200:
            payload = response.json()
            assert isinstance(payload, dict)
            assert any(
                key in payload
                for key in (
                    "usage",
                    "summary",
                    "units",
                    "quota",
                    "remaining",
                    "events",
                    "records",
                )
            )
            return

    pytest.fail("no usage API route returned 200")


def test_usage_api_usage_collection_is_valid_when_present() -> None:
    for path in USAGE_API_PATHS:
        response = client.get(path)
        if response.status_code != 200:
            continue

        payload = response.json()
        for key in ("events", "records", "entries", "usage"):
            if key in payload:
                assert isinstance(payload[key], (list, dict))
                return

    pytest.skip("no usage collection field exposed")


def test_usage_api_quota_relationship_is_valid_when_present() -> None:
    for path in USAGE_API_PATHS:
        response = client.get(path)
        if response.status_code != 200:
            continue

        payload = response.json()
        quota = payload.get("quota")
        remaining = payload.get("remaining")
        if quota is not None and remaining is not None:
            assert float(remaining) <= float(quota)
            return

    pytest.skip("quota and remaining fields not exposed together")


def test_usage_api_owner_identifier_is_non_empty_when_present() -> None:
    for path in USAGE_API_PATHS:
        response = client.get(path)
        if response.status_code != 200:
            continue

        payload = response.json()
        owner = payload.get("ownerid", payload.get("owner_id"))
        if owner is not None:
            assert isinstance(owner, str)
            assert owner.strip()
            return

    pytest.skip("owner identifier not exposed")


def test_usage_api_routes_are_not_redirects() -> None:
    for path in USAGE_API_PATHS:
        response = client.get(path, follow_redirects=False)
        if response.status_code == 404:
            continue
        assert response.status_code not in {301, 302, 307, 308}


def test_usage_api_exposes_generated_timestamp_when_present() -> None:
    for path in USAGE_API_PATHS:
        response = client.get(path)
        if response.status_code != 200:
            continue

        payload = response.json()
        timestamp = payload.get("generatedat", payload.get("timestamp"))
        if timestamp is not None:
            assert isinstance(timestamp, str)
            assert timestamp.strip()
            return

    pytest.skip("generated timestamp not exposed")