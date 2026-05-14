from __future__ import annotations

from typing import Any, Final

import pytest
from fastapi.testclient import TestClient

from app.main import app

ADMIN_SYSTEM_DIAGNOSTICS_PATH: Final[str] = "/admin/system-diagnostics"


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def _get_payload(client: TestClient) -> tuple[Any, dict[str, Any]]:
    response = client.get(ADMIN_SYSTEM_DIAGNOSTICS_PATH)
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/json")
    payload = response.json()
    assert isinstance(payload, dict)
    return response, payload


def test_admin_system_diagnostics_route_is_registered(client: TestClient) -> None:
    response = client.get(ADMIN_SYSTEM_DIAGNOSTICS_PATH)
    assert response.status_code == 200, response.text


def test_admin_system_diagnostics_returns_json_object(client: TestClient) -> None:
    response, data = _get_payload(client)

    assert response.status_code == 200
    assert isinstance(data, dict)


def test_admin_system_diagnostics_contains_basic_shape(client: TestClient) -> None:
    _, data = _get_payload(client)

    assert data
    assert any(
        key in data
        for key in (
            "title",
            "system_diagnostics",
            "diagnostics",
            "checks",
            "health",
            "summary",
            "status",
            "items",
        )
    )


def test_admin_system_diagnostics_surface_does_not_return_array_root(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)
    assert not isinstance(data, list)


def test_admin_system_diagnostics_nested_collections_are_json_safe_when_present(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)

    for key in ("checks", "items"):
        if key in data:
            assert isinstance(data[key], list)


def test_admin_system_diagnostics_status_field_is_string_when_present(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)

    if "status" in data:
        assert isinstance(data["status"], str)
        assert data["status"].strip()


def test_admin_system_diagnostics_title_field_is_string_when_present(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)

    if "title" in data:
        assert isinstance(data["title"], str)
        assert data["title"].strip()


def test_admin_system_diagnostics_summary_field_is_json_safe_when_present(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)

    if "summary" in data:
        assert isinstance(data["summary"], (str, dict, list))


def test_admin_system_diagnostics_response_is_stable_across_repeated_reads(
    client: TestClient,
) -> None:
    first_response, first_payload = _get_payload(client)
    second_response, second_payload = _get_payload(client)

    assert first_response.status_code == 200
    assert second_response.status_code == 200
    assert first_payload == second_payload
