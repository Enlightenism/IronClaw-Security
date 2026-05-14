from __future__ import annotations

from typing import Any, Final

import pytest
from fastapi.testclient import TestClient

from app.main import app

UI_TELEMETRY_ACCESS_SUMMARY_PATH: Final[str] = "/ui/telemetry-access-summary"


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def _get_payload(client: TestClient) -> tuple[Any, dict[str, Any]]:
    response = client.get(UI_TELEMETRY_ACCESS_SUMMARY_PATH)
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/json")
    payload = response.json()
    assert isinstance(payload, dict)
    return response, payload


def test_ui_telemetry_access_summary_route_is_registered(client: TestClient) -> None:
    response = client.get(UI_TELEMETRY_ACCESS_SUMMARY_PATH)
    assert response.status_code == 200, response.text


def test_ui_telemetry_access_summary_returns_json_object(client: TestClient) -> None:
    response, data = _get_payload(client)

    assert response.status_code == 200
    assert isinstance(data, dict)


def test_ui_telemetry_access_summary_contains_core_fields(client: TestClient) -> None:
    _, data = _get_payload(client)

    assert data
    assert any(k in data for k in ("title", "headline", "summary", "dashboard_title"))
    assert any(k in data for k in ("metrics", "stats", "items", "cards", "summary_blocks"))
    assert any(k in data for k in ("permissions", "scopes", "policies", "filters", "sections", "actions"))


def test_ui_telemetry_access_summary_surface_does_not_return_array_root(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)
    assert not isinstance(data, list)


def test_ui_telemetry_access_summary_title_like_fields_are_strings_when_present(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)

    for key in ("title", "headline", "summary", "dashboard_title"):
        if key in data:
            assert isinstance(data[key], str)
            assert data[key].strip()


def test_ui_telemetry_access_summary_collection_fields_are_lists_when_present(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)

    for key in (
        "metrics",
        "stats",
        "items",
        "cards",
        "summary_blocks",
        "permissions",
        "scopes",
        "policies",
        "filters",
        "sections",
        "actions",
    ):
        if key in data:
            assert isinstance(data[key], list)


def test_ui_telemetry_access_summary_response_is_stable_across_repeated_reads(
    client: TestClient,
) -> None:
    first_response, first_payload = _get_payload(client)
    second_response, second_payload = _get_payload(client)

    assert first_response.status_code == 200
    assert second_response.status_code == 200
    assert first_payload == second_payload
