from __future__ import annotations

from typing import Any, Final

import pytest
from fastapi.testclient import TestClient

from app.main import app


UI_STATUS_PATH: Final[str] = "/ui/status"


@pytest.fixture()
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def _get_payload(client: TestClient) -> tuple[Any, dict[str, Any]]:
    response = client.get(UI_STATUS_PATH)
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/json")
    payload = response.json()
    assert isinstance(payload, dict)
    return response, payload


def test_ui_status_route_is_registered(client: TestClient) -> None:
    response = client.get(UI_STATUS_PATH)
    assert response.status_code == 200, response.text


def test_ui_status_returns_json_object(client: TestClient) -> None:
    response, data = _get_payload(client)

    assert response.status_code == 200
    assert isinstance(data, dict)


def test_ui_status_contains_core_fields(client: TestClient) -> None:
    _, data = _get_payload(client)

    assert data
    assert any(
        key in data
        for key in (
            "title",
            "headline",
            "summary",
            "dashboard_title",
            "hero",
            "status",
        )
    )
    assert any(
        key in data
        for key in (
            "health",
            "health_snapshot",
            "status_cards",
            "cards",
            "items",
            "sections",
            "blocks",
        )
    )
    assert any(
        key in data
        for key in (
            "metrics",
            "metrics_summary",
            "kpis",
            "checks",
            "details",
        )
    )


def test_ui_status_surface_does_not_return_array_root(client: TestClient) -> None:
    _, data = _get_payload(client)
    assert not isinstance(data, list)


def test_ui_status_title_like_fields_are_strings_when_present(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)

    for key in ("title", "headline", "summary", "dashboard_title", "hero", "status"):
        if key in data:
            assert isinstance(data[key], str)
            assert data[key].strip()


def test_ui_status_collection_fields_are_lists_when_present(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)

    for key in ("status_cards", "cards", "items", "sections", "blocks", "kpis", "checks"):
        if key in data:
            assert isinstance(data[key], list)


def test_ui_status_structured_fields_are_json_safe_when_present(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)

    for key in ("health", "health_snapshot", "metrics", "metrics_summary", "details"):
        if key in data:
            assert isinstance(data[key], (dict, list, str))


def test_ui_status_response_is_stable_across_repeated_reads(
    client: TestClient,
) -> None:
    first_response, first_payload = _get_payload(client)
    second_response, second_payload = _get_payload(client)

    assert first_response.status_code == 200
    assert second_response.status_code == 200
    assert first_payload == second_payload