from __future__ import annotations

from typing import Any, Final

import pytest
from fastapi.testclient import TestClient

from app.main import app

UI_HEALTH_SNAPSHOT_PATH: Final[str] = "/ui/health-snapshot"


@pytest.fixture()
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def _get_payload(client: TestClient) -> tuple[Any, dict[str, Any]]:
    response = client.get(UI_HEALTH_SNAPSHOT_PATH)
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/json")
    payload = response.json()
    assert isinstance(payload, dict)
    return response, payload


def test_ui_health_snapshot_route_is_registered(client: TestClient) -> None:
    response = client.get(UI_HEALTH_SNAPSHOT_PATH)
    assert response.status_code == 200, response.text


def test_ui_health_snapshot_returns_json_object(client: TestClient) -> None:
    response, data = _get_payload(client)

    assert response.status_code == 200
    assert isinstance(data, dict)


def test_ui_health_snapshot_contains_core_fields(client: TestClient) -> None:
    _, data = _get_payload(client)

    assert data
    assert any(k in data for k in ("title", "headline", "summary", "status"))
    assert any(
        k in data
        for k in ("checks", "items", "cards", "services", "components")
    )


def test_ui_health_snapshot_surface_does_not_return_array_root(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)
    assert not isinstance(data, list)


def test_ui_health_snapshot_title_like_fields_are_strings_when_present(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)

    for key in ("title", "headline", "summary", "status"):
        if key in data:
            assert isinstance(data[key], str)
            assert data[key].strip()


def test_ui_health_snapshot_collection_fields_are_lists_when_present(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)

    for key in ("checks", "items", "cards", "services", "components"):
        if key in data:
            assert isinstance(data[key], list)


def test_ui_health_snapshot_response_is_stable_across_repeated_reads(
    client: TestClient,
) -> None:
    first_response, first_payload = _get_payload(client)
    second_response, second_payload = _get_payload(client)

    assert first_response.status_code == 200
    assert second_response.status_code == 200
    assert first_payload == second_payload