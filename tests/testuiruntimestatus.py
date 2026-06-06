from __future__ import annotations

from collections.abc import Generator
from typing import Any, Final

from fastapi.testclient import TestClient
import pytest

from app.main import app

RUNTIME_STATUS_PATH: Final[str] = "/runtime/status"


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    with TestClient(app) as test_client:
        yield test_client


def _get_payload(client: TestClient) -> tuple[Any, dict[str, Any]]:
    response = client.get(RUNTIME_STATUS_PATH)
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/json")
    payload = response.json()
    assert isinstance(payload, dict)
    return response, payload


def test_runtime_status_route_is_registered(client: TestClient) -> None:
    response = client.get(RUNTIME_STATUS_PATH)
    assert response.status_code == 200, response.text


def test_runtime_status_returns_json_object(client: TestClient) -> None:
    response, data = _get_payload(client)
    assert response.status_code == 200
    assert isinstance(data, dict)


def test_runtime_status_contains_basic_runtime_shape(client: TestClient) -> None:
    _, data = _get_payload(client)
    assert data
    assert any(
        key in data
        for key in (
            "title",
            "status",
            "runtime",
            "summary",
            "items",
        )
    )


def test_runtime_status_surface_does_not_return_array_root(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)
    assert not isinstance(data, list)


def test_runtime_status_nested_collections_are_json_safe_when_present(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)
    if "items" in data:
        assert isinstance(data["items"], list)


def test_runtime_status_status_field_is_string_when_present(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)
    if "status" in data:
        assert isinstance(data["status"], str)
        assert data["status"].strip()


def test_runtime_status_title_field_is_string_when_present(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)
    if "title" in data:
        assert isinstance(data["title"], str)
        assert data["title"].strip()


def test_runtime_status_summary_field_is_json_safe_when_present(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)
    if "summary" in data:
        assert isinstance(data["summary"], str | dict | list)


def test_runtime_status_runtime_field_is_json_safe_when_present(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)
    if "runtime" in data:
        assert isinstance(data["runtime"], dict | list | str)


def test_runtime_status_response_is_stable_across_repeated_reads(
    client: TestClient,
) -> None:
    first_response, first_payload = _get_payload(client)
    second_response, second_payload = _get_payload(client)
    assert first_response.status_code == 200
    assert second_response.status_code == 200
    assert first_payload == second_payload
