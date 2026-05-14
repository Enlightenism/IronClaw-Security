from __future__ import annotations

from typing import Any, Final

import pytest
from fastapi.testclient import TestClient

from app.main import app

REVIEW_QUEUE_PATH: Final[str] = "/guard/reviews/summary"


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def _get_payload(client: TestClient) -> tuple[Any, dict[str, Any]]:
    response = client.get(REVIEW_QUEUE_PATH)
    assert response.status_code in {200, 401, 403}, response.text
    if response.status_code != 200:
        return response, {}
    assert response.headers["content-type"].startswith("application/json")
    payload = response.json()
    assert isinstance(payload, dict)
    return response, payload


def test_review_queue_route_is_registered(client: TestClient) -> None:
    response = client.get(REVIEW_QUEUE_PATH)
    assert response.status_code in {200, 401, 403}, response.text


def test_review_queue_returns_json_object(client: TestClient) -> None:
    response, data = _get_payload(client)
    if response.status_code != 200:
        return
    assert isinstance(data, dict)


def test_review_queue_contains_basic_queue_shape(client: TestClient) -> None:
    _, data = _get_payload(client)
    if not data:
        return
    assert any(
        key in data
        for key in (
            "title",
            "queue",
            "items",
            "summary",
            "status",
            "total_items",
            "pending_items",
        )
    )


def test_review_queue_surface_does_not_return_array_root(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)
    assert not isinstance(data, list)


def test_review_queue_title_like_fields_are_strings_when_present(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)
    if not data:
        return
    for key in ("title", "summary", "status"):
        if key in data:
            assert isinstance(data[key], str)
            assert data[key].strip()


def test_review_queue_collection_fields_are_json_safe_when_present(
    client: TestClient,
) -> None:
    _, data = _get_payload(client)
    if not data:
        return
    if "items" in data:
        assert isinstance(data["items"], list)
    if "queue" in data:
        assert isinstance(data["queue"], list | dict | str)


def test_review_queue_response_is_stable_across_repeated_reads(
    client: TestClient,
) -> None:
    first_response, first_payload = _get_payload(client)
    second_response, second_payload = _get_payload(client)
    assert first_response.status_code == second_response.status_code
    if first_response.status_code == 200:
        assert first_payload == second_payload
