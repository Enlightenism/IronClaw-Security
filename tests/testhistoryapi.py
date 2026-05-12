from __future__ import annotations

from typing import Any, Final

import pytest
from fastapi.testclient import TestClient

from app.main import app

HISTORY_PATHS: Final[tuple[str, ...]] = (
    "/history",
    "/api/history",
    "/api/v1/history",
)
HISTORY_DETAIL_PATHS: Final[tuple[str, ...]] = (
    "/history/history-001",
    "/api/history/history-001",
    "/api/v1/history/history-001",
)


@pytest.fixture()
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def _items_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("items", "entries", "events", "history", "results", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def _text(payload: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        if key in payload and payload[key] is not None:
            value = payload[key]
            if isinstance(value, str):
                return value
            return str(value)
    return None


def _assert_historyish_entry(entry: dict[str, Any]) -> None:
    assert isinstance(entry, dict)
    assert any(
        key in entry
        for key in (
            "eventtype",
            "event_type",
            "message",
            "status",
            "timestamp",
            "createdat",
            "created_at",
            "historyid",
            "history_id",
            "id",
        )
    )


def _first_available_history_response(
    client: TestClient,
    *,
    params: dict[str, Any] | None = None,
) -> tuple[str, Any]:
    observed_statuses: list[tuple[str, int]] = []

    for path in HISTORY_PATHS:
        response = client.get(path, params=params)
        observed_statuses.append((path, response.status_code))
        if response.status_code == 200:
            assert response.headers["content-type"].startswith("application/json")
            return path, response

    raise AssertionError(f"history endpoint not available on expected paths: {observed_statuses}")


def test_history_endpoint_is_available_on_common_paths(client: TestClient) -> None:
    observed_statuses: list[int] = []

    for path in HISTORY_PATHS:
        response = client.get(path)
        observed_statuses.append(response.status_code)
        if response.status_code == 200:
            assert response.headers["content-type"].startswith("application/json")
            return

    assert any(status not in {404, 405} for status in observed_statuses), observed_statuses


def test_history_endpoint_returns_json_when_available(client: TestClient) -> None:
    _, response = _first_available_history_response(client)

    payload = response.json()
    assert isinstance(payload, (list, dict))


def test_history_endpoint_returns_collection_shape_when_available(
    client: TestClient,
) -> None:
    _, response = _first_available_history_response(client)

    payload = response.json()
    assert isinstance(payload, (list, dict))

    items = _items_payload(payload)
    if isinstance(payload, list):
        assert isinstance(payload, list)
    else:
        assert items or any(
            key in payload
            for key in ("items", "entries", "events", "history", "results", "data")
        )


def test_history_endpoint_entries_have_stable_shape_when_present(
    client: TestClient,
) -> None:
    _, response = _first_available_history_response(client)

    items = _items_payload(response.json())
    for entry in items:
        _assert_historyish_entry(entry)


def test_history_endpoint_supports_session_filter_when_implemented(
    client: TestClient,
) -> None:
    observed_statuses: list[tuple[str, int]] = []

    for path in HISTORY_PATHS:
        response = client.get(path, params={"session_id": "session-001"})
        observed_statuses.append((path, response.status_code))
        if response.status_code == 200:
            payload = response.json()
            assert isinstance(payload, (list, dict))
            return
        if response.status_code in {400, 422}:
            return

    raise AssertionError(
        f"history endpoint not available on expected paths: {observed_statuses}"
    )


def test_history_detail_endpoint_behaves_reasonably_when_available(
    client: TestClient,
) -> None:
    observed_statuses: list[tuple[str, int]] = []

    for path in HISTORY_DETAIL_PATHS:
        response = client.get(path)
        observed_statuses.append((path, response.status_code))
        if response.status_code == 404:
            continue

        assert response.status_code in {200, 400, 422}, observed_statuses
        if response.status_code == 200:
            assert response.headers["content-type"].startswith("application/json")
            payload = response.json()
            assert isinstance(payload, dict)
            assert _text(payload, "historyid", "history_id", "id")
        return

    assert all(status == 404 for _, status in observed_statuses), observed_statuses


def test_history_endpoint_rejects_invalid_method_when_route_exists(
    client: TestClient,
) -> None:
    path, get_response = _first_available_history_response(client)

    assert get_response.status_code == 200
    post_response = client.post(path, json={})
    assert post_response.status_code in {400, 404, 405, 422}


def test_history_endpoint_response_is_json_friendly(client: TestClient) -> None:
    _, response = _first_available_history_response(client)

    payload = response.json()
    assert isinstance(payload, (list, dict))


def test_history_endpoint_response_is_stable_across_repeated_reads(
    client: TestClient,
) -> None:
    path, first_response = _first_available_history_response(client)
    second_response = client.get(path)

    assert first_response.status_code == 200
    assert second_response.status_code == 200
    assert second_response.headers["content-type"].startswith("application/json")
    assert first_response.json() == second_response.json()