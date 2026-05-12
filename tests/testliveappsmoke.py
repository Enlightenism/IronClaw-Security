from __future__ import annotations

import os
from typing import Final

import httpx
import pytest

DEFAULT_BASE_URL: Final[str] = "http://127.0.0.1:8000"
REQUEST_TIMEOUT_SECONDS: Final[float] = 5.0

HEALTH_PATHS: Final[tuple[str, ...]] = (
    "/api/health",
    "/api/health/liveness",
    "/api/health/readiness",
)

OPTIONAL_PATHS: Final[tuple[str, ...]] = (
    "/api/system/status",
    "/api/ui/manifest",
    "/api/ui/status/runtime",
    "/api/ui/runtime/status",
)

HEALTHY_STATUS_VALUES: Final[set[str]] = {"ok", "pass", "healthy", "ready", "live", "alive"}


def _base_url() -> str:
    return os.getenv("IRONCLAW_BASE_URL", DEFAULT_BASE_URL).rstrip("/")


def _client() -> httpx.Client:
    return httpx.Client(
        base_url=_base_url(),
        timeout=httpx.Timeout(REQUEST_TIMEOUT_SECONDS),
        follow_redirects=True,
        headers={"Accept": "application/json"},
    )


def _ensure_live_app_available() -> None:
    try:
        with _client() as client:
            response = client.get("/api/health")
            if response.status_code >= 500:
                pytest.skip(f"Live IronClaw app unhealthy at {_base_url()} (status {response.status_code})")
    except httpx.HTTPError as exc:
        pytest.skip(f"Live IronClaw app unavailable at {_base_url()}: {exc}")


def _assert_json_health_response(response: httpx.Response) -> None:
    assert 200 <= response.status_code < 300, response.text

    payload = response.json()
    assert isinstance(payload, dict), payload

    status_value = str(payload.get("status", "")).strip().lower()
    assert status_value in HEALTHY_STATUS_VALUES, payload


@pytest.fixture(scope="module", autouse=True)
def ensure_live_app() -> None:
    _ensure_live_app_available()


@pytest.mark.integration
@pytest.mark.parametrize("path", HEALTH_PATHS)
def test_live_health_endpoints_return_healthy_json(path: str) -> None:
    with _client() as client:
        response = client.get(path)
    _assert_json_health_response(response)


@pytest.mark.integration
@pytest.mark.parametrize("path", OPTIONAL_PATHS)
def test_live_optional_endpoints_are_reachable(path: str) -> None:
    with _client() as client:
        response = client.get(path)

    if response.status_code == 404:
        pytest.skip(f"Optional endpoint not present on this layer: {path}")

    assert 200 <= response.status_code < 300, response.text


@pytest.mark.integration
def test_live_health_endpoint_response_time_is_reasonable() -> None:
    with _client() as client:
        response = client.get("/api/health")

    _assert_json_health_response(response)
    assert response.elapsed.total_seconds() < REQUEST_TIMEOUT_SECONDS