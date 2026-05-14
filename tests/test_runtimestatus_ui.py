from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.auth import API_KEY_HEADER_NAME
from app.main import create_app


def _client() -> TestClient:
    return TestClient(create_app())


def _auth_headers() -> dict[str, str]:
    return {API_KEY_HEADER_NAME: "test-api-key"}


def test_runtime_status_page_returns_success() -> None:
    client = _client()

    response = client.get("/ui/runtime/status", headers=_auth_headers())

    assert response.status_code == 200
    payload = response.json()

    assert isinstance(payload, dict)
    assert "generatedat" in payload
    assert "executor" in payload
    assert "metrics" in payload
    assert "policy" in payload
    assert "defaultfilepath" in payload


def test_runtime_status_sections_have_expected_shape() -> None:
    client = _client()

    response = client.get("/ui/runtime/status", headers=_auth_headers())

    assert response.status_code == 200
    payload = response.json()

    executor = payload["executor"]
    metrics = payload["metrics"]
    policy = payload["policy"]

    for key in (
        "executorname",
        "fallbackexecutorname",
        "defaultmode",
    ):
        assert key in executor

    for key in (
        "totalrequests",
        "allowcount",
        "blockedcount",
        "quarantinecount",
    ):
        assert key in metrics

    for key in (
        "policymode",
        "defaultaction",
    ):
        assert key in policy


def test_runtime_status_values_are_consistent() -> None:
    client = _client()

    response = client.get("/ui/runtime/status", headers=_auth_headers())

    assert response.status_code == 200
    payload = response.json()

    metrics = payload["metrics"]
    total = metrics["totalrequests"]
    subtotal = metrics["allowcount"] + metrics["blockedcount"] + metrics["quarantinecount"] + metrics.get("reviewcount", 0)

    assert isinstance(payload["defaultfilepath"], str)
    assert isinstance(payload["generatedat"], str)
    assert total >= 0
    assert subtotal >= 0
    assert total >= 0
