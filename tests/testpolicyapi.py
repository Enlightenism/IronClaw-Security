from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_policy_status_is_reachable() -> None:
    response = client.get(
        "/policy/status",
        headers={"x-api-key": "test-api-key"},
    )
    assert response.status_code == 200


def test_policy_status_returns_dict() -> None:
    response = client.get(
        "/policy/status",
        headers={"x-api-key": "test-api-key"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    data = response.json()
    assert isinstance(data, dict)


def test_policy_status_response_is_non_empty() -> None:
    response = client.get(
        "/policy/status",
        headers={"x-api-key": "test-api-key"},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1


def test_policy_guard_bundle_returns_verdict_field() -> None:
    response = client.post(
        "/policy/guard-bundle",
        headers={"x-api-key": "test-api-key"},
        json={
            "user_prompt": "Summarize this safe text",
            "retrieved_doc": "Reference document content",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, dict)
    assert "highest_verdict" in data


def test_policy_guard_bundle_response_is_json() -> None:
    response = client.post(
        "/policy/guard-bundle",
        headers={"x-api-key": "test-api-key"},
        json={
            "user_prompt": "List safe files",
            "retrieved_doc": "Safe doc",
        },
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")


def test_policy_guard_bundle_empty_body_returns_400() -> None:
    response = client.post(
        "/policy/guard-bundle",
        headers={"x-api-key": "test-api-key"},
        json={},
    )
    assert response.status_code == 400