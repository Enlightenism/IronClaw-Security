from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_policy_status_returns_current_policy_state():
    response = client.get(
        "/policy/status",
        headers={"x-api-key": "test-api-key"},
    )
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, dict)
    assert len(data) >= 1


def test_policy_guard_bundle_accepts_valid_payload():
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


def test_policy_guard_bundle_rejects_empty_payload_via_policy_api():
    response = client.post(
        "/policy/guard-bundle",
        headers={"x-api-key": "test-api-key"},
        json={},
    )

    assert response.status_code == 400


def test_policy_endpoint_allows_access_with_api_key():
    response = client.get(
        "/policy/status",
        headers={"x-api-key": "test-api-key"},
    )

    assert response.status_code == 200
