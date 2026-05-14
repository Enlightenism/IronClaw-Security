from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_policy_guard_bundle_accepts_user_prompt_only():
    response = client.post(
        "/policy/guard-bundle",
        headers={"x-api-key": "test-api-key"},
        json={
            "user_prompt": "Summarize this safe content for the user.",
        },
    )
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, dict)
    assert "highest_verdict" in data
    assert "should_halt" in data
    assert "should_warn" in data


def test_policy_guard_bundle_accepts_multi_source_payload():
    response = client.post(
        "/policy/guard-bundle",
        headers={"x-api-key": "test-api-key"},
        json={
            "user_prompt": "Please review this result.",
            "retrieved_doc": "Reference material content.",
            "tool_output": "Tool returned a harmless response.",
            "model_output": "Draft assistant response.",
        },
    )
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, dict)
    assert "highest_verdict" in data
    assert "user_prompt" in data


def test_policy_guard_bundle_rejects_empty_payload():
    response = client.post(
        "/policy/guard-bundle",
        headers={"x-api-key": "test-api-key"},
        json={},
    )

    assert response.status_code == 400


def test_policy_guard_bundle_allows_access_with_api_key():
    response = client.post(
        "/policy/guard-bundle",
        headers={"x-api-key": "test-api-key"},
        json={
            "user_prompt": "Hello world",
        },
    )

    assert response.status_code == 200
