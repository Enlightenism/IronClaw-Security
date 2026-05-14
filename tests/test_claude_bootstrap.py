from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.claude_bootstrap import router as claude_bootstrap_router


def _build_test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(claude_bootstrap_router)
    return app


def _headers() -> dict[str, str]:
    return {"X-API-Key": "test-key"}


def test_claude_bootstrap_returns_expected_shape() -> None:
    app = _build_test_app()
    client = TestClient(app)

    response = client.post(
        "/claude/bootstrap",
        headers=_headers(),
        json={
            "platform": "claude-code",
            "display_name": "Jesse Workspace",
            "base_guard_url": "https://ironclaw.local",
            "guard_mode": "enforce",
            "default_timeout_ms": 8000,
            "max_payload_kb": 256,
        },
    )

    assert response.status_code == 200
    payload = response.json()

    assert payload["platform"] == "claude-code"
    assert payload["workspace_name"] == "Jesse Workspace"
    assert "generated_at" in payload
    assert "client_config" in payload
    assert "one_command_snippet" in payload
    assert isinstance(payload["notes"], list)

    config = payload["client_config"]
    assert config["guard_base_url"] == "https://ironclaw.local"
    assert config["api_key"] == "test-key"
    assert config["guard_mode"] == "enforce"
    assert config["default_timeout_ms"] == 8000
    assert config["max_payload_kb"] == 256
    assert config["use_bundle_guard"] is True
    assert config["use_guard_execute"] is True


def test_claude_bootstrap_infers_base_url_from_request_when_missing() -> None:
    app = _build_test_app()
    client = TestClient(app)

    response = client.post(
        "/claude/bootstrap",
        headers={
            **_headers(),
            "Host": "example.test",
            "X-Forwarded-Proto": "https",
        },
        json={
            "platform": "claude-code",
            "display_name": "Forwarded Workspace",
            "guard_mode": "assist",
            "default_timeout_ms": 9000,
            "max_payload_kb": 512,
        },
    )

    assert response.status_code == 200
    payload = response.json()

    assert payload["client_config"]["guard_base_url"] == "https://example.test"
    assert payload["client_config"]["guard_mode"] == "assist"
    assert payload["client_config"]["default_timeout_ms"] == 9000
    assert payload["client_config"]["max_payload_kb"] == 512


def test_claude_bootstrap_snippet_contains_expected_exports() -> None:
    app = _build_test_app()
    client = TestClient(app)

    response = client.post(
        "/claude/bootstrap",
        headers=_headers(),
        json={
            "platform": "claude-code",
            "display_name": "Snippet Workspace",
            "base_guard_url": "https://ironclaw.local",
            "guard_mode": "dryrun",
            "default_timeout_ms": 7000,
            "max_payload_kb": 128,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    snippet = payload["one_command_snippet"]

    assert 'export IRONCLAW_GUARD_BASE_URL="https://ironclaw.local"' in snippet
    assert 'export IRONCLAW_GUARD_API_KEY="test-key"' in snippet
    assert 'export IRONCLAW_GUARD_MODE="dryrun"' in snippet
    assert 'export IRONCLAW_GUARD_TIMEOUT_MS="7000"' in snippet
    assert 'export IRONCLAW_GUARD_MAX_PAYLOAD_KB="128"' in snippet
    assert 'export IRONCLAW_WORKSPACE_NAME="Snippet Workspace"' in snippet


def test_claude_bootstrap_requires_display_name() -> None:
    app = _build_test_app()
    client = TestClient(app)

    response = client.post(
        "/claude/bootstrap",
        headers=_headers(),
        json={
            "platform": "claude-code",
            "display_name": "",
            "base_guard_url": "https://ironclaw.local",
        },
    )

    assert response.status_code == 422


def test_claude_bootstrap_validates_numeric_ranges() -> None:
    app = _build_test_app()
    client = TestClient(app)

    response = client.post(
        "/claude/bootstrap",
        headers=_headers(),
        json={
            "platform": "claude-code",
            "display_name": "Invalid Workspace",
            "base_guard_url": "https://ironclaw.local",
            "default_timeout_ms": 999,
            "max_payload_kb": 8,
        },
    )

    assert response.status_code == 422
