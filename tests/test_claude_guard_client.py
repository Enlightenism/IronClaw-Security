from __future__ import annotations

import os

import httpx
import pytest

from app.clients.claude_guard_client import (
    ClaudeGuardClient,
    ClaudeGuardClientConfig,
)


def test_config_from_env_reads_required_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IRONCLAW_GUARD_BASE_URL", "https://ironclaw.local/")
    monkeypatch.setenv("IRONCLAW_GUARD_API_KEY", "secret-key")
    monkeypatch.setenv("IRONCLAW_GUARD_MODE", "assist")
    monkeypatch.setenv("IRONCLAW_GUARD_TIMEOUT_MS", "9000")
    monkeypatch.setenv("IRONCLAW_GUARD_MAX_PAYLOAD_KB", "512")

    config = ClaudeGuardClientConfig.from_env()

    assert config.guard_base_url == "https://ironclaw.local"
    assert config.api_key == "secret-key"
    assert config.guard_mode == "assist"
    assert config.default_timeout_ms == 9000
    assert config.max_payload_kb == 512
    assert config.use_bundle_guard is True
    assert config.use_guard_execute is True


def test_config_from_env_requires_base_url_and_api_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("IRONCLAW_GUARD_BASE_URL", raising=False)
    monkeypatch.delenv("IRONCLAW_GUARD_API_KEY", raising=False)

    with pytest.raises(RuntimeError):
        ClaudeGuardClientConfig.from_env()


def test_config_from_env_clamps_invalid_numeric_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IRONCLAW_GUARD_BASE_URL", "https://ironclaw.local")
    monkeypatch.setenv("IRONCLAW_GUARD_API_KEY", "secret-key")
    monkeypatch.setenv("IRONCLAW_GUARD_TIMEOUT_MS", "999999")
    monkeypatch.setenv("IRONCLAW_GUARD_MAX_PAYLOAD_KB", "-1")
    monkeypatch.setenv("IRONCLAW_GUARD_MODE", "not-a-real-mode")

    config = ClaudeGuardClientConfig.from_env()

    assert config.default_timeout_ms == 30000
    assert config.max_payload_kb == 16
    assert config.guard_mode == "enforce"


def test_guard_execute_posts_to_guard_endpoint() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["json"] = request.content.decode("utf-8")
        return httpx.Response(
            200,
            json={
                "policy_verdict": "allow",
                "should_execute": True,
                "halted_by_boundary": False,
            },
        )

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)

    guard_client = ClaudeGuardClient(
        ClaudeGuardClientConfig(
            guard_base_url="https://ironclaw.local",
            api_key="secret-key",
        ),
        client=client,
    )

    payload = {
        "action_type": "toolcall",
        "target": "shell",
        "content": {"command": "dir"},
    }

    response = guard_client.guard_execute(payload)

    assert response["policy_verdict"] == "allow"
    assert response["should_execute"] is True
    assert captured["url"] == "https://ironclaw.local/guard/execute"
    assert "secret-key" in str(captured["headers"])


def test_guard_bundle_posts_to_policy_guard_endpoint() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["json"] = request.content.decode("utf-8")
        return httpx.Response(
            200,
            json={
                "bundle_verdict": "allow",
                "reason": "",
            },
        )

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)

    guard_client = ClaudeGuardClient(
        ClaudeGuardClientConfig(
            guard_base_url="https://ironclaw.local",
            api_key="secret-key",
            max_payload_kb=256,
        ),
        client=client,
    )

    bundle = {
        "userprompt": "Build a safe script",
        "retrieveddoc": "Internal docs",
        "tooloutput": [{"name": "search", "result": "ok"}],
        "modeloutput": "Here is the result.",
    }

    response = guard_client.guard_bundle(bundle)

    assert response["bundle_verdict"] == "allow"
    assert captured["url"] == "https://ironclaw.local/policy/guard-bundle"
    assert "secret-key" in str(captured["headers"])


def test_guard_bundle_blocks_when_payload_is_too_large() -> None:
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={})))

    guard_client = ClaudeGuardClient(
        ClaudeGuardClientConfig(
            guard_base_url="https://ironclaw.local",
            api_key="secret-key",
            max_payload_kb=1,
        ),
        client=client,
    )

    bundle = {
        "modeloutput": "x" * 4096,
    }

    response = guard_client.guard_bundle(bundle)

    assert response["status"] == "blocked"
    assert "Bundle too large" in response["reason"]


def test_guard_execute_can_be_disabled() -> None:
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={})))

    guard_client = ClaudeGuardClient(
        ClaudeGuardClientConfig(
            guard_base_url="https://ironclaw.local",
            api_key="secret-key",
            use_guard_execute=False,
        ),
        client=client,
    )

    response = guard_client.guard_execute({"action_type": "toolcall"})

    assert response["status"] == "bypassed"


def test_guard_bundle_can_be_disabled() -> None:
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={})))

    guard_client = ClaudeGuardClient(
        ClaudeGuardClientConfig(
            guard_base_url="https://ironclaw.local",
            api_key="secret-key",
            use_bundle_guard=False,
        ),
        client=client,
    )

    response = guard_client.guard_bundle({"modeloutput": "safe"})

    assert response["status"] == "bypassed"