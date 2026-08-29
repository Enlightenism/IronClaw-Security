from __future__ import annotations

from app.services.integration_registry import initialize_integration_registry
from app.services.platform_capabilities import (
    get_platform_profile,
    list_platform_profiles,
    summarize_platform_profile,
)
from app.ui.integrations.capabilities import build_integration_capabilities_view


def test_list_platform_profiles_returns_expected_platforms():
    profiles = list_platform_profiles()
    profile_names = {profile.platform for profile in profiles}

    expected_platforms = {
        "claude-code",
        "openclaw",
        "cursor",
        "goose",
        "gemini-cli",
        "copilot",
        "security-guardian",
        "generic-agent",
    }

    assert len(profiles) >= len(expected_platforms)
    assert profile_names >= expected_platforms

    expected_capabilities = {
        "prompt_interception",
        "tool_interception",
        "execution_interception",
        "shell_guard",
        "file_guard",
        "network_guard",
        "review_queue",
        "telemetry",
        "policy_sync",
        "audit_export",
    }
    assert all({capability.name for capability in profile.capabilities} >= expected_capabilities for profile in profiles)


def test_get_platform_profile_returns_known_profile():
    profile = get_platform_profile("claude-code")

    assert profile is not None
    assert profile.platform == "claude-code"
    assert profile.display_name == "Claude Code"
    assert any(capability.name == "prompt_interception" for capability in profile.capabilities)
    assert any(capability.name == "shell_guard" for capability in profile.capabilities)


def test_get_platform_profile_returns_none_for_unknown_platform():
    profile = get_platform_profile("missing-platform")

    assert profile is None


def test_summarize_platform_profile_returns_expected_shape():
    profile = get_platform_profile("openclaw")
    assert profile is not None

    summary = summarize_platform_profile(profile)

    assert summary["platform"] == "openclaw"
    assert summary["display_name"] == "OpenClaw"
    assert summary["capability_count"] >= 1
    assert summary["native_capabilities"] >= 1
    assert "checked_at" in summary


def test_build_integration_capabilities_view_maps_platform_capability_matrix():
    registry = initialize_integration_registry()
    view = build_integration_capabilities_view(registry=registry)
    payload = view.to_dict()

    assert view.total >= 1
    assert view.total_capabilities >= 1
    assert any(item["capability_matrix"] for item in payload["items"])
    assert any("prompt_interception" in {cap["name"] for cap in item["capability_matrix"]} for item in payload["items"])
    assert all(item["capability_count"] == len(item["capability_matrix"]) for item in payload["items"])
