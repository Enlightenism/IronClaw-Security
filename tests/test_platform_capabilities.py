from __future__ import annotations

from app.services.platform_capabilities import (
    get_platform_profile,
    list_platform_profiles,
    summarize_platform_profile,
)


def test_list_platform_profiles_returns_expected_platforms():
    profiles = list_platform_profiles()

    assert len(profiles) >= 3
    assert any(profile.platform == "claude-code" for profile in profiles)
    assert any(profile.platform == "openclaw" for profile in profiles)
    assert any(profile.platform == "generic-agent" for profile in profiles)


def test_get_platform_profile_returns_known_profile():
    profile = get_platform_profile("claude-code")

    assert profile is not None
    assert profile.platform == "claude-code"
    assert profile.display_name == "Claude Code"
    assert any(capability.name == "prompt_interception" for capability in profile.capabilities)


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