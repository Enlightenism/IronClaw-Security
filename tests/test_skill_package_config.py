from __future__ import annotations

import json
from pathlib import Path

from ironclawskill.config import IronClawSkillConfig, load_config, loadconfig


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def test_loadconfig_uses_package_local_json_when_present(tmp_path: Path) -> None:
    config_path = tmp_path / "ironclawskill.json"
    _write_json(
        config_path,
        {
            "app_name": "ironclawskill-test",
            "environment": "test",
            "default_provider": "claude",
            "fail_closed": True,
            "telemetry_enabled": False,
            "providers": {
                "claude": {
                    "enabled": True,
                    "configured": True,
                    "model": "claude-3-5-sonnet",
                    "endpoint": "https://example.com/claude",
                    "timeout_seconds": 17,
                    "connect_timeout_seconds": 5,
                    "max_retries": 4,
                },
                "openclaw": {
                    "enabled": False,
                    "configured": False,
                    "model": "openclaw-local",
                    "endpoint": "http://localhost:11434",
                    "timeout_seconds": 11,
                    "connect_timeout_seconds": 3,
                    "max_retries": 1,
                },
            },
            "security": {
                "enable_sandbox": True,
                "allow_network": False,
                "allow_filesystem_write": False,
                "allow_tool_invocation": False,
            },
        },
    )

    config = loadconfig(config_path=str(config_path))

    assert isinstance(config, IronClawSkillConfig)
    assert config.app_name == "ironclawskill-test"
    assert config.environment == "test"
    assert config.default_provider == "claude"
    assert config.fail_closed is True
    assert config.telemetry_enabled is False
    assert "claude" in config.providers
    assert config.providers["claude"].enabled is True
    assert config.providers["claude"].configured is True
    assert config.providers["claude"].timeout_seconds == 17
    assert "openclaw" in config.providers
    assert config.providers["openclaw"].enabled is False


def test_load_config_and_loadconfig_return_equivalent_configs(tmp_path: Path) -> None:
    config_path = tmp_path / "ironclawskill.json"
    _write_json(
        config_path,
        {
            "app_name": "ironclawskill-alias-test",
            "environment": "ci",
            "default_provider": "openclaw",
            "providers": {
                "openclaw": {
                    "enabled": True,
                    "configured": True,
                    "model": "openclaw-guard",
                    "endpoint": "http://localhost:8080",
                },
                "claude": {
                    "enabled": False,
                    "configured": False,
                },
            },
        },
    )

    snake_case = load_config(config_path=str(config_path))
    compact = loadconfig(config_path=str(config_path))

    assert isinstance(snake_case, IronClawSkillConfig)
    assert isinstance(compact, IronClawSkillConfig)
    assert snake_case.model_dump() == compact.model_dump()


def test_loadconfig_returns_safe_defaults_without_file() -> None:
    config = loadconfig(config_path="Z:/this/path/should/not/exist/ironclawskill.json")

    assert isinstance(config, IronClawSkillConfig)
    assert isinstance(config.app_name, str)
    assert config.app_name
    assert isinstance(config.environment, str)
    assert config.environment
    assert isinstance(config.default_provider, str)
    assert config.default_provider in {"openclaw", "claude"}
    assert isinstance(config.providers, dict)
    assert "openclaw" in config.providers
    assert "claude" in config.providers


def test_default_provider_is_present_in_provider_registry_when_defaults_are_loaded() -> None:
    config = loadconfig(config_path="Z:/this/path/should/not/exist/ironclawskill.json")

    assert config.default_provider in config.providers
    assert isinstance(config.providers[config.default_provider].enabled, bool)
    assert isinstance(config.providers[config.default_provider].configured, bool)


def test_skill_config_coerces_canonical_runtime_family_targets() -> None:
    from app.core.install_key_formats import InstallKeyFormatRegistry
    from ironclaw_skill.config import DEFAULT_PROVIDER_TARGETS, _coerce_provider_targets

    expected_targets = InstallKeyFormatRegistry.list_programs()

    assert DEFAULT_PROVIDER_TARGETS == expected_targets
    assert list(DEFAULT_PROVIDER_TARGETS) == [
        "openclaw",
        "claude_code",
        "cursor",
        "goose",
        "gemini_cli",
        "copilot",
        "hermes",
    ]
    assert "security_guardian" not in DEFAULT_PROVIDER_TARGETS
    assert _coerce_provider_targets("claude,openclaw") == ("claude_code", "openclaw")
    assert _coerce_provider_targets(["gemini-cli", "github-copilot", "security-guardian"]) == (
        "gemini_cli",
        "copilot",
        "security_guardian",
    )
    assert _coerce_provider_targets(("security-guardian", "claude", "github-copilot", "claude")) == (
        "security_guardian",
        "claude_code",
        "copilot",
    )
    assert _coerce_provider_targets(["skills", "claude code", "OpenClaw"]) == (
        "security_guardian",
        "claude_code",
        "openclaw",
    )
    assert _coerce_provider_targets(None) == expected_targets

    try:
        _coerce_provider_targets(["not-a-provider"])
    except Exception as exc:  # pragma: no cover - assertion only for validation behavior
        assert "Unsupported provider target" in str(exc)
    else:
        raise AssertionError("Expected unsupported provider target to raise")


def test_enabledproviders_matches_enabled_provider_configs() -> None:
    config = loadconfig(config_path="Z:/this/path/should/not/exist/ironclawskill.json")

    expected = sorted(name for name, provider in config.providers.items() if provider.enabled)
    actual = sorted(config.enabledproviders)

    assert actual == expected
