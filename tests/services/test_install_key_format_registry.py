from __future__ import annotations

import pytest

from app.services.install_key_format_registry import (
    InstallKeyFormatRegistryService,
    InstallKeyPlatformFormat,
    get_install_key_format_registry_service,
    is_compatible_install_key_platform,
    list_install_key_format_groups,
    list_install_key_platforms,
    normalize_install_key_platform,
    resolve_install_key_format_for_key,
)


@pytest.mark.parametrize(
    ("platform_name", "expected_program", "expected_prefix"),
    [
        ("openclaw", "openclaw", "ic_install_openclaw_"),
        ("ironclaw", "openclaw", "ic_install_openclaw_"),
        ("open-claw", "openclaw", "ic_install_openclaw_"),
        ("claude_code", "claude_code", "ic_install_claude_code_"),
        ("claude-code", "claude_code", "ic_install_claude_code_"),
        ("anthropic", "claude_code", "ic_install_claude_code_"),
        ("cursor", "cursor", "ic_install_cursor_"),
        ("cursor-agent", "cursor", "ic_install_cursor_"),
        ("goose", "goose", "ic_install_goose_"),
        ("gemini-cli", "gemini_cli", "ic_install_gemini_cli_"),
        ("github-copilot", "copilot", "ic_install_copilot_"),
        ("security-guardian", "security_guardian", "ic_install_security_guardian_"),
    ],
)
def test_resolve_for_platform_matches_canonical_format_family(platform_name: str, expected_program: str, expected_prefix: str) -> None:
    resolved = InstallKeyFormatRegistryService.resolve_for_platform(platform_name)

    assert isinstance(resolved, InstallKeyPlatformFormat)
    assert resolved.program == expected_program
    assert resolved.family == expected_program
    assert resolved.prefix == expected_prefix
    assert resolved.platform == normalize_install_key_platform(platform_name)


@pytest.mark.parametrize(
    ("candidate", "expected_program"),
    [
        ("ic_install_openclaw_abc123", "openclaw"),
        ("ic_install_claude_code_abc123", "claude_code"),
        ("ic_install_cursor_abc123", "cursor"),
        ("ic_install_goose_abc123", "goose"),
        ("ic_install_gemini_cli_abc123", "gemini_cli"),
        ("ic_install_copilot_abc123", "copilot"),
        ("ic_install_security_guardian_abc123", "security_guardian"),
    ],
)
def test_resolve_for_key_uses_canonical_format_from_install_key(candidate: str, expected_program: str) -> None:
    resolved = resolve_install_key_format_for_key(candidate)

    assert resolved.program == expected_program
    assert resolved.matches_key(candidate)


def test_resolve_for_key_rejects_non_install_key_value() -> None:
    with pytest.raises(ValueError, match="Unsupported install-key format"):
        resolve_install_key_format_for_key("sk_live_123456")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("openclaw", "openclaw"),
        ("open-claw", "open_claw"),
        ("claude-code", "claude_code"),
        ("Anthropic", "anthropic"),
        (None, ""),
    ],
)
def test_normalize_platform_returns_canonical_lowercase_slug(value: str | None, expected: str) -> None:
    assert normalize_install_key_platform(value) == expected


@pytest.mark.parametrize(
    ("platform_name", "program", "expected"),
    [
        ("openclaw", "openclaw", True),
        ("claude-code", "claude_code", True),
        ("anthropic", "claude_code", True),
        ("generic", "openclaw", False),
        ("groq", "claude_code", False),
    ],
)
def test_is_compatible_install_key_platform_checks_platform_to_program_mapping(platform_name: str, program: str, expected: bool) -> None:
    assert is_compatible_install_key_platform(platform_name, program) is expected


@pytest.mark.parametrize(
    ("program", "secret", "expected_prefix"),
    [
        ("openclaw", "abc123", "ic_install_openclaw_"),
        ("claude_code", "secret456", "ic_install_claude_code_"),
    ],
)
def test_format_key_for_program_builds_canonical_value(program: str, secret: str, expected_prefix: str) -> None:
    formatted = InstallKeyFormatRegistryService.format_key_for_program(program, secret)

    assert formatted.startswith(expected_prefix)
    assert formatted == f"{expected_prefix}{secret}"


def test_format_key_for_program_rejects_blank_secret() -> None:
    with pytest.raises(ValueError, match="secret is required"):
        InstallKeyFormatRegistryService.format_key_for_program("openclaw", "")


def test_list_programs_cover_the_full_canonical_runtime_set() -> None:
    assert InstallKeyFormatRegistryService.list_programs() == (
        "openclaw",
        "claude_code",
        "cursor",
        "goose",
        "gemini_cli",
        "copilot",
        "security_guardian",
    )


def test_list_platforms_returns_unique_supported_aliases() -> None:
    platforms = list_install_key_platforms()

    assert "openclaw" in platforms
    assert "ironclaw" in platforms
    assert "claude_code" in platforms
    assert "anthropic" in platforms
    assert "cursor" in platforms
    assert "goose" in platforms
    assert "gemini_cli" in platforms
    assert "gemini" in platforms
    assert "copilot" in platforms
    assert "githubcopilot" in platforms
    assert "security_guardian" in platforms
    assert "skill" in platforms
    assert len(set(platforms)) == len(platforms)


def test_list_platforms_accepts_canonical_ironclaw_alias_and_rejects_legacy_labels() -> None:
    platforms = list_install_key_platforms()

    assert "openclaw" in platforms
    assert "ironclaw" in platforms
    assert "standalone_ironclaw" not in platforms
    assert "standalone ironclaw" not in platforms
    assert "Standalone IronClaw" not in platforms


def test_list_platforms_for_program_uses_full_runtime_grouping() -> None:
    security_group = InstallKeyFormatRegistryService.list_platforms_for_program("security_guardian")
    openclaw_group = InstallKeyFormatRegistryService.list_platforms_for_program("openclaw")

    assert "security_guardian" in security_group
    assert "securityguardian" in security_group
    assert "security_guardian_skill" in security_group
    assert "skill" in security_group
    assert "skills" in security_group
    assert "ironclaw" in openclaw_group
    assert len(set(security_group)) == len(security_group)


def test_list_format_groups_returns_canonical_registry_entries() -> None:
    groups = list_install_key_format_groups()

    assert len(groups) == 7
    programs = {group.program for group in groups}
    assert programs == {"openclaw", "claude_code", "cursor", "goose", "gemini_cli", "copilot", "security_guardian"}

    by_program = {group.program: group for group in groups}
    assert by_program["openclaw"].prefix == "ic_install_openclaw_"
    assert by_program["claude_code"].prefix == "ic_install_claude_code_"
    assert by_program["cursor"].prefix == "ic_install_cursor_"
    assert by_program["goose"].prefix == "ic_install_goose_"
    assert by_program["gemini_cli"].prefix == "ic_install_gemini_cli_"
    assert by_program["copilot"].prefix == "ic_install_copilot_"
    assert by_program["security_guardian"].prefix == "ic_install_security_guardian_"
    assert by_program["security_guardian"].platform == "security_guardian"


def test_service_factory_returns_singleton_registry() -> None:
    first = get_install_key_format_registry_service()
    second = get_install_key_format_registry_service()

    assert first is second
    assert first.list_programs() == second.list_programs()


@pytest.mark.parametrize(
    "bad_platform",
    [
        "",
        "generic",
        "groq",
        "not_a_platform",
    ],
)
def test_resolve_for_platform_raises_for_unsupported_platform(bad_platform: str) -> None:
    with pytest.raises(ValueError, match="Unsupported platform"):
        InstallKeyFormatRegistryService.resolve_for_platform(bad_platform)
