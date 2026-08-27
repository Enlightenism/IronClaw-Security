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
        ("ironclaw", "openclaw", True),
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


def test_list_platforms_returns_unique_supported_aliases() -> None:
    platforms = list_install_key_platforms()

    assert "openclaw" in platforms
    assert "ironclaw" in platforms
    assert "claude_code" in platforms
    assert "anthropic" in platforms
    assert len(set(platforms)) == len(platforms)


def test_list_format_groups_returns_canonical_registry_entries() -> None:
    groups = list_install_key_format_groups()

    assert len(groups) == 2
    programs = {group.program for group in groups}
    assert programs == {"openclaw", "claude_code"}

    by_program = {group.program: group for group in groups}
    assert by_program["openclaw"].prefix == "ic_install_openclaw_"
    assert by_program["claude_code"].prefix == "ic_install_claude_code_"


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
