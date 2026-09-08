from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.services.install_key_provisioning import InstallKeyIssued
from app.services.platform_install_key_router import (
    PlatformInstallKeyGroup,
    PlatformInstallKeyRoute,
    PlatformInstallKeyRouter,
    get_platform_install_key_router,
    list_platform_install_key_groups,
    list_platform_install_key_platforms,
    resolve_platform_install_key_group,
    resolve_platform_install_key_route,
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
        ("goose-agent", "goose", "ic_install_goose_"),
        ("gemini-cli", "gemini_cli", "ic_install_gemini_cli_"),
        ("gemini_cli", "gemini_cli", "ic_install_gemini_cli_"),
        ("github-copilot", "copilot", "ic_install_copilot_"),
        ("githubcopilot", "copilot", "ic_install_copilot_"),
        ("hermes", "hermes", "ic_install_hermes_"),
        ("hermes-agent", "hermes", "ic_install_hermes_"),
        ("hermes-cli", "hermes", "ic_install_hermes_"),
    ],
)
def test_resolve_platform_routes_aliases_to_canonical_install_key_program(platform_name: str, expected_program: str, expected_prefix: str) -> None:
    route = PlatformInstallKeyRouter().resolve_platform(platform_name)

    assert isinstance(route, PlatformInstallKeyRoute)
    assert route.program == expected_program
    assert route.family == expected_program
    assert route.prefix == expected_prefix
    assert route.requested_platform == platform_name.strip().lower().replace("-", "_")
    assert route.canonical_platform in route.group_platforms


@pytest.mark.parametrize(
    ("platform_name", "candidate", "expected"),
    [
        ("openclaw", "ic_install_openclaw_secret_123", True),
        ("ironclaw", "ic_install_openclaw_secret_123", True),
        ("claude-code", "ic_install_claude_code_secret_123", True),
        ("anthropic", "ic_install_claude_code_secret_123", True),
        ("cursor", "ic_install_cursor_secret_123", True),
        ("goose-agent", "ic_install_goose_secret_123", True),
        ("gemini_cli", "ic_install_gemini_cli_secret_123", True),
        ("github-copilot", "ic_install_copilot_secret_123", True),
        ("hermes-agent", "ic_install_hermes_secret_123", True),
        ("security-guardian", "ic_install_security_guardian_secret_123", False),
        ("openclaw", "ic_install_claude_code_secret_123", False),
        ("claude_code", "ic_install_openclaw_secret_123", False),
        ("hermes", "ic_install_copilot_secret_123", False),
    ],
)
def test_is_valid_platform_key_matches_canonical_prefix_for_the_platform_family(platform_name: str, candidate: str, expected: bool) -> None:
    router = PlatformInstallKeyRouter()

    assert router.is_valid_platform_key(platform_name, candidate) is expected


def test_resolve_group_groups_compatible_platforms_together() -> None:
    group = PlatformInstallKeyRouter().resolve_group("ironclaw")

    assert isinstance(group, PlatformInstallKeyGroup)
    assert group.program == "openclaw"
    assert group.family == "openclaw"
    assert group.prefix == "ic_install_openclaw_"
    assert "openclaw" in group.platforms
    assert "ironclaw" in group.platforms


def test_list_groups_returns_shared_format_sections() -> None:
    groups = list_platform_install_key_groups()

    assert len(groups) == 7
    programs = {group.program for group in groups}
    assert programs == {"openclaw", "claude_code", "cursor", "goose", "gemini_cli", "copilot", "hermes"}
    assert all(group.platforms for group in groups)
    assert all(group.program != "security_guardian" for group in groups)
    assert any(group.program == "hermes" and "hermes" in group.platforms for group in groups)


def test_list_platforms_returns_aliases_and_canonical_names() -> None:
    platforms = list_platform_install_key_platforms()
    expected_alias_mapping = {
        "openclaw": "openclaw",
        "ironclaw": "openclaw",
        "claude_code": "claude_code",
        "claude-code": "claude_code",
        "anthropic": "claude_code",
        "cursor": "cursor",
        "cursor_agent": "cursor",
        "cursor-agent": "cursor",
        "goose": "goose",
        "goose_agent": "goose",
        "goose-agent": "goose",
        "gemini_cli": "gemini_cli",
        "gemini-cli": "gemini_cli",
        "gemini": "gemini_cli",
        "copilot": "copilot",
        "github_copilot": "copilot",
        "github-copilot": "copilot",
        "githubcopilot": "copilot",
        "hermes": "hermes",
        "hermes_agent": "hermes",
        "hermes-agent": "hermes",
        "hermes_cli": "hermes",
        "hermes-cli": "hermes",
    }

    for alias, expected_program in expected_alias_mapping.items():
        route = PlatformInstallKeyRouter().resolve_platform(alias)
        assert route.program == expected_program
        assert route.family == expected_program
        assert route.canonical_platform in route.group_platforms
        assert alias in platforms or alias.replace("-", "_") in platforms

    assert "openclaw" in platforms
    assert "ironclaw" in platforms
    assert "claude_code" in platforms
    assert "anthropic" in platforms
    assert "cursor" in platforms
    assert "cursor_agent" in platforms
    assert "goose" in platforms
    assert "gemini_cli" in platforms
    assert "gemini" in platforms
    assert "copilot" in platforms
    assert "githubcopilot" in platforms
    assert "hermes" in platforms
    assert "hermes_cli" in platforms
    assert "security_guardian" not in platforms
    assert "security-guardian" not in platforms
    assert "skill" not in platforms
    assert "skills" not in platforms
    assert len(set(platforms)) == len(platforms)


def test_get_platform_install_key_router_returns_singleton_default_router() -> None:
    first = get_platform_install_key_router()
    second = get_platform_install_key_router()

    assert first is second
    assert isinstance(first, PlatformInstallKeyRouter)


def test_resolve_platform_install_key_route_function_matches_router() -> None:
    route = resolve_platform_install_key_route("claude-code")

    assert route.program == "claude_code"
    assert route.prefix == "ic_install_claude_code_"
    assert route.is_grouped_with("anthropic")


def test_resolve_platform_install_key_group_function_matches_router() -> None:
    group = resolve_platform_install_key_group("open-claw")

    assert group.program == "openclaw"
    assert group.includes("ironclaw")
    assert group.includes("openclaw")


def test_provision_for_platform_delegates_to_canonical_install_key_service() -> None:
    provisioning_service = MagicMock()
    record = SimpleNamespace(
        key_id="ik_test_001",
        owner_key="buyer@ironclaw.test",
        subscription_id="sub_123",
        program="openclaw",
        masked_key="ic_install_openclaw_...1234",
        label="auto-provisioned",
        active=True,
        units_consumed=0,
        created_at=SimpleNamespace(isoformat=lambda: "2026-01-01T00:00:00+00:00"),
        last_used_at=None,
        metadata={"source": "purchase"},
        payment_status="paid",
        entitlements_status="active",
        issued_after_payment=True,
    )
    provisioning_service.provision_for_program.return_value = InstallKeyIssued(record=record, raw_key="ic_install_openclaw_secret_value_123", source="purchase")

    router = PlatformInstallKeyRouter(provisioning_service=provisioning_service)
    issued = router.provision_for_platform(
        platform_name="ironclaw",
        owner_key="buyer@ironclaw.test",
        subscription_id="sub_123",
        source="purchase",
        label="auto-provisioned",
        metadata={"customer_id": "cus_123"},
        payment_status="paid",
        entitlements_status="active",
        issued_after_payment=True,
        checkout_session_id="cs_123",
        purchase_reference="sub_123",
        customer_id="cus_123",
        org_id="org_42",
    )

    assert isinstance(issued, InstallKeyIssued)
    provisioning_service.provision_for_program.assert_called_once()
    kwargs = provisioning_service.provision_for_program.call_args.kwargs
    assert kwargs["program"] == "openclaw"
    assert kwargs["owner_key"] == "buyer@ironclaw.test"
    assert kwargs["subscription_id"] == "sub_123"
    assert kwargs["metadata"]["platform"] == "ironclaw"
    assert kwargs["metadata"]["canonical_platform"] == "openclaw"
    assert kwargs["metadata"]["family"] == "openclaw"
    assert kwargs["metadata"]["prefix"] == "ic_install_openclaw_"
    assert "openclaw" in kwargs["metadata"]["group_platforms"]
    assert "ironclaw" in kwargs["metadata"]["group_platforms"]
    assert kwargs["payment_status"] == "paid"
    assert kwargs["entitlements_status"] == "active"


@pytest.mark.parametrize("bad_platform", [None, "", "generic", "groq", "not_a_platform", "security-guardian", "security_guardian", "skill", "skills"])
def test_unsupported_platforms_are_rejected(bad_platform: str | None) -> None:
    router = PlatformInstallKeyRouter()
    with pytest.raises(ValueError):
        router.resolve_platform(bad_platform)


@pytest.mark.parametrize(
    ("platform_name", "candidate"),
    [
        (None, "ic_install_openclaw_abc"),
        ("openclaw", None),
        ("generic", "ic_install_openclaw_abc"),
    ],
)
def test_invalid_platform_key_checks_fail_cleanly(platform_name: str | None, candidate: str | None) -> None:
    router = PlatformInstallKeyRouter()

    assert router.is_valid_platform_key(platform_name, candidate) is False


def test_validate_platform_key_rejects_wrong_runtime_family_before_use() -> None:
    router = PlatformInstallKeyRouter()

    with pytest.raises(ValueError, match="does not match|wrong runtime family"):
        router.validate_platform_key("cursor", "ic_install_claude_code_secret_123")

    assert router.is_valid_platform_key("cursor", "ic_install_claude_code_secret_123") is False
