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
        ("openclaw", "ic_install_claude_code_secret_123", False),
        ("claude_code", "ic_install_openclaw_secret_123", False),
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

    assert len(groups) == 2
    programs = {group.program for group in groups}
    assert programs == {"openclaw", "claude_code"}
    assert all(group.platforms for group in groups)


def test_list_platforms_returns_aliases_and_canonical_names() -> None:
    platforms = list_platform_install_key_platforms()

    assert "openclaw" in platforms
    assert "ironclaw" in platforms
    assert "claude_code" in platforms
    assert "anthropic" in platforms
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
    assert kwargs["metadata"]["family"] == "openclaw"
    assert kwargs["payment_status"] == "paid"
    assert kwargs["entitlements_status"] == "active"


@pytest.mark.parametrize("bad_platform", [None, "", "generic", "groq", "not_a_platform"])
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
