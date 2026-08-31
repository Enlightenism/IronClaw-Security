from __future__ import annotations

from pydantic import ValidationError
import pytest

from app.schemas.install_key_platform import InstallKeyPlatform, InstallKeyPlatformGroup


@pytest.mark.parametrize(
    ("platform", "program", "family", "display_name", "expected_platform"),
    [
        ("OpenClaw", "openclaw", "openclaw", "OpenClaw", "openclaw"),
        ("ironclaw", "openclaw", "openclaw", "IronClaw", "ironclaw"),
        ("claude-code", "claude_code", "claude_code", "Claude Code", "claude_code"),
        ("Anthropic", "claude_code", "claude_code", "Anthropic", "anthropic"),
        ("Hermes", "hermes", "hermes", "Hermes", "hermes"),
    ],
)
def test_install_key_platform_normalizes_platform_and_program(platform: str, program: str, family: str, display_name: str, expected_platform: str) -> None:
    record = InstallKeyPlatform(
        platform=platform,
        program=program,
        family=family,
        display_name=display_name,
        owner_key="buyer@ironclaw.test",
        payment_status="paid",
        entitlements_status="active",
        active=True,
    )

    assert record.platform == expected_platform
    assert record.program == program
    assert record.family == family
    assert record.display_name == display_name
    assert record.is_paid is True
    assert record.has_active_entitlement is True
    assert record.status == "active"


def test_install_key_platform_sets_paid_active_contract_for_active_record() -> None:
    record = InstallKeyPlatform(
        platform="ironclaw",
        program="openclaw",
        family="openclaw",
        display_name="IronClaw",
        active=True,
        payment_status="pending",
        entitlements_status="pending",
    )

    assert record.active is True
    assert record.payment_status == "paid"
    assert record.entitlements_status == "active"
    assert record.status == "active"


def test_install_key_platform_normalizes_pending_entitlement_states() -> None:
    record = InstallKeyPlatform(
        platform="anthropic",
        program="claude_code",
        family="claude_code",
        display_name="Anthropic",
        payment_status="pending",
        entitlements_status="pending",
        active=False,
    )

    assert record.payment_status == "pending"
    assert record.entitlements_status == "pending"
    assert record.status == "pending"


def test_install_key_platform_rejects_missing_required_fields() -> None:
    with pytest.raises(ValidationError):
        InstallKeyPlatform(
            platform="",
            program="openclaw",
            family="openclaw",
            display_name="OpenClaw",
        )

    with pytest.raises(ValidationError):
        InstallKeyPlatform(
            platform="openclaw",
            program="",
            family="openclaw",
            display_name="OpenClaw",
        )

    with pytest.raises(ValidationError):
        InstallKeyPlatform(
            platform="openclaw",
            program="openclaw",
            family="",
            display_name="OpenClaw",
        )


def test_install_key_platform_rejects_unknown_program() -> None:
    with pytest.raises(ValidationError, match="program must be one of"):
        InstallKeyPlatform(
            platform="openclaw",
            program="gpt-4o",
            family="openclaw",
            display_name="OpenClaw",
        )


def test_install_key_platform_from_runtime_payload_builds_values() -> None:
    payload = {
        "platform": "claude-code",
        "canonical_program": "claude_code",
        "family": "claude_code",
        "display_name": "Claude Code",
        "label": "Prod Claude",
        "owner_key": "ic_org_org_42",
        "payment_status": "success",
        "entitlements_status": "enabled",
        "active": False,
        "status": "active",
        "key_id": "ik_123",
        "masked_key": "ic_install_claude_code_...1234",
        "metadata": {"slug": "claude-code"},
    }

    record = InstallKeyPlatform.from_runtime_payload(payload)

    assert record.platform == "claude_code"
    assert record.program == "claude_code"
    assert record.family == "claude_code"
    assert record.display_name == "Claude Code"
    assert record.label == "Prod Claude"
    assert record.owner_key == "ic_org_org_42"
    assert record.payment_status == "paid"
    assert record.entitlements_status == "active"
    assert record.status == "active"
    assert record.key_id == "ik_123"
    assert record.masked_key == "ic_install_claude_code_...1234"
    assert record.metadata["slug"] == "claude-code"


def test_install_key_platform_group_normalizes_platforms_and_derives_status() -> None:
    card_a = InstallKeyPlatform(
        platform="openclaw",
        program="openclaw",
        family="openclaw",
        display_name="OpenClaw",
        payment_status="paid",
        entitlements_status="active",
        active=True,
    )
    card_b = InstallKeyPlatform(
        platform="ironclaw",
        program="openclaw",
        family="openclaw",
        display_name="IronClaw",
        payment_status="paid",
        entitlements_status="active",
        active=False,
    )

    group = InstallKeyPlatformGroup(
        family="openclaw",
        program="openclaw",
        display_name="OpenClaw",
        platforms=["openclaw", "ironclaw"],
        cards=[card_a, card_b],
    )

    assert group.family == "openclaw"
    assert group.program == "openclaw"
    assert group.status == "active"
    assert "openclaw" in group.platforms
    assert "ironclaw" in group.platforms


def test_install_key_platform_group_status_tracks_pending_or_not_configured_state() -> None:
    pending_group = InstallKeyPlatformGroup(
        family="claude_code",
        program="claude_code",
        display_name="Claude Code",
        platforms=["claude-code"],
        cards=[
            InstallKeyPlatform(
                platform="claude-code",
                program="claude_code",
                family="claude_code",
                display_name="Claude Code",
                payment_status="pending",
                entitlements_status="pending",
                active=False,
            )
        ],
    )
    empty_group = InstallKeyPlatformGroup(
        family="claude_code",
        program="claude_code",
        display_name="Claude Code",
        platforms=[],
        cards=[],
    )

    assert pending_group.status == "pending"
    assert empty_group.status == "inactive"


def test_install_key_platform_properties_expose_paid_and_active_flags() -> None:
    paid_record = InstallKeyPlatform(
        platform="openclaw",
        program="openclaw",
        family="openclaw",
        display_name="OpenClaw",
        payment_status="paid",
        entitlements_status="active",
        active=True,
    )
    unpaid_record = InstallKeyPlatform(
        platform="openclaw",
        program="openclaw",
        family="openclaw",
        display_name="OpenClaw",
        payment_status="unpaid",
        entitlements_status="not_active",
        active=False,
    )

    assert paid_record.is_paid is True
    assert paid_record.has_active_entitlement is True
    assert unpaid_record.is_paid is False
    assert unpaid_record.has_active_entitlement is False


def test_install_key_platform_status_rejects_unknown_values_by_falling_back_to_pending() -> None:
    record = InstallKeyPlatform(
        platform="openclaw",
        program="openclaw",
        family="openclaw",
        display_name="OpenClaw",
        status="unknown_status",
    )

    assert record.status == "pending"


def test_install_key_platform_group_rejects_unknown_program() -> None:
    with pytest.raises(ValidationError, match="program must be one of"):
        InstallKeyPlatformGroup(
            family="openclaw",
            program="gpt-4o",
            display_name="OpenClaw",
            platforms=["openclaw"],
            cards=[],
        )


def test_install_key_platform_group_converts_string_platform_list_to_normalized_values() -> None:
    group = InstallKeyPlatformGroup(
        family="claude_code",
        program="claude_code",
        display_name="Claude Code",
        platforms="claude-code",
        cards=[],
    )

    assert group.platforms == ["claude_code"]
