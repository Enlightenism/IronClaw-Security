from __future__ import annotations

from unittest.mock import patch

import pytest

from app.services.integration_installer import (
    build_install_plan,
    install_integration,
    summarize_install_result,
)
from app.services.integration_registry import (
    get_integration,
    initialize_integration_registry,
)


def _fake_paid_install_key(owner_key: str = "owner-123", program: str = "openclaw"):
    class _FakeKeyRecord:
        def __init__(self) -> None:
            self.key_id = "ik_test_123"
            self.owner_key = owner_key.lower()
            self.program = program
            self.payment_status = "paid"
            self.entitlements_status = "active"
            self.active = True
            self.issued_after_payment = True

    return _FakeKeyRecord()


def test_install_integration_dry_run_does_not_change_status():
    registry = initialize_integration_registry()
    record_before = get_integration(registry, "integration-claude-code")
    assert record_before is not None
    assert record_before.status == "planned"

    with patch("app.services.integration_installer.get_install_key_registry") as mock_registry:
        mock_registry.return_value.authenticate_install_key.return_value = _fake_paid_install_key(
            owner_key="owner-123",
            program="claude_code",
        )
        result = install_integration(
            registry,
            "integration-claude-code",
            dry_run=True,
            requested_by="tester",
            install_key="ic_install_claude_code_validkey",
            owner_key="owner-123",
        )

    record_after = get_integration(registry, "integration-claude-code")
    assert record_after is not None
    assert record_after.status == "planned"
    assert result.installed is False
    assert result.status_before == "planned"
    assert result.status_after == "planned"
    assert any(step.name == "validate-paid-install-key" and step.state == "installed" for step in result.steps)
    assert any(step.name == "apply-install" and step.state == "skipped" for step in result.steps)


def test_install_integration_marks_record_active_with_valid_paid_install_key():
    registry = initialize_integration_registry()

    with patch("app.services.integration_installer.get_install_key_registry") as mock_registry:
        mock_registry.return_value.authenticate_install_key.return_value = _fake_paid_install_key(owner_key="owner-456")
        result = install_integration(
            registry,
            "integration-openclaw",
            requested_by="tester",
            install_key="ic_install_openclaw_validkey",
            owner_key="owner-456",
        )

    record_after = get_integration(registry, "integration-openclaw")
    assert record_after is not None
    assert record_after.status == "active"
    assert result.installed is True
    assert result.status_before == "planned"
    assert result.status_after == "active"
    assert any(step.name == "validate-paid-install-key" and step.state == "installed" for step in result.steps)
    assert any(step.name == "apply-install" and step.state == "installed" for step in result.steps)


def test_install_integration_accepts_supported_multi_platform_paid_keys():
    registry = initialize_integration_registry()
    supported = [
        ("integration-cursor", "ic_install_cursor_validkey", "owner-800", "cursor"),
        ("integration-goose", "ic_install_goose_validkey", "owner-801", "goose"),
        ("integration-gemini-cli", "ic_install_gemini_cli_validkey", "owner-802", "gemini_cli"),
        ("integration-copilot", "ic_install_copilot_validkey", "owner-803", "copilot"),
        ("integration-hermes", "ic_install_hermes_validkey", "owner-804", "hermes"),
        ("integration-security-guardian", "ic_install_security_guardian_validkey", "owner-805", "security_guardian"),
    ]

    for integration_id, install_key, owner_key, program in supported:
        with patch("app.services.integration_installer.get_install_key_registry") as mock_registry:
            mock_registry.return_value.authenticate_install_key.return_value = _fake_paid_install_key(
                owner_key=owner_key,
                program=program,
            )
            result = install_integration(
                registry,
                integration_id,
                requested_by="tester",
                install_key=install_key,
                owner_key=owner_key,
            )

        assert result.installed is True, integration_id
        assert result.status_after == "active", integration_id
        assert any(step.name == "validate-paid-install-key" and step.state == "installed" for step in result.steps), integration_id


def test_install_integration_blocks_without_paid_install_key():
    registry = initialize_integration_registry()

    result = install_integration(
        registry,
        "integration-claude-code",
        requested_by="tester",
    )

    record_after = get_integration(registry, "integration-claude-code")
    assert record_after is not None
    assert record_after.status == "planned"
    assert result.installed is False
    assert result.status_after == "blocked"
    assert any(step.name == "validate-paid-install-key" and step.state == "failed" for step in result.steps)


def test_install_integration_rejects_generic_system_keys_before_registry_lookup():
    registry = initialize_integration_registry()

    for bad_key in ("ic_org_1234", "sk_live_abc123", "token_12345", "ghp_abc123", "ic_12345"):
        with patch("app.services.integration_installer.get_install_key_registry") as mock_registry:
            result = install_integration(
                registry,
                "integration-claude-code",
                requested_by="tester",
                install_key=bad_key,
                owner_key="owner-123",
            )

        assert result.installed is False
        assert result.status_after == "blocked"
        assert any(step.name == "validate-paid-install-key" and step.state == "failed" for step in result.steps)
        assert bad_key not in str(result.steps)
        mock_registry.return_value.authenticate_install_key.assert_not_called()


def test_install_integration_rejects_revoked_or_inactive_paid_key():
    registry = initialize_integration_registry()

    class _RevokedKeyRecord:
        def __init__(self) -> None:
            self.key_id = "ik_revoked_123"
            self.owner_key = "owner-123"
            self.program = "claude_code"
            self.payment_status = "paid"
            self.entitlements_status = "active"
            self.active = False
            self.issued_after_payment = True

    with patch("app.services.integration_installer.get_install_key_registry") as mock_registry:
        mock_registry.return_value.authenticate_install_key.return_value = _RevokedKeyRecord()
        result = install_integration(
            registry,
            "integration-claude-code",
            requested_by="tester",
            install_key="ic_install_claude_code_revokedkey",
            owner_key="owner-123",
        )

    assert result.installed is False
    assert result.status_after == "blocked"
    assert any(step.name == "validate-paid-install-key" and step.state == "failed" for step in result.steps)
    assert result.steps[-1].metadata["install_key_valid"] is False


def test_install_integration_rejects_mismatched_owner_for_valid_key():
    registry = initialize_integration_registry()

    with patch("app.services.integration_installer.get_install_key_registry") as mock_registry:
        mock_registry.return_value.authenticate_install_key.return_value = _fake_paid_install_key(owner_key="owner-456")
        result = install_integration(
            registry,
            "integration-openclaw",
            requested_by="tester",
            install_key="ic_install_openclaw_validkey",
            owner_key="owner-123",
        )

    assert result.installed is False
    assert result.status_after == "blocked"
    assert any(step.name == "validate-paid-install-key" and step.state == "failed" for step in result.steps)
    assert result.steps[-1].metadata["supplied_owner_key"] == "owner-123"


def test_install_integration_raises_for_unknown_integration():
    registry = initialize_integration_registry()

    with pytest.raises(KeyError):
        install_integration(registry, "integration-missing")


def test_build_install_plan_contains_expected_steps():
    registry = initialize_integration_registry()
    record = get_integration(registry, "integration-generic-agent")
    assert record is not None

    plan = build_install_plan(record)

    assert [step["step"] for step in plan] == [
        "resolve-integration",
        "validate-command",
        "prepare-target",
        "validate-paid-install-key",
        "apply-install",
    ]


def test_summarize_install_result_returns_expected_shape():
    registry = initialize_integration_registry()

    with patch("app.services.integration_installer.get_install_key_registry") as mock_registry:
        mock_registry.return_value.authenticate_install_key.return_value = _fake_paid_install_key(owner_key="owner-777")
        result = install_integration(
            registry,
            "integration-generic-agent",
            requested_by="tester",
            install_key="ic_install_openclaw_validkey",
            owner_key="owner-777",
        )
    summary = summarize_install_result(result)

    assert summary["integration_id"] == "integration-generic-agent"
    assert summary["slug"] == "generic-agent"
    assert summary["installed"] is True
    assert summary["status_after"] == "active"
    assert summary["step_count"] == len(result.steps)
