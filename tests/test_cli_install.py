from __future__ import annotations

import json
from types import SimpleNamespace

from app.cli.main import run_cli
from cli.install import build_operator_install_result


def test_cli_list_returns_zero_and_outputs_integrations(capsys):
    exit_code = run_cli(["list"])

    assert exit_code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert payload["total"] >= 3
    assert any(item["slug"] == "claude-code" for item in payload["items"])


def test_cli_install_dry_run_returns_zero_but_reports_blocked_without_paid_key(capsys):
    exit_code = run_cli(
        ["install", "integration-claude-code", "--dry-run", "--requested-by", "pytest"],
    )

    assert exit_code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert payload["integration_id"] == "integration-claude-code"
    assert payload["installed"] is False
    assert payload["status_before"] == "planned"
    assert payload["status_after"] == "blocked"
    assert "step_count" in payload


def test_cli_install_blocks_known_integration_when_paid_key_is_missing(capsys):
    exit_code = run_cli(
        ["install", "integration-openclaw", "--requested-by", "pytest"],
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert payload["integration_id"] == "integration-openclaw"
    assert payload["installed"] is False
    assert payload["status_after"] == "blocked"
    assert "step_count" in payload


def test_cli_install_requires_valid_paid_key_before_building_command() -> None:
    blocked = build_operator_install_result(
        platform="openclaw",
        install_key=None,
        owner_key="owner@example.com",
    )

    assert blocked.status == "blocked"
    assert blocked.retry_after_purchase is True
    assert blocked.install_command is None

    blocked_generic = build_operator_install_result(
        platform="openclaw",
        install_key="sk_live_abc123",
        owner_key="owner@example.com",
    )

    assert blocked_generic.status == "blocked"
    assert blocked_generic.install_command is None


def test_cli_install_builds_canonical_command_only_for_active_paid_key(monkeypatch) -> None:
    from cli import install as cli_install

    fake_registry = SimpleNamespace(
        authenticate_install_key=lambda candidate: SimpleNamespace(
            active=True,
            payment_status="paid",
            entitlements_status="active",
            issued_after_payment=True,
            owner_key="owner@example.com",
            program="openclaw",
            key_id="ik_openclaw_1",
        )
    )
    monkeypatch.setattr(cli_install, "get_install_key_registry", lambda: fake_registry)

    result = build_operator_install_result(
        platform="openclaw",
        install_key="ic_install_openclaw_abc123",
        owner_key="owner@example.com",
    )

    assert result.status == "ready"
    assert result.retry_after_purchase is False
    assert result.install_command is not None
    assert "ic_install_openclaw_abc123" in result.install_command
    assert "--agent openclaw" in result.install_command
    assert "--scope user" in result.install_command


def test_cli_install_rejects_generic_owner_identity_and_platform_auth(monkeypatch) -> None:
    from cli import install as cli_install

    fake_registry = SimpleNamespace(
        authenticate_install_key=lambda candidate: SimpleNamespace(
            active=True,
            payment_status="paid",
            entitlements_status="active",
            issued_after_payment=True,
            owner_key="owner@example.com",
            program="claude_code",
            key_id="ik_claude_1",
        )
    )
    monkeypatch.setattr(cli_install, "get_install_key_registry", lambda: fake_registry)

    blocked_owner = build_operator_install_result(
        platform="claude-code",
        install_key="ic_install_claude_code_abc123",
        owner_key="ghp_example_token",
    )
    blocked_generic = build_operator_install_result(
        platform="claude-code",
        install_key="sk_live_abc123",
        owner_key="owner@example.com",
    )

    assert blocked_owner.status == "blocked"
    assert blocked_owner.install_command is None
    assert blocked_generic.status == "blocked"
    assert blocked_generic.install_command is None
