from __future__ import annotations

import json

from app.cli.main import run_cli
from app.core.install_key_formats import InstallKeyFormatRegistry
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


def test_cli_install_requires_a_valid_claim_before_building_command() -> None:
    blocked = build_operator_install_result(
        platform="openclaw",
        claim_token=None,
    )

    assert blocked.status == "blocked"
    assert blocked.retry_after_purchase is True
    assert blocked.install_command is None

    blocked_generic = build_operator_install_result(
        platform="openclaw",
        claim_token="ic_install_openclaw_abc123",
    )

    assert blocked_generic.status == "blocked"
    assert blocked_generic.install_command is None


def test_cli_install_builds_canonical_command_from_one_time_claim() -> None:
    claim_token = "ic_claim_0123456789abcdefghij"
    result = build_operator_install_result(
        platform="openclaw",
        claim_token=claim_token,
    )

    assert result.status == "ready"
    assert result.retry_after_purchase is False
    assert result.install_command is not None
    assert result.install_command == InstallKeyFormatRegistry.get_spec("openclaw").format_command(claim_token)


def test_cli_install_rejects_raw_keys_and_malformed_claims() -> None:
    blocked_raw_key = build_operator_install_result(
        platform="claude-code",
        claim_token="ic_install_claude_code_abc123",
    )
    blocked_malformed = build_operator_install_result(
        platform="claude-code",
        claim_token="ic_claim_...",
    )

    assert blocked_raw_key.status == "blocked"
    assert blocked_raw_key.install_command is None
    assert blocked_malformed.status == "blocked"
    assert blocked_malformed.install_command is None
