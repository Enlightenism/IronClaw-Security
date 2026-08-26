from __future__ import annotations

import json

from app.cli.main import run_cli


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
