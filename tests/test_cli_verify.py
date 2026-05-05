from __future__ import annotations

import json

from app.cli.main import run_cli


def test_cli_verify_non_strict_returns_zero(capsys):
    exit_code = run_cli(
        ["verify", "integration-claude-code", "--requested-by", "pytest"]
    )

    assert exit_code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert payload["integration_id"] == "integration-claude-code"
    assert payload["verified"] is True
    assert payload["warn_count"] >= 1


def test_cli_verify_strict_returns_zero_with_failed_verification_summary(capsys):
    exit_code = run_cli(
        ["verify", "integration-openclaw", "--strict", "--requested-by", "pytest"]
    )

    assert exit_code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert payload["integration_id"] == "integration-openclaw"
    assert payload["verified"] is False
    assert payload["fail_count"] >= 1