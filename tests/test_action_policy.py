from __future__ import annotations

from app.services.action_policy import evaluate_action_policy


def test_evaluate_action_policy_allows_safe_local_target() -> None:
    result = evaluate_action_policy(
        action_type="file_edit",
        target="workspace/docs/notes.txt",
        client_id="policy-client-001",
        session_id="policy-session-001",
    )

    assert result["policy_mode"] == "allow"
    assert result["verdict"] == "allow"
    assert result["should_halt"] is False
    assert result["should_warn"] is False
    assert result["reasons"][0]["source"] == "policy"


def test_evaluate_action_policy_reviews_elevated_action_type() -> None:
    result = evaluate_action_policy(
        action_type="tool_call",
        target="safe-tool",
        client_id="policy-client-002",
        session_id="policy-session-002",
    )

    assert result["policy_mode"] == "review"
    assert result["verdict"] == "warn"
    assert result["should_halt"] is False
    assert result["should_warn"] is True
    assert result["reasons"][0]["label"] == "Elevated action type"


def test_evaluate_action_policy_blocks_sensitive_target() -> None:
    result = evaluate_action_policy(
        action_type="file_edit",
        target="/etc/passwd",
        client_id="policy-client-003",
        session_id="policy-session-003",
    )

    assert result["policy_mode"] == "block"
    assert result["verdict"] == "block"
    assert result["should_halt"] is True
    assert result["should_warn"] is False
    assert result["reasons"][0]["label"] == "Blocked target"


def test_evaluate_action_policy_reviews_elevated_target_when_action_is_safe() -> None:
    result = evaluate_action_policy(
        action_type="file_edit",
        target="powershell.exe",
        client_id="policy-client-004",
        session_id="policy-session-004",
    )

    assert result["policy_mode"] == "review"
    assert result["verdict"] == "warn"
    assert result["should_halt"] is False
    assert result["should_warn"] is True
    assert result["reasons"][0]["label"] == "Elevated target"