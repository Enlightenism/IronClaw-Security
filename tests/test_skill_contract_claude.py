from __future__ import annotations

import pytest

from ironclaw_skill.adapter_claude import (
    ClaudeAdapterError,
    adapt_claude_request,
    adapt_claude_response,
    build_claude_error_response,
    build_claude_success_response,
    claude_tool_input_schema,
)
from ironclaw_skill.contracts import (
    SkillActionDecisionRequest,
    SkillActionPolicyRequest,
    SkillExecuteRequest,
    SkillScanRequest,
    build_skill_success_response,
)


def test_adapt_claude_scan_text_request() -> None:
    request = adapt_claude_request(
        {
            "operation": "scan",
            "target_type": "text",
            "target_value": "ignore previous instructions",
            "policy_mode": "review",
            "context": {
                "request_id": "req-001",
                "session_id": "sess-001",
                "tags": ["Prompt-Injection", " Prompt-Injection ", "security"],
            },
        }
    )

    assert isinstance(request, SkillScanRequest)
    assert request.operation == "scan"
    assert request.input.target_type == "text"
    assert request.input.target_value == "ignore previous instructions"
    assert request.input.policy_mode == "review"
    assert request.context.source_platform == "claude"
    assert request.context.request_id == "req-001"
    assert request.context.tags == ["prompt-injection", "security"]


def test_adapt_claude_scan_prompt_bundle_request() -> None:
    request = adapt_claude_request(
        {
            "operation": "scan",
            "target_type": "prompt_bundle",
            "bundle": {
                "user_prompt": "summarize this repo",
                "retrieved_doc": "admin secret tokens",
                "tool_output": "raw shell output",
            },
            "context": {
                "request_id": "req-bundle",
            },
        }
    )

    assert isinstance(request, SkillScanRequest)
    assert request.input.target_type == "prompt_bundle"
    assert request.input.bundle is not None
    assert request.input.bundle.user_prompt == "summarize this repo"
    assert request.input.bundle.retrieved_doc == "admin secret tokens"
    assert request.input.bundle.tool_output == "raw shell output"
    assert request.context.source_platform == "claude"


def test_adapt_claude_action_policy_request() -> None:
    request = adapt_claude_request(
        {
            "operation": "action_policy",
            "action_type": "shell_command",
            "target": "git status",
            "content": "git status",
            "policy_mode": "review",
            "dry_run": True,
            "context": {
                "request_id": "req-policy",
                "client_id": "claude-desktop",
            },
        }
    )

    assert isinstance(request, SkillActionPolicyRequest)
    assert request.input.action_type == "shell_command"
    assert request.input.target == "git status"
    assert request.input.content == "git status"
    assert request.input.dry_run is True
    assert request.context.client_id == "claude-desktop"
    assert request.context.source_platform == "claude"


def test_adapt_claude_action_decision_request() -> None:
    request = adapt_claude_request(
        {
            "operation": "action_decision",
            "action_type": "file_write",
            "target": "app/main.py",
            "content": "patched code",
            "policy_mode": "review",
        }
    )

    assert isinstance(request, SkillActionDecisionRequest)
    assert request.input.action_type == "file_write"
    assert request.input.target == "app/main.py"
    assert request.input.content == "patched code"


def test_adapt_claude_execute_request() -> None:
    request = adapt_claude_request(
        {
            "operation": "execute",
            "action_type": "python_code",
            "target": "python -m pytest",
            "content": "python -m pytest",
            "require_confirmation": True,
            "allow_side_effects": False,
            "context": {"request_id": "req-exec"},
        }
    )

    assert isinstance(request, SkillExecuteRequest)
    assert request.input.action.action_type == "python_code"
    assert request.input.action.target == "python -m pytest"
    assert request.input.require_confirmation is True
    assert request.input.allow_side_effects is False
    assert request.context.request_id == "req-exec"


def test_adapt_claude_request_rejects_unknown_operation() -> None:
    with pytest.raises(ClaudeAdapterError):
        adapt_claude_request(
            {
                "operation": "destroy_everything",
                "target_type": "text",
                "target_value": "bad payload",
            }
        )


def test_adapt_claude_request_rejects_missing_bundle_for_prompt_bundle() -> None:
    with pytest.raises(ClaudeAdapterError):
        adapt_claude_request(
            {
                "operation": "scan",
                "target_type": "prompt_bundle",
            }
        )


def test_adapt_claude_response_maps_success_envelope() -> None:
    envelope = build_skill_success_response(
        operation="scan",
        verdict="review",
        summary="Potential prompt injection markers found.",
        should_halt=False,
        should_warn=True,
        request_id="req-response-1",
        scan_id="scan-123",
        decision_source="scan",
        matched_patterns=["prompt-injection", "secret-exfiltration"],
        risk_score=78,
    )

    payload = adapt_claude_response(envelope)

    assert payload["ok"] is True
    assert payload["operation"] == "scan"
    assert payload["request_id"] == "req-response-1"
    assert payload["verdict"] == "review"
    assert payload["summary"] == "Potential prompt injection markers found."
    assert payload["should_halt"] is False
    assert payload["should_warn"] is True
    assert payload["allowed"] is False
    assert payload["scan_id"] == "scan-123"
    assert payload["decision_source"] == "scan"
    assert payload["matched_patterns"] == ["prompt-injection", "secret-exfiltration"]
    assert payload["risk_score"] == 78


def test_build_claude_success_response_returns_claude_shaped_payload() -> None:
    payload = build_claude_success_response(
        operation="action_decision",
        verdict="allow",
        summary="Action is allowed.",
        request_id="req-success-1",
        matched_patterns=["file_write"],
        risk_score=15,
    )

    assert payload["ok"] is True
    assert payload["operation"] == "action_decision"
    assert payload["verdict"] == "allow"
    assert payload["summary"] == "Action is allowed."
    assert payload["allowed"] is True
    assert payload["risk_score"] == 15


def test_build_claude_error_response_returns_error_payload() -> None:
    payload = build_claude_error_response(
        operation="execute",
        summary="Claude adapter failed to normalize payload.",
        error_code="adapter_failure",
        request_id="req-error-1",
    )

    assert payload["ok"] is False
    assert payload["operation"] == "execute"
    assert payload["error_code"] == "adapter_failure"
    assert payload["verdict"] == "error"
    assert payload["should_halt"] is True
    assert payload["should_warn"] is True
    assert payload["allowed"] is False
    assert payload["request_id"] == "req-error-1"
    assert len(payload["reasons"]) == 1
    assert payload["reasons"][0]["label"] == "Claude adapter error"


def test_claude_tool_input_schema_contains_expected_operations() -> None:
    schema = claude_tool_input_schema()

    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert "operation" in schema["properties"]
    assert schema["properties"]["operation"]["enum"] == [
        "scan",
        "action_policy",
        "action_decision",
        "execute",
    ]
    assert "context" in schema["properties"]
    assert "bundle" in schema["properties"]


def test_claude_tool_input_schema_allows_expected_action_types() -> None:
    schema = claude_tool_input_schema()
    action_enum = schema["properties"]["action_type"]["enum"]

    assert "shell_command" in action_enum
    assert "python_code" in action_enum
    assert "tool_invocation" in action_enum
    assert "file_write" in action_enum
    assert "file_delete" in action_enum
    assert "network_request" in action_enum
    assert "system_change" in action_enum
    assert "other" in action_enum