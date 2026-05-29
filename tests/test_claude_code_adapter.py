from __future__ import annotations

from app.adapters.base import AdapterExecutionRequest
from app.adapters.claude_code_adapter import (
    ClaudeCodeAdapter,
    ClaudeCodeAdapterRequest,
    ClaudeCodeAdapterResponse,
    build_claude_code_adapter_request,
    summarize_claude_code_adapter_response,
)
from app.services.integration_registry import (
    get_integration,
    initialize_integration_registry,
)


def _make_adapter() -> ClaudeCodeAdapter:
    registry = initialize_integration_registry()
    record = get_integration(registry, "claude-code")
    return ClaudeCodeAdapter(record=record)


def test_claude_code_adapter_record_identity():
    adapter = _make_adapter()

    assert adapter.record.integration_id == "integration-claude-code"
    assert adapter.record.slug == "claude-code"
    assert adapter.record.platform == "claude-code"


def test_claude_code_adapter_handshake_contains_expected_metadata():
    adapter = _make_adapter()

    handshake = adapter.handshake()

    assert handshake.adapter_slug == "claude-code"
    assert handshake.platform == "claude-code"
    assert handshake.status == "ready"
    assert handshake.metadata["integration_id"] == "integration-claude-code"
    assert handshake.metadata["runtime"] == "claude-code"
    assert handshake.metadata["guard_mode"] == "strict"


def test_claude_code_adapter_manifest_includes_adapter_metadata():
    adapter = _make_adapter()

    manifest = adapter.manifest()

    assert manifest.slug == "claude-code"
    assert manifest.platform == "claude-code"
    assert manifest.metadata["runtime"] == "claude-code"
    assert manifest.metadata["guard_mode"] == "strict"


def test_claude_code_adapter_execute_returns_guarded_result():
    adapter = _make_adapter()

    result = adapter.execute(
        AdapterExecutionRequest(
            action_type="toolcall",
            target="workspace://claude/session",
            payload={"tool": "read_file", "path": "README.md"},
        ),
    )

    assert result.adapter_slug == "claude-code"
    assert result.platform == "claude-code"
    assert result.success is True
    assert result.status == "accepted"
    assert result.metadata["runtime"] == "claude-code"
    assert result.output["guard_applied"] is True
    assert result.output["request"]["action_type"] == "toolcall"


def test_claude_code_adapter_execute_offline_returns_failure():
    adapter = _make_adapter()
    adapter.health = "offline"

    result = adapter.execute(
        AdapterExecutionRequest(
            action_type="toolcall",
            target="workspace://claude/session",
        ),
    )

    assert result.success is False
    assert result.status == "offline"


def test_build_claude_code_adapter_request_normalizes_inputs():
    req = build_claude_code_adapter_request(
        action_type="  toolcall  ",
        target="  workspace://claude/session  ",
        content="some content",
        client_id="agent-1",
    )

    assert req.action_type == "toolcall"
    assert req.target == "workspace://claude/session"
    assert req.client_id == "agent-1"


def test_build_claude_code_adapter_request_raises_on_empty_action_type():
    import pytest

    with pytest.raises(ValueError, match="action_type"):
        build_claude_code_adapter_request(action_type="", target="some-target")


def test_build_claude_code_adapter_request_raises_on_empty_target():
    import pytest

    with pytest.raises(ValueError, match="target"):
        build_claude_code_adapter_request(action_type="toolcall", target="  ")


def test_claude_code_adapter_request_to_policy_input_maps_client_id():
    req = ClaudeCodeAdapterRequest(
        action_type="toolcall",
        target="workspace://claude/session",
        content="run script",
        client_id="agent-42",
        session_id="session-99",
    )

    policy_input = req.to_policy_input()

    assert policy_input.action_type == "toolcall"
    assert policy_input.agent_id == "agent-42"
    assert policy_input.session_id == "session-99"
    assert policy_input.content == "run script"


def test_claude_code_adapter_request_model_dump_is_complete():
    req = ClaudeCodeAdapterRequest(
        action_type="toolcall",
        target="workspace://claude/session",
        metadata={"key": "value"},
    )

    dumped = req.model_dump()

    assert dumped["action_type"] == "toolcall"
    assert dumped["target"] == "workspace://claude/session"
    assert dumped["metadata"] == {"key": "value"}
    assert "client_id" in dumped
    assert "session_id" in dumped
    assert "content" in dumped


def test_claude_code_adapter_response_model_dump_includes_secret_scan():
    response = ClaudeCodeAdapterResponse(
        adapter_name="ironclaw-claude-code",
        platform="claude-code",
        mode="enforce",
        verdict="allow",
        should_allow=True,
        should_warn=False,
        should_quarantine=False,
        should_block=False,
        risk_score=0,
        risk_level="low",
        summary="Clean action.",
        secret_scan={},
    )

    dumped = response.model_dump()

    assert dumped["verdict"] == "allow"
    assert dumped["secret_scan"] == {}
    assert "risk_score" in dumped
    assert "matched_rules" in dumped


def test_claude_code_adapter_response_secret_scan_populated():
    response = ClaudeCodeAdapterResponse(
        adapter_name="ironclaw-claude-code",
        platform="claude-code",
        mode="enforce",
        verdict="block",
        should_allow=False,
        should_warn=False,
        should_quarantine=False,
        should_block=True,
        risk_score=90,
        risk_level="critical",
        summary="Secret detected in payload.",
        secret_scan={"detected": True, "type": "api_key", "redacted": "sk-***"},
    )

    dumped = response.model_dump()

    assert dumped["secret_scan"]["detected"] is True
    assert dumped["secret_scan"]["type"] == "api_key"
    assert dumped["verdict"] == "block"


def test_summarize_claude_code_adapter_response_shape():
    response = ClaudeCodeAdapterResponse(
        adapter_name="ironclaw-claude-code",
        platform="claude-code",
        mode="enforce",
        verdict="warn",
        should_allow=False,
        should_warn=True,
        should_quarantine=False,
        should_block=False,
        risk_score=45,
        risk_level="medium",
        summary="Suspicious pattern detected.",
        secret_scan={},
    )

    summary = summarize_claude_code_adapter_response(response)

    assert summary["verdict"] == "warn"
    assert summary["risk_score"] == 45
    assert summary["risk_level"] == "medium"
    assert "decision_id" in summary
    assert "trace_id" in summary
    assert "reviewed_at" in summary
