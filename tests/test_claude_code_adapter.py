from __future__ import annotations

from app.adapters.base import AdapterExecutionRequest
from app.adapters.claude_code_adapter import ClaudeCodeAdapter, build_claude_code_adapter
from app.services.integration_registry import initialize_integration_registry


def test_build_claude_code_adapter_returns_expected_adapter():
    registry = initialize_integration_registry()

    adapter = build_claude_code_adapter(registry)

    assert adapter.record.integration_id == "integration-claude-code"
    assert adapter.record.slug == "claude-code"
    assert adapter.record.platform == "claude-code"


def test_claude_code_adapter_handshake_contains_expected_metadata():
    registry = initialize_integration_registry()
    adapter = build_claude_code_adapter(registry)

    handshake = adapter.handshake()

    assert handshake.adapter_slug == "claude-code"
    assert handshake.platform == "claude-code"
    assert handshake.status == "ready"
    assert handshake.metadata["integration_id"] == "integration-claude-code"
    assert handshake.metadata["runtime"] == "claude-code"
    assert handshake.metadata["guard_mode"] == "strict"


def test_claude_code_adapter_manifest_includes_adapter_metadata():
    registry = initialize_integration_registry()
    adapter = build_claude_code_adapter(registry)

    manifest = adapter.manifest()

    assert manifest.slug == "claude-code"
    assert manifest.platform == "claude-code"
    assert manifest.metadata["runtime"] == "claude-code"
    assert manifest.metadata["guard_mode"] == "strict"


def test_claude_code_adapter_execute_returns_guarded_result():
    registry = initialize_integration_registry()
    adapter = build_claude_code_adapter(registry)

    result = adapter.execute(
        AdapterExecutionRequest(
            action_type="toolcall",
            target="workspace://claude/session",
            payload={"tool": "read_file", "path": "README.md"},
        )
    )

    assert result.adapter_slug == "claude-code"
    assert result.platform == "claude-code"
    assert result.success is True
    assert result.status == "guarded"
    assert result.metadata["runtime"] == "claude-code"
    assert result.output["guard_applied"] is True
    assert result.output["request"]["action_type"] == "toolcall"