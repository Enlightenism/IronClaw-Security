from __future__ import annotations

import pytest

from app.adapters.base import AdapterExecutionRequest
from app.adapters.secret_scanner_adapter import (
    SecretScannerAdapter,
    SecretScannerAdapterRequest,
    SecretScannerAdapterResponse,
    build_secret_scanner_adapter,
    build_secret_scanner_adapter_request,
    evaluate_secret_scanner_request,
    scan_for_secrets,
    summarize_secret_scanner_adapter_response,
)
from app.config import RISK_THRESHOLD_BLOCK_MIN
from app.orchestrator.policy_enforcer import initialize_policy_engine
from app.services.integration_registry import (
    initialize_integration_registry,
)


def _make_adapter() -> SecretScannerAdapter:
    registry = initialize_integration_registry()
    return build_secret_scanner_adapter(registry)


# ---------------------------------------------------------------------------
# build_secret_scanner_adapter — slug resolution
# ---------------------------------------------------------------------------


def test_secret_scanner_adapter_record_identity() -> None:
    adapter = _make_adapter()
    assert adapter.record is not None
    assert adapter.record.integration_id == "integration-secret-scanner"


def test_secret_scanner_adapter_record_slug() -> None:
    adapter = _make_adapter()
    assert adapter.record.slug == "secret-scanner"


def test_secret_scanner_adapter_handshake_contains_expected_metadata() -> None:
    adapter = _make_adapter()
    handshake = adapter.handshake()
    assert handshake.metadata["integration_id"] == "integration-secret-scanner"
    assert handshake.metadata["runtime"] == "secret-scanner"


def test_secret_scanner_adapter_manifest_includes_adapter_metadata() -> None:
    adapter = _make_adapter()
    manifest = adapter.manifest()
    assert manifest.metadata["integration_id"] == "integration-secret-scanner"
    assert manifest.metadata["runtime"] == "secret-scanner"


# ---------------------------------------------------------------------------
# build_secret_scanner_adapter_request
# ---------------------------------------------------------------------------


def test_build_request_normalizes_fields() -> None:
    req = build_secret_scanner_adapter_request(
        action_type="  scan_prompt  ",
        target="  agent-1  ",
        prompt_text="hello world",
    )
    assert req.action_type == "scan_prompt"
    assert req.target == "agent-1"
    assert req.prompt_text == "hello world"


def test_build_request_raises_on_missing_action_type() -> None:
    with pytest.raises(ValueError, match="action_type"):
        build_secret_scanner_adapter_request(action_type="", target="agent-1")


def test_build_request_raises_on_missing_target() -> None:
    with pytest.raises(ValueError, match="target"):
        build_secret_scanner_adapter_request(action_type="scan_prompt", target="")


# ---------------------------------------------------------------------------
# scan_for_secrets — clean
# ---------------------------------------------------------------------------


def test_scan_clean_text_returns_clean_status() -> None:
    result = scan_for_secrets(prompt_text="This is a safe message.")
    assert result.scan_status == "clean"
    assert result.verdict == "allow"
    assert result.total_matches == 0


# ---------------------------------------------------------------------------
# scan_for_secrets — block-level
# ---------------------------------------------------------------------------


def test_scan_detects_openai_key_as_block() -> None:
    fake_key = "sk-" + "A" * 20 + "T3BlbkFJ" + "B" * 20
    result = scan_for_secrets(prompt_text=f"My key is {fake_key}")
    assert result.verdict == "block"
    assert result.block_matches >= 1
    assert any(m.pattern_type == "openai_api_key" for m in result.matches if m.verdict == "block")


def test_scan_detects_github_pat_as_block() -> None:
    fake_pat = "ghp_" + "A" * 36
    result = scan_for_secrets(prompt_text=f"token={fake_pat}")
    assert result.verdict == "block"
    assert any(m.pattern_type == "github_pat_classic" for m in result.matches)


def test_scan_detects_aws_access_key_as_block() -> None:
    result = scan_for_secrets(prompt_text="AKIAIOSFODNN7EXAMPLE")
    assert result.verdict == "block"
    assert any(m.pattern_type == "aws_access_key_id" for m in result.matches)


def test_scan_detects_private_key_block() -> None:
    result = scan_for_secrets(prompt_text="-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...")
    assert result.verdict == "block"
    assert any(m.pattern_type == "private_key_block" for m in result.matches)


# ---------------------------------------------------------------------------
# scan_for_secrets — matched-token blocking
# ---------------------------------------------------------------------------


def test_scan_detects_jwt_and_blocks() -> None:
    fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
    result = scan_for_secrets(prompt_text=f"auth={fake_jwt}")
    assert result.verdict == "block"
    assert result.total_matches >= 1
    assert result.scan_status == "blocked"
    assert result.block_matches == result.total_matches
    assert result.warn_matches == 0
    assert all(match.verdict == "block" for match in result.matches)


# ---------------------------------------------------------------------------
# scan_for_secrets — tool_call_arguments
# ---------------------------------------------------------------------------


def test_scan_detects_secret_in_tool_call_arguments() -> None:
    fake_key = "sk-" + "C" * 20 + "T3BlbkFJ" + "D" * 20
    result = scan_for_secrets(tool_call_arguments={"api_key": fake_key})
    assert result.verdict == "block"
    assert result.block_matches >= 1


# ---------------------------------------------------------------------------
# scan_for_secrets — file_content
# ---------------------------------------------------------------------------


def test_scan_detects_secret_in_file_content() -> None:
    fake_groq = "gsk_" + "E" * 52
    result = scan_for_secrets(file_content=f"GROQ_API_KEY={fake_groq}")
    assert result.verdict == "block"
    assert any(m.pattern_type == "groq_api_key" for m in result.matches)


# ---------------------------------------------------------------------------
# scan_for_secrets — redaction
# ---------------------------------------------------------------------------


def test_scan_redacts_matched_value() -> None:
    fake_key = "sk-" + "F" * 20 + "T3BlbkFJ" + "G" * 20
    result = scan_for_secrets(prompt_text=fake_key)
    for match in result.matches:
        assert fake_key not in match.matched_value_redacted
        assert "*" in match.matched_value_redacted


# ---------------------------------------------------------------------------
# SecretScannerAdapter.execute — accepted (clean)
# ---------------------------------------------------------------------------


def test_adapter_execute_clean_payload_returns_accepted() -> None:
    adapter = _make_adapter()
    req = AdapterExecutionRequest(
        action_type="scan_prompt",
        target="agent-test",
        payload={"prompt_text": "Hello, world."},
    )
    result = adapter.execute(req)
    assert result.status == "accepted"
    assert result.success is True


# ---------------------------------------------------------------------------
# SecretScannerAdapter.execute — blocked
# ---------------------------------------------------------------------------


def test_adapter_execute_blocked_on_secret() -> None:
    adapter = _make_adapter()
    fake_key = "sk-" + "H" * 20 + "T3BlbkFJ" + "I" * 20
    req = AdapterExecutionRequest(
        action_type="scan_prompt",
        target="agent-test",
        payload={"prompt_text": f"My key: {fake_key}"},
    )
    result = adapter.execute(req)
    assert result.status == "blocked"
    assert result.success is False


def test_adapter_execute_blocks_jwt_match() -> None:
    adapter = _make_adapter()
    fake_jwt = "eyJ" + "A" * 12 + "." + "B" * 8 + "." + "C" * 8
    req = AdapterExecutionRequest(
        action_type="scan_prompt",
        target="agent-test",
        payload={"prompt_text": f"auth={fake_jwt}"},
    )

    result = adapter.execute(req)

    assert result.status == "blocked"
    assert result.success is False
    assert result.output["scan_result"]["verdict"] == "block"
    assert result.output["scan_result"]["warn_matches"] == 0


def test_policy_adapter_blocks_jwt_match() -> None:
    req = build_secret_scanner_adapter_request(
        action_type="scan_prompt",
        target="agent-test",
        prompt_text="eyJ" + "A" * 12 + "." + "B" * 8 + "." + "C" * 8,
    )

    response = evaluate_secret_scanner_request(initialize_policy_engine(), req)

    assert response.verdict == "block"
    assert response.should_warn is False
    assert response.should_quarantine is False
    assert response.should_block is True
    assert response.warn_matches == 0
    assert response.risk_score >= RISK_THRESHOLD_BLOCK_MIN


# ---------------------------------------------------------------------------
# SecretScannerAdapter.execute — offline guard
# ---------------------------------------------------------------------------


def test_adapter_execute_offline_returns_offline() -> None:
    adapter = _make_adapter()
    adapter.health = "offline"
    req = AdapterExecutionRequest(
        action_type="scan_prompt",
        target="agent-test",
        payload={"prompt_text": "any content"},
    )
    result = adapter.execute(req)
    assert result.status == "offline"
    assert result.success is False


# ---------------------------------------------------------------------------
# SecretScannerAdapterResponse — required fields including should_quarantine
# ---------------------------------------------------------------------------


def test_secret_scanner_adapter_response_required_fields() -> None:
    resp = SecretScannerAdapterResponse(
        adapter_name="ironclaw-secret-scanner",
        platform="secret-scanner",
        mode="enforce",
        verdict="allow",
        should_allow=True,
        should_warn=False,
        should_quarantine=False,
        should_block=False,
        scan_status="clean",
        risk_score=0,
        risk_level="low",
        summary="No secrets detected.",
        total_matches=0,
        block_matches=0,
        warn_matches=0,
    )
    assert resp.should_quarantine is False
    assert resp.verdict == "allow"


# ---------------------------------------------------------------------------
# SecretScannerAdapterRequest.to_policy_input
# ---------------------------------------------------------------------------


def test_secret_scanner_request_to_policy_input_maps_fields() -> None:
    req = SecretScannerAdapterRequest(
        action_type="scan_prompt",
        target="agent-42",
        content="scan this",
        agent_id="agent-42",
        session_id="session-99",
    )
    policy_input = req.to_policy_input()
    assert policy_input.action_type == "scan_prompt"
    assert policy_input.agent_id == "agent-42"
    assert policy_input.session_id == "session-99"


# ---------------------------------------------------------------------------
# SecretScannerAdapterRequest.model_dump
# ---------------------------------------------------------------------------


def test_secret_scanner_request_model_dump_is_complete() -> None:
    req = SecretScannerAdapterRequest(
        action_type="scan_tool_call",
        target="tool-runner",
        metadata={"env": "test"},
    )
    dumped = req.model_dump()
    assert dumped["action_type"] == "scan_tool_call"
    assert dumped["target"] == "tool-runner"
    assert dumped["metadata"] == {"env": "test"}
    assert "agent_id" in dumped
    assert "session_id" in dumped


# ---------------------------------------------------------------------------
# summarize_secret_scanner_adapter_response shape
# ---------------------------------------------------------------------------


def test_summarize_secret_scanner_adapter_response_shape() -> None:
    resp = SecretScannerAdapterResponse(
        adapter_name="ironclaw-secret-scanner",
        platform="secret-scanner",
        mode="enforce",
        verdict="block",
        should_allow=False,
        should_warn=False,
        should_quarantine=False,
        should_block=True,
        scan_status="blocked",
        risk_score=90,
        risk_level="critical",
        summary="Secret detected and blocked.",
        total_matches=1,
        block_matches=1,
        warn_matches=0,
    )
    summary = summarize_secret_scanner_adapter_response(resp)
    assert summary["verdict"] == "block"
    assert summary["risk_score"] == 90
    assert summary["risk_level"] == "critical"
    assert "decision_id" in summary
    assert "trace_id" in summary
    assert "reviewed_at" in summary


# ---------------------------------------------------------------------------
# supported_action_types
# ---------------------------------------------------------------------------


def test_adapter_supported_action_types() -> None:
    adapter = _make_adapter()
    types = adapter.supported_action_types()
    assert "scan_prompt" in types
    assert "scan_tool_call" in types
    assert "scan_file_content" in types
