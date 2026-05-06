from __future__ import annotations

import json
from typing import Any

import pytest

from ironclaw_skill.adapter_claude import (
    ClaudeAdapterError,
    adapt_claude_request,
    adapt_claude_response,
    build_claude_error_response,
    build_claude_success_response,
    claude_tool_input_schema,
)
from ironclaw_skill.adapter_openclaw import (
    OpenClawAdapterError,
    adapt_openclaw_request,
    adapt_openclaw_response,
    build_openclaw_error_response,
    build_openclaw_success_response,
    openclaw_tool_input_schema,
)
from ironclaw_skill.contracts import (
    SkillActionDecisionRequest,
    SkillActionPolicyRequest,
    SkillExecuteRequest,
    SkillScanRequest,
    build_skill_error_response,
    build_skill_success_response,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

OPERATIONS = ("scan", "action_policy", "action_decision", "execute")


def _scan_payload(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"operation": "scan", "target_value": "test content"}
    base.update(overrides)
    return base


def _action_payload(operation: str = "action_policy", **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"operation": operation, "action_type": "shell_command", "target": "/bin/ls"}
    base.update(overrides)
    return base


def _execute_payload(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "operation": "execute",
        "action_type": "shell_command",
        "target": "/bin/ls",
        "require_confirmation": True,
    }
    base.update(overrides)
    return base


def _success_envelope(operation: str = "scan") -> Any:
    return build_skill_success_response(
        operation=operation,  # type: ignore[arg-type]
        verdict="allow",
        summary="All clear.",
        decision_source="policy",
    )


def _error_envelope(operation: str = "scan") -> Any:
    return build_skill_error_response(
        operation=operation,  # type: ignore[arg-type]
        summary="Something failed.",
        error_code="SKILL_ERROR",
    )


# ---------------------------------------------------------------------------
# Registry contract — both adapters expose the same four operations
# ---------------------------------------------------------------------------


class TestAdapterRegistryOperationParity:
    """Both adapters must accept all four canonical operations."""

    @pytest.mark.parametrize("operation", OPERATIONS)
    def test_claude_accepts_operation(self, operation: str):
        if operation in ("scan",):
            raw = _scan_payload(operation=operation)
        elif operation == "execute":
            raw = _execute_payload()
        else:
            raw = _action_payload(operation=operation)
        req = adapt_claude_request(raw)
        assert req is not None

    @pytest.mark.parametrize("operation", OPERATIONS)
    def test_openclaw_accepts_operation(self, operation: str):
        if operation in ("scan",):
            raw = _scan_payload(operation=operation)
        elif operation == "execute":
            raw = _execute_payload()
        else:
            raw = _action_payload(operation=operation)
        req = adapt_openclaw_request(raw)
        assert req is not None

    @pytest.mark.parametrize("operation", OPERATIONS)
    def test_both_adapters_return_same_request_type(self, operation: str):
        if operation == "scan":
            raw = _scan_payload(operation=operation)
            expected_type = SkillScanRequest
        elif operation == "action_policy":
            raw = _action_payload(operation=operation)
            expected_type = SkillActionPolicyRequest
        elif operation == "action_decision":
            raw = _action_payload(operation=operation)
            expected_type = SkillActionDecisionRequest
        else:
            raw = _execute_payload()
            expected_type = SkillExecuteRequest

        claude_req = adapt_claude_request(raw)
        openclaw_req = adapt_openclaw_request(raw)
        assert type(claude_req) is type(openclaw_req)
        assert isinstance(claude_req, expected_type)


# ---------------------------------------------------------------------------
# Registry contract — source_platform stamped correctly per adapter
# ---------------------------------------------------------------------------


class TestAdapterRegistrySourcePlatform:
    def test_claude_stamps_platform_claude(self):
        req = adapt_claude_request(_scan_payload())
        assert req.context.source_platform == "claude"

    def test_openclaw_stamps_platform_openclaw(self):
        req = adapt_openclaw_request(_scan_payload())
        assert req.context.source_platform == "openclaw"

    @pytest.mark.parametrize("operation", OPERATIONS)
    def test_claude_source_platform_stable_across_operations(self, operation: str):
        if operation == "scan":
            raw = _scan_payload(operation=operation)
        elif operation == "execute":
            raw = _execute_payload()
        else:
            raw = _action_payload(operation=operation)
        req = adapt_claude_request(raw)
        assert req.context.source_platform == "claude"

    @pytest.mark.parametrize("operation", OPERATIONS)
    def test_openclaw_source_platform_stable_across_operations(self, operation: str):
        if operation == "scan":
            raw = _scan_payload(operation=operation)
        elif operation == "execute":
            raw = _execute_payload()
        else:
            raw = _action_payload(operation=operation)
        req = adapt_openclaw_request(raw)
        assert req.context.source_platform == "openclaw"


# ---------------------------------------------------------------------------
# Registry contract — error type isolation (no cross-contamination)
# ---------------------------------------------------------------------------


class TestAdapterRegistryErrorIsolation:
    def test_claude_invalid_payload_raises_claude_error(self):
        with pytest.raises(ClaudeAdapterError):
            adapt_claude_request("not a dict")  # type: ignore[arg-type]

    def test_openclaw_invalid_payload_raises_openclaw_error(self):
        with pytest.raises(OpenClawAdapterError):
            adapt_openclaw_request("not a dict")  # type: ignore[arg-type]

    def test_claude_unsupported_operation_raises_claude_error(self):
        with pytest.raises(ClaudeAdapterError, match="Unsupported Claude operation"):
            adapt_claude_request({"operation": "destroy_everything"})

    def test_openclaw_unsupported_operation_raises_openclaw_error(self):
        with pytest.raises(OpenClawAdapterError, match="Unsupported OpenClaw operation"):
            adapt_openclaw_request({"operation": "destroy_everything"})

    def test_claude_error_is_not_openclaw_error(self):
        assert not issubclass(ClaudeAdapterError, OpenClawAdapterError)

    def test_openclaw_error_is_not_claude_error(self):
        assert not issubclass(OpenClawAdapterError, ClaudeAdapterError)

    def test_both_errors_are_runtime_errors(self):
        assert issubclass(ClaudeAdapterError, RuntimeError)
        assert issubclass(OpenClawAdapterError, RuntimeError)


# ---------------------------------------------------------------------------
# Registry contract — response shape divergence (ok vs success)
# ---------------------------------------------------------------------------


class TestAdapterRegistryResponseShape:
    def test_claude_response_has_ok_field(self):
        envelope = _success_envelope()
        result = adapt_claude_response(envelope)
        assert "ok" in result

    def test_openclaw_response_has_success_field(self):
        envelope = _success_envelope()
        result = adapt_openclaw_response(envelope)
        assert "success" in result

    def test_claude_response_no_success_key(self):
        envelope = _success_envelope()
        result = adapt_claude_response(envelope)
        assert "success" not in result

    def test_openclaw_response_no_ok_key(self):
        envelope = _success_envelope()
        result = adapt_openclaw_response(envelope)
        assert "ok" not in result

    def test_claude_response_verdict_top_level(self):
        envelope = _success_envelope()
        result = adapt_claude_response(envelope)
        assert "verdict" in result

    def test_openclaw_response_verdict_nested_in_result(self):
        envelope = _success_envelope()
        result = adapt_openclaw_response(envelope)
        assert "result" in result
        assert "verdict" in result["result"]

    def test_claude_response_reasons_top_level(self):
        envelope = _success_envelope()
        result = adapt_claude_response(envelope)
        assert "reasons" in result

    def test_openclaw_response_reasons_nested_in_result(self):
        envelope = _success_envelope()
        result = adapt_openclaw_response(envelope)
        assert "reasons" in result["result"]

    def test_claude_response_scan_id_top_level(self):
        envelope = _success_envelope()
        result = adapt_claude_response(envelope)
        assert "scan_id" in result

    def test_openclaw_response_scan_id_nested(self):
        envelope = _success_envelope()
        result = adapt_openclaw_response(envelope)
        assert "scan_id" in result["result"]

    @pytest.mark.parametrize("operation", OPERATIONS)
    def test_claude_response_ok_true_on_success(self, operation: str):
        envelope = _success_envelope(operation)
        result = adapt_claude_response(envelope)
        assert result["ok"] is True

    @pytest.mark.parametrize("operation", OPERATIONS)
    def test_openclaw_response_success_true_on_success(self, operation: str):
        envelope = _success_envelope(operation)
        result = adapt_openclaw_response(envelope)
        assert result["success"] is True

    @pytest.mark.parametrize("operation", OPERATIONS)
    def test_claude_response_ok_false_on_error(self, operation: str):
        envelope = _error_envelope(operation)
        result = adapt_claude_response(envelope)
        assert result["ok"] is False

    @pytest.mark.parametrize("operation", OPERATIONS)
    def test_openclaw_response_success_false_on_error(self, operation: str):
        envelope = _error_envelope(operation)
        result = adapt_openclaw_response(envelope)
        assert result["success"] is False


# ---------------------------------------------------------------------------
# Registry contract — both response helpers are JSON-serializable
# ---------------------------------------------------------------------------


class TestAdapterRegistryJsonSerializability:
    @pytest.mark.parametrize("operation", OPERATIONS)
    def test_claude_success_response_serializable(self, operation: str):
        result = build_claude_success_response(
            operation=operation,  # type: ignore[arg-type]
            verdict="allow",
            summary="ok",
        )
        assert json.dumps(result)

    @pytest.mark.parametrize("operation", OPERATIONS)
    def test_openclaw_success_response_serializable(self, operation: str):
        result = build_openclaw_success_response(
            operation=operation,  # type: ignore[arg-type]
            verdict="allow",
            summary="ok",
        )
        assert json.dumps(result)

    @pytest.mark.parametrize("operation", OPERATIONS)
    def test_claude_error_response_serializable(self, operation: str):
        result = build_claude_error_response(
            operation=operation,  # type: ignore[arg-type]
            summary="fail",
            error_code="ERR",
        )
        assert json.dumps(result)

    @pytest.mark.parametrize("operation", OPERATIONS)
    def test_openclaw_error_response_serializable(self, operation: str):
        result = build_openclaw_error_response(
            operation=operation,  # type: ignore[arg-type]
            summary="fail",
            error_code="ERR",
        )
        assert json.dumps(result)


# ---------------------------------------------------------------------------
# Claude adapter — adapt_claude_request detail
# ---------------------------------------------------------------------------


class TestClaudeAdapterRequest:
    def test_default_operation_is_scan(self):
        req = adapt_claude_request({"target_value": "hello"})
        assert isinstance(req, SkillScanRequest)

    def test_scan_target_value_mapped(self):
        req = adapt_claude_request(_scan_payload(target_value="hello world"))
        assert isinstance(req, SkillScanRequest)
        assert req.input.target_value == "hello world"

    def test_scan_content_field_alias(self):
        req = adapt_claude_request({"operation": "scan", "content": "alias content"})
        assert isinstance(req, SkillScanRequest)
        assert req.input.target_value == "alias content"

    def test_scan_policy_mode_default_review(self):
        req = adapt_claude_request(_scan_payload())
        assert isinstance(req, SkillScanRequest)
        assert req.input.policy_mode == "review"

    def test_scan_policy_mode_override(self):
        req = adapt_claude_request(_scan_payload(policy_mode="block"))
        assert isinstance(req, SkillScanRequest)
        assert req.input.policy_mode == "block"

    def test_scan_target_type_default_text(self):
        req = adapt_claude_request(_scan_payload())
        assert isinstance(req, SkillScanRequest)
        assert req.input.target_type == "text"

    def test_scan_bundle_alias_normalizes_to_prompt_bundle(self):
        payload = {
            "operation": "scan",
            "target_type": "bundle",
            "bundle": {"user_prompt": "hello"},
        }
        req = adapt_claude_request(payload)
        assert isinstance(req, SkillScanRequest)
        assert req.input.target_type == "prompt_bundle"

    def test_scan_prompt_bundle_missing_bundle_raises(self):
        with pytest.raises(ClaudeAdapterError, match="bundle"):
            adapt_claude_request({"operation": "scan", "target_type": "prompt_bundle"})

    def test_action_policy_request_type(self):
        req = adapt_claude_request(_action_payload("action_policy"))
        assert isinstance(req, SkillActionPolicyRequest)

    def test_action_decision_request_type(self):
        req = adapt_claude_request(_action_payload("action_decision"))
        assert isinstance(req, SkillActionDecisionRequest)

    def test_execute_request_type(self):
        req = adapt_claude_request(_execute_payload())
        assert isinstance(req, SkillExecuteRequest)

    def test_execute_require_confirmation_mapped(self):
        req = adapt_claude_request(_execute_payload(require_confirmation=True))
        assert isinstance(req, SkillExecuteRequest)
        assert req.input.require_confirmation is True

    def test_execute_allow_side_effects_mapped(self):
        req = adapt_claude_request(_execute_payload(allow_side_effects=True))
        assert isinstance(req, SkillExecuteRequest)
        assert req.input.allow_side_effects is True

    def test_context_client_id_mapped(self):
        raw = _scan_payload(context={"client_id": "cid-1"})
        req = adapt_claude_request(raw)
        assert req.context.client_id == "cid-1"

    def test_context_request_id_mapped(self):
        raw = _scan_payload(context={"request_id": "req-abc"})
        req = adapt_claude_request(raw)
        assert req.context.request_id == "req-abc"

    def test_context_tenant_id_mapped(self):
        raw = _scan_payload(context={"tenant_id": "tenant-x"})
        req = adapt_claude_request(raw)
        assert req.context.tenant_id == "tenant-x"

    def test_context_tags_mapped(self):
        raw = _scan_payload(context={"tags": ["a", "b"]})
        req = adapt_claude_request(raw)
        assert req.context.tags == ["a", "b"]

    def test_action_dry_run_defaults_false(self):
        req = adapt_claude_request(_action_payload())
        assert isinstance(req, SkillActionPolicyRequest)
        assert req.input.dry_run is False

    def test_action_dry_run_true(self):
        req = adapt_claude_request(_action_payload(dry_run=True))
        assert isinstance(req, SkillActionPolicyRequest)
        assert req.input.dry_run is True

    def test_action_target_default_unspecified(self):
        req = adapt_claude_request({"operation": "action_policy", "action_type": "shell_command"})
        assert isinstance(req, SkillActionPolicyRequest)
        assert req.input.target == "unspecified"


# ---------------------------------------------------------------------------
# Claude adapter — adapt_claude_response detail
# ---------------------------------------------------------------------------


class TestClaudeAdapterResponse:
    def test_verdict_present(self):
        result = adapt_claude_response(_success_envelope())
        assert result["verdict"] == "allow"

    def test_summary_present(self):
        result = adapt_claude_response(_success_envelope())
        assert result["summary"] == "All clear."

    def test_operation_field_present(self):
        result = adapt_claude_response(_success_envelope("execute"))
        assert result["operation"] == "execute"

    def test_should_halt_present(self):
        result = adapt_claude_response(_success_envelope())
        assert "should_halt" in result

    def test_should_warn_present(self):
        result = adapt_claude_response(_success_envelope())
        assert "should_warn" in result

    def test_allowed_present(self):
        result = adapt_claude_response(_success_envelope())
        assert "allowed" in result

    def test_reasons_is_list(self):
        result = adapt_claude_response(_success_envelope())
        assert isinstance(result["reasons"], list)

    def test_matched_patterns_present(self):
        result = adapt_claude_response(_success_envelope())
        assert "matched_patterns" in result

    def test_risk_score_present(self):
        result = adapt_claude_response(_success_envelope())
        assert "risk_score" in result

    def test_decision_source_present(self):
        result = adapt_claude_response(_success_envelope())
        assert "decision_source" in result

    def test_error_response_ok_false(self):
        result = adapt_claude_response(_error_envelope())
        assert result["ok"] is False

    def test_error_code_present(self):
        result = adapt_claude_response(_error_envelope())
        assert result["error_code"] == "SKILL_ERROR"


# ---------------------------------------------------------------------------
# Claude adapter — build_claude_success_response / build_claude_error_response
# ---------------------------------------------------------------------------


class TestBuildClaudeResponses:
    def test_success_verdict_allow(self):
        r = build_claude_success_response(operation="scan", verdict="allow", summary="ok")
        assert r["verdict"] == "allow"

    def test_success_verdict_block(self):
        r = build_claude_success_response(operation="scan", verdict="block", summary="blocked")
        assert r["verdict"] == "block"

    def test_success_ok_true(self):
        r = build_claude_success_response(operation="scan", verdict="allow", summary="ok")
        assert r["ok"] is True

    def test_error_ok_false(self):
        r = build_claude_error_response(operation="scan", summary="fail", error_code="ERR_X")
        assert r["ok"] is False

    def test_error_code_propagated(self):
        r = build_claude_error_response(operation="scan", summary="fail", error_code="ERR_X")
        assert r["error_code"] == "ERR_X"

    def test_success_scan_id_propagated(self):
        r = build_claude_success_response(operation="scan", verdict="allow", summary="ok", scan_id="sid-1")
        assert r["scan_id"] == "sid-1"

    def test_success_risk_score_propagated(self):
        r = build_claude_success_response(operation="scan", verdict="review", summary="check", risk_score=42)
        assert r["risk_score"] == 42

    def test_success_request_id_propagated(self):
        r = build_claude_success_response(operation="scan", verdict="allow", summary="ok", request_id="req-1")
        assert r["request_id"] == "req-1"

    def test_success_matched_patterns_propagated(self):
        r = build_claude_success_response(
            operation="scan", verdict="block", summary="blocked", matched_patterns=["p1", "p2"]
        )
        assert r["matched_patterns"] == ["p1", "p2"]

    def test_error_reasons_list(self):
        r = build_claude_error_response(operation="scan", summary="fail", error_code="ERR")
        assert isinstance(r["reasons"], list)
        assert len(r["reasons"]) >= 1

    def test_error_reason_label_is_claude_adapter_error(self):
        r = build_claude_error_response(operation="scan", summary="fail", error_code="ERR")
        assert r["reasons"][0]["label"] == "Claude adapter error"


# ---------------------------------------------------------------------------
# OpenClaw adapter — adapt_openclaw_request detail
# ---------------------------------------------------------------------------


class TestOpenClawAdapterRequest:
    def test_default_operation_is_scan_when_no_fields(self):
        req = adapt_openclaw_request({})
        assert isinstance(req, SkillScanRequest)

    def test_operation_from_tool_name(self):
        req = adapt_openclaw_request({"tool_name": "execute", "action_type": "shell_command"})
        assert isinstance(req, SkillExecuteRequest)

    def test_operation_from_mode_field(self):
        req = adapt_openclaw_request({"mode": "action_policy", "action_type": "shell_command"})
        assert isinstance(req, SkillActionPolicyRequest)

    def test_scan_content_type_alias(self):
        req = adapt_openclaw_request({"operation": "scan", "content_type": "url", "url": "http://example.com"})
        assert isinstance(req, SkillScanRequest)
        assert req.input.target_type == "url"

    def test_scan_input_field_alias(self):
        req = adapt_openclaw_request({"operation": "scan", "input": "from input field"})
        assert isinstance(req, SkillScanRequest)
        assert req.input.target_value == "from input field"

    def test_scan_text_field_alias(self):
        req = adapt_openclaw_request({"operation": "scan", "text": "from text field"})
        assert isinstance(req, SkillScanRequest)
        assert req.input.target_value == "from text field"

    def test_scan_url_field_alias(self):
        req = adapt_openclaw_request({"operation": "scan", "target_type": "url", "url": "http://test.com"})
        assert isinstance(req, SkillScanRequest)
        assert req.input.target_value == "http://test.com"

    def test_scan_bundle_alias(self):
        payload = {
            "operation": "scan",
            "target_type": "bundle",
            "bundle": {"user_prompt": "hi"},
        }
        req = adapt_openclaw_request(payload)
        assert isinstance(req, SkillScanRequest)
        assert req.input.target_type == "prompt_bundle"

    def test_scan_bundle_prompt_alias(self):
        payload = {
            "operation": "scan",
            "target_type": "prompt_bundle",
            "bundle": {"prompt": "aliased prompt"},
        }
        req = adapt_openclaw_request(payload)
        assert isinstance(req, SkillScanRequest)
        assert req.input.bundle is not None
        assert req.input.bundle.user_prompt == "aliased prompt"

    def test_scan_bundle_retrieval_alias(self):
        payload = {
            "operation": "scan",
            "target_type": "prompt_bundle",
            "bundle": {"retrieval": "retrieved doc"},
        }
        req = adapt_openclaw_request(payload)
        assert isinstance(req, SkillScanRequest)
        assert req.input.bundle is not None
        assert req.input.bundle.retrieved_doc == "retrieved doc"

    def test_scan_bundle_assistant_output_alias(self):
        payload = {
            "operation": "scan",
            "target_type": "prompt_bundle",
            "bundle": {"assistant_output": "model response"},
        }
        req = adapt_openclaw_request(payload)
        assert isinstance(req, SkillScanRequest)
        assert req.input.bundle is not None
        assert req.input.bundle.model_output == "model response"

    def test_action_kind_alias(self):
        req = adapt_openclaw_request({"operation": "action_policy", "kind": "file_write", "target": "/tmp/x"})
        assert isinstance(req, SkillActionPolicyRequest)
        assert req.input.action_type == "file_write"

    def test_action_tool_kind_alias(self):
        req = adapt_openclaw_request({"operation": "action_policy", "tool_kind": "network_request"})
        assert isinstance(req, SkillActionPolicyRequest)
        assert req.input.action_type == "network_request"

    def test_action_command_alias_for_target(self):
        req = adapt_openclaw_request({"operation": "action_policy", "command": "ls -la"})
        assert isinstance(req, SkillActionPolicyRequest)
        assert req.input.target == "ls -la"

    def test_action_endpoint_alias_for_target(self):
        req = adapt_openclaw_request({"operation": "action_policy", "endpoint": "/api/v1/test"})
        assert isinstance(req, SkillActionPolicyRequest)
        assert req.input.target == "/api/v1/test"

    def test_action_payload_alias_for_content(self):
        req = adapt_openclaw_request({"operation": "action_policy", "payload": "raw data"})
        assert isinstance(req, SkillActionPolicyRequest)
        assert req.input.content == "raw data"

    def test_action_body_alias_for_content(self):
        req = adapt_openclaw_request({"operation": "action_policy", "body": "body content"})
        assert isinstance(req, SkillActionPolicyRequest)
        assert req.input.content == "body content"

    def test_action_code_alias_for_content(self):
        req = adapt_openclaw_request({"operation": "action_policy", "code": "print('hi')"})
        assert isinstance(req, SkillActionPolicyRequest)
        assert req.input.content == "print('hi')"

    def test_context_agent_id_maps_to_client_id(self):
        req = adapt_openclaw_request(_scan_payload(context={"agent_id": "agent-1"}))
        assert req.context.client_id == "agent-1"

    def test_context_conversation_id_maps_to_session_id(self):
        req = adapt_openclaw_request(_scan_payload(context={"conversation_id": "conv-1"}))
        assert req.context.session_id == "conv-1"

    def test_context_workspace_id_maps_to_tenant_id(self):
        req = adapt_openclaw_request(_scan_payload(context={"workspace_id": "ws-1"}))
        assert req.context.tenant_id == "ws-1"

    def test_context_trace_id_maps_to_request_id(self):
        req = adapt_openclaw_request(_scan_payload(context={"trace_id": "trace-1"}))
        assert req.context.request_id == "trace-1"

    def test_context_agent_version_maps_to_source_version(self):
        req = adapt_openclaw_request(_scan_payload(context={"agent_version": "1.2.3"}))
        assert req.context.source_version == "1.2.3"

    def test_context_tags_from_csv_string(self):
        req = adapt_openclaw_request(_scan_payload(context={"tags": "a,b,c"}))
        assert req.context.tags == ["a", "b", "c"]

    def test_context_tags_from_list(self):
        req = adapt_openclaw_request(_scan_payload(context={"tags": ["x", "y"]}))
        assert req.context.tags == ["x", "y"]

    def test_context_tags_empty_string_gives_empty_list(self):
        req = adapt_openclaw_request(_scan_payload(context={"tags": ""}))
        assert req.context.tags == []


# ---------------------------------------------------------------------------
# OpenClaw adapter — adapt_openclaw_response detail
# ---------------------------------------------------------------------------


class TestOpenClawAdapterResponse:
    def test_result_verdict_allow(self):
        result = adapt_openclaw_response(_success_envelope())
        assert result["result"]["verdict"] == "allow"

    def test_result_summary_present(self):
        result = adapt_openclaw_response(_success_envelope())
        assert result["result"]["summary"] == "All clear."

    def test_operation_field_present(self):
        result = adapt_openclaw_response(_success_envelope("execute"))
        assert result["operation"] == "execute"

    def test_result_should_halt_present(self):
        result = adapt_openclaw_response(_success_envelope())
        assert "should_halt" in result["result"]

    def test_result_should_warn_present(self):
        result = adapt_openclaw_response(_success_envelope())
        assert "should_warn" in result["result"]

    def test_result_allowed_present(self):
        result = adapt_openclaw_response(_success_envelope())
        assert "allowed" in result["result"]

    def test_result_reasons_is_list(self):
        result = adapt_openclaw_response(_success_envelope())
        assert isinstance(result["result"]["reasons"], list)

    def test_result_matched_patterns_present(self):
        result = adapt_openclaw_response(_success_envelope())
        assert "matched_patterns" in result["result"]

    def test_result_risk_score_present(self):
        result = adapt_openclaw_response(_success_envelope())
        assert "risk_score" in result["result"]

    def test_result_decision_source_present(self):
        result = adapt_openclaw_response(_success_envelope())
        assert "decision_source" in result["result"]

    def test_error_response_success_false(self):
        result = adapt_openclaw_response(_error_envelope())
        assert result["success"] is False

    def test_error_code_present(self):
        result = adapt_openclaw_response(_error_envelope())
        assert result["error_code"] == "SKILL_ERROR"


# ---------------------------------------------------------------------------
# OpenClaw adapter — build_openclaw_success_response / build_openclaw_error_response
# ---------------------------------------------------------------------------


class TestBuildOpenClawResponses:
    def test_success_result_verdict_allow(self):
        r = build_openclaw_success_response(operation="scan", verdict="allow", summary="ok")
        assert r["result"]["verdict"] == "allow"

    def test_success_result_verdict_block(self):
        r = build_openclaw_success_response(operation="scan", verdict="block", summary="blocked")
        assert r["result"]["verdict"] == "block"

    def test_success_success_true(self):
        r = build_openclaw_success_response(operation="scan", verdict="allow", summary="ok")
        assert r["success"] is True

    def test_error_success_false(self):
        r = build_openclaw_error_response(operation="scan", summary="fail", error_code="ERR_X")
        assert r["success"] is False

    def test_error_code_propagated(self):
        r = build_openclaw_error_response(operation="scan", summary="fail", error_code="ERR_X")
        assert r["error_code"] == "ERR_X"

    def test_success_scan_id_propagated(self):
        r = build_openclaw_success_response(operation="scan", verdict="allow", summary="ok", scan_id="sid-2")
        assert r["result"]["scan_id"] == "sid-2"

    def test_success_risk_score_propagated(self):
        r = build_openclaw_success_response(operation="scan", verdict="review", summary="check", risk_score=77)
        assert r["result"]["risk_score"] == 77

    def test_success_request_id_propagated(self):
        r = build_openclaw_success_response(operation="scan", verdict="allow", summary="ok", request_id="req-2")
        assert r["request_id"] == "req-2"

    def test_success_matched_patterns_propagated(self):
        r = build_openclaw_success_response(
            operation="scan", verdict="block", summary="blocked", matched_patterns=["p1"]
        )
        assert r["result"]["matched_patterns"] == ["p1"]

    def test_error_reasons_list(self):
        r = build_openclaw_error_response(operation="scan", summary="fail", error_code="ERR")
        assert isinstance(r["result"]["reasons"], list)
        assert len(r["result"]["reasons"]) >= 1

    def test_error_reason_label_is_openclaw_adapter_error(self):
        r = build_openclaw_error_response(operation="scan", summary="fail", error_code="ERR")
        assert r["result"]["reasons"][0]["label"] == "OpenClaw adapter error"


# ---------------------------------------------------------------------------
# Tool input schema — structural registry contracts
# ---------------------------------------------------------------------------


class TestAdapterRegistryToolInputSchema:
    def test_claude_schema_is_dict(self):
        schema = claude_tool_input_schema()
        assert isinstance(schema, dict)

    def test_openclaw_schema_is_dict(self):
        schema = openclaw_tool_input_schema()
        assert isinstance(schema, dict)

    def test_claude_schema_type_is_object(self):
        assert claude_tool_input_schema()["type"] == "object"

    def test_openclaw_schema_type_is_object(self):
        assert openclaw_tool_input_schema()["type"] == "object"

    def test_claude_schema_required_contains_operation(self):
        schema = claude_tool_input_schema()
        assert "operation" in schema.get("required", [])

    def test_openclaw_schema_required_is_empty(self):
        schema = openclaw_tool_input_schema()
        assert schema.get("required", []) == []

    def test_claude_schema_operation_enum(self):
        schema = claude_tool_input_schema()
        ops = schema["properties"]["operation"]["enum"]
        assert set(ops) == {"scan", "action_policy", "action_decision", "execute"}

    def test_openclaw_schema_operation_enum(self):
        schema = openclaw_tool_input_schema()
        ops = schema["properties"]["operation"]["enum"]
        assert set(ops) == {"scan", "action_policy", "action_decision", "execute"}

    def test_openclaw_schema_has_tool_name_property(self):
        schema = openclaw_tool_input_schema()
        assert "tool_name" in schema["properties"]

    def test_openclaw_schema_has_mode_property(self):
        schema = openclaw_tool_input_schema()
        assert "mode" in schema["properties"]

    def test_claude_schema_has_no_tool_name_property(self):
        schema = claude_tool_input_schema()
        assert "tool_name" not in schema["properties"]

    def test_claude_schema_has_no_mode_property(self):
        schema = claude_tool_input_schema()
        assert "mode" not in schema["properties"]

    def test_claude_schema_serializable(self):
        assert json.dumps(claude_tool_input_schema())

    def test_openclaw_schema_serializable(self):
        assert json.dumps(openclaw_tool_input_schema())

    def test_claude_schema_additional_properties_false(self):
        assert claude_tool_input_schema()["additionalProperties"] is False

    def test_openclaw_schema_additional_properties_false(self):
        assert openclaw_tool_input_schema()["additionalProperties"] is False

    def test_both_schemas_have_context_property(self):
        assert "context" in claude_tool_input_schema()["properties"]
        assert "context" in openclaw_tool_input_schema()["properties"]

    def test_openclaw_context_has_agent_id(self):
        schema = openclaw_tool_input_schema()
        assert "agent_id" in schema["properties"]["context"]["properties"]

    def test_claude_context_has_no_agent_id(self):
        schema = claude_tool_input_schema()
        assert "agent_id" not in schema["properties"]["context"]["properties"]

    def test_openclaw_context_tags_supports_string_or_array(self):
        schema = openclaw_tool_input_schema()
        tags_schema = schema["properties"]["context"]["properties"]["tags"]
        assert "oneOf" in tags_schema

    def test_claude_context_tags_is_array_only(self):
        schema = claude_tool_input_schema()
        tags_schema = schema["properties"]["context"]["properties"]["tags"]
        assert tags_schema["type"] == "array"