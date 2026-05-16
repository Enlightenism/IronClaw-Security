from __future__ import annotations

import pytest

from app.adapters.base import AdapterExecutionRequest
from app.adapters.cape_adapter import (
    CapeAdapter,
    CapeAdapterRequest,
    CapeAdapterResponse,
    adapt_policy_decision_to_cape,
    build_cape_adapter_request,
    evaluate_cape_request,
    summarize_cape_adapter_response,
)
from app.orchestrator.policy_enforcer import PolicyDecision, PolicyEngine
from app.services.integration_registry import IntegrationRecord

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _make_record(**kwargs) -> IntegrationRecord:
    defaults = dict(
        integration_id="integration-cape",
        name="CAPE Sandbox",
        slug="cape",
        platform="cape",
        integration_type="sandbox",
        status="active",
        capabilities=[],
        metadata={},
    )
    defaults.update(kwargs)
    return IntegrationRecord(**defaults)


def _make_adapter(**kwargs) -> CapeAdapter:
    record = _make_record()
    base = dict(
        record=record,
        protocol_version="1.0.0",
        health="ready",
        metadata={},
    )
    base.update(kwargs)
    return CapeAdapter(**base)


def _make_exec_request(action_type: str = "submit_sample", target: str = "malware.exe") -> AdapterExecutionRequest:
    return AdapterExecutionRequest(action_type=action_type, target=target)


def _make_decision(
    verdict: str = "allow",
    risk_score: int = 0,
    mode: str = "enforce",
) -> PolicyDecision:
    allow_execution = verdict in {"allow", "warn"} if mode == "enforce" else True
    requires_review = verdict in {"warn", "quarantine"}
    return PolicyDecision(
        decision_id="dec-001",
        verdict=verdict,
        risk_score=risk_score,
        risk_level="low" if risk_score < 40 else "high",
        mode=mode,
        allow_execution=allow_execution,
        requires_review=requires_review,
        summary=f"verdict={verdict}",
        matched_rules=[],
        reasons=[],
    )


# ---------------------------------------------------------------------------
# build_cape_adapter_request
# ---------------------------------------------------------------------------


class TestBuildCapeAdapterRequest:
    def test_returns_cape_adapter_request(self):
        req = build_cape_adapter_request(action_type="submit_sample", target="evil.exe")
        assert isinstance(req, CapeAdapterRequest)

    def test_normalizes_action_type_and_target(self):
        req = build_cape_adapter_request(action_type="  submit_url  ", target="  http://evil.com  ")
        assert req.action_type == "submit_url"
        assert req.target == "http://evil.com"

    def test_raises_on_blank_action_type(self):
        with pytest.raises(ValueError, match="action_type"):
            build_cape_adapter_request(action_type="   ", target="evil.exe")

    def test_raises_on_blank_target(self):
        with pytest.raises(ValueError, match="target"):
            build_cape_adapter_request(action_type="submit_sample", target="   ")

    def test_optional_fields_default_to_none(self):
        req = build_cape_adapter_request(action_type="submit_sample", target="evil.exe")
        assert req.sample_hash is None
        assert req.sample_path is None
        assert req.analysis_package is None
        assert req.machine_label is None
        assert req.agent_id is None
        assert req.session_id is None

    def test_optional_fields_populated(self):
        req = build_cape_adapter_request(
            action_type="submit_sample",
            target="evil.exe",
            sample_hash="abc123",
            sample_path="/tmp/evil.exe",
            analysis_package="pdf",
            machine_label="win10",
            agent_id="agent-1",
            session_id="sess-99",
            metadata={"key": "value"},
        )
        assert req.sample_hash == "abc123"
        assert req.sample_path == "/tmp/evil.exe"
        assert req.analysis_package == "pdf"
        assert req.machine_label == "win10"
        assert req.agent_id == "agent-1"
        assert req.session_id == "sess-99"
        assert req.metadata == {"key": "value"}

    def test_metadata_defaults_to_empty_dict(self):
        req = build_cape_adapter_request(action_type="submit_sample", target="evil.exe")
        assert req.metadata == {}

    def test_blank_optional_strings_normalize_to_none(self):
        req = build_cape_adapter_request(
            action_type="submit_sample",
            target="evil.exe",
            sample_hash="  ",
            machine_label="  ",
        )
        assert req.sample_hash is None
        assert req.machine_label is None


# ---------------------------------------------------------------------------
# CapeAdapterRequest.to_policy_input / to_dict
# ---------------------------------------------------------------------------


class TestCapeAdapterRequest:
    def _req(self) -> CapeAdapterRequest:
        return build_cape_adapter_request(
            action_type="submit_sample",
            target="evil.exe",
            sample_hash="deadbeef",
            agent_id="agent-1",
            session_id="sess-1",
        )

    def test_to_policy_input_fields(self):
        req = self._req()
        pi = req.to_policy_input()
        assert pi.action_type == "submit_sample"
        assert pi.target == "evil.exe"
        assert pi.agent_id == "agent-1"
        assert pi.session_id == "sess-1"
        assert pi.metadata["sample_hash"] == "deadbeef"

    def test_to_dict_has_all_keys(self):
        req = self._req()
        d = req.to_dict()
        for key in (
            "action_type",
            "target",
            "content",
            "sample_hash",
            "sample_path",
            "analysis_package",
            "machine_label",
            "agent_id",
            "session_id",
            "metadata",
        ):
            assert key in d

    def test_to_dict_values_match(self):
        req = self._req()
        d = req.to_dict()
        assert d["action_type"] == "submit_sample"
        assert d["target"] == "evil.exe"
        assert d["sample_hash"] == "deadbeef"

    def test_to_policy_input_excludes_none_optional_fields(self):
        req = build_cape_adapter_request(action_type="submit_url", target="http://bad.com")
        pi = req.to_policy_input()
        assert "sample_hash" not in pi.metadata
        assert "sample_path" not in pi.metadata
        assert "analysis_package" not in pi.metadata
        assert "machine_label" not in pi.metadata


# ---------------------------------------------------------------------------
# adapt_policy_decision_to_cape
# ---------------------------------------------------------------------------


class TestAdaptPolicyDecisionToCape:
    def test_allow_verdict_flags(self):
        resp = adapt_policy_decision_to_cape(_make_decision("allow"))
        assert resp.should_allow is True
        assert resp.should_warn is False
        assert resp.should_quarantine is False
        assert resp.should_block is False
        assert resp.should_hold is False

    def test_warn_verdict_flags(self):
        resp = adapt_policy_decision_to_cape(_make_decision("warn"))
        assert resp.should_allow is False
        assert resp.should_warn is True
        assert resp.should_hold is True

    def test_quarantine_verdict_flags(self):
        resp = adapt_policy_decision_to_cape(_make_decision("quarantine"))
        assert resp.should_quarantine is True
        assert resp.should_hold is True

    def test_block_verdict_flags(self):
        resp = adapt_policy_decision_to_cape(_make_decision("block"))
        assert resp.should_block is True
        assert resp.should_hold is True

    def test_adapter_name_and_platform(self):
        resp = adapt_policy_decision_to_cape(_make_decision())
        assert resp.adapter_name == "ironclaw-cape"
        assert resp.platform == "cape"

    def test_decision_id_propagated(self):
        resp = adapt_policy_decision_to_cape(_make_decision())
        assert resp.decision_id == "dec-001"

    def test_trace_id_propagated(self):
        resp = adapt_policy_decision_to_cape(_make_decision(), trace_id="trace-xyz")
        assert resp.trace_id == "trace-xyz"

    def test_request_dict_included(self):
        req = build_cape_adapter_request(action_type="submit_sample", target="evil.exe")
        resp = adapt_policy_decision_to_cape(_make_decision(), request=req)
        assert resp.request["action_type"] == "submit_sample"

    def test_mode_default_enforce(self):
        resp = adapt_policy_decision_to_cape(_make_decision())
        assert resp.mode == "enforce"

    def test_mode_monitor(self):
        resp = adapt_policy_decision_to_cape(_make_decision(), mode="monitor")
        assert resp.mode == "monitor"

    def test_returns_cape_adapter_response(self):
        resp = adapt_policy_decision_to_cape(_make_decision())
        assert isinstance(resp, CapeAdapterResponse)


# ---------------------------------------------------------------------------
# CapeAdapterResponse.to_dict
# ---------------------------------------------------------------------------


class TestCapeAdapterResponseToDict:
    def _response(self) -> CapeAdapterResponse:
        return adapt_policy_decision_to_cape(
            _make_decision("allow", risk_score=0),
        )

    def test_to_dict_has_all_keys(self):
        d = self._response().to_dict()
        for key in (
            "adapter_name",
            "platform",
            "mode",
            "verdict",
            "should_allow",
            "should_warn",
            "should_quarantine",
            "should_block",
            "should_hold",
            "risk_score",
            "risk_level",
            "summary",
            "matched_rules",
            "reasons",
            "decision_id",
            "trace_id",
            "reviewed_at",
            "request",
            "metadata",
        ):
            assert key in d

    def test_matched_rules_is_list(self):
        d = self._response().to_dict()
        assert isinstance(d["matched_rules"], list)

    def test_reasons_is_list(self):
        d = self._response().to_dict()
        assert isinstance(d["reasons"], list)


# ---------------------------------------------------------------------------
# summarize_cape_adapter_response
# ---------------------------------------------------------------------------


class TestSummarizeCapeAdapterResponse:
    def _response(self) -> CapeAdapterResponse:
        return adapt_policy_decision_to_cape(
            _make_decision("allow", risk_score=10),
            trace_id="trace-abc",
        )

    def test_summary_keys(self):
        s = summarize_cape_adapter_response(self._response())
        for key in (
            "adapter_name",
            "platform",
            "mode",
            "verdict",
            "should_hold",
            "risk_score",
            "risk_level",
            "summary",
            "matched_rule_count",
            "decision_id",
            "trace_id",
            "reviewed_at",
        ):
            assert key in s

    def test_matched_rule_count_zero(self):
        s = summarize_cape_adapter_response(self._response())
        assert s["matched_rule_count"] == 0

    def test_trace_id_in_summary(self):
        s = summarize_cape_adapter_response(self._response())
        assert s["trace_id"] == "trace-abc"


# ---------------------------------------------------------------------------
# CapeAdapter — supported_action_types
# ---------------------------------------------------------------------------


class TestCapeAdapterSupportedActionTypes:
    def test_contains_submit_sample(self):
        assert "submit_sample" in _make_adapter().supported_action_types()

    def test_contains_submit_url(self):
        assert "submit_url" in _make_adapter().supported_action_types()

    def test_contains_submit_process(self):
        assert "submit_process" in _make_adapter().supported_action_types()

    def test_contains_retrieve_report(self):
        assert "retrieve_report" in _make_adapter().supported_action_types()

    def test_contains_cancel_task(self):
        assert "cancel_task" in _make_adapter().supported_action_types()

    def test_returns_list(self):
        assert isinstance(_make_adapter().supported_action_types(), list)


# ---------------------------------------------------------------------------
# CapeAdapter.execute — submit_sample
# ---------------------------------------------------------------------------


class TestCapeAdapterExecuteSubmitSample:
    def test_execute_submit_sample_success(self):
        result = _make_adapter().execute(_make_exec_request("submit_sample", "evil.exe"))
        assert result.success is True

    def test_execute_submit_sample_status_guarded(self):
        result = _make_adapter().execute(_make_exec_request("submit_sample", "evil.exe"))
        assert result.status == "guarded"

    def test_execute_submit_sample_summary_mentions_action(self):
        result = _make_adapter().execute(_make_exec_request("submit_sample", "evil.exe"))
        assert "submit_sample" in result.summary

    def test_execute_submit_sample_output_guard_applied(self):
        result = _make_adapter().execute(_make_exec_request("submit_sample", "evil.exe"))
        assert result.output.get("guard_applied") is True

    def test_execute_submit_sample_output_execution_mode(self):
        result = _make_adapter().execute(_make_exec_request("submit_sample", "evil.exe"))
        assert result.output.get("execution_mode") == "sandbox-gated"

    def test_execute_submit_sample_metadata_runtime(self):
        result = _make_adapter().execute(_make_exec_request("submit_sample", "evil.exe"))
        assert result.metadata.get("runtime") == "cape"

    def test_execute_submit_sample_metadata_analysis_mode(self):
        result = _make_adapter().execute(_make_exec_request("submit_sample", "evil.exe"))
        assert result.metadata.get("analysis_mode") == "sandbox-guard"


# ---------------------------------------------------------------------------
# CapeAdapter.execute — submit_url
# ---------------------------------------------------------------------------


class TestCapeAdapterExecuteSubmitUrl:
    def test_execute_submit_url_success(self):
        result = _make_adapter().execute(_make_exec_request("submit_url", "http://evil.com"))
        assert result.success is True

    def test_execute_submit_url_status_guarded(self):
        result = _make_adapter().execute(_make_exec_request("submit_url", "http://evil.com"))
        assert result.status == "guarded"

    def test_execute_submit_url_output_has_request(self):
        result = _make_adapter().execute(_make_exec_request("submit_url", "http://evil.com"))
        assert "request" in result.output


# ---------------------------------------------------------------------------
# CapeAdapter.execute — unsupported action raises
# ---------------------------------------------------------------------------


class TestCapeAdapterExecuteUnsupportedAction:
    def test_unsupported_action_raises_value_error(self):
        with pytest.raises(ValueError, match="unsupported action_type"):
            _make_adapter().execute(_make_exec_request("detonate_nuke", "earth"))


# ---------------------------------------------------------------------------
# CapeAdapter.execute — offline health
# ---------------------------------------------------------------------------


class TestCapeAdapterOffline:
    def test_offline_returns_offline_status(self):
        result = _make_adapter(health="offline").execute(_make_exec_request("submit_sample", "evil.exe"))
        assert result.status == "offline"

    def test_offline_success_is_false(self):
        result = _make_adapter(health="offline").execute(_make_exec_request("submit_sample", "evil.exe"))
        assert result.success is False

    def test_offline_summary_mentions_offline(self):
        result = _make_adapter(health="offline").execute(_make_exec_request("submit_sample", "evil.exe"))
        assert "offline" in result.summary.lower()


# ---------------------------------------------------------------------------
# CapeAdapter.execute — degraded health
# ---------------------------------------------------------------------------


class TestCapeAdapterDegraded:
    def test_degraded_success_is_true(self):
        result = _make_adapter(health="degraded").execute(_make_exec_request("submit_sample", "evil.exe"))
        assert result.success is True

    def test_degraded_status_accepted_with_warnings_or_guarded(self):
        result = _make_adapter(health="degraded").execute(_make_exec_request("submit_sample", "evil.exe"))
        assert result.status in ("accepted_with_warnings", "guarded")

    def test_degraded_output_guard_applied(self):
        result = _make_adapter(health="degraded").execute(_make_exec_request("submit_sample", "evil.exe"))
        assert result.output.get("guard_applied") is True


# ---------------------------------------------------------------------------
# CapeAdapter.execute — result metadata contains runtime
# ---------------------------------------------------------------------------


class TestCapeAdapterResultMetadata:
    def test_result_metadata_contains_runtime(self):
        result = _make_adapter().execute(_make_exec_request("retrieve_report", "task-42"))
        assert "runtime" in result.metadata

    def test_result_metadata_contains_analysis_mode(self):
        result = _make_adapter().execute(_make_exec_request("retrieve_report", "task-42"))
        assert "analysis_mode" in result.metadata

    def test_result_metadata_runtime_value(self):
        result = _make_adapter().execute(_make_exec_request("cancel_task", "task-99"))
        assert result.metadata["runtime"] == "cape"


# ---------------------------------------------------------------------------
# evaluate_cape_request (integration path via PolicyEngine)
# ---------------------------------------------------------------------------


class TestEvaluateCapeRequest:
    def _engine(self) -> PolicyEngine:
        return PolicyEngine(rules=[])

    def test_returns_cape_adapter_response(self):
        req = build_cape_adapter_request(action_type="submit_sample", target="evil.exe")
        resp = evaluate_cape_request(self._engine(), req)
        assert isinstance(resp, CapeAdapterResponse)

    def test_verdict_is_valid(self):
        req = build_cape_adapter_request(action_type="submit_url", target="http://bad.com")
        resp = evaluate_cape_request(self._engine(), req)
        assert resp.verdict in ("allow", "warn", "quarantine", "block")

    def test_mode_default_enforce(self):
        req = build_cape_adapter_request(action_type="submit_sample", target="evil.exe")
        resp = evaluate_cape_request(self._engine(), req)
        assert resp.mode == "enforce"

    def test_mode_monitor(self):
        req = build_cape_adapter_request(action_type="submit_sample", target="evil.exe")
        resp = evaluate_cape_request(self._engine(), req, mode="monitor")
        assert resp.mode == "monitor"

    def test_risk_score_propagated(self):
        req = build_cape_adapter_request(action_type="submit_sample", target="evil.exe")
        resp = evaluate_cape_request(self._engine(), req, risk_score=75)
        assert resp.risk_score == 75

    def test_trace_id_propagated(self):
        req = build_cape_adapter_request(action_type="submit_sample", target="evil.exe")
        resp = evaluate_cape_request(self._engine(), req, trace_id="t-123")
        assert resp.trace_id == "t-123"
