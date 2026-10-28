from __future__ import annotations

import pytest

from app.adapters.base import AdapterExecutionRequest
from app.adapters.cape_adapter import (
    CapeAdapterRequest,
    CapeAdapterResponse,
    adapt_policy_decision_to_cape,
    build_cape_adapter,
    build_cape_adapter_request,
    evaluate_cape_request,
    summarize_cape_adapter_response,
)
from app.config import RISK_THRESHOLD_BLOCK_MIN
from app.orchestrator.policy_enforcer import PolicyEngine, build_policy_engine
from app.services.integration_registry import (
    IntegrationCapability,
    IntegrationRecord,
    IntegrationRegistry,
    register_integration,
)

# ---------- fixtures ----------


def _make_registry() -> IntegrationRegistry:
    registry = IntegrationRegistry()
    record = IntegrationRecord(
        integration_id="integration-cape",
        name="CAPE Sandbox Adapter",
        slug="cape",
        platform="cape",
        integration_type="adapter",
        status="active",
        version="1.0.0",
        description="IronClaw protection layer for CAPE malware sandbox submissions.",
        entrypoint="app.adapters.cape_adapter",
        capabilities=[
            IntegrationCapability("execution_interception", True),
            IntegrationCapability("file_guard", True),
            IntegrationCapability("review_queue", True),
            IntegrationCapability("telemetry", True),
        ],
    )
    register_integration(registry, record)
    return registry


def _make_engine() -> PolicyEngine:
    return build_policy_engine()


def _make_request(
    action_type: str = "submit_sample",
    target: str = "malware.exe",
    **kwargs: object,
) -> CapeAdapterRequest:
    return build_cape_adapter_request(
        action_type=action_type,
        target=target,
        **kwargs,  # type: ignore[arg-type]
    )


# ---------- build_cape_adapter_request ----------


def test_build_cape_adapter_request_basic() -> None:
    req = _make_request()
    assert req.action_type == "submit_sample"
    assert req.target == "malware.exe"
    assert req.content == ""
    assert req.sample_hash is None
    assert req.metadata == {}


def test_build_cape_adapter_request_all_fields() -> None:
    req = build_cape_adapter_request(
        action_type="submit_url",
        target="http://evil.example.com",
        content="raw bytes here",
        sample_hash="abc123",
        sample_path="/tmp/sample.exe",
        analysis_package="doc",
        machine_label="win10-x64",
        agent_id="agent-001",
        session_id="sess-999",
        metadata={"env": "test"},
    )
    assert req.action_type == "submit_url"
    assert req.target == "http://evil.example.com"
    assert req.sample_hash == "abc123"
    assert req.sample_path == "/tmp/sample.exe"
    assert req.analysis_package == "doc"
    assert req.machine_label == "win10-x64"
    assert req.agent_id == "agent-001"
    assert req.session_id == "sess-999"
    assert req.metadata == {"env": "test"}


def test_build_cape_adapter_request_strips_whitespace() -> None:
    req = build_cape_adapter_request(
        action_type="  submit_sample  ",
        target="  malware.exe  ",
        sample_hash="  deadbeef  ",
    )
    assert req.action_type == "submit_sample"
    assert req.target == "malware.exe"
    assert req.sample_hash == "deadbeef"


def test_build_cape_adapter_request_missing_action_type_raises() -> None:
    with pytest.raises(ValueError, match="action_type is required"):
        build_cape_adapter_request(action_type="", target="malware.exe")


def test_build_cape_adapter_request_missing_target_raises() -> None:
    with pytest.raises(ValueError, match="target is required"):
        build_cape_adapter_request(action_type="submit_sample", target="")


def test_build_cape_adapter_request_whitespace_only_raises() -> None:
    with pytest.raises(ValueError, match="action_type is required"):
        build_cape_adapter_request(action_type="   ", target="malware.exe")


# ---------- CapeAdapterRequest.to_policy_input ----------


def test_to_policy_input_basic_cape() -> None:
    req = _make_request()
    policy_input = req.to_policy_input()
    assert policy_input.action_type == "submit_sample"
    assert policy_input.target == "malware.exe"


def test_to_policy_input_folds_sample_fields_into_metadata() -> None:
    req = build_cape_adapter_request(
        action_type="submit_sample",
        target="evil.exe",
        sample_hash="cafebabe",
        sample_path="/tmp/evil.exe",
        analysis_package="exe",
        machine_label="win7-x86",
    )
    policy_input = req.to_policy_input()
    assert policy_input.metadata["sample_hash"] == "cafebabe"
    assert policy_input.metadata["sample_path"] == "/tmp/evil.exe"
    assert policy_input.metadata["analysis_package"] == "exe"
    assert policy_input.metadata["machine_label"] == "win7-x86"


def test_to_policy_input_omits_none_fields() -> None:
    req = _make_request()
    policy_input = req.to_policy_input()
    assert "sample_hash" not in policy_input.metadata
    assert "sample_path" not in policy_input.metadata


def test_to_dict_round_trip() -> None:
    req = _make_request(sample_hash="abc", agent_id="a1")
    d = req.to_dict()
    assert d["action_type"] == "submit_sample"
    assert d["sample_hash"] == "abc"
    assert d["agent_id"] == "a1"
    assert isinstance(d["metadata"], dict)


# ---------- adapt_policy_decision_to_cape ----------


def test_adapt_allow_verdict() -> None:
    engine = _make_engine()
    req = _make_request()
    from app.orchestrator.policy_enforcer import evaluate_policy

    decision = evaluate_policy(engine, req.to_policy_input(), risk_score=0)
    response = adapt_policy_decision_to_cape(decision, request=req)

    assert response.adapter_name == "ironclaw-cape"
    assert response.platform == "cape"
    assert response.verdict in {"allow", "block"}
    assert isinstance(response.should_allow, bool)
    assert isinstance(response.should_hold, bool)
    assert isinstance(response.risk_score, int)
    assert isinstance(response.matched_rules, list)
    assert isinstance(response.reasons, list)


def test_adapt_sets_should_hold_for_non_allow() -> None:
    engine = _make_engine()
    req = _make_request(action_type="submit_sample", target="suspicious.exe")
    from app.orchestrator.policy_enforcer import evaluate_policy

    decision = evaluate_policy(engine, req.to_policy_input(), risk_score=90)
    response = adapt_policy_decision_to_cape(decision, request=req)

    if response.verdict != "allow":
        assert response.should_hold is True
        assert response.should_block is True
        assert response.should_warn is False
        assert response.should_quarantine is False
        assert response.risk_score >= RISK_THRESHOLD_BLOCK_MIN
    else:
        assert response.should_hold is False


def test_adapt_mode_default_is_enforce() -> None:
    engine = _make_engine()
    req = _make_request()
    from app.orchestrator.policy_enforcer import evaluate_policy

    decision = evaluate_policy(engine, req.to_policy_input(), risk_score=0)
    response = adapt_policy_decision_to_cape(decision, request=req)
    assert response.mode == "enforce"


def test_adapt_monitor_mode() -> None:
    engine = _make_engine()
    req = _make_request()
    from app.orchestrator.policy_enforcer import evaluate_policy

    decision = evaluate_policy(engine, req.to_policy_input(), risk_score=0)
    response = adapt_policy_decision_to_cape(decision, mode="monitor", request=req)
    assert response.mode == "monitor"


def test_adapt_trace_id_propagated() -> None:
    engine = _make_engine()
    req = _make_request()
    from app.orchestrator.policy_enforcer import evaluate_policy

    decision = evaluate_policy(engine, req.to_policy_input(), risk_score=0)
    response = adapt_policy_decision_to_cape(decision, trace_id="trace-xyz", request=req)
    assert response.trace_id == "trace-xyz"


def test_adapt_no_request_yields_empty_request_dict() -> None:
    engine = _make_engine()
    req = _make_request()
    from app.orchestrator.policy_enforcer import evaluate_policy

    decision = evaluate_policy(engine, req.to_policy_input(), risk_score=0)
    response = adapt_policy_decision_to_cape(decision, request=None)
    assert response.request == {}


# ---------- evaluate_cape_request ----------


def test_evaluate_cape_request_returns_response() -> None:
    engine = _make_engine()
    req = _make_request()
    response = evaluate_cape_request(engine, req)
    assert isinstance(response, CapeAdapterResponse)
    assert response.adapter_name == "ironclaw-cape"


def test_evaluate_cape_request_high_risk_score() -> None:
    engine = _make_engine()
    req = _make_request(action_type="submit_sample", target="ransomware.exe")
    response = evaluate_cape_request(engine, req, risk_score=95)
    assert response.risk_score >= 0


def test_evaluate_cape_request_to_dict_shape() -> None:
    engine = _make_engine()
    req = _make_request()
    response = evaluate_cape_request(engine, req)
    d = response.to_dict()
    required_keys = {
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
    }
    assert required_keys.issubset(d.keys())


# ---------- summarize_cape_adapter_response ----------


def test_summarize_cape_adapter_response_shape() -> None:
    engine = _make_engine()
    req = _make_request()
    response = evaluate_cape_request(engine, req)
    summary = summarize_cape_adapter_response(response)
    assert summary["adapter_name"] == "ironclaw-cape"
    assert summary["platform"] == "cape"
    assert "verdict" in summary
    assert "should_hold" in summary
    assert "risk_score" in summary
    assert "matched_rule_count" in summary
    assert isinstance(summary["matched_rule_count"], int)


# ---------- CapeAdapter (integration-facing) ----------


def test_cape_adapter_handshake() -> None:
    registry = _make_registry()
    adapter = build_cape_adapter(registry)
    handshake = adapter.handshake()
    assert handshake.adapter_slug == "cape"
    assert handshake.platform == "cape"
    assert handshake.status == "ready"


def test_cape_adapter_supported_action_types() -> None:
    registry = _make_registry()
    adapter = build_cape_adapter(registry)
    action_types = adapter.supported_action_types()
    assert "submit_sample" in action_types
    assert "submit_url" in action_types
    assert "submit_process" in action_types
    assert "retrieve_report" in action_types
    assert "cancel_task" in action_types


def test_cape_adapter_execute_submit_sample() -> None:
    registry = _make_registry()
    adapter = build_cape_adapter(registry)
    request = AdapterExecutionRequest(
        action_type="submit_sample",
        target="malware.exe",
        payload={"sample_hash": "deadbeef"},
    )
    result = adapter.execute(request)
    assert result.success is True
    assert result.status == "guarded"
    assert "malware.exe" in result.summary
    assert result.output["guard_applied"] is True
    assert result.output["execution_mode"] == "sandbox-gated"


def test_cape_adapter_execute_submit_url() -> None:
    registry = _make_registry()
    adapter = build_cape_adapter(registry)
    request = AdapterExecutionRequest(
        action_type="submit_url",
        target="http://evil.example.com",
    )
    result = adapter.execute(request)
    assert result.success is True
    assert result.status == "guarded"


def test_cape_adapter_execute_unsupported_action_raises() -> None:
    registry = _make_registry()
    adapter = build_cape_adapter(registry)
    request = AdapterExecutionRequest(
        action_type="unsupported_action",
        target="malware.exe",
    )
    with pytest.raises(ValueError, match="unsupported action_type"):
        adapter.execute(request)


def test_cape_adapter_offline_returns_offline_status() -> None:
    registry = _make_registry()
    adapter = build_cape_adapter(registry)
    adapter.health = "offline"
    request = AdapterExecutionRequest(
        action_type="submit_sample",
        target="malware.exe",
    )
    result = adapter.execute(request)
    assert result.success is False
    assert result.status == "offline"


def test_cape_adapter_degraded_returns_accepted_with_warnings() -> None:
    registry = _make_registry()
    adapter = build_cape_adapter(registry)
    adapter.health = "degraded"
    request = AdapterExecutionRequest(
        action_type="submit_sample",
        target="malware.exe",
    )
    result = adapter.execute(request)
    assert result.success is True
    assert result.status == "guarded"


def test_cape_adapter_manifest_shape() -> None:
    registry = _make_registry()
    adapter = build_cape_adapter(registry)
    manifest = adapter.manifest()
    assert manifest is not None


def test_cape_adapter_result_metadata_contains_runtime() -> None:
    registry = _make_registry()
    adapter = build_cape_adapter(registry)
    request = AdapterExecutionRequest(
        action_type="submit_sample",
        target="evil.bin",
    )
    result = adapter.execute(request)
    assert result.metadata.get("runtime") == "cape"


def test_build_cape_adapter_missing_integration_raises() -> None:
    empty_registry = IntegrationRegistry()
    with pytest.raises(KeyError, match="integration-cape"):
        build_cape_adapter(empty_registry)


def test_cape_adapter_is_available_when_ready() -> None:
    registry = _make_registry()
    adapter = build_cape_adapter(registry)
    assert adapter.is_available() is True


def test_cape_adapter_not_available_when_offline() -> None:
    registry = _make_registry()
    adapter = build_cape_adapter(registry)
    adapter.health = "offline"
    assert adapter.is_available() is False
