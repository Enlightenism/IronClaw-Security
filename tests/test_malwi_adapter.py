from __future__ import annotations

import pytest

from app.adapters.base import AdapterExecutionRequest
from app.adapters.malwi_adapter import (
    MalwiAdapter,
    adapt_policy_decision_to_malwi,
    build_malwi_adapter_request,
    evaluate_malwi_request,
    summarize_malwi_adapter_response,
)
from app.orchestrator.policy_enforcer import initialize_policy_engine
from app.services.integration_registry import IntegrationRecord

# ---------- Fixtures ----------


def _make_record(health: str = "ready") -> IntegrationRecord:
    return IntegrationRecord(
        integration_id="integration-malwi",
        name="Malwi Threat Intel",
        slug="malwi",
        platform="malwi",
        integration_type="threat-intelligence",
        status=health,
        capabilities=[],
        metadata={},
    )


def _make_adapter(health: str = "ready") -> MalwiAdapter:
    return MalwiAdapter(
        record=_make_record(health),
        protocol_version="1.0.0",
        health=health,  # type: ignore[arg-type]
        metadata={},
    )


_ENGINE = initialize_policy_engine(mode="enforce")


# ---------- build_malwi_adapter_request ----------


def test_build_malwi_adapter_request_minimal() -> None:
    req = build_malwi_adapter_request(action_type="lookup_hash", target="abc123")
    assert req.action_type == "lookup_hash"
    assert req.target == "abc123"
    assert req.content == ""
    assert req.ioc_type is None
    assert req.metadata == {}


def test_build_malwi_adapter_request_full() -> None:
    req = build_malwi_adapter_request(
        action_type="lookup_ip",
        target="1.2.3.4",
        content="suspicious",
        ioc_type="ip",
        ioc_value="1.2.3.4",
        threat_category="c2",
        confidence_threshold=80,
        agent_id="agent-1",
        session_id="session-1",
        metadata={"source": "scanner"},
    )
    assert req.ioc_type == "ip"
    assert req.ioc_value == "1.2.3.4"
    assert req.threat_category == "c2"
    assert req.confidence_threshold == 80
    assert req.agent_id == "agent-1"
    assert req.session_id == "session-1"
    assert req.metadata["source"] == "scanner"


def test_build_malwi_adapter_request_strips_whitespace() -> None:
    req = build_malwi_adapter_request(action_type="  lookup_url  ", target="  http://example.com  ")
    assert req.action_type == "lookup_url"
    assert req.target == "http://example.com"


def test_build_malwi_adapter_request_empty_action_type_raises() -> None:
    with pytest.raises(ValueError, match="action_type is required"):
        build_malwi_adapter_request(action_type="", target="abc123")


def test_build_malwi_adapter_request_empty_target_raises() -> None:
    with pytest.raises(ValueError, match="target is required"):
        build_malwi_adapter_request(action_type="lookup_hash", target="")


# ---------- MalwiAdapterRequest.to_policy_input ----------


def test_malwi_request_to_policy_input_merges_metadata() -> None:
    req = build_malwi_adapter_request(
        action_type="lookup_domain",
        target="evil.com",
        ioc_type="domain",
        threat_category="phishing",
        metadata={"extra": "value"},
    )
    pi = req.to_policy_input()
    assert pi.action_type == "lookup_domain"
    assert pi.target == "evil.com"
    assert pi.metadata["ioc_type"] == "domain"
    assert pi.metadata["threat_category"] == "phishing"
    assert pi.metadata["extra"] == "value"


def test_malwi_request_to_dict_roundtrip() -> None:
    req = build_malwi_adapter_request(
        action_type="lookup_hash",
        target="deadbeef",
        ioc_type="md5",
    )
    d = req.to_dict()
    assert d["action_type"] == "lookup_hash"
    assert d["target"] == "deadbeef"
    assert d["ioc_type"] == "md5"


# ---------- adapt_policy_decision_to_malwi ----------


def test_adapt_policy_decision_allow() -> None:
    req = build_malwi_adapter_request(action_type="lookup_hash", target="abc123")
    decision = evaluate_malwi_request(_ENGINE, req)
    assert decision.verdict in {"allow", "warn", "quarantine", "block"}
    assert isinstance(decision.risk_score, int)
    assert decision.adapter_name == "ironclaw-malwi"
    assert decision.platform == "malwi"


def test_adapt_policy_decision_verdicts_are_consistent_malwi() -> None:
    req = build_malwi_adapter_request(action_type="lookup_ip", target="10.0.0.1")
    resp = evaluate_malwi_request(_ENGINE, req, mode="monitor")
    assert resp.should_allow == (resp.verdict == "allow")
    assert resp.should_warn == (resp.verdict == "warn")
    assert resp.should_quarantine == (resp.verdict == "quarantine")
    assert resp.should_block == (resp.verdict == "block")
    assert resp.should_hold == (resp.verdict in {"warn", "quarantine", "block"})


def test_adapt_policy_decision_trace_id_propagated_malwi() -> None:
    req = build_malwi_adapter_request(action_type="lookup_url", target="http://bad.com")
    from app.orchestrator.policy_enforcer import evaluate_policy

    decision = evaluate_policy(_ENGINE, req.to_policy_input(), risk_score=0)
    resp = adapt_policy_decision_to_malwi(decision, trace_id="trace-xyz", request=req)
    assert resp.trace_id == "trace-xyz"
    assert resp.request["action_type"] == "lookup_url"


def test_adapt_policy_decision_no_request_malwi() -> None:
    req = build_malwi_adapter_request(action_type="lookup_hash", target="abc")
    from app.orchestrator.policy_enforcer import evaluate_policy

    decision = evaluate_policy(_ENGINE, req.to_policy_input(), risk_score=0)
    resp = adapt_policy_decision_to_malwi(decision)
    assert resp.request == {}


# ---------- MalwiAdapterResponse.to_dict ----------


def test_malwi_response_to_dict_shape() -> None:
    req = build_malwi_adapter_request(action_type="lookup_hash", target="abc123")
    resp = evaluate_malwi_request(_ENGINE, req)
    d = resp.to_dict()
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


# ---------- summarize_malwi_adapter_response ----------


def test_summarize_malwi_adapter_response_keys() -> None:
    req = build_malwi_adapter_request(action_type="lookup_hash", target="abc123")
    resp = evaluate_malwi_request(_ENGINE, req)
    summary = summarize_malwi_adapter_response(resp)
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
        assert key in summary
    assert summary["matched_rule_count"] == len(resp.matched_rules)


# ---------- MalwiAdapter.execute ----------


def test_malwi_adapter_execute_lookup_hash() -> None:
    adapter = _make_adapter()
    request = AdapterExecutionRequest(action_type="lookup_hash", target="deadbeef")
    result = adapter.execute(request)
    assert result.success is True
    assert result.status == "guarded"
    assert "guard_applied" in result.output
    assert result.output["execution_mode"] == "threat-intel-gated"


def test_malwi_adapter_execute_lookup_url() -> None:
    adapter = _make_adapter()
    request = AdapterExecutionRequest(action_type="lookup_url", target="http://evil.com")
    result = adapter.execute(request)
    assert result.success is True
    assert result.status == "guarded"


def test_malwi_adapter_execute_unsupported_action_raises() -> None:
    adapter = _make_adapter()
    request = AdapterExecutionRequest(action_type="detonate_bomb", target="x")
    with pytest.raises(ValueError, match="unsupported action_type"):
        adapter.execute(request)


def test_malwi_adapter_offline_returns_offline_status() -> None:
    adapter = _make_adapter(health="offline")
    request = AdapterExecutionRequest(action_type="lookup_hash", target="abc")
    result = adapter.execute(request)
    assert result.success is False
    assert result.status == "offline"


def test_malwi_adapter_degraded_returns_accepted_with_warnings() -> None:
    adapter = _make_adapter(health="degraded")
    request = AdapterExecutionRequest(action_type="lookup_ip", target="192.168.1.1")
    result = adapter.execute(request)
    assert result.success is True
    assert result.status == "guarded"


def test_malwi_adapter_result_metadata_contains_runtime() -> None:
    adapter = _make_adapter()
    request = AdapterExecutionRequest(action_type="lookup_domain", target="test.com")
    result = adapter.execute(request)
    assert result.metadata.get("runtime") == "malwi"
    assert result.metadata.get("analysis_mode") == "threat-intel-guard"
