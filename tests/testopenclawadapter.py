from __future__ import annotations

from typing import Any

import pytest

from app.adapters.base import AdapterExecutionRequest
from app.adapters.openclaw_adapter import (
    OpenClawAdapter,
    OpenClawAdapterRequest,
    adapt_policy_decision_to_openclaw,
    build_openclaw_adapter,
    build_openclaw_adapter_request,
)
from app.orchestrator.policy_enforcer import (
    PolicyDecision,
    PolicyMatch,
    initialize_policy_engine,
)
from app.services.integration_registry import initialize_integration_registry

# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


def _make_decision(
    verdict: str = "allow",
    risk_score: int = 0,
    risk_level: str = "low",
    matched_rules: list[str] | None = None,
) -> PolicyDecision:
    engine = initialize_policy_engine()
    matches: list[PolicyMatch] = [
        PolicyMatch(
            rule_id=r,
            name=r,
            verdict=verdict,
            risk_level=risk_level,
            reason=f"stub match for {r}",
        )
        for r in (matched_rules or [])
    ]
    return PolicyDecision(
        decision_id=f"dec-{verdict}",
        verdict=verdict,
        risk_score=risk_score,
        risk_level=risk_level,
        mode=engine.mode,
        allow_execution=verdict in {"allow", "warn"},
        requires_review=verdict in {"warn", "quarantine"},
        summary=f"{verdict} by policy",
        matched_rules=matches,
        reasons=[f"stub reason for {verdict}"],
    )


def _registry():
    return initialize_integration_registry()


def _adapter() -> OpenClawAdapter:
    return build_openclaw_adapter(_registry())


def _ocrequest(**overrides: Any) -> OpenClawAdapterRequest:
    defaults: dict[str, Any] = dict(
        action_type="workflow",
        target="workspace://openclaw/pipeline",
        content="",
        builder_id="builder-001",
        workflow_id="wf-001",
        metadata={"org": "ironclaw"},
    )
    defaults.update(overrides)
    return build_openclaw_adapter_request(**defaults)


def _exec_request(**overrides: Any) -> AdapterExecutionRequest:
    defaults: dict[str, Any] = dict(
        action_type="workflow",
        target="workspace://openclaw/pipeline",
        payload={"step": "toolchain-build", "policy_gate": True},
    )
    defaults.update(overrides)
    return AdapterExecutionRequest(**defaults)


# ---------------------------------------------------------------------------
# build_openclaw_adapter
# ---------------------------------------------------------------------------


def test_build_openclaw_adapter_returns_correct_type() -> None:
    adapter = _adapter()
    assert isinstance(adapter, OpenClawAdapter)


def test_build_openclaw_adapter_has_correct_integration_id() -> None:
    adapter = _adapter()
    assert adapter.record.integration_id == "integration-openclaw"


def test_build_openclaw_adapter_has_correct_slug() -> None:
    adapter = _adapter()
    assert adapter.record.slug == "openclaw"


def test_build_openclaw_adapter_has_correct_platform() -> None:
    adapter = _adapter()
    assert adapter.record.platform == "openclaw"


def test_build_openclaw_adapter_runtime_metadata() -> None:
    adapter = _adapter()
    assert adapter.metadata["runtime"] == "openclaw"
    assert adapter.metadata["workflow_mode"] == "builder-guard"


# ---------------------------------------------------------------------------
# build_openclaw_adapter_request
# ---------------------------------------------------------------------------


def test_build_request_normalizes_whitespace() -> None:
    req = _ocrequest(action_type="  workflow  ", target="  ws://pipe  ")
    assert req.action_type == "workflow"
    assert req.target == "ws://pipe"


def test_build_request_rejects_empty_action_type() -> None:
    with pytest.raises(ValueError, match="action_type"):
        build_openclaw_adapter_request(action_type="", target="ws://pipe")


def test_build_request_rejects_empty_target() -> None:
    with pytest.raises(ValueError, match="target"):
        build_openclaw_adapter_request(action_type="workflow", target="")


def test_build_request_to_policy_input_carries_builder_and_workflow_ids() -> None:
    req = _ocrequest(builder_id="b-1", workflow_id="wf-1")
    pi = req.to_policy_input()
    assert pi.metadata["builder_id"] == "b-1"
    assert pi.metadata["workflow_id"] == "wf-1"


def test_build_request_to_policy_input_carries_extra_metadata() -> None:
    req = _ocrequest(metadata={"env": "prod"})
    pi = req.to_policy_input()
    assert pi.metadata["env"] == "prod"


def test_build_request_to_dict_is_json_friendly() -> None:
    req = _ocrequest()
    d = req.to_dict()
    assert isinstance(d, dict)
    assert d["action_type"] == "workflow"
    assert d["target"] == "workspace://openclaw/pipeline"


# ---------------------------------------------------------------------------
# adapt_policy_decision_to_openclaw
# ---------------------------------------------------------------------------


def test_adapt_allow_sets_should_allow_true() -> None:
    decision = _make_decision("allow")
    resp = adapt_policy_decision_to_openclaw(decision, request=_ocrequest())
    assert resp.should_allow is True
    assert resp.should_block is False
    assert resp.should_hold is False
    assert resp.verdict == "allow"


def test_adapt_block_sets_should_block_and_hold() -> None:
    decision = _make_decision("block", risk_score=90, risk_level="high",
                              matched_rules=["signature_mismatch"])
    resp = adapt_policy_decision_to_openclaw(decision, request=_ocrequest())
    assert resp.should_block is True
    assert resp.should_allow is False
    assert resp.should_hold is True
    assert resp.verdict == "block"
    assert "signature_mismatch" in resp.matched_rules


def test_adapt_quarantine_sets_should_hold() -> None:
    decision = _make_decision("quarantine", matched_rules=["policy:review"])
    resp = adapt_policy_decision_to_openclaw(decision, request=_ocrequest())
    assert resp.should_quarantine is True
    assert resp.should_hold is True
    assert resp.verdict == "quarantine"


def test_adapt_warn_sets_should_warn_and_hold() -> None:
    decision = _make_decision("warn", matched_rules=["risk:elevated"])
    resp = adapt_policy_decision_to_openclaw(decision, request=_ocrequest())
    assert resp.should_warn is True
    assert resp.should_hold is True
    assert resp.verdict == "warn"


def test_adapt_carries_decision_id() -> None:
    decision = _make_decision("allow")
    resp = adapt_policy_decision_to_openclaw(decision, request=_ocrequest())
    assert resp.decision_id == "dec-allow"


def test_adapt_carries_trace_id() -> None:
    decision = _make_decision("allow")
    resp = adapt_policy_decision_to_openclaw(decision, request=_ocrequest(),
                                              trace_id="trace-xyz")
    assert resp.trace_id == "trace-xyz"


def test_adapt_response_to_dict_is_json_friendly() -> None:
    decision = _make_decision("allow", matched_rules=["bundle:verified"])
    resp = adapt_policy_decision_to_openclaw(decision, request=_ocrequest())
    d = resp.to_dict()
    assert isinstance(d, dict)
    assert isinstance(d["matched_rules"], list)
    assert isinstance(d["reasons"], list)
    assert d["platform"] == "openclaw"


# ---------------------------------------------------------------------------
# OpenClawAdapter.execute  (via BaseIntegrationAdapter)
# ---------------------------------------------------------------------------


def test_execute_returns_guarded_status() -> None:
    adapter = _adapter()
    result = adapter.execute(_exec_request())
    assert result.status == "guarded"


def test_execute_sets_guard_applied_in_output() -> None:
    adapter = _adapter()
    result = adapter.execute(_exec_request())
    assert result.output["guard_applied"] is True


def test_execute_sets_execution_mode_in_output() -> None:
    adapter = _adapter()
    result = adapter.execute(_exec_request())
    assert result.output["execution_mode"] == "workflow-gated"


def test_execute_echoes_request_in_output() -> None:
    adapter = _adapter()
    result = adapter.execute(_exec_request())
    assert result.output["request"]["action_type"] == "workflow"


def test_execute_propagates_runtime_metadata() -> None:
    adapter = _adapter()
    result = adapter.execute(_exec_request())
    assert result.metadata["runtime"] == "openclaw"
    assert result.metadata["workflow_mode"] == "builder-guard"


def test_execute_success_is_true() -> None:
    adapter = _adapter()
    result = adapter.execute(_exec_request())
    assert result.success is True


def test_execute_adapter_slug_is_openclaw() -> None:
    adapter = _adapter()
    result = adapter.execute(_exec_request())
    assert result.adapter_slug == "openclaw"


def test_execute_platform_is_openclaw() -> None:
    adapter = _adapter()
    result = adapter.execute(_exec_request())
    assert result.platform == "openclaw"