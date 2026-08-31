from __future__ import annotations

from app.adapters import HermesAdapter
from app.adapters.base import AdapterExecutionRequest
from app.adapters.generic_agent_adapter import (
    GenericAgentAdapter,
    GenericAgentAdapterRequest,
    adapt_policy_decision_to_generic_agent,
    build_generic_agent_adapter,
    build_generic_agent_adapter_request,
)
from app.orchestrator.policy_enforcer import PolicyDecision
from app.services.integration_registry import initialize_integration_registry


def test_package_exports_hermes_adapter():
    assert HermesAdapter.__name__ == "HermesAdapter"


def test_generic_agent_adapter_preserves_hermes_runtime_identity():
    request = build_generic_agent_adapter_request(
        action_type="prompt_submission",
        target="workspace:prompt",
        agent_id="agent-42",
        runtime_name="hermes",
        metadata={"runtime": "hermes"},
    )
    policy_input = request.to_policy_input()

    assert policy_input.agent_id == "agent-42"
    assert policy_input.metadata["runtime_name"] == "hermes"

    decision = GenericAgentAdapterRequest(
        action_type="prompt_submission",
        target="workspace:prompt",
        runtime_name="hermes",
        client_id="agent-42",
        metadata={"runtime": "hermes"},
    )
    response = adapt_policy_decision_to_generic_agent(
        PolicyDecision(
            decision_id="decision-hermes",
            verdict="allow",
            risk_score=12,
            risk_level="low",
            mode="enforce",
            allow_execution=True,
            requires_review=False,
            summary="Allow Hermes prompt",
            matched_rules=[],
            reasons=[],
        ),
        request=decision,
        metadata={"runtime": "hermes"},
    )

    assert response.platform == "hermes"
    assert response.metadata["runtime"] == "hermes"


def test_build_generic_agent_adapter_returns_expected_adapter():
    registry = initialize_integration_registry()

    adapter = build_generic_agent_adapter(registry)

    assert isinstance(adapter, GenericAgentAdapter)
    assert adapter.record.integration_id == "integration-generic-agent"
    assert adapter.record.slug == "generic-agent"
    assert adapter.record.platform == "generic"


def test_generic_agent_adapter_handshake_contains_expected_metadata():
    registry = initialize_integration_registry()

    adapter = build_generic_agent_adapter(registry)
    handshake = adapter.handshake()

    assert handshake.adapter_slug == "generic-agent"
    assert handshake.platform == "generic"
    assert handshake.status == "ready"
    assert handshake.metadata["integration_id"] == "integration-generic-agent"
    assert handshake.metadata["runtime"] == "generic-agent"
    assert handshake.metadata["guard_mode"] == "strict"


def test_generic_agent_adapter_manifest_includes_adapter_metadata():
    registry = initialize_integration_registry()

    adapter = build_generic_agent_adapter(registry)
    manifest = adapter.manifest()

    assert manifest.slug == "generic-agent"
    assert manifest.platform == "generic"
    assert manifest.metadata["runtime"] == "generic-agent"
    assert manifest.metadata["guard_mode"] == "strict"


def test_generic_agent_adapter_execute_returns_guarded_result():
    registry = initialize_integration_registry()

    adapter = build_generic_agent_adapter(registry)
    result = adapter.execute(
        AdapterExecutionRequest(
            action_type="toolcall",
            target="local-http://127.0.0.1/agent/run",
            payload={
                "prompt": "Summarize the repository status.",
                "tool_name": "http.post",
            },
        ),
    )

    assert result.adapter_slug == "generic-agent"
    assert result.platform == "generic"
    assert result.success is True
    assert result.status == "guarded"
    assert result.metadata["runtime"] == "generic-agent"
    assert result.output["guard_applied"] is True
    assert result.output["request"]["action_type"] == "toolcall"
