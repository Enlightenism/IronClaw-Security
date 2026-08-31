from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from app.adapters.generic_agent_adapter import (
    GenericAgentAdapter,
    GenericAgentAdapterRequest,
    GenericAgentAdapterResponse,
    adapt_policy_decision_to_generic_agent,
    build_generic_agent_adapter,
    build_generic_agent_adapter_request,
    evaluate_generic_agent_request,
    summarize_generic_agent_adapter_response,
)
from app.services.integration_registry import IntegrationRegistry

AdapterVerdict = Literal["allow", "warn", "quarantine", "block"]
AdapterExecutionMode = Literal["monitor", "enforce"]

HermesAdapterRequest = GenericAgentAdapterRequest
HermesAdapterResponse = GenericAgentAdapterResponse


def build_hermes_adapter_request(
    *,
    action_type: str,
    target: str,
    content: str = "",
    agent_id: str | None = None,
    agent_name: str | None = None,
    runtime_name: str | None = "hermes",
    client_id: str | None = None,
    session_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> HermesAdapterRequest:
    return build_generic_agent_adapter_request(
        action_type=action_type,
        target=target,
        content=content,
        agent_id=agent_id,
        agent_name=agent_name,
        runtime_name=runtime_name or "hermes",
        client_id=client_id,
        session_id=session_id,
        metadata=metadata,
    )


def adapt_policy_decision_to_hermes(
    decision: Any,
    *,
    mode: AdapterExecutionMode = "enforce",
    trace_id: str | None = None,
    request: HermesAdapterRequest | None = None,
    metadata: dict[str, Any] | None = None,
) -> HermesAdapterResponse:
    response = adapt_policy_decision_to_generic_agent(
        decision,
        mode=mode,
        trace_id=trace_id,
        request=request,
        metadata=metadata,
    )
    response.adapter_name = "ironclaw-hermes"
    response.platform = "hermes"
    response.metadata.setdefault("runtime", "hermes")
    if not response.request.get("runtime_name"):
        response.request["runtime_name"] = "hermes"
    return response


def evaluate_hermes_request(
    engine: Any,
    request: HermesAdapterRequest,
    *,
    risk_score: int = 0,
    mode: AdapterExecutionMode = "enforce",
    trace_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> HermesAdapterResponse:
    response = evaluate_generic_agent_request(
        engine,
        request,
        risk_score=risk_score,
        mode=mode,
        trace_id=trace_id,
        metadata=metadata,
    )
    response.adapter_name = "ironclaw-hermes"
    response.platform = "hermes"
    response.metadata.setdefault("runtime", "hermes")
    if not response.request.get("runtime_name"):
        response.request["runtime_name"] = "hermes"
    return response


def summarize_hermes_adapter_response(response: HermesAdapterResponse) -> dict[str, Any]:
    return summarize_generic_agent_adapter_response(response)


@dataclass(slots=True)
class HermesAdapter(GenericAgentAdapter):
    runtime: str = "hermes"
    guard_mode: str = "strict"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        super().__post_init__()
        self.metadata.setdefault("runtime", self.runtime)
        self.metadata.setdefault("guard_mode", self.guard_mode)


def build_hermes_adapter(registry: IntegrationRegistry | None = None) -> HermesAdapter:
    if registry is not None:
        try:
            return HermesAdapter(
                record=build_generic_agent_adapter(registry).record,
                protocol_version="1.0.0",
                health="ready",
                metadata={"runtime": "hermes", "guard_mode": "strict"},
            )
        except Exception:
            pass
    return HermesAdapter(
        protocol_version="1.0.0",
        health="ready",
        metadata={"runtime": "hermes", "guard_mode": "strict"},
    )
