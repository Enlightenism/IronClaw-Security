from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from app.adapters.base import (
    AdapterExecutionRequest,
    AdapterExecutionResult,
    BaseIntegrationAdapter,
)
from app.orchestrator.policy_enforcer import (
    PolicyDecision,
    PolicyEngine,
    PolicyInput,
    evaluate_policy,
)
from app.services.integration_registry import (
    IntegrationRecord,
    IntegrationRegistry,
    get_integration,
)

AdapterVerdict = Literal["allow", "warn", "quarantine", "block"]
AdapterExecutionMode = Literal["monitor", "enforce"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_text(value: str | None) -> str:
    return (value or "").strip()


@dataclass(slots=True)
class GenericAgentAdapterRequest:
    action_type: str
    target: str
    content: str = ""
    agent_id: str | None = None
    agent_name: str | None = None
    runtime_name: str | None = None
    client_id: str | None = None
    session_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_policy_input(self) -> PolicyInput:
        merged_metadata = dict(self.metadata)
        if self.agent_id:
            merged_metadata["agent_id"] = self.agent_id
        if self.agent_name:
            merged_metadata["agent_name"] = self.agent_name
        if self.runtime_name:
            merged_metadata["runtime_name"] = self.runtime_name

        return PolicyInput(
            action_type=self.action_type,
            target=self.target,
            content=self.content,
            client_id=self.client_id,
            session_id=self.session_id,
            metadata=merged_metadata,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "target": self.target,
            "content": self.content,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "runtime_name": self.runtime_name,
            "client_id": self.client_id,
            "session_id": self.session_id,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class GenericAgentAdapterResponse:
    adapter_name: str
    platform: str
    mode: AdapterExecutionMode
    verdict: AdapterVerdict
    should_allow: bool
    should_warn: bool
    should_quarantine: bool
    should_block: bool
    should_review: bool
    risk_score: int
    risk_level: str
    summary: str
    matched_rules: list[str] = field(default_factory=list)
    reasons: list[dict[str, Any]] = field(default_factory=list)
    decision_id: str | None = None
    trace_id: str | None = None
    reviewed_at: str = field(default_factory=_utc_now)
    request: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_name": self.adapter_name,
            "platform": self.platform,
            "mode": self.mode,
            "verdict": self.verdict,
            "should_allow": self.should_allow,
            "should_warn": self.should_warn,
            "should_quarantine": self.should_quarantine,
            "should_block": self.should_block,
            "should_review": self.should_review,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "summary": self.summary,
            "matched_rules": list(self.matched_rules),
            "reasons": list(self.reasons),
            "decision_id": self.decision_id,
            "trace_id": self.trace_id,
            "reviewed_at": self.reviewed_at,
            "request": dict(self.request),
            "metadata": dict(self.metadata),
        }


def build_generic_agent_adapter_request(
    *,
    action_type: str,
    target: str,
    content: str = "",
    agent_id: str | None = None,
    agent_name: str | None = None,
    runtime_name: str | None = None,
    client_id: str | None = None,
    session_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> GenericAgentAdapterRequest:
    normalized_action_type = _normalize_text(action_type)
    normalized_target = _normalize_text(target)

    if not normalized_action_type:
        raise ValueError("action_type is required")
    if not normalized_target:
        raise ValueError("target is required")

    return GenericAgentAdapterRequest(
        action_type=normalized_action_type,
        target=normalized_target,
        content=content or "",
        agent_id=_normalize_text(agent_id) or None,
        agent_name=_normalize_text(agent_name) or None,
        runtime_name=_normalize_text(runtime_name) or None,
        client_id=_normalize_text(client_id) or None,
        session_id=_normalize_text(session_id) or None,
        metadata=dict(metadata or {}),
    )


def adapt_policy_decision_to_generic_agent(
    decision: PolicyDecision,
    *,
    mode: AdapterExecutionMode = "enforce",
    trace_id: str | None = None,
    request: GenericAgentAdapterRequest | None = None,
    metadata: dict[str, Any] | None = None,
) -> GenericAgentAdapterResponse:
    verdict: AdapterVerdict = decision.verdict
    matched_rules = [match.rule_id for match in decision.matches]
    reasons = [match.to_dict() for match in decision.matches]
    should_review = verdict in {"warn", "quarantine"}

    return GenericAgentAdapterResponse(
        adapter_name="ironclaw-generic-agent",
        platform="generic",
        mode=mode,
        verdict=verdict,
        should_allow=verdict == "allow",
        should_warn=verdict == "warn",
        should_quarantine=verdict == "quarantine",
        should_block=verdict == "block",
        should_review=should_review,
        risk_score=decision.risk_score,
        risk_level=decision.risk_level,
        summary=decision.summary,
        matched_rules=matched_rules,
        reasons=reasons,
        decision_id=decision.decision_id,
        trace_id=trace_id,
        request=request.to_dict() if request else {},
        metadata=dict(metadata or {}),
    )


def evaluate_generic_agent_request(
    engine: PolicyEngine,
    request: GenericAgentAdapterRequest,
    *,
    risk_score: int = 0,
    mode: AdapterExecutionMode = "enforce",
    trace_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> GenericAgentAdapterResponse:
    decision = evaluate_policy(
        engine,
        request.to_policy_input(),
        risk_score=risk_score,
    )
    return adapt_policy_decision_to_generic_agent(
        decision,
        mode=mode,
        trace_id=trace_id,
        request=request,
        metadata=metadata,
    )


def summarize_generic_agent_adapter_response(
    response: GenericAgentAdapterResponse,
) -> dict[str, Any]:
    return {
        "adapter_name": response.adapter_name,
        "platform": response.platform,
        "mode": response.mode,
        "verdict": response.verdict,
        "should_review": response.should_review,
        "risk_score": response.risk_score,
        "risk_level": response.risk_level,
        "summary": response.summary,
        "matched_rule_count": len(response.matched_rules),
        "decision_id": response.decision_id,
        "trace_id": response.trace_id,
        "reviewed_at": response.reviewed_at,
    }


# --- Integration adapter class + factory for tests ---


@dataclass(slots=True)
class GenericAgentAdapter(BaseIntegrationAdapter):
    """Integration adapter for 'integration-generic-agent' records."""

    runtime: str = "generic-agent"
    guard_mode: str = "strict"

    def __post_init__(self) -> None:
        # Ensure runtime and guard_mode are reflected in metadata for handshake/manifest.
        if "runtime" not in self.metadata:
            self.metadata["runtime"] = self.runtime
        if "guard_mode" not in self.metadata:
            self.metadata["guard_mode"] = self.guard_mode

    def execute(self, request: AdapterExecutionRequest) -> AdapterExecutionResult:
        # Start from the base adapter execution result.
        result = super().execute(request)
        # Mark that IronClaw guard logic has been applied for this generic agent.
        result.status = "guarded"
        result.summary = (
            f"{self.record.name} guarded action "
            f"'{request.action_type}' for target '{request.target}'."
        )
        result.output.setdefault("request", request.to_dict())
        result.output["guard_applied"] = True
        result.metadata["runtime"] = self.runtime
        result.metadata["guard_mode"] = self.guard_mode
        return result


def build_generic_agent_adapter(registry: IntegrationRegistry) -> GenericAgentAdapter:
    """Factory for the generic-agent adapter used in tests and integrations."""
    record: IntegrationRecord | None = get_integration(registry, "integration-generic-agent")
    if record is None:
        raise KeyError("unknown integration_id: integration-generic-agent")

    return GenericAgentAdapter(
        record=record,
        protocol_version="1.0.0",
        health="ready",
        metadata={
            "runtime": "generic-agent",
            "guard_mode": "strict",
        },
    )