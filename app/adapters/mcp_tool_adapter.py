from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from app.adapters.base import (
    AdapterExecutionRequest,
    AdapterExecutionResult,
    AdapterExecutionStatus,
    BaseIntegrationAdapter,
)
from app.services.integration_registry import (
    IntegrationCapability,
    IntegrationRecord,
    IntegrationRegistry,
    get_integration,
)


McpToolCallPhase = Literal["plan", "preflight", "execute"]
McpToolKind = Literal["mcp", "openai-tool", "custom"]
McpGuardMode = Literal["monitor", "enforce"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_text(value: str | None) -> str:
    return (value or "").strip()


def _clean_dict(value: dict[str, Any] | None) -> dict[str, Any]:
    return dict(value or {})


def _clean_list(value: list[Any] | None) -> list[Any]:
    return list(value or [])


@dataclass(slots=True)
class McpToolInvocation:
    """High-level description of a tool invocation coming from an MCP/tool client."""

    tool_name: str
    phase: McpToolCallPhase
    arguments: dict[str, Any] = field(default_factory=dict)
    client_id: str | None = None
    session_id: str | None = None
    agent_id: str | None = None
    agent_name: str | None = None
    runtime_name: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.tool_name = _normalize_text(self.tool_name)
        self.phase = _normalize_text(self.phase) or "execute"  # type: ignore[assignment]
        self.arguments = _clean_dict(self.arguments)
        self.client_id = _normalize_text(self.client_id) or None
        self.session_id = _normalize_text(self.session_id) or None
        self.agent_id = _normalize_text(self.agent_id) or None
        self.agent_name = _normalize_text(self.agent_name) or None
        self.runtime_name = _normalize_text(self.runtime_name) or None
        self.metadata = _clean_dict(self.metadata)

    def to_adapter_request(self) -> AdapterExecutionRequest:
        """Adapt to the generic AdapterExecutionRequest envelope."""
        payload: dict[str, Any] = {
            "tool_name": self.tool_name,
            "phase": self.phase,
            "arguments": dict(self.arguments),
            "client_id": self.client_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "runtime_name": self.runtime_name,
            "metadata": dict(self.metadata),
        }
        payload = {k: v for k, v in payload.items() if v is not None}

        return AdapterExecutionRequest(
            action_type=f"toolcall:{self.phase}",
            target=f"tool://{self.tool_name}",
            payload=payload,
            metadata={},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "phase": self.phase,
            "arguments": dict(self.arguments),
            "client_id": self.client_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "runtime_name": self.runtime_name,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class McpToolGuardDecision:
    """Result of guarding a tool invocation before or after real execution."""

    adapter_name: str
    platform: str
    mode: McpGuardMode
    verdict: str
    status: AdapterExecutionStatus
    should_allow: bool
    should_warn: bool
    should_block: bool
    should_review: bool
    summary: str
    risk_score: int
    risk_level: str
    matched_rules: list[str] = field(default_factory=list)
    reasons: list[dict[str, Any]] = field(default_factory=list)
    decision_id: str | None = None
    trace_id: str | None = None
    decided_at: str = field(default_factory=_utc_now)
    request: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_name": self.adapter_name,
            "platform": self.platform,
            "mode": self.mode,
            "verdict": self.verdict,
            "status": self.status,
            "should_allow": self.should_allow,
            "should_warn": self.should_warn,
            "should_block": self.should_block,
            "should_review": self.should_review,
            "summary": self.summary,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "matched_rules": _clean_list(self.matched_rules),
            "reasons": _clean_list(self.reasons),
            "decision_id": self.decision_id,
            "trace_id": self.trace_id,
            "decided_at": self.decided_at,
            "request": dict(self.request),
            "metadata": dict(self.metadata),
        }


def summarize_mcp_tool_guard_decision(
    decision: McpToolGuardDecision,
) -> dict[str, Any]:
    return {
        "adapter_name": decision.adapter_name,
        "platform": decision.platform,
        "mode": decision.mode,
        "verdict": decision.verdict,
        "status": decision.status,
        "should_review": decision.should_review,
        "risk_score": decision.risk_score,
        "risk_level": decision.risk_level,
        "summary": decision.summary,
        "matched_rule_count": len(decision.matched_rules),
        "decision_id": decision.decision_id,
        "trace_id": decision.trace_id,
        "decided_at": decision.decided_at,
    }


@dataclass(slots=True)
class McpToolAdapter(BaseIntegrationAdapter):
    """Integration adapter that wraps MCP/server tools behind the base adapter contract."""

    kind: McpToolKind = "mcp"
    guard_mode: McpGuardMode = "enforce"

    def __post_init__(self) -> None:
        if "kind" not in self.metadata:
            self.metadata["kind"] = self.kind
        if "guard_mode" not in self.metadata:
            self.metadata["guard_mode"] = self.guard_mode

    def supported_action_types(self) -> list[str]:
        # All toolcall phases go through this adapter.
        return [
            "toolcall:plan",
            "toolcall:preflight",
            "toolcall:execute",
        ]

    def _tool_capabilities(self) -> list[dict[str, Any]]:
        caps: list[dict[str, Any]] = []
        for capability in self.record.capabilities:
            if isinstance(capability, IntegrationCapability):
                caps.append(capability.to_dict())
            else:
                caps.append(getattr(capability, "to_dict", lambda: dict(capability))())
        return caps

    def guard_invocation(
        self,
        invocation: McpToolInvocation,
        *,
        mode: McpGuardMode = "enforce",
        trace_id: str | None = None,
        risk_score: int = 0,
        risk_level: str = "low",
        matched_rules: list[str] | None = None,
        reasons: list[dict[str, Any]] | None = None,
    ) -> McpToolGuardDecision:
        """Placeholder hook where policy / Groq verdict logic will plug in."""
        should_review = mode == "enforce" and invocation.phase != "plan"
        verdict = "allow"
        status: AdapterExecutionStatus = "guarded"

        summary = (
            f"Guarded tool '{invocation.tool_name}' at phase '{invocation.phase}' "
            f"for runtime '{invocation.runtime_name or 'unknown-runtime'}'."
        )

        return McpToolGuardDecision(
            adapter_name=self.record.name,
            platform=self.record.platform,
            mode=mode,
            verdict=verdict,
            status=status,
            should_allow=True,
            should_warn=False,
            should_block=False,
            should_review=should_review,
            summary=summary,
            risk_score=risk_score,
            risk_level=risk_level,
            matched_rules=_clean_list(matched_rules),
            reasons=_clean_list(reasons),
            decision_id=None,
            trace_id=trace_id,
            request=invocation.to_dict(),
            metadata={
                **self.base_metadata(),
                "tool_name": invocation.tool_name,
                "phase": invocation.phase,
            },
        )

    def execute(self, request: AdapterExecutionRequest) -> AdapterExecutionResult:
        """
        Execute a tool call through the base adapter contract.

        At this layer we do not talk to a real MCP server yet; we envelope the request,
        attach guard decision metadata, and let upstream orchestration decide how to
        route the actual tool execution for IronClaw-Security.
        """
        # Let the base adapter validate action_type/target and health first.
        base_result = super().execute(request)

        # Derive tool name + phase from the request envelope if present.
        tool_name = _normalize_text(request.payload.get("tool_name")) or request.target
        phase = _normalize_text(request.payload.get("phase")) or "execute"

        invocation = McpToolInvocation(
            tool_name=tool_name,
            phase=phase,  # type: ignore[arg-type]
            arguments=request.payload.get("arguments") or {},
            client_id=request.payload.get("client_id"),
            session_id=request.payload.get("session_id"),
            agent_id=request.payload.get("agent_id"),
            agent_name=request.payload.get("agent_name"),
            runtime_name=request.payload.get("runtime_name"),
            metadata=request.payload.get("metadata") or {},
        )

        decision = self.guard_invocation(invocation, mode=self.guard_mode)

        # Attach guard decision into the adapter result without changing success.
        base_result.status = decision.status
        base_result.summary = decision.summary
        base_result.output.setdefault("request", request.to_dict())
        base_result.output["guard_decision"] = decision.to_dict()
        base_result.metadata["guard_mode"] = self.guard_mode
        base_result.metadata["kind"] = self.kind

        return base_result


def build_mcp_tool_adapter(registry: IntegrationRegistry) -> McpToolAdapter:
    """
    Factory for the MCP tool adapter used in tests and integrations.

    Expects an IntegrationRecord with id 'integration-mcp-tools' to exist in the registry.
    """
    record: IntegrationRecord | None = get_integration(
        registry,
        "integration-mcp-tools",
    )
    if record is None:
        raise KeyError("unknown integration_id: integration-mcp-tools")

    return McpToolAdapter(
        record=record,
        protocol_version="1.0.0",
        health="ready",
        metadata={
            "kind": "mcp",
            "guard_mode": "enforce",
        },
    )