from __future__ import annotations


from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal


from app.adapters.base import AdapterExecutionRequest, AdapterExecutionResult, BaseIntegrationAdapter
from app.orchestrator.policy_enforcer import PolicyDecision, PolicyEngine, PolicyInput, evaluate_policy
from app.services.integration_registry import IntegrationRecord, IntegrationRegistry, get_integration


AdapterVerdict = Literal["allow", "warn", "quarantine", "block"]
AdapterExecutionMode = Literal["monitor", "enforce"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_text(value: str | None) -> str:
    return (value or "").strip()


@dataclass(slots=True)
class ClaudeCodeAdapterRequest:
    action_type: str
    target: str
    content: str = ""
    client_id: str | None = None
    session_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_policy_input(self) -> PolicyInput:
        return PolicyInput(
            action_type=self.action_type,
            target=self.target,
            content=self.content,
            client_id=self.client_id,
            session_id=self.session_id,
            metadata=dict(self.metadata),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "target": self.target,
            "content": self.content,
            "client_id": self.client_id,
            "session_id": self.session_id,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class ClaudeCodeAdapterResponse:
    adapter_name: str
    platform: str
    mode: AdapterExecutionMode
    verdict: AdapterVerdict
    should_allow: bool
    should_warn: bool
    should_quarantine: bool
    should_block: bool
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


def build_claude_code_adapter_request(
    *,
    action_type: str,
    target: str,
    content: str = "",
    client_id: str | None = None,
    session_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> ClaudeCodeAdapterRequest:
    normalized_action_type = _normalize_text(action_type)
    normalized_target = _normalize_text(target)

    if not normalized_action_type:
        raise ValueError("action_type is required")
    if not normalized_target:
        raise ValueError("target is required")

    return ClaudeCodeAdapterRequest(
        action_type=normalized_action_type,
        target=normalized_target,
        content=content or "",
        client_id=_normalize_text(client_id) or None,
        session_id=_normalize_text(session_id) or None,
        metadata=dict(metadata or {}),
    )


def adapt_policy_decision_to_claude_code(
    decision: PolicyDecision,
    *,
    mode: AdapterExecutionMode = "enforce",
    trace_id: str | None = None,
    request: ClaudeCodeAdapterRequest | None = None,
    metadata: dict[str, Any] | None = None,
) -> ClaudeCodeAdapterResponse:
    verdict: AdapterVerdict = decision.verdict
    matched_rules = [match.rule_id for match in decision.matches]
    reasons = [match.to_dict() for match in decision.matches]

    return ClaudeCodeAdapterResponse(
        adapter_name="ironclaw-claude-code",
        platform="claude-code",
        mode=mode,
        verdict=verdict,
        should_allow=verdict == "allow",
        should_warn=verdict == "warn",
        should_quarantine=verdict == "quarantine",
        should_block=verdict == "block",
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


def evaluate_claude_code_request(
    engine: PolicyEngine,
    request: ClaudeCodeAdapterRequest,
    *,
    risk_score: int = 0,
    mode: AdapterExecutionMode = "enforce",
    trace_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> ClaudeCodeAdapterResponse:
    decision = evaluate_policy(
        engine,
        request.to_policy_input(),
        risk_score=risk_score,
    )
    return adapt_policy_decision_to_claude_code(
        decision,
        mode=mode,
        trace_id=trace_id,
        request=request,
        metadata=metadata,
    )


def summarize_claude_code_adapter_response(
    response: ClaudeCodeAdapterResponse,
) -> dict[str, Any]:
    return {
        "adapter_name": response.adapter_name,
        "platform": response.platform,
        "mode": response.mode,
        "verdict": response.verdict,
        "risk_score": response.risk_score,
        "risk_level": response.risk_level,
        "summary": response.summary,
        "matched_rule_count": len(response.matched_rules),
        "decision_id": response.decision_id,
        "trace_id": response.trace_id,
        "reviewed_at": response.reviewed_at,
    }


@dataclass(slots=True)
class ClaudeCodeAdapter(BaseIntegrationAdapter):
    runtime: str = "claude-code"
    guard_mode: str = "strict"

    def __post_init__(self) -> None:
        self.metadata.setdefault("runtime", self.runtime)
        self.metadata.setdefault("guard_mode", self.guard_mode)

    def execute(self, request: AdapterExecutionRequest) -> AdapterExecutionResult:
        result = super().execute(request)
        result.status = "guarded"
        result.summary = f"{self.record.name} guarded action '{request.action_type}' for target '{request.target}'."
        result.output["guard_applied"] = True
        result.metadata["runtime"] = self.runtime
        result.metadata["guard_mode"] = self.guard_mode
        return result


def build_claude_code_adapter(registry: IntegrationRegistry) -> ClaudeCodeAdapter:
    record = get_integration(registry, "integration-claude-code")
    if record is None:
        raise KeyError("unknown integration_id: integration-claude-code")

    return ClaudeCodeAdapter(
        record=record,
        protocol_version="1.0.0",
        health="ready",
        metadata={
            "runtime": "claude-code",
            "guard_mode": "strict",
        },
    )