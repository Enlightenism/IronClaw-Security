from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
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
    IntegrationRegistry,
    get_integration,
)

AdapterVerdict = Literal["allow", "warn", "quarantine", "block"]
AdapterExecutionMode = Literal["monitor", "enforce"]
RebuffScanStatus = Literal["pending", "running", "completed", "failed", "timeout"]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_text(value: str | None) -> str:
    return (value or "").strip()


# ---------- Policy-facing adapter request/response ----------


@dataclass(slots=True)
class RebuffAdapterRequest:
    """High-level request wrapper for Rebuff prompt injection detection actions.

    Represents a prompt or user input submitted to the Rebuff prompt injection
    detection platform that will be evaluated by the IronClaw policy engine
    before dispatching to the Rebuff API.
    """

    action_type: str
    target: str
    content: str = ""
    prompt: str | None = None
    injection_score_threshold: float | None = None
    detection_strategy: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_policy_input(self) -> PolicyInput:
        merged_metadata: dict[str, Any] = dict(self.metadata)
        if self.prompt:
            merged_metadata["prompt"] = self.prompt
        if self.injection_score_threshold is not None:
            merged_metadata["injection_score_threshold"] = self.injection_score_threshold
        if self.detection_strategy:
            merged_metadata["detection_strategy"] = self.detection_strategy

        return PolicyInput(
            action_type=self.action_type,
            target=self.target,
            content=self.content,
            agent_id=self.agent_id,
            session_id=self.session_id,
            metadata=merged_metadata,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "target": self.target,
            "content": self.content,
            "prompt": self.prompt,
            "injection_score_threshold": self.injection_score_threshold,
            "detection_strategy": self.detection_strategy,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class RebuffAdapterResponse:
    """Normalized policy decision payload for Rebuff prompt injection scans."""

    adapter_name: str
    platform: str
    mode: AdapterExecutionMode
    verdict: AdapterVerdict
    should_allow: bool
    should_warn: bool
    should_quarantine: bool
    should_block: bool
    should_hold: bool
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
            "should_hold": self.should_hold,
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


def build_rebuff_adapter_request(
    *,
    action_type: str,
    target: str,
    content: str = "",
    prompt: str | None = None,
    injection_score_threshold: float | None = None,
    detection_strategy: str | None = None,
    agent_id: str | None = None,
    session_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> RebuffAdapterRequest:
    normalized_action_type = _normalize_text(action_type)
    normalized_target = _normalize_text(target)

    if not normalized_action_type:
        raise ValueError("action_type is required")
    if not normalized_target:
        raise ValueError("target is required")

    return RebuffAdapterRequest(
        action_type=normalized_action_type,
        target=normalized_target,
        content=content or "",
        prompt=_normalize_text(prompt) or None,
        injection_score_threshold=injection_score_threshold,
        detection_strategy=_normalize_text(detection_strategy) or None,
        agent_id=_normalize_text(agent_id) or None,
        session_id=_normalize_text(session_id) or None,
        metadata=dict(metadata or {}),
    )


def adapt_policy_decision_to_rebuff(
    decision: PolicyDecision,
    *,
    mode: AdapterExecutionMode = "enforce",
    trace_id: str | None = None,
    request: RebuffAdapterRequest | None = None,
    metadata: dict[str, Any] | None = None,
) -> RebuffAdapterResponse:
    verdict: AdapterVerdict = decision.verdict
    matched_rules = [match.rule_id for match in decision.matched_rules]
    reasons = [match.to_dict() for match in decision.matched_rules]
    should_hold = verdict in {"warn", "quarantine", "block"}

    return RebuffAdapterResponse(
        adapter_name="ironclaw-rebuff",
        platform="rebuff",
        mode=mode,
        verdict=verdict,
        should_allow=verdict == "allow",
        should_warn=verdict == "warn",
        should_quarantine=verdict == "quarantine",
        should_block=verdict == "block",
        should_hold=should_hold,
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


def evaluate_rebuff_request(
    engine: PolicyEngine,
    request: RebuffAdapterRequest,
    *,
    risk_score: int = 0,
    mode: AdapterExecutionMode = "enforce",
    trace_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> RebuffAdapterResponse:
    decision = evaluate_policy(
        engine,
        request.to_policy_input(),
        risk_score=risk_score,
    )
    return adapt_policy_decision_to_rebuff(
        decision,
        mode=mode,
        trace_id=trace_id,
        request=request,
        metadata=metadata,
    )


def summarize_rebuff_adapter_response(
    response: RebuffAdapterResponse,
) -> dict[str, Any]:
    return {
        "adapter_name": response.adapter_name,
        "platform": response.platform,
        "mode": response.mode,
        "verdict": response.verdict,
        "should_hold": response.should_hold,
        "risk_score": response.risk_score,
        "risk_level": response.risk_level,
        "summary": response.summary,
        "matched_rule_count": len(response.matched_rules),
        "decision_id": response.decision_id,
        "trace_id": response.trace_id,
        "reviewed_at": response.reviewed_at,
    }


# ---------- Integration-facing Rebuff adapter class ----------


@dataclass
class RebuffAdapter(BaseIntegrationAdapter):
    """Integration adapter for the Rebuff prompt injection detection platform."""

    runtime: str = "rebuff"
    analysis_mode: str = "injection-guard"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.metadata.setdefault("integration_id", self.record.integration_id)
        self.metadata.setdefault("runtime", self.runtime)
        self.metadata.setdefault("analysis_mode", self.analysis_mode)

    def supported_action_types(self) -> list[str]:
        return [
            "scan_prompt",
            "scan_completion",
            "scan_tool_input",
            "scan_tool_output",
            "report_injection",
        ]

    def execute(self, request: AdapterExecutionRequest) -> AdapterExecutionResult:
        result = super().execute(request)

        if not result.success:
            return result

        result.status = "guarded"
        result.summary = f"{self.record.name} guarded injection-detection action " f"'{request.action_type}' for target '{request.target}'."

        result.output.setdefault("guard_applied", True)
        result.output.setdefault("execution_mode", "injection-gated")
        result.output.setdefault(
            "request",
            {
                "action_type": request.action_type,
                "target": request.target,
                "payload": request.payload,
            },
        )

        result.metadata.setdefault("runtime", self.runtime)
        result.metadata.setdefault("analysis_mode", self.analysis_mode)

        return result


def build_rebuff_adapter(registry: IntegrationRegistry) -> RebuffAdapter:
    record = get_integration(registry, "integration-rebuff")
    if record is None:
        raise KeyError("unknown integration_id: integration-rebuff")

    return RebuffAdapter(
        record=record,
        protocol_version="1.0.0",
        health="ready",
        metadata={
            "integration_id": record.integration_id,
            "runtime": "rebuff",
            "analysis_mode": "injection-guard",
        },
    )
