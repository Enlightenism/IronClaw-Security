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
    IntegrationRegistry,
    get_integration,
)

AdapterVerdict = Literal["allow", "warn", "quarantine", "block"]
AdapterExecutionMode = Literal["monitor", "enforce"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_text(value: str | None) -> str:
    return (value or "").strip()


# ---------- Policy-facing adapter request/response ----------


@dataclass(slots=True)
class OpenClawAdapterRequest:
    """
    High-level request wrapper for OpenClaw builder/workflow actions.

    This is the policy-facing representation of an OpenClaw action that will be
    evaluated by the IronClaw policy engine.
    """

    action_type: str
    target: str
    content: str = ""
    builder_id: str | None = None
    workflow_id: str | None = None
    client_id: str | None = None
    session_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_policy_input(self) -> PolicyInput:
        """
        Convert this request into a PolicyInput for the policy engine.

        builder_id and workflow_id are folded into metadata so they can be
        targeted by policy rules without changing the PolicyInput shape.
        """
        merged_metadata: dict[str, Any] = dict(self.metadata)
        if self.builder_id:
            merged_metadata["builder_id"] = self.builder_id
        if self.workflow_id:
            merged_metadata["workflow_id"] = self.workflow_id

        return PolicyInput(
            action_type=self.action_type,
            target=self.target,
            content=self.content,
            client_id=self.client_id,
            session_id=self.session_id,
            metadata=merged_metadata,
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize this request into a JSON-safe dict for logging/telemetry.
        """
        return {
            "action_type": self.action_type,
            "target": self.target,
            "content": self.content,
            "builder_id": self.builder_id,
            "workflow_id": self.workflow_id,
            "client_id": self.client_id,
            "session_id": self.session_id,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class OpenClawAdapterResponse:
    """
    Normalized policy decision payload for OpenClaw.

    This wraps a PolicyDecision with OpenClaw-specific flags (should_hold, etc.)
    so the builder/workflow runtime can make simple allow/hold decisions.
    """

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
        """
        Serialize this response into a JSON-safe dict for logging/telemetry.
        """
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


def build_openclaw_adapter_request(
    *,
    action_type: str,
    target: str,
    content: str = "",
    builder_id: str | None = None,
    workflow_id: str | None = None,
    client_id: str | None = None,
    session_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> OpenClawAdapterRequest:
    """
    Convenience constructor that normalizes and validates inbound fields.

    Ensures action_type and target are non-empty, trims string fields, and
    shields callers from having to know about default metadata behavior.
    """
    normalized_action_type = _normalize_text(action_type)
    normalized_target = _normalize_text(target)

    if not normalized_action_type:
        raise ValueError("action_type is required")
    if not normalized_target:
        raise ValueError("target is required")

    return OpenClawAdapterRequest(
        action_type=normalized_action_type,
        target=normalized_target,
        content=content or "",
        builder_id=_normalize_text(builder_id) or None,
        workflow_id=_normalize_text(workflow_id) or None,
        client_id=_normalize_text(client_id) or None,
        session_id=_normalize_text(session_id) or None,
        metadata=dict(metadata or {}),
    )


def adapt_policy_decision_to_openclaw(
    decision: PolicyDecision,
    *,
    mode: AdapterExecutionMode = "enforce",
    trace_id: str | None = None,
    request: OpenClawAdapterRequest | None = None,
    metadata: dict[str, Any] | None = None,
) -> OpenClawAdapterResponse:
    """
    Map a PolicyDecision into an OpenClawAdapterResponse.

    should_hold is when a decision is anything other than allow so the
    OpenClaw runtime can pause the workflow until a human reviews.
    """
    verdict: AdapterVerdict = decision.verdict
    matched_rules = [match.rule_id for match in decision.matches]
    reasons = [match.to_dict() for match in decision.matches]
    should_hold = verdict in {"warn", "quarantine", "block"}

    return OpenClawAdapterResponse(
        adapter_name="ironclaw-openclaw",
        platform="openclaw",
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


def evaluate_openclaw_request(
    engine: PolicyEngine,
    request: OpenClawAdapterRequest,
    *,
    risk_score: int = 0,
    mode: AdapterExecutionMode = "enforce",
    trace_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> OpenClawAdapterResponse:
    """
    One-shot helper: evaluate a request and return an OpenClawAdapterResponse.
    """
    decision = evaluate_policy(
        engine,
        request.to_policy_input(),
        risk_score=risk_score,
    )
    return adapt_policy_decision_to_openclaw(
        decision,
        mode=mode,
        trace_id=trace_id,
        request=request,
        metadata=metadata,
    )


def summarize_openclaw_adapter_response(
    response: OpenClawAdapterResponse,
) -> dict[str, Any]:
    """
    Compact summary record for dashboards, logs, or telemetry streams.
    """
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


# ---------- Integration-facing OpenClaw adapter class ----------


@dataclass(slots=True)
class OpenClawAdapter(BaseIntegrationAdapter):
    """
    Integration adapter for the OpenClaw runtime.

    This wraps guarded OpenClaw workflow executions and annotates results so the
    IronClaw UI can show that a builder workflow was gate-kept by policy.
    """

    runtime: str = "openclaw"
    workflow_mode: str = "builder-guard"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Ensure core metadata keys are present and stable for handshakes/manifests.
        self.metadata.setdefault("integration_id", self.record.integration_id)
        self.metadata.setdefault("runtime", self.runtime)
        self.metadata.setdefault("workflow_mode", self.workflow_mode)

    def execute(self, request: AdapterExecutionRequest) -> AdapterExecutionResult:
        """
        Execute a guarded OpenClaw workflow action.

        For now we delegate to the BaseIntegrationAdapter for any shared plumbing
        and then mark the result as "guarded" with OpenClaw-specific metadata.
        """
        result = super().execute(request)

        # Mark this as a guarded workflow execution for dashboards/telemetry.
        result.status = "guarded"
        result.summary = (
            f"{self.record.name} guarded workflow action "
            f"'{request.action_type}' for target '{request.target}'."
        )

        # Attach guard-specific output details and a minimal echo of the request.
        result.output.setdefault("guard_applied", True)
        result.output.setdefault("execution_mode", "workflow-gated")
        result.output.setdefault(
            "request",
            {
                "action_type": request.action_type,
                "target": request.target,
                "payload": request.payload,
            },
        )

        # Propagate runtime metadata so tests and UI can assert on it.
        result.metadata.setdefault("runtime", self.runtime)
        result.metadata.setdefault("workflow_mode", self.workflow_mode)

        return result


def build_openclaw_adapter(registry: IntegrationRegistry) -> OpenClawAdapter:
    """
    Factory to construct an OpenClawAdapter from the integration registry.

    Expected to back tests in tests/test_openclaw_adapter.py.
    """
    record = get_integration(registry, "integration-openclaw")
    if record is None:
        raise KeyError("unknown integration_id: integration-openclaw")

    return OpenClawAdapter(
        record=record,
        protocol_version="1.0.0",
        health="ready",
        metadata={
            "integration_id": record.integration_id,
            "runtime": "openclaw",
            "workflow_mode": "builder-guard",
        },
    )