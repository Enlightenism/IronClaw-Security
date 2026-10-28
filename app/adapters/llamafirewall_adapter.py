from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from app.adapters.base import (
    AdapterExecutionRequest,
    AdapterExecutionResult,
    BaseIntegrationAdapter,
)
from app.clients.llamafirewall_client import (
    LlamaFirewallClient,
    LlamaFirewallClientConfig,
)
from app.config import RISK_THRESHOLD_ALLOW_MAX, RISK_THRESHOLD_BLOCK_MIN
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

AdapterVerdict = Literal["allow", "block"]
AdapterExecutionMode = Literal["monitor", "enforce"]
LlamaFirewallScanStatus = Literal["pending", "running", "completed", "failed", "timeout"]

_PROMPT_ACTION_TYPES = frozenset({"prompt_submission", "message"})
_AGENT_ACTION_TYPES = frozenset({"tool_call", "agent_action"})
_CODE_ACTION_TYPES = frozenset({"scan_request"})


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_text(value: str | None) -> str:
    return (value or "").strip()


def _extract_lf_verdict(scan_result: dict[str, Any]) -> str | None:
    """Extract the LlamaFirewall scanner's own verdict from a normalized scan result."""
    verdict = scan_result.get("verdict")
    if verdict and isinstance(verdict, str):
        return verdict.lower() or None
    return None


def _extract_lf_categories(scan_result: dict[str, Any]) -> list[str]:
    """Extract the LlamaFirewall scanner's attack categories from a normalized scan result."""
    cats = scan_result.get("categories", [])
    if isinstance(cats, list):
        return [str(c) for c in cats]
    return []


@dataclass(slots=True)
class LlamaFirewallAdapterRequest:
    action_type: str
    target: str
    content: str = ""
    prompt: str | None = None
    scanner_id: str | None = None
    policy_id: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_policy_input(self) -> PolicyInput:
        merged_metadata: dict[str, Any] = dict(self.metadata)
        if self.prompt:
            merged_metadata["prompt"] = self.prompt
        if self.scanner_id:
            merged_metadata["scanner_id"] = self.scanner_id
        if self.policy_id:
            merged_metadata["policy_id"] = self.policy_id

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
            "scanner_id": self.scanner_id,
            "policy_id": self.policy_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class LlamaFirewallAdapterResponse:
    """Normalized policy decision payload for LlamaFirewall scan submissions.

    Carries both the IronClaw policy verdict and the LlamaFirewall scanner's
    own verdict + attack categories so the audit log has both layers.
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
    # LlamaFirewall scanner layer — populated when a real scan was performed
    lf_verdict: str | None = None
    lf_categories: list[str] = field(default_factory=list)
    # Internal: raw normalized scan result (not emitted by to_dict)
    scan_result: dict[str, Any] = field(default_factory=dict)
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
            "lf_verdict": self.lf_verdict,
            "lf_categories": list(self.lf_categories),
            "decision_id": self.decision_id,
            "trace_id": self.trace_id,
            "reviewed_at": self.reviewed_at,
            "request": dict(self.request),
            "metadata": dict(self.metadata),
        }


def build_llamafirewall_adapter_request(
    *,
    action_type: str,
    target: str,
    content: str = "",
    prompt: str | None = None,
    scanner_id: str | None = None,
    policy_id: str | None = None,
    agent_id: str | None = None,
    session_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> LlamaFirewallAdapterRequest:
    normalized_action_type = _normalize_text(action_type)
    normalized_target = _normalize_text(target)

    if not normalized_action_type:
        raise ValueError("action_type is required")
    if not normalized_target:
        raise ValueError("target is required")

    return LlamaFirewallAdapterRequest(
        action_type=normalized_action_type,
        target=normalized_target,
        content=content or "",
        prompt=_normalize_text(prompt) or None,
        scanner_id=_normalize_text(scanner_id) or None,
        policy_id=_normalize_text(policy_id) or None,
        agent_id=_normalize_text(agent_id) or None,
        session_id=_normalize_text(session_id) or None,
        metadata=dict(metadata or {}),
    )


def adapt_policy_decision_to_llamafirewall(
    decision: PolicyDecision,
    *,
    mode: AdapterExecutionMode = "enforce",
    trace_id: str | None = None,
    request: LlamaFirewallAdapterRequest | None = None,
    scan_result: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> LlamaFirewallAdapterResponse:
    """Map a PolicyDecision into a LlamaFirewallAdapterResponse.

    When scan_result is supplied (from a real LlamaFirewall HTTP scan),
    the scanner's own verdict and attack categories are extracted and stored
    on lf_verdict / lf_categories so the audit log carries both layers.
    """
    verdict: AdapterVerdict = "allow" if decision.verdict == "allow" and decision.allow_execution is True and not decision.requires_review and not decision.matched_rules and 0 <= decision.risk_score <= RISK_THRESHOLD_ALLOW_MAX else "block"
    matched_rules = [match.rule_id for match in decision.matched_rules]
    reasons = [match.to_dict() for match in decision.matched_rules]
    should_hold = verdict == "block"
    risk_score = max(decision.risk_score, RISK_THRESHOLD_BLOCK_MIN) if should_hold else decision.risk_score
    risk_level = "high" if should_hold and decision.risk_level in {"low", "medium"} else decision.risk_level

    resolved_scan: dict[str, Any] = dict(scan_result or {})
    lf_verdict = _extract_lf_verdict(resolved_scan)
    lf_categories = _extract_lf_categories(resolved_scan)

    return LlamaFirewallAdapterResponse(
        adapter_name="ironclaw-llamafirewall",
        platform="llamafirewall",
        mode=mode,
        verdict=verdict,
        should_allow=verdict == "allow",
        should_warn=False,
        should_quarantine=False,
        should_block=verdict == "block",
        should_hold=should_hold,
        risk_score=risk_score,
        risk_level=risk_level,
        summary=decision.summary,
        matched_rules=matched_rules,
        reasons=reasons,
        lf_verdict=lf_verdict,
        lf_categories=lf_categories,
        scan_result=resolved_scan,
        decision_id=decision.decision_id,
        trace_id=trace_id,
        request=request.to_dict() if request else {},
        metadata=dict(metadata or {}),
    )


def evaluate_llamafirewall_request(
    engine: PolicyEngine,
    request: LlamaFirewallAdapterRequest,
    *,
    risk_score: int = 0,
    mode: AdapterExecutionMode = "enforce",
    trace_id: str | None = None,
    scan_result: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> LlamaFirewallAdapterResponse:
    decision = evaluate_policy(
        engine,
        request.to_policy_input(),
        risk_score=risk_score,
    )
    return adapt_policy_decision_to_llamafirewall(
        decision,
        mode=mode,
        trace_id=trace_id,
        request=request,
        scan_result=scan_result,
        metadata=metadata,
    )


def summarize_llamafirewall_adapter_response(
    response: LlamaFirewallAdapterResponse,
) -> dict[str, Any]:
    """Compact summary for dashboards, logs, and telemetry.

    Includes both the IronClaw policy verdict and the LlamaFirewall scanner
    layer (lf_verdict, lf_categories) so audit consumers have full context.
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
        "lf_verdict": response.lf_verdict,
        "lf_categories": list(response.lf_categories),
        "decision_id": response.decision_id,
        "trace_id": response.trace_id,
        "reviewed_at": response.reviewed_at,
    }


@dataclass(slots=True)
class LlamaFirewallAdapter(BaseIntegrationAdapter):
    """Integration adapter for the LlamaFirewall prompt-injection scanning layer."""

    runtime: str = "llamafirewall"
    guard_mode: str = "prompt-guard"
    client_config: LlamaFirewallClientConfig | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.metadata.setdefault("integration_id", self.record.integration_id)
        self.metadata.setdefault("runtime", self.runtime)
        self.metadata.setdefault("guard_mode", self.guard_mode)

    def supported_action_types(self) -> list[str]:
        return [
            "prompt_submission",
            "tool_call",
            "message",
            "agent_action",
            "scan_request",
        ]

    def _run_scan(
        self,
        request: AdapterExecutionRequest,
    ) -> dict[str, Any]:
        if self.client_config is None:
            return {}

        client = LlamaFirewallClient(self.client_config)
        action_type = request.action_type
        payload = request.payload

        try:
            if action_type in _PROMPT_ACTION_TYPES:
                return client.scan_prompt(
                    prompt=str(payload.get("prompt") or payload.get("content") or request.target),
                    agent_id=str(payload["agent_id"]) if "agent_id" in payload else None,
                    session_id=str(payload["session_id"]) if "session_id" in payload else None,
                    metadata=dict(request.metadata),
                )

            if action_type in _AGENT_ACTION_TYPES:
                return client.scan_agent_action(
                    action_type=action_type,
                    target=request.target,
                    content=str(payload.get("content") or ""),
                    agent_id=str(payload["agent_id"]) if "agent_id" in payload else None,
                    session_id=str(payload["session_id"]) if "session_id" in payload else None,
                    metadata=dict(request.metadata),
                )

            if action_type in _CODE_ACTION_TYPES:
                return client.scan_code(
                    code=str(payload.get("code") or payload.get("content") or ""),
                    language=str(payload.get("language") or "unknown"),
                    agent_id=str(payload["agent_id"]) if "agent_id" in payload else None,
                    session_id=str(payload["session_id"]) if "session_id" in payload else None,
                    metadata=dict(request.metadata),
                )

            return client.scan_all(
                prompt=str(payload.get("prompt") or payload.get("content") or None),
                action_type=action_type,
                target=request.target,
                content=str(payload.get("content") or ""),
                metadata=dict(request.metadata),
            )
        finally:
            client.close()

    def execute(self, request: AdapterExecutionRequest) -> AdapterExecutionResult:
        result = super().execute(request)

        if not result.success:
            return result

        scan_result = self._run_scan(request)

        result.status = "guarded"
        result.summary = f"{self.record.name} guarded scan action '{request.action_type}' for target '{request.target}'."

        result.output["guard_applied"] = True
        result.output["execution_mode"] = "prompt-gated"
        result.output["scan_result"] = scan_result
        result.output["scan_performed"] = bool(scan_result)
        result.output["lf_verdict"] = _extract_lf_verdict(scan_result)
        result.output["lf_categories"] = _extract_lf_categories(scan_result)

        result.metadata["runtime"] = self.runtime
        result.metadata["guard_mode"] = self.guard_mode

        return result


def build_llamafirewall_adapter(
    registry: IntegrationRegistry,
    *,
    client_config: LlamaFirewallClientConfig | None = None,
) -> LlamaFirewallAdapter:
    record = get_integration(registry, "integration-llamafirewall")
    if record is None:
        raise KeyError("unknown integration_id: integration-llamafirewall")

    return LlamaFirewallAdapter(
        record=record,
        protocol_version="1.0.0",
        health="ready",
        client_config=client_config,
        metadata={
            "integration_id": record.integration_id,
            "runtime": "llamafirewall",
            "guard_mode": "prompt-guard",
        },
    )
