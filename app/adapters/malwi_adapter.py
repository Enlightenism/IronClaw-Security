from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from app.adapters.base import (
    AdapterExecutionRequest,
    AdapterExecutionResult,
    BaseIntegrationAdapter,
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
MalwiScanStatus = Literal["pending", "running", "completed", "failed", "timeout"]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_text(value: str | None) -> str:
    return (value or "").strip()


# ---------- Policy-facing adapter request/response ----------


@dataclass(slots=True)
class MalwiAdapterRequest:
    """High-level request wrapper for Malwi threat intelligence actions.

    Represents a file hash, URL, IP, or domain lookup submitted to the Malwi
    threat intelligence platform that will be evaluated by the IronClaw policy
    engine before dispatching to the Malwi API.
    """

    action_type: str
    target: str
    content: str = ""
    ioc_type: str | None = None
    ioc_value: str | None = None
    threat_category: str | None = None
    confidence_threshold: int | None = None
    agent_id: str | None = None
    session_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_policy_input(self) -> PolicyInput:
        merged_metadata: dict[str, Any] = dict(self.metadata)
        if self.ioc_type:
            merged_metadata["ioc_type"] = self.ioc_type
        if self.ioc_value:
            merged_metadata["ioc_value"] = self.ioc_value
        if self.threat_category:
            merged_metadata["threat_category"] = self.threat_category
        if self.confidence_threshold is not None:
            merged_metadata["confidence_threshold"] = self.confidence_threshold

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
            "ioc_type": self.ioc_type,
            "ioc_value": self.ioc_value,
            "threat_category": self.threat_category,
            "confidence_threshold": self.confidence_threshold,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class MalwiAdapterResponse:
    """Normalized policy decision payload for Malwi threat intelligence lookups."""

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


def build_malwi_adapter_request(
    *,
    action_type: str,
    target: str,
    content: str = "",
    ioc_type: str | None = None,
    ioc_value: str | None = None,
    threat_category: str | None = None,
    confidence_threshold: int | None = None,
    agent_id: str | None = None,
    session_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> MalwiAdapterRequest:
    normalized_action_type = _normalize_text(action_type)
    normalized_target = _normalize_text(target)

    if not normalized_action_type:
        raise ValueError("action_type is required")
    if not normalized_target:
        raise ValueError("target is required")

    return MalwiAdapterRequest(
        action_type=normalized_action_type,
        target=normalized_target,
        content=content or "",
        ioc_type=_normalize_text(ioc_type) or None,
        ioc_value=_normalize_text(ioc_value) or None,
        threat_category=_normalize_text(threat_category) or None,
        confidence_threshold=confidence_threshold,
        agent_id=_normalize_text(agent_id) or None,
        session_id=_normalize_text(session_id) or None,
        metadata=dict(metadata or {}),
    )


def adapt_policy_decision_to_malwi(
    decision: PolicyDecision,
    *,
    mode: AdapterExecutionMode = "enforce",
    trace_id: str | None = None,
    request: MalwiAdapterRequest | None = None,
    metadata: dict[str, Any] | None = None,
) -> MalwiAdapterResponse:
    verdict: AdapterVerdict = "allow" if decision.verdict == "allow" and decision.allow_execution is True and not decision.requires_review and not decision.matched_rules and 0 <= decision.risk_score <= RISK_THRESHOLD_ALLOW_MAX else "block"
    matched_rules = [match.rule_id for match in decision.matched_rules]
    reasons = [match.to_dict() for match in decision.matched_rules]
    should_hold = verdict == "block"
    risk_score = max(decision.risk_score, RISK_THRESHOLD_BLOCK_MIN) if should_hold else decision.risk_score
    risk_level = "high" if should_hold and decision.risk_level in {"low", "medium"} else decision.risk_level

    return MalwiAdapterResponse(
        adapter_name="ironclaw-malwi",
        platform="malwi",
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
        decision_id=decision.decision_id,
        trace_id=trace_id,
        request=request.to_dict() if request else {},
        metadata=dict(metadata or {}),
    )


def evaluate_malwi_request(
    engine: PolicyEngine,
    request: MalwiAdapterRequest,
    *,
    risk_score: int = 0,
    mode: AdapterExecutionMode = "enforce",
    trace_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> MalwiAdapterResponse:
    decision = evaluate_policy(
        engine,
        request.to_policy_input(),
        risk_score=risk_score,
    )
    return adapt_policy_decision_to_malwi(
        decision,
        mode=mode,
        trace_id=trace_id,
        request=request,
        metadata=metadata,
    )


def summarize_malwi_adapter_response(
    response: MalwiAdapterResponse,
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


# ---------- Integration-facing Malwi adapter class ----------


@dataclass
class MalwiAdapter(BaseIntegrationAdapter):
    """Integration adapter for the Malwi threat intelligence platform."""

    runtime: str = "malwi"
    analysis_mode: str = "threat-intel-guard"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.metadata.setdefault("integration_id", self.record.integration_id)
        self.metadata.setdefault("runtime", self.runtime)
        self.metadata.setdefault("analysis_mode", self.analysis_mode)

    def supported_action_types(self) -> list[str]:
        return [
            "lookup_hash",
            "lookup_url",
            "lookup_ip",
            "lookup_domain",
            "submit_ioc",
            "retrieve_report",
        ]

    def execute(self, request: AdapterExecutionRequest) -> AdapterExecutionResult:
        result = super().execute(request)

        if not result.success:
            return result

        result.status = "guarded"
        result.summary = f"{self.record.name} guarded threat-intel action '{request.action_type}' for target '{request.target}'."

        result.output.setdefault("guard_applied", True)
        result.output.setdefault("execution_mode", "threat-intel-gated")
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


def build_malwi_adapter(registry: IntegrationRegistry) -> MalwiAdapter:
    record = get_integration(registry, "integration-malwi")
    if record is None:
        raise KeyError("unknown integration_id: integration-malwi")

    return MalwiAdapter(
        record=record,
        protocol_version="1.0.0",
        health="ready",
        metadata={
            "integration_id": record.integration_id,
            "runtime": "malwi",
            "analysis_mode": "threat-intel-guard",
        },
    )
