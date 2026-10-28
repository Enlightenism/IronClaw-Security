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
CapeAnalysisStatus = Literal["pending", "running", "completed", "failed", "timeout"]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_text(value: str | None) -> str:
    return (value or "").strip()


# ---------- Policy-facing adapter request/response ----------


@dataclass(slots=True)
class CapeAdapterRequest:
    """High-level request wrapper for CAPE sandbox analysis actions."""

    action_type: str
    target: str
    content: str = ""
    sample_hash: str | None = None
    sample_path: str | None = None
    analysis_package: str | None = None
    machine_label: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_policy_input(self) -> PolicyInput:
        merged_metadata: dict[str, Any] = dict(self.metadata)
        if self.sample_hash:
            merged_metadata["sample_hash"] = self.sample_hash
        if self.sample_path:
            merged_metadata["sample_path"] = self.sample_path
        if self.analysis_package:
            merged_metadata["analysis_package"] = self.analysis_package
        if self.machine_label:
            merged_metadata["machine_label"] = self.machine_label

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
            "sample_hash": self.sample_hash,
            "sample_path": self.sample_path,
            "analysis_package": self.analysis_package,
            "machine_label": self.machine_label,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class CapeAdapterResponse:
    """Normalized policy decision payload for CAPE sandbox submissions."""

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


def build_cape_adapter_request(
    *,
    action_type: str,
    target: str,
    content: str = "",
    sample_hash: str | None = None,
    sample_path: str | None = None,
    analysis_package: str | None = None,
    machine_label: str | None = None,
    agent_id: str | None = None,
    session_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> CapeAdapterRequest:
    normalized_action_type = _normalize_text(action_type)
    normalized_target = _normalize_text(target)

    if not normalized_action_type:
        raise ValueError("action_type is required")
    if not normalized_target:
        raise ValueError("target is required")

    return CapeAdapterRequest(
        action_type=normalized_action_type,
        target=normalized_target,
        content=content or "",
        sample_hash=_normalize_text(sample_hash) or None,
        sample_path=_normalize_text(sample_path) or None,
        analysis_package=_normalize_text(analysis_package) or None,
        machine_label=_normalize_text(machine_label) or None,
        agent_id=_normalize_text(agent_id) or None,
        session_id=_normalize_text(session_id) or None,
        metadata=dict(metadata or {}),
    )


def adapt_policy_decision_to_cape(
    decision: PolicyDecision,
    *,
    mode: AdapterExecutionMode = "enforce",
    trace_id: str | None = None,
    request: CapeAdapterRequest | None = None,
    metadata: dict[str, Any] | None = None,
) -> CapeAdapterResponse:
    verdict: AdapterVerdict = "allow" if decision.verdict == "allow" and decision.allow_execution is True and not decision.requires_review and not decision.matched_rules and 0 <= decision.risk_score <= RISK_THRESHOLD_ALLOW_MAX else "block"
    matched_rules = [match.rule_id for match in decision.matched_rules]
    reasons = [match.to_dict() for match in decision.matched_rules]
    should_hold = verdict == "block"
    risk_score = max(decision.risk_score, RISK_THRESHOLD_BLOCK_MIN) if should_hold else decision.risk_score
    risk_level = "high" if should_hold and decision.risk_level in {"low", "medium"} else decision.risk_level

    return CapeAdapterResponse(
        adapter_name="ironclaw-cape",
        platform="cape",
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


def evaluate_cape_request(
    engine: PolicyEngine,
    request: CapeAdapterRequest,
    *,
    risk_score: int = 0,
    mode: AdapterExecutionMode = "enforce",
    trace_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> CapeAdapterResponse:
    decision = evaluate_policy(
        engine,
        request.to_policy_input(),
        risk_score=risk_score,
    )
    return adapt_policy_decision_to_cape(
        decision,
        mode=mode,
        trace_id=trace_id,
        request=request,
        metadata=metadata,
    )


def summarize_cape_adapter_response(
    response: CapeAdapterResponse,
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


# ---------- Integration-facing CAPE adapter class ----------


class CapeAdapter(BaseIntegrationAdapter):
    """Integration adapter for the CAPE malware analysis sandbox."""

    def __init__(
        self,
        *,
        record: Any,
        protocol_version: str = "1.0.0",
        health: str = "ready",
        runtime: str = "cape",
        analysis_mode: str = "sandbox-guard",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        merged: dict[str, Any] = dict(metadata or {})
        merged.setdefault("runtime", runtime)
        merged.setdefault("analysis_mode", analysis_mode)
        # BaseIntegrationAdapter uses slots=True so we must init via object.__setattr__
        object.__setattr__(self, "record", record)
        object.__setattr__(self, "protocol_version", protocol_version)
        object.__setattr__(self, "health", health)
        object.__setattr__(self, "metadata", merged)
        self.runtime = runtime
        self.analysis_mode = analysis_mode
        # call base __post_init__ to normalize protocol_version and metadata
        super().__post_init__()

    def supported_action_types(self) -> list[str]:
        return [
            "submit_sample",
            "submit_url",
            "submit_process",
            "retrieve_report",
            "cancel_task",
        ]

    def execute(self, request: AdapterExecutionRequest) -> AdapterExecutionResult:
        result = BaseIntegrationAdapter.execute(self, request)

        if not result.success:
            return result

        result.status = "guarded"
        result.summary = f"{self.record.name} guarded sandbox action '{request.action_type}' for target '{request.target}'."

        result.output.setdefault("guard_applied", True)
        result.output.setdefault("execution_mode", "sandbox-gated")
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


def build_cape_adapter(registry: IntegrationRegistry) -> CapeAdapter:
    record = get_integration(registry, "integration-cape")
    if record is None:
        raise KeyError("unknown integration_id: integration-cape")

    return CapeAdapter(
        record=record,
        protocol_version="1.0.0",
        health="ready",
        metadata={
            "integration_id": record.integration_id,
            "runtime": "cape",
            "analysis_mode": "sandbox-guard",
        },
    )
