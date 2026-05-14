from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from app.adapters.base import (
    AdapterExecutionRequest,
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

_BLOCK_RESULT_KEYS = ("allowed", "verdict", "runtime", "policy", "result")


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_text(value: str | None) -> str:
    return (value or "").strip()


def _dedup_list(items: list[Any]) -> list[Any]:
    seen: list[Any] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


# ---------------------------------------------------------------------------
# Request / Response dataclasses (policy-engine path)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Builder / adapter helpers (policy-engine path)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Stub-mode helpers — used when adapter is constructed with injected stubs
# ---------------------------------------------------------------------------


def _block_response(
    *,
    runtime: str,
    bundle_id: str,
    version: str,
    matched_rules: list[str],
    reasons: list[dict[str, Any]] | None = None,
    verdict: str = "block",
) -> dict[str, Any]:
    return {
        "allowed": False,
        "verdict": verdict,
        "runtime": runtime,
        "policy": {
            "bundleid": bundle_id,
            "version": version,
            "matchedrules": matched_rules,
            "reasons": reasons or [],
            "overrideactive": False,
            "rolloutenabled": True,
        },
        "result": None,
    }


def _execute_stub(
    policy_enforcer: Any,
    runtime_client: Any,
    **kwargs: Any,
) -> dict[str, Any]:
    bundle = kwargs.get("bundle")
    signature = kwargs.get("signature", "")
    runtime_name = kwargs.get("runtime", "")
    action = kwargs.get("action", "")
    payload = kwargs.get("payload") or {}
    context = kwargs.get("context") or {}
    manifest = kwargs.get("manifest") or {}
    secret = kwargs.get("secret", "")

    bundle_id = ""
    version = ""
    if bundle:
        bundle_id = bundle.get("bundle_id", "")
        version = bundle.get("version", "")

    if not bundle:
        return _block_response(
            runtime=runtime_name,
            bundle_id=bundle_id,
            version=version,
            matched_rules=["missing_bundle"],
        )
    if not signature:
        return _block_response(
            runtime=runtime_name,
            bundle_id=bundle_id,
            version=version,
            matched_rules=["missing_signature"],
        )
    if not runtime_name:
        return _block_response(
            runtime=runtime_name,
            bundle_id=bundle_id,
            version=version,
            matched_rules=["missing_runtime"],
        )

    decision = policy_enforcer.evaluate(
        bundle=bundle,
        signature=signature,
        secret=secret,
        manifest=manifest,
        runtime=runtime_name,
        action=action,
        payload=payload,
        context=context,
    )

    allowed: bool = decision.allowed
    verdict: str = decision.verdict
    policy_dict = decision.as_dict()

    policy_dict["matchedrules"] = _dedup_list(policy_dict.get("matchedrules", []))
    raw_reasons: list[Any] = policy_dict.get("reasons", [])
    policy_dict["reasons"] = _dedup_list(raw_reasons)

    if not allowed:
        return {
            "allowed": False,
            "verdict": verdict,
            "runtime": runtime_name,
            "policy": policy_dict,
            "result": None,
        }

    try:
        runtime_result = runtime_client.execute(
            payload=payload,
            context=context,
            runtime=runtime_name,
            action=action,
        )
    except Exception as exc:
        policy_dict["matchedrules"] = _dedup_list(
            policy_dict["matchedrules"] + ["runtime_execution_error"],
        )
        return {
            "allowed": False,
            "verdict": "error",
            "runtime": runtime_name,
            "policy": policy_dict,
            "result": {"error": str(exc)},
        }

    return {
        "allowed": True,
        "verdict": verdict,
        "runtime": runtime_name,
        "policy": policy_dict,
        "result": runtime_result,
    }


def _allow_stub(policy_enforcer: Any, **kwargs: Any) -> bool:
    bundle = kwargs.get("bundle")
    signature = kwargs.get("signature", "")
    runtime_name = kwargs.get("runtime", "")
    if not bundle or not signature or not runtime_name:
        return False
    return policy_enforcer.allow(
        bundle=bundle,
        signature=kwargs.get("signature", ""),
        secret=kwargs.get("secret", ""),
        manifest=kwargs.get("manifest") or {},
        runtime=runtime_name,
        action=kwargs.get("action", ""),
        payload=kwargs.get("payload") or {},
        context=kwargs.get("context") or {},
    )


# ---------------------------------------------------------------------------
# GenericAgentAdapter — dual-mode: stub injection OR integration record
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class GenericAgentAdapter(BaseIntegrationAdapter):
    """Integration adapter for 'integration-generic-agent' records.

    Dual-mode construction:
      • Stub mode  — GenericAgentAdapter(policy_enforcer=..., runtime_client=...)
      • Record mode — GenericAgentAdapter(record=..., ...)
    """

    runtime: str = "generic-agent"
    guard_mode: str = "strict"
    policy_enforcer: Any = field(default=None)
    runtime_client: Any = field(default=None)

    def __post_init__(self) -> None:
        if self.policy_enforcer is not None or self.runtime_client is not None:
            return
        super(GenericAgentAdapter, self).__post_init__()
        if "runtime" not in self.metadata:
            self.metadata["runtime"] = self.runtime
        if "guard_mode" not in self.metadata:
            self.metadata["guard_mode"] = self.guard_mode

    def execute(self, request: AdapterExecutionRequest | None = None, **kwargs: Any) -> Any:
        if self.policy_enforcer is not None or self.runtime_client is not None:
            if kwargs:
                return _execute_stub(self.policy_enforcer, self.runtime_client, **kwargs)
            if request is not None and isinstance(request, dict):
                return _execute_stub(self.policy_enforcer, self.runtime_client, **request)
            raise TypeError("execute() in stub mode requires keyword arguments")

        if request is None:
            raise TypeError("request is required in record mode")

        result = super(GenericAgentAdapter, self).execute(request)
        result.status = "guarded"
        result.summary = (
            f"{self.record.name} guarded action '{request.action_type}' "
            f"for target '{request.target}'."
        )
        result.output.setdefault("request", request.to_dict())
        result.output["guard_applied"] = True
        result.metadata["runtime"] = self.runtime
        result.metadata["guard_mode"] = self.guard_mode
        return result

    def allow(self, **kwargs: Any) -> bool:
        if self.policy_enforcer is not None:
            return _allow_stub(self.policy_enforcer, **kwargs)
        raise NotImplementedError("allow() requires stub mode (policy_enforcer injected)")


# ---------------------------------------------------------------------------
# Sentinel record used when constructing adapter in stub mode
# ---------------------------------------------------------------------------


def _stub_record() -> IntegrationRecord:
    return IntegrationRecord(
        integration_id="integration-generic-agent-stub",
        name="Generic Agent Stub",
        slug="generic-agent-stub",
        platform="generic",
        integration_type="agent",
        status="active",
    )


_ORIG_INIT = GenericAgentAdapter.__init__


def _patched_init(
    self: GenericAgentAdapter,
    *,
    policy_enforcer: Any = None,
    runtime_client: Any = None,
    record: IntegrationRecord | None = None,
    **kwargs: Any,
) -> None:
    if (policy_enforcer is not None or runtime_client is not None) and record is None:
        record = _stub_record()
    _ORIG_INIT(
        self,
        record=record,
        policy_enforcer=policy_enforcer,
        runtime_client=runtime_client,
        **kwargs,
    )


GenericAgentAdapter.__init__ = _patched_init  # type: ignore[method-assign]


# ---------------------------------------------------------------------------
# Factory for record mode
# ---------------------------------------------------------------------------


def build_generic_agent_adapter(registry: IntegrationRegistry) -> GenericAgentAdapter:
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