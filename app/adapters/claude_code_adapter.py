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


def _deduplicate_list(items: list) -> list:
    seen: list = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


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


@dataclass
class ClaudeCodeAdapter:
    policy_enforcer: Any = field(default=None, repr=False)
    runtime_client: Any = field(default=None, repr=False)
    record: Any = field(default=None, repr=False)
    protocol_version: str = "1.0.0"
    health: str = "ready"
    runtime: str = "claude-code"
    guard_mode: str = "strict"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.metadata is None:
            self.metadata = {}
        if self.record is not None:
            # registry-wired path — initialise base adapter state
            self.metadata.setdefault("runtime", self.runtime)
            self.metadata.setdefault("guard_mode", self.guard_mode)

    # --- registry-wired path helpers (delegate to BaseIntegrationAdapter logic) ---

    @property
    def adapter_slug(self) -> str:
        return self.record.slug if self.record else "claude-code"

    @property
    def platform(self) -> str:
        return self.record.platform if self.record else "claude-code"

    def base_metadata(self) -> dict[str, Any]:
        if self.record is None:
            return dict(self.metadata)
        return {
            "integration_id": self.record.integration_id,
            "integration_type": self.record.integration_type,
            "integration_status": self.record.status,
            "protocol_version": self.protocol_version,
            "adapter_health": self.health,
            **self.metadata,
        }

    def handshake(self) -> Any:
        from app.adapters.base import AdapterHandshake
        from datetime import datetime, timezone
        return AdapterHandshake(
            adapter_slug=self.adapter_slug,
            platform=self.platform,
            protocol_version=self.protocol_version,
            status=self.health,
            connected_at=datetime.now(timezone.utc).isoformat(),
            capabilities=[c.to_dict() for c in self.record.capabilities] if self.record else [],
            metadata=self.base_metadata(),
        )

    def manifest(self) -> Any:
        from app.services.adapter_manifest import build_adapter_manifest
        return build_adapter_manifest(
            self.record,
            extra_metadata={
                **self.base_metadata(),
                "supported_action_types": [],
            },
        )

    # --- execute dispatch ---

    def execute(self, *args: Any, **kwargs: Any) -> Any:
        if self.policy_enforcer is not None:
            return self._execute_with_enforcer(**kwargs)
        # registry path
        request: AdapterExecutionRequest = args[0] if args else kwargs.get("request")
        from app.adapters.base import _utc_now as _base_utc_now, AdapterExecutionResult
        from app.adapters.base import _clean_dict

        self.from_base_validate(request)

        if self.health == "offline":
            return AdapterExecutionResult(
                adapter_slug=self.adapter_slug,
                platform=self.platform,
                success=False,
                status="offline",
                summary=f"{self.record.name} is offline and cannot execute '{request.action_type}'.",
                completed_at=_base_utc_now(),
            )

        result = AdapterExecutionResult(
            adapter_slug=self.adapter_slug,
            platform=self.platform,
            success=True,
            status="guarded",
            summary=f"{self.record.name} guarded action '{request.action_type}' for target '{request.target}'.",
            completed_at=_base_utc_now(),
            output={
                "request": request.to_dict(),
                "integration_id": self.record.integration_id,
                "guard_applied": True,
            },
            metadata={
                **self.base_metadata(),
                "runtime": self.runtime,
                "guard_mode": self.guard_mode,
            },
        )
        return result

    def from_base_validate(self, request: AdapterExecutionRequest) -> None:
        pass

    def allow(self, **kwargs: Any) -> bool:
        result = self._execute_with_enforcer(**kwargs)
        return bool(result.get("allowed", False))

    def _execute_with_enforcer(self, **kwargs: Any) -> dict[str, Any]:
        bundle = kwargs.get("bundle")
        signature = kwargs.get("signature", "")
        secret = kwargs.get("secret", "")
        manifest = kwargs.get("manifest", {})
        action = kwargs.get("action", "")
        messages = kwargs.get("messages", [])
        context = kwargs.get("context", {})

        if not bundle:
            return self._blocked(["missing_bundle"], [])
        if not signature:
            return self._blocked(["missing_signature"], [])

        try:
            decision = self.policy_enforcer.evaluate(
                bundle=bundle,
                signature=signature,
                secret=secret,
                manifest=manifest,
                runtime="claude",
                action=action,
                messages=messages,
                context=context,
            )
        except Exception as exc:
            return self._blocked(["policy_evaluation_error"], [], error=str(exc))

        policy_dict = decision.as_dict()
        policy_dict["matchedrules"] = _deduplicate_list(policy_dict.get("matchedrules", []))
        policy_dict["reasons"] = _deduplicate_list(policy_dict.get("reasons", []))

        if not decision.allowed:
            return {
                "allowed": False,
                "verdict": decision.verdict,
                "runtime": "claude",
                "policy": policy_dict,
                "result": None,
            }

        try:
            runtime_result = self.runtime_client.execute(
                messages=messages,
                context=context,
                action=action,
            )
        except Exception as exc:
            blocked = self._blocked(["runtime_execution_error"], [], error=str(exc))
            blocked["error"] = str(exc)
            return blocked

        return {
            "allowed": True,
            "verdict": decision.verdict,
            "runtime": "claude",
            "policy": policy_dict,
            "result": runtime_result,
        }

    @staticmethod
    def _blocked(
        matched_rules: list[str],
        reasons: list[Any],
        *,
        error: str | None = None,
    ) -> dict[str, Any]:
        out: dict[str, Any] = {
            "allowed": False,
            "verdict": "block",
            "runtime": "claude",
            "policy": {
                "allowed": False,
                "verdict": "block",
                "bundleid": "",
                "version": "",
                "runtime": "claude",
                "overrideactive": False,
                "rolloutenabled": True,
                "matchedrules": list(matched_rules),
                "reasons": list(reasons),
            },
            "result": None,
        }
        if error is not None:
            out["error"] = error
        return out


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