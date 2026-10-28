from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.config import RISK_THRESHOLD_ALLOW_MAX, RISK_THRESHOLD_BLOCK_MIN
from orchestrator.policyengine import (
    PolicyDecision,
    PolicyEngine,
    PolicyRequest,
    PolicyTarget,
    PolicyVerdict,
)


def _is_valid_risk_score(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 100


@dataclass(slots=True)
class EnforcementContext:
    request_id: str
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    source: str | None = None
    actor_id: str | None = None
    session_id: str | None = None
    organization_id: str | None = None
    trace_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        request_id: str | None = None,
        source: str | None = None,
        actor_id: str | None = None,
        session_id: str | None = None,
        organization_id: str | None = None,
        trace_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> EnforcementContext:
        return cls(
            request_id=request_id or f"req-{uuid4().hex}",
            source=source,
            actor_id=actor_id,
            session_id=session_id,
            organization_id=organization_id,
            trace_id=trace_id,
            metadata=dict(metadata or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "actor_id": self.actor_id,
            "session_id": self.session_id,
            "organization_id": self.organization_id,
            "trace_id": self.trace_id,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class EnforcementResult:
    enforcement_id: str
    request_id: str
    decision: PolicyDecision
    status: str
    actions: list[str] = field(default_factory=list)
    review_required: bool = False
    quarantine_required: bool = False
    blocked: bool = False
    audit_record: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "enforcement_id": self.enforcement_id,
            "request_id": self.request_id,
            "status": self.status,
            "actions": list(self.actions),
            "review_required": self.review_required,
            "quarantine_required": self.quarantine_required,
            "blocked": self.blocked,
            "decision": self.decision.to_dict(),
            "audit_record": dict(self.audit_record),
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
        }


class PolicyEnforcer:
    def __init__(
        self,
        policy_engine: PolicyEngine | None = None,
        *,
        audit_sink: Callable[[dict[str, Any]], Any] | None = None,
        review_sink: Callable[[dict[str, Any]], Any] | None = None,
        quarantine_sink: Callable[[dict[str, Any]], Any] | None = None,
        block_sink: Callable[[dict[str, Any]], Any] | None = None,
        warn_sink: Callable[[dict[str, Any]], Any] | None = None,
        allow_sink: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        self.policy_engine = policy_engine or PolicyEngine()
        self.audit_sink = audit_sink
        self.review_sink = review_sink
        self.quarantine_sink = quarantine_sink
        self.block_sink = block_sink
        self.warn_sink = warn_sink
        self.allow_sink = allow_sink

    def enforce(
        self,
        request: PolicyRequest | Mapping[str, Any] | None,
        *,
        context: EnforcementContext | Mapping[str, Any] | None = None,
    ) -> EnforcementResult:
        normalized_request = request if isinstance(request, PolicyRequest) else PolicyRequest.from_mapping(request)
        normalized_context = self._normalize_context(context, normalized_request)

        if normalized_request.source is None and normalized_context.source:
            normalized_request.source = normalized_context.source
        if normalized_request.actor_id is None and normalized_context.actor_id:
            normalized_request.actor_id = normalized_context.actor_id
        if normalized_request.session_id is None and normalized_context.session_id:
            normalized_request.session_id = normalized_context.session_id
        if normalized_request.organization_id is None and normalized_context.organization_id:
            normalized_request.organization_id = normalized_context.organization_id

        decision = self.policy_engine.evaluate(normalized_request)
        self._normalize_decision(decision, normalized_request)
        result = self._build_result(decision=decision, request=normalized_request, context=normalized_context)
        self._dispatch(result)
        return result

    def enforce_dict(
        self,
        request: PolicyRequest | Mapping[str, Any] | None,
        *,
        context: EnforcementContext | Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.enforce(request, context=context).to_dict()

    def enforce_batch(
        self,
        requests: Iterable[PolicyRequest | Mapping[str, Any] | None],
        *,
        context_factory: Callable[[int, PolicyRequest], EnforcementContext | Mapping[str, Any] | None] | None = None,
    ) -> list[EnforcementResult]:
        results: list[EnforcementResult] = []
        for index, item in enumerate(requests):
            normalized_request = item if isinstance(item, PolicyRequest) else PolicyRequest.from_mapping(item)
            context = context_factory(index, normalized_request) if context_factory else None
            results.append(self.enforce(normalized_request, context=context))
        return results

    def _normalize_context(
        self,
        context: EnforcementContext | Mapping[str, Any] | None,
        request: PolicyRequest,
    ) -> EnforcementContext:
        if isinstance(context, EnforcementContext):
            return context

        payload = dict(context or {})
        return EnforcementContext.create(
            request_id=payload.get("request_id"),
            source=payload.get("source") or request.source,
            actor_id=payload.get("actor_id") or request.actor_id,
            session_id=payload.get("session_id") or request.session_id,
            organization_id=payload.get("organization_id") or request.organization_id,
            trace_id=payload.get("trace_id"),
            metadata=payload.get("metadata") or {},
        )

    def _normalize_decision(
        self,
        decision: PolicyDecision,
        request: PolicyRequest,
    ) -> None:
        decision_score_is_valid = _is_valid_risk_score(decision.risk_score)
        decision_score = decision.risk_score if decision_score_is_valid else RISK_THRESHOLD_BLOCK_MIN
        risk_score = max(decision_score, request.risk_score)
        should_block = (
            decision.verdict != PolicyVerdict.ALLOW
            or decision.allowed is not True
            or bool(decision.matched_rules)
            or decision.requires_human_review
            or request.requires_human_review
            or not decision_score_is_valid
            or risk_score > RISK_THRESHOLD_ALLOW_MAX
            or request.target == PolicyTarget.UNKNOWN
            or request.requires_secrets
            and request.requires_network
        )

        decision.verdict = PolicyVerdict.BLOCK if should_block else PolicyVerdict.ALLOW
        decision.allowed = not should_block
        decision.requires_human_review = decision.requires_human_review or request.requires_human_review
        decision.risk_score = max(risk_score, RISK_THRESHOLD_BLOCK_MIN) if should_block else risk_score
        if should_block and not decision.reasons:
            decision.reasons.append(
                "Policy enforcer blocked a non-allow or invalid decision.",
            )

    def _build_result(
        self,
        *,
        decision: PolicyDecision,
        request: PolicyRequest,
        context: EnforcementContext,
    ) -> EnforcementResult:
        actions = self._actions_for_decision(decision, request)
        review_required = decision.requires_human_review or "enqueue_review" in actions
        blocked = decision.verdict == PolicyVerdict.BLOCK

        status = self._status_for_verdict(decision.verdict, review_required=review_required)
        audit_record = self._build_audit_record(
            decision=decision,
            request=request,
            context=context,
            actions=actions,
            status=status,
        )

        metadata = {
            "target": request.target.value,
            "action": request.action,
            "risk_score": request.risk_score,
            "trace_id": context.trace_id,
            "decision_confidence": decision.confidence,
        }

        return EnforcementResult(
            enforcement_id=f"enf-{uuid4().hex}",
            request_id=context.request_id,
            decision=decision,
            status=status,
            actions=actions,
            review_required=review_required,
            quarantine_required=False,
            blocked=blocked,
            audit_record=audit_record,
            metadata=metadata,
        )

    def _actions_for_decision(self, decision: PolicyDecision, request: PolicyRequest) -> list[str]:
        actions: list[str] = []

        if decision.verdict == PolicyVerdict.ALLOW:
            actions.append("allow_execution")

        if decision.verdict == PolicyVerdict.BLOCK:
            actions.extend(["block_request", "halt_execution", "preserve_evidence"])

        if decision.requires_human_review:
            actions.append("enqueue_review")

        if request.requires_network:
            actions.append("monitor_network_scope")

        if request.requires_filesystem:
            actions.append("monitor_filesystem_scope")

        if request.requires_secrets:
            actions.append("apply_secret_redaction")

        return _dedupe(actions)

    def _status_for_verdict(self, verdict: PolicyVerdict, *, review_required: bool) -> str:
        del review_required
        return "allowed" if verdict == PolicyVerdict.ALLOW else "blocked"

    def _build_audit_record(
        self,
        *,
        decision: PolicyDecision,
        request: PolicyRequest,
        context: EnforcementContext,
        actions: list[str],
        status: str,
    ) -> dict[str, Any]:
        return {
            "audit_id": f"aud-{uuid4().hex}",
            "request_id": context.request_id,
            "trace_id": context.trace_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "status": status,
            "target": request.target.value,
            "action": request.action,
            "risk_score": request.risk_score,
            "verdict": decision.verdict.value,
            "matched_rules": list(decision.matched_rules),
            "reasons": list(decision.reasons),
            "actions": list(actions),
            "actor_id": context.actor_id,
            "session_id": context.session_id,
            "organization_id": context.organization_id,
            "source": context.source,
            "context_metadata": dict(context.metadata),
        }

    def _dispatch(self, result: EnforcementResult) -> None:
        if self.audit_sink is not None:
            self.audit_sink(result.audit_record)

        payload = result.to_dict()

        if result.review_required and self.review_sink is not None:
            self.review_sink(payload)

        if result.blocked and self.block_sink is not None:
            self.block_sink(payload)

        if result.decision.verdict == PolicyVerdict.ALLOW and self.allow_sink is not None:
            self.allow_sink(payload)


def enforce_policy(
    request: PolicyRequest | Mapping[str, Any] | None,
    *,
    context: EnforcementContext | Mapping[str, Any] | None = None,
    enforcer: PolicyEnforcer | None = None,
) -> EnforcementResult:
    active_enforcer = enforcer or PolicyEnforcer()
    return active_enforcer.enforce(request, context=context)


def enforce_policy_dict(
    request: PolicyRequest | Mapping[str, Any] | None,
    *,
    context: EnforcementContext | Mapping[str, Any] | None = None,
    enforcer: PolicyEnforcer | None = None,
) -> dict[str, Any]:
    return enforce_policy(request, context=context, enforcer=enforcer).to_dict()


def build_policy_request(
    *,
    target: PolicyTarget | str = PolicyTarget.UNKNOWN,
    action: str = "unknown",
    risk_score: int = 0,
    attributes: Mapping[str, Any] | None = None,
    source: str | None = None,
    actor_id: str | None = None,
    session_id: str | None = None,
    organization_id: str | None = None,
    requires_network: bool = False,
    requires_filesystem: bool = False,
    requires_secrets: bool = False,
    requires_human_review: bool = False,
    fail_closed: bool = True,
) -> PolicyRequest:
    if not isinstance(target, PolicyTarget):
        target_value = str(target).lower()
        target = PolicyTarget(target_value) if target_value in {item.value for item in PolicyTarget} else PolicyTarget.UNKNOWN

    return PolicyRequest(
        target=target,
        action=action,
        risk_score=risk_score,
        attributes=dict(attributes or {}),
        source=source,
        actor_id=actor_id,
        session_id=session_id,
        organization_id=organization_id,
        requires_network=requires_network,
        requires_filesystem=requires_filesystem,
        requires_secrets=requires_secrets,
        requires_human_review=requires_human_review,
        fail_closed=fail_closed,
    )


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


__all__ = [
    "EnforcementContext",
    "EnforcementResult",
    "PolicyEnforcer",
    "build_policy_request",
    "enforce_policy",
    "enforce_policy_dict",
]
