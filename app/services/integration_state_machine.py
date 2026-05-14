from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum


class IntegrationState(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    DEGRADED = "degraded"
    BLOCKED = "blocked"
    RETIRED = "retired"


@dataclass(frozen=True)
class TransitionContext:
    has_supported_configuration: bool = False
    has_blocking_findings: bool = False
    telemetry_state: str | None = None
    actor: str = "system"


@dataclass(frozen=True)
class TransitionResult:
    allowed: bool
    from_state: IntegrationState
    to_state: IntegrationState
    actor: str
    reason: str
    transition_key: str
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "from_state": self.from_state.value,
            "to_state": self.to_state.value,
            "actor": self.actor,
            "reason": self.reason,
            "transition_key": self.transition_key,
            "metadata": dict(self.metadata),
        }


_ALLOWED_TRANSITIONS: Mapping[IntegrationState, frozenset[IntegrationState]] = {
    IntegrationState.DRAFT: frozenset(
        {
            IntegrationState.ACTIVE,
            IntegrationState.BLOCKED,
            IntegrationState.RETIRED,
        },
    ),
    IntegrationState.ACTIVE: frozenset(
        {
            IntegrationState.DEGRADED,
            IntegrationState.BLOCKED,
            IntegrationState.RETIRED,
        },
    ),
    IntegrationState.DEGRADED: frozenset(
        {
            IntegrationState.ACTIVE,
            IntegrationState.BLOCKED,
            IntegrationState.RETIRED,
        },
    ),
    IntegrationState.BLOCKED: frozenset(
        {
            IntegrationState.DRAFT,
            IntegrationState.DEGRADED,
            IntegrationState.RETIRED,
        },
    ),
    IntegrationState.RETIRED: frozenset(),
}


def list_allowed_transitions(state: IntegrationState) -> set[IntegrationState]:
    return set(_ALLOWED_TRANSITIONS.get(state, frozenset()))


def can_transition(
    from_state: IntegrationState,
    to_state: IntegrationState,
) -> bool:
    return to_state in _ALLOWED_TRANSITIONS.get(from_state, frozenset())


def transition_integration_state(
    *,
    from_state: IntegrationState,
    to_state: IntegrationState,
    context: TransitionContext | None = None,
) -> TransitionResult:
    ctx = context or TransitionContext()
    transition_key = f"{from_state.value}->{to_state.value}"

    if from_state == to_state:
        return TransitionResult(
            allowed=True,
            from_state=from_state,
            to_state=to_state,
            actor=ctx.actor,
            reason="No-op transition accepted because the integration is already in the requested state.",
            transition_key=transition_key,
            metadata=_context_metadata(ctx),
        )

    if not can_transition(from_state, to_state):
        return TransitionResult(
            allowed=False,
            from_state=from_state,
            to_state=to_state,
            actor=ctx.actor,
            reason="Requested transition is not permitted by the lifecycle policy.",
            transition_key=transition_key,
            metadata=_context_metadata(ctx),
        )

    guard_failure = _validate_transition_guards(
        from_state=from_state,
        to_state=to_state,
        context=ctx,
    )
    if guard_failure is not None:
        return TransitionResult(
            allowed=False,
            from_state=from_state,
            to_state=to_state,
            actor=ctx.actor,
            reason=guard_failure,
            transition_key=transition_key,
            metadata=_context_metadata(ctx),
        )

    return TransitionResult(
        allowed=True,
        from_state=from_state,
        to_state=to_state,
        actor=ctx.actor,
        reason="Transition approved by lifecycle policy.",
        transition_key=transition_key,
        metadata=_context_metadata(ctx),
    )


def _validate_transition_guards(
    *,
    from_state: IntegrationState,
    to_state: IntegrationState,
    context: TransitionContext,
) -> str | None:
    if to_state == IntegrationState.ACTIVE and not context.has_supported_configuration:
        return "Integration cannot move to active without a supported configuration."

    if to_state == IntegrationState.ACTIVE and context.telemetry_state == "unsupported":
        return "Integration cannot move to active while telemetry reports unsupported."

    if to_state == IntegrationState.DEGRADED and context.telemetry_state == "supported":
        return "Integration should not move to degraded while telemetry is fully supported."

    if to_state == IntegrationState.BLOCKED and not context.has_blocking_findings:
        return "Integration cannot move to blocked without blocking findings."

    if from_state == IntegrationState.BLOCKED and to_state == IntegrationState.DRAFT:
        if context.has_blocking_findings:
            return "Integration cannot return to draft while blocking findings remain open."

    if from_state == IntegrationState.RETIRED:
        return "Retired integrations are terminal and cannot transition."

    return None


def _context_metadata(context: TransitionContext) -> dict[str, str]:
    metadata: dict[str, str] = {
        "has_supported_configuration": str(context.has_supported_configuration).lower(),
        "has_blocking_findings": str(context.has_blocking_findings).lower(),
        "actor": context.actor,
    }
    if context.telemetry_state is not None:
        metadata["telemetry_state"] = context.telemetry_state
    return metadata
