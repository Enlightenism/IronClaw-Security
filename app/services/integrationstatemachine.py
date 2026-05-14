from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.services.integrationregistry import IntegrationStatus, get_integration_registry

_ALLOWED_TRANSITIONS: dict[IntegrationStatus, set[IntegrationStatus]] = {
    "planned": {"available", "disabled"},
    "available": {"configured", "disabled", "degraded"},
    "configured": {"verifying", "disabled", "degraded", "ready"},
    "verifying": {"ready", "degraded", "disabled"},
    "ready": {"degraded", "disabled"},
    "degraded": {"configured", "verifying", "ready", "disabled"},
    "disabled": {"planned", "available"},
}


@dataclass(slots=True)
class IntegrationStateTransition:
    integrationid: str
    previousstatus: IntegrationStatus
    nextstatus: IntegrationStatus
    allowed: bool
    changedat: str
    reason: str


@dataclass(slots=True)
class IntegrationStateMachineResult:
    integrationid: str
    currentstatus: IntegrationStatus
    transitions: list[IntegrationStateTransition] = field(default_factory=list)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


class IntegrationStateMachine:
    def transition(
        self,
        integrationid: str,
        nextstatus: IntegrationStatus,
        *,
        reason: str = "state-update",
    ) -> IntegrationStateMachineResult | None:
        registry = get_integration_registry()
        record = registry.get_integration(integrationid)
        if record is None:
            return None

        previous = record.status
        allowed = nextstatus in _ALLOWED_TRANSITIONS.get(previous, set())

        transition = IntegrationStateTransition(
            integrationid=record.integrationid,
            previousstatus=previous,
            nextstatus=nextstatus,
            allowed=allowed,
            changedat=_utc_now(),
            reason=reason,
        )

        if allowed:
            registry.update_status(record.integrationid, nextstatus, verified=nextstatus == "ready")
            currentstatus = nextstatus
        else:
            currentstatus = previous

        return IntegrationStateMachineResult(
            integrationid=record.integrationid,
            currentstatus=currentstatus,
            transitions=[transition],
        )

    def allowed_targets(self, integrationid: str) -> list[IntegrationStatus] | None:
        registry = get_integration_registry()
        record = registry.get_integration(integrationid)
        if record is None:
            return None
        return sorted(_ALLOWED_TRANSITIONS.get(record.status, set()))


_state_machine = IntegrationStateMachine()


def get_integration_state_machine() -> IntegrationStateMachine:
    return _state_machine
