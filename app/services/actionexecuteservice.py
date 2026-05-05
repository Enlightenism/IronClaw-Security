from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


from app.services.usagemetering import (
    UsageAuthorization,
    UsageConsumptionResult,
    UsageMeteringService,
    get_usage_metering_service,
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(slots=True)
class ActionExecutionRequest:
    owner_key: str
    action_name: str
    requested_units: int = 1
    payload: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ActionExecutionDecision:
    execution_allowed: bool
    owner_key: str
    action_name: str
    requested_units: int
    reason: str
    authorization: UsageAuthorization
    decided_at: datetime = field(default_factory=_utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ActionExecutionReceipt:
    execution_id: str
    owner_key: str
    action_name: str
    executed: bool
    consumed_units: int
    remaining_units: int
    reason: str
    consumption: UsageConsumptionResult
    executed_at: datetime = field(default_factory=_utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)


class ActionExecuteService:
    """
    Billing-aware execution guard.

    This service does not perform the dangerous action itself. It decides
    whether the action is allowed to proceed and records prepaid unit usage.
    """

    def __init__(
        self,
        *,
        usage_metering_service: UsageMeteringService | None = None,
    ) -> None:
        self._usage_metering_service = (
            usage_metering_service or get_usage_metering_service()
        )

    def evaluate_request(
        self,
        request: ActionExecutionRequest,
    ) -> ActionExecutionDecision:
        normalized_action_name = request.action_name.strip()
        if not normalized_action_name:
            raise ValueError("action_name must not be empty")

        authorization = self._usage_metering_service.authorize_usage(
            owner_key=request.owner_key,
            units=request.requested_units,
            metadata={
                "action_name": normalized_action_name,
                **request.metadata,
            },
        )

        if not authorization.allowed:
            return ActionExecutionDecision(
                execution_allowed=False,
                owner_key=authorization.owner_key,
                action_name=normalized_action_name,
                requested_units=request.requested_units,
                reason=authorization.reason,
                authorization=authorization,
                metadata=request.metadata,
            )

        return ActionExecutionDecision(
            execution_allowed=True,
            owner_key=authorization.owner_key,
            action_name=normalized_action_name,
            requested_units=request.requested_units,
            reason="authorized",
            authorization=authorization,
            metadata=request.metadata,
        )

    def execute(
        self,
        request: ActionExecutionRequest,
    ) -> ActionExecutionReceipt:
        decision = self.evaluate_request(request)
        execution_id = self._build_execution_id(
            owner_key=decision.owner_key,
            action_name=decision.action_name,
        )

        if not decision.execution_allowed:
            return ActionExecutionReceipt(
                execution_id=execution_id,
                owner_key=decision.owner_key,
                action_name=decision.action_name,
                executed=False,
                consumed_units=0,
                remaining_units=decision.authorization.remaining_units_before,
                reason=decision.reason,
                consumption=UsageConsumptionResult(
                    applied=False,
                    owner_key=decision.owner_key,
                    consumed_units=0,
                    remaining_units=decision.authorization.remaining_units_before,
                    reason=decision.reason,
                    plan=decision.authorization.plan,
                    subscription_id=decision.authorization.subscription_id,
                    wallet_balance=decision.authorization.wallet_balance_before,
                    metadata=request.metadata,
                ),
                metadata=request.metadata,
            )

        consumption = self._usage_metering_service.consume_usage(
            owner_key=decision.owner_key,
            units=decision.requested_units,
            metadata={
                "action_name": decision.action_name,
                **request.metadata,
            },
        )

        return ActionExecutionReceipt(
            execution_id=execution_id,
            owner_key=decision.owner_key,
            action_name=decision.action_name,
            executed=consumption.applied,
            consumed_units=consumption.consumed_units,
            remaining_units=consumption.remaining_units,
            reason=consumption.reason,
            consumption=consumption,
            metadata=request.metadata,
        )

    def get_usage_snapshot(self, *, owner_key: str) -> dict[str, Any]:
        return self._usage_metering_service.get_usage_snapshot(owner_key=owner_key)

    def _build_execution_id(self, *, owner_key: str, action_name: str) -> str:
        now = _utc_now()
        owner_fragment = owner_key.replace("@", "_").replace(".", "_")
        action_fragment = action_name.strip().lower().replace(" ", "_")
        return f"exec_{owner_fragment}_{action_fragment}_{int(now.timestamp() * 1000)}"


_action_execute_service = ActionExecuteService()


def get_action_execute_service() -> ActionExecuteService:
    return _action_execute_service