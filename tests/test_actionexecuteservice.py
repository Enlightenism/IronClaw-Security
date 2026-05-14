from __future__ import annotations

from app.services.actionexecuteservice import (
    ActionExecuteService,
    ActionExecutionRequest,
)


class FakeUsageMeteringService:
    def __init__(
        self,
        *,
        allowed: bool = True,
        remaining_before: int = 10,
        remaining_after: int = 9,
        wallet_balance: int = 5,
        reason: str = "authorized",
    ) -> None:
        self.allowed = allowed
        self.remaining_before = remaining_before
        self.remaining_after = remaining_after
        self.wallet_balance = wallet_balance
        self.reason = reason

    def authorize_usage(self, *, owner_key: str, units: int, metadata: dict) -> object:
        return type(
            "UsageAuthorization",
            (),
            {
                "allowed": self.allowed,
                "owner_key": owner_key,
                "remaining_units_before": self.remaining_before,
                "reason": self.reason,
                "plan": "pro",
                "subscription_id": "sub_test",
                "wallet_balance_before": self.wallet_balance,
            },
        )()

    def consume_usage(self, *, owner_key: str, units: int, metadata: dict) -> object:
        return type(
            "UsageConsumptionResult",
            (),
            {
                "applied": self.allowed,
                "owner_key": owner_key,
                "consumed_units": units if self.allowed else 0,
                "remaining_units": self.remaining_after if self.allowed else self.remaining_before,
                "reason": self.reason,
                "plan": "pro",
                "subscription_id": "sub_test",
                "wallet_balance": self.wallet_balance,
                "metadata": metadata,
            },
        )()

    def get_usage_snapshot(self, *, owner_key: str) -> dict[str, object]:
        return {
            "plan": "pro",
            "subscription_id": "sub_test",
            "remaining_units": self.remaining_after,
            "wallet_balance": self.wallet_balance,
            "allowed": self.allowed,
        }


def test_evaluate_request_allows_authorized_usage() -> None:
    service = ActionExecuteService(
        usage_metering_service=FakeUsageMeteringService(
            allowed=True,
            remaining_before=12,
            remaining_after=11,
            wallet_balance=7,
        ),
    )

    decision = service.evaluate_request(
        ActionExecutionRequest(
            owner_key="owner-301",
            action_name="httpfetch:https://example.com",
            requested_units=1,
        ),
    )

    assert decision.execution_allowed is True
    assert decision.owner_key == "owner-301"
    assert decision.requested_units == 1
    assert decision.reason == "authorized"


def test_execute_returns_receipt_when_usage_is_consumed() -> None:
    service = ActionExecuteService(
        usage_metering_service=FakeUsageMeteringService(
            allowed=True,
            remaining_before=5,
            remaining_after=4,
            wallet_balance=2,
        ),
    )

    receipt = service.execute(
        ActionExecutionRequest(
            owner_key="owner-302",
            action_name="browseropen:https://example.com",
            requested_units=1,
            metadata={"source": "test"},
        ),
    )

    assert receipt.executed is True
    assert receipt.consumed_units == 1
    assert receipt.remaining_units == 4
    assert receipt.reason == "authorized"
    assert receipt.consumption.applied is True


def test_execute_blocks_when_usage_is_not_authorized() -> None:
    service = ActionExecuteService(
        usage_metering_service=FakeUsageMeteringService(
            allowed=False,
            remaining_before=0,
            remaining_after=0,
            wallet_balance=0,
            reason="insufficient_units",
        ),
    )

    receipt = service.execute(
        ActionExecutionRequest(
            owner_key="owner-303",
            action_name="toolcall:shell",
            requested_units=2,
        ),
    )

    assert receipt.executed is False
    assert receipt.consumed_units == 0
    assert receipt.remaining_units == 0
    assert receipt.reason == "insufficient_units"
    assert receipt.consumption.applied is False


def test_get_usage_snapshot_returns_underlying_snapshot() -> None:
    service = ActionExecuteService(
        usage_metering_service=FakeUsageMeteringService(
            allowed=True,
            remaining_before=9,
            remaining_after=8,
            wallet_balance=3,
        ),
    )

    snapshot = service.get_usage_snapshot(owner_key="owner-304")

    assert snapshot["plan"] == "pro"
    assert snapshot["subscription_id"] == "sub_test"
    assert snapshot["remaining_units"] == 8
    assert snapshot["wallet_balance"] == 3
    assert snapshot["allowed"] is True
