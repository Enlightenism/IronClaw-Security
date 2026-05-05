from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import Lock
from typing import Any


from app.core.billing import BillingRegistry, get_billing_registry
from app.core.unit_wallet import get_unit_wallet_registry


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(slots=True)
class UsageAuthorization:
    allowed: bool
    owner_key: str
    requested_units: int
    remaining_units_before: int
    remaining_units_after: int
    reason: str
    plan: str | None = None
    subscription_id: str | None = None
    wallet_balance_before: int | None = None
    wallet_balance_after: int | None = None
    checked_at: datetime = field(default_factory=_utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class UsageConsumptionResult:
    applied: bool
    owner_key: str
    consumed_units: int
    remaining_units: int
    reason: str
    plan: str | None = None
    subscription_id: str | None = None
    wallet_balance: int | None = None
    consumed_at: datetime = field(default_factory=_utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)


class UsageMeteringService:
    """
    Enforces prepaid unit consumption against the billing subscription first,
    while mirroring purchased units into the local unit wallet for visibility.
    """

    def __init__(self, *, billing_registry: BillingRegistry | None = None) -> None:
        self._lock = Lock()
        self._billing_registry = billing_registry or get_billing_registry()
        self._wallet_registry = get_unit_wallet_registry()

    def _normalize_owner_key(self, owner_key: str) -> str:
        normalized = owner_key.strip().lower()
        if not normalized:
            raise ValueError("owner_key must not be empty")
        return normalized

    def _get_wallet_balance(self, owner_key: str) -> int:
        wallet = self._wallet_registry.get_wallet(owner_key)
        if wallet is None:
            return 0
        return int(wallet.balance_units)

    def authorize_usage(
        self,
        *,
        owner_key: str,
        units: int,
        metadata: dict[str, Any] | None = None,
    ) -> UsageAuthorization:
        if units <= 0:
            raise ValueError("units must be positive")

        normalized_owner_key = self._normalize_owner_key(owner_key)
        metadata = dict(metadata or {})

        with self._lock:
            subscription = self._billing_registry.get_active_subscription_for_customer(
                normalized_owner_key
            )
            wallet_balance_before = self._get_wallet_balance(normalized_owner_key)

            if subscription is None:
                return UsageAuthorization(
                    allowed=False,
                    owner_key=normalized_owner_key,
                    requested_units=units,
                    remaining_units_before=0,
                    remaining_units_after=0,
                    reason="no_active_subscription",
                    wallet_balance_before=wallet_balance_before,
                    wallet_balance_after=wallet_balance_before,
                    metadata=metadata,
                )

            remaining_before = subscription.remaining_units
            allowed = self._billing_registry.can_consume(
                customer_id=normalized_owner_key,
                units=units,
            )

            if not allowed:
                return UsageAuthorization(
                    allowed=False,
                    owner_key=normalized_owner_key,
                    requested_units=units,
                    remaining_units_before=remaining_before,
                    remaining_units_after=remaining_before,
                    reason="insufficient_plan_units",
                    plan=subscription.plan,
                    subscription_id=subscription.subscription_id,
                    wallet_balance_before=wallet_balance_before,
                    wallet_balance_after=wallet_balance_before,
                    metadata=metadata,
                )

            return UsageAuthorization(
                allowed=True,
                owner_key=normalized_owner_key,
                requested_units=units,
                remaining_units_before=remaining_before,
                remaining_units_after=max(remaining_before - units, 0),
                reason="authorized",
                plan=subscription.plan,
                subscription_id=subscription.subscription_id,
                wallet_balance_before=wallet_balance_before,
                wallet_balance_after=wallet_balance_before,
                metadata=metadata,
            )

    def consume_usage(
        self,
        *,
        owner_key: str,
        units: int,
        metadata: dict[str, Any] | None = None,
    ) -> UsageConsumptionResult:
        if units <= 0:
            raise ValueError("units must be positive")

        normalized_owner_key = self._normalize_owner_key(owner_key)
        metadata = dict(metadata or {})

        with self._lock:
            authorization = self.authorize_usage(
                owner_key=normalized_owner_key,
                units=units,
                metadata=metadata,
            )
            if not authorization.allowed:
                return UsageConsumptionResult(
                    applied=False,
                    owner_key=normalized_owner_key,
                    consumed_units=0,
                    remaining_units=authorization.remaining_units_before,
                    reason=authorization.reason,
                    plan=authorization.plan,
                    subscription_id=authorization.subscription_id,
                    wallet_balance=authorization.wallet_balance_before,
                    metadata=metadata,
                )

            subscription = self._billing_registry.record_usage(
                customer_id=normalized_owner_key,
                units=units,
            )

            wallet = self._wallet_registry.debit_units(
                owner_key=normalized_owner_key,
                units=units,
                metadata={
                    "source": "usage_metering",
                    "subscription_id": subscription.subscription_id,
                    "plan": subscription.plan,
                    **metadata,
                },
            )

            return UsageConsumptionResult(
                applied=True,
                owner_key=normalized_owner_key,
                consumed_units=units,
                remaining_units=subscription.remaining_units,
                reason="consumed",
                plan=subscription.plan,
                subscription_id=subscription.subscription_id,
                wallet_balance=wallet.balance_units,
                metadata=metadata,
            )

    def get_usage_snapshot(self, *, owner_key: str) -> dict[str, Any]:
        normalized_owner_key = self._normalize_owner_key(owner_key)

        with self._lock:
            subscription = self._billing_registry.get_active_subscription_for_customer(
                normalized_owner_key
            )
            wallet = self._wallet_registry.get_wallet(normalized_owner_key)

            if subscription is None:
                return {
                    "owner_key": normalized_owner_key,
                    "has_active_subscription": False,
                    "plan": None,
                    "subscription_id": None,
                    "unit_limit": 0,
                    "units_consumed": 0,
                    "remaining_units": 0,
                    "wallet_balance_units": wallet.balance_units if wallet else 0,
                    "checked_at": _utc_now().isoformat().replace("+00:00", "Z"),
                }

            return {
                "owner_key": normalized_owner_key,
                "has_active_subscription": True,
                "plan": subscription.plan,
                "subscription_id": subscription.subscription_id,
                "unit_limit": subscription.unit_limit,
                "units_consumed": subscription.units_consumed,
                "remaining_units": subscription.remaining_units,
                "wallet_balance_units": wallet.balance_units if wallet else 0,
                "checked_at": _utc_now().isoformat().replace("+00:00", "Z"),
            }


_usage_metering_service = UsageMeteringService()


def get_usage_metering_service() -> UsageMeteringService:
    return _usage_metering_service