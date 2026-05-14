from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import Lock
from typing import Any, Final, Literal, TypedDict

PlanCode = Literal["starter-20k", "growth-100k", "scale-200k"]


class PlanDefinition(TypedDict):
    code: PlanCode
    name: str
    unit_limit: int
    price_usd: int


PLAN_DEFINITIONS: Final[dict[PlanCode, PlanDefinition]] = {
    "starter-20k": {
        "code": "starter-20k",
        "name": "Starter 20k",
        "unit_limit": 20_000,
        "price_usd": 20,
    },
    "growth-100k": {
        "code": "growth-100k",
        "name": "Growth 100k",
        "unit_limit": 100_000,
        "price_usd": 90,
    },
    "scale-200k": {
        "code": "scale-200k",
        "name": "Scale 200k",
        "unit_limit": 200_000,
        "price_usd": 150,
    },
}


@dataclass
class BillingCustomer:
    customer_id: str
    email: str
    display_name: str
    plan: PlanCode
    active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class BillingSubscription:
    subscription_id: str
    customer_id: str
    plan: PlanCode
    status: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    current_period_start: datetime = field(default_factory=lambda: datetime.now(UTC))
    current_period_end: datetime = field(default_factory=lambda: datetime.now(UTC))
    units_consumed: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def plan_definition(self) -> PlanDefinition:
        return PLAN_DEFINITIONS[self.plan]

    @property
    def unit_limit(self) -> int:
        return self.plan_definition["unit_limit"]

    @property
    def remaining_units(self) -> int:
        return max(self.unit_limit - self.units_consumed, 0)

    @property
    def is_active(self) -> bool:
        return self.status == "active" and self.remaining_units > 0


class BillingRegistry:
    """Local-first billing foundation for fast revenue experiments.

    This keeps the public contract simple so we can later swap in Stripe
    without changing route payloads or dashboard expectations.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._customers: dict[str, BillingCustomer] = {}
        self._subscriptions: dict[str, BillingSubscription] = {}

    def _require_valid_plan(self, plan: str) -> PlanCode:
        plan_code = plan.strip()
        if plan_code not in PLAN_DEFINITIONS:
            raise ValueError(f"Unknown plan code: {plan_code}")
        return plan_code  # type: ignore[return-value]

    def create_customer(
        self,
        *,
        email: str,
        display_name: str,
        plan: str,
        metadata: dict[str, Any] | None = None,
    ) -> BillingCustomer:
        with self._lock:
            plan_code = self._require_valid_plan(plan)
            customer_id = f"cus_{len(self._customers) + 1}"
            customer = BillingCustomer(
                customer_id=customer_id,
                email=email.strip().lower(),
                display_name=display_name.strip(),
                plan=plan_code,
                metadata=metadata or {},
            )
            self._customers[customer_id] = customer
            return customer

    def list_customers(self) -> list[BillingCustomer]:
        with self._lock:
            return list(self._customers.values())

    def get_customer(self, customer_id: str) -> BillingCustomer | None:
        with self._lock:
            return self._customers.get(customer_id)

    def create_subscription(
        self,
        *,
        customer_id: str,
        plan: str,
        status: str = "active",
        metadata: dict[str, Any] | None = None,
    ) -> BillingSubscription:
        with self._lock:
            if customer_id not in self._customers:
                raise KeyError(f"Unknown customer_id: {customer_id}")

            plan_code = self._require_valid_plan(plan)
            subscription_id = f"sub_{len(self._subscriptions) + 1}"
            now = datetime.now(UTC)
            subscription = BillingSubscription(
                subscription_id=subscription_id,
                customer_id=customer_id,
                plan=plan_code,
                status=status,
                created_at=now,
                current_period_start=now,
                current_period_end=now,
                units_consumed=0,
                metadata=metadata or {},
            )
            self._subscriptions[subscription_id] = subscription
            return subscription

    def list_subscriptions(self) -> list[BillingSubscription]:
        with self._lock:
            return list(self._subscriptions.values())

    def get_active_subscription_for_customer(
        self,
        customer_id: str,
    ) -> BillingSubscription | None:
        with self._lock:
            for sub in self._subscriptions.values():
                if sub.customer_id == customer_id and sub.is_active:
                    return sub
            return None

    def record_usage(
        self,
        *,
        customer_id: str,
        units: int,
    ) -> BillingSubscription:
        """Record usage units for a customer.

        Raises:
            KeyError: if no active subscription exists.
            ValueError: if usage would exceed the subscription's unit limit.

        """
        if units <= 0:
            raise ValueError("units must be positive")

        with self._lock:
            subscription = self.get_active_subscription_for_customer(customer_id)
            if subscription is None:
                raise KeyError(f"No active subscription for customer_id={customer_id}")

            if subscription.units_consumed + units > subscription.unit_limit:
                raise ValueError(
                    f"Usage would exceed plan limit: {subscription.units_consumed + units} > {subscription.unit_limit}",
                )

            subscription.units_consumed += units
            return subscription

    def can_consume(
        self,
        *,
        customer_id: str,
        units: int,
    ) -> bool:
        """Check if a customer can consume the requested units under current plan."""
        if units <= 0:
            return False

        with self._lock:
            subscription = self.get_active_subscription_for_customer(customer_id)
            if subscription is None:
                return False
            return subscription.units_consumed + units <= subscription.unit_limit


_billing_registry = BillingRegistry()


def get_billing_registry() -> BillingRegistry:
    return _billing_registry
