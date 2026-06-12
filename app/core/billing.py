from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import logging
import math
from threading import Lock
from typing import Any, Final, Literal, TypedDict
from uuid import uuid4

from app.persistencebootstrap import (
    StoreType,
    build_store,
)
from app.supabaseclient import (
    BILLING_TIER_5K_PRICE_USD,
    BILLING_TIER_5K_UNITS,
    BILLING_TIER_25K_PRICE_USD,
    BILLING_TIER_25K_UNITS,
    BILLING_TIER_60K_PRICE_USD,
    BILLING_TIER_60K_UNITS,
)

logger = logging.getLogger(__name__)


__all__ = [
    "BillingCustomer",
    "BillingRegistry",
    "BillingSubscription",
    "BillingUsageError",
    "PlanCode",
    "PlanDefinition",
    "PLAN_DEFINITIONS",
    "TOKENS_PER_UNIT",
    "units_required_for_tokens",
    "get_billing_registry",
]


TOKENS_PER_UNIT: Final[int] = 25_000


def units_required_for_tokens(token_count: int) -> int:
    if token_count <= 0:
        return 0
    return math.ceil(token_count / TOKENS_PER_UNIT)


PlanCode = Literal["starter-5k", "team-25k", "enterprise-60k"]


class PlanDefinition(TypedDict):
    code: PlanCode
    name: str
    unit_limit: int
    price_usd: int
    tokens_per_unit: int


PLAN_DEFINITIONS: Final[dict[PlanCode, PlanDefinition]] = {
    "starter-5k": {
        "code": "starter-5k",
        "name": "Starter",
        "unit_limit": BILLING_TIER_5K_UNITS,
        "price_usd": BILLING_TIER_5K_PRICE_USD,
        "tokens_per_unit": TOKENS_PER_UNIT,
    },
    "team-25k": {
        "code": "team-25k",
        "name": "Team",
        "unit_limit": BILLING_TIER_25K_UNITS,
        "price_usd": BILLING_TIER_25K_PRICE_USD,
        "tokens_per_unit": TOKENS_PER_UNIT,
    },
    "enterprise-60k": {
        "code": "enterprise-60k",
        "name": "Enterprise",
        "unit_limit": BILLING_TIER_60K_UNITS,
        "price_usd": BILLING_TIER_60K_PRICE_USD,
        "tokens_per_unit": TOKENS_PER_UNIT,
    },
}


_CUSTOMERS_TABLE = "billing_customers"
_SUBSCRIPTIONS_TABLE = "billing_subscriptions"


class BillingUsageError(Exception):
    """Raised when a usage record operation is rejected.

    Carries structured context for auditability.
    """

    def __init__(
        self,
        message: str,
        *,
        customer_id: str,
        subscription_id: str,
        units_requested: int,
        units_consumed: int,
        unit_limit: int,
    ) -> None:
        super().__init__(message)
        self.customer_id = customer_id
        self.subscription_id = subscription_id
        self.units_requested = units_requested
        self.units_consumed = units_consumed
        self.unit_limit = unit_limit


@dataclass
class BillingCustomer:
    customer_id: str
    email: str
    display_name: str
    plan: PlanCode
    active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.email or "@" not in self.email:
            raise ValueError(f"Invalid email: {self.email!r}")
        if self.plan not in PLAN_DEFINITIONS:
            raise ValueError(f"Unknown plan code: {self.plan!r}")


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

    def __post_init__(self) -> None:
        if self.plan not in PLAN_DEFINITIONS:
            raise ValueError(f"Unknown plan code: {self.plan!r}")
        if self.units_consumed < 0:
            raise ValueError("units_consumed cannot be negative")

    @property
    def plan_definition(self) -> PlanDefinition:
        return PLAN_DEFINITIONS[self.plan]

    @property
    def unit_limit(self) -> int:
        return self.plan_definition["unit_limit"]

    @property
    def price_usd(self) -> int:
        return self.plan_definition["price_usd"]

    @property
    def tokens_per_unit(self) -> int:
        return self.plan_definition["tokens_per_unit"]

    @property
    def remaining_units(self) -> int:
        return max(self.unit_limit - self.units_consumed, 0)

    @property
    def token_coverage_limit(self) -> int:
        return self.unit_limit * self.tokens_per_unit

    @property
    def remaining_token_coverage(self) -> int:
        return self.remaining_units * self.tokens_per_unit

    @property
    def is_period_active(self) -> bool:
        """True when the current wall-clock time is within the billing period."""
        now = datetime.now(UTC)
        return self.current_period_start <= now <= self.current_period_end

    @property
    def is_active(self) -> bool:
        """True when status is active, units remain, and the period has not expired."""
        return self.status == "active" and self.remaining_units > 0 and self.is_period_active


def _customer_from_row(row: dict[str, Any]) -> BillingCustomer:
    created_raw = row.get("created_at")
    if isinstance(created_raw, str):
        created_at = datetime.fromisoformat(created_raw)
    elif isinstance(created_raw, datetime):
        created_at = created_raw
    else:
        created_at = datetime.now(UTC)

    return BillingCustomer(
        customer_id=row["customer_id"],
        email=row["email"],
        display_name=row["display_name"],
        plan=row["plan"],
        active=bool(row.get("active", True)),
        created_at=created_at,
        metadata=row.get("metadata") or {},
    )


def _subscription_from_row(row: dict[str, Any]) -> BillingSubscription:
    def _parse_dt(val: Any) -> datetime:
        if isinstance(val, str):
            return datetime.fromisoformat(val)
        if isinstance(val, datetime):
            return val
        return datetime.now(UTC)

    return BillingSubscription(
        subscription_id=row["subscription_id"],
        customer_id=row["customer_id"],
        plan=row["plan"],
        status=row["status"],
        created_at=_parse_dt(row.get("created_at")),
        current_period_start=_parse_dt(row.get("current_period_start")),
        current_period_end=_parse_dt(row.get("current_period_end")),
        units_consumed=int(row.get("units_consumed", 0)),
        metadata=row.get("metadata") or {},
    )


class BillingRegistry:
    """Billing foundation for IronClaw agentic systems.

    Persists customers and subscriptions to Supabase via the canonical
    StoreType interface. Falls back to in-memory when Supabase is unavailable.
    IDs are uuid4-based — no sequential collision risk.
    """

    def __init__(self, *, store: StoreType | None = None) -> None:
        self._lock = Lock()
        self._store: StoreType = store if store is not None else build_store()
        self._customers: dict[str, BillingCustomer] = {}
        self._subscriptions: dict[str, BillingSubscription] = {}
        # customer_id -> list[subscription_id] index for O(1) lookup
        self._customer_sub_index: dict[str, list[str]] = {}
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        try:
            for row in self._store.select(_CUSTOMERS_TABLE):
                c = _customer_from_row(row)
                self._customers[c.customer_id] = c
            for row in self._store.select(_SUBSCRIPTIONS_TABLE):
                s = _subscription_from_row(row)
                self._subscriptions[s.subscription_id] = s
                self._customer_sub_index.setdefault(s.customer_id, []).append(s.subscription_id)
        except Exception:
            logger.exception("billing: failed to load from store; continuing with empty state")
        self._loaded = True

    def _require_valid_plan(self, plan: str) -> PlanCode:
        plan_code = plan.strip()
        if plan_code not in PLAN_DEFINITIONS:
            raise ValueError(f"Unknown plan code: {plan_code!r}. Valid codes: {list(PLAN_DEFINITIONS)}")
        return plan_code  # type: ignore[return-value]

    def _get_active_subscription_unlocked(self, customer_id: str) -> BillingSubscription | None:
        for sub_id in self._customer_sub_index.get(customer_id, []):
            sub = self._subscriptions.get(sub_id)
            if sub is not None and sub.is_active:
                return sub
        return None

    def _cancel_all_active_subscriptions_unlocked(self, customer_id: str) -> None:
        """Cancel every active subscription for a customer (handles data-corruption duplicates)."""
        for sub_id in list(self._customer_sub_index.get(customer_id, [])):
            sub = self._subscriptions.get(sub_id)
            if sub is not None and sub.status == "active":
                sub.status = "cancelled"
                try:
                    self._store.update(
                        _SUBSCRIPTIONS_TABLE,
                        {"status": "cancelled"},
                        filters={"subscription_id": sub_id},
                    )
                except Exception:
                    logger.exception(
                        "billing: failed to persist cancellation for subscription %s",
                        sub_id,
                    )

    def create_customer(
        self,
        *,
        email: str,
        display_name: str,
        plan: str,
        metadata: dict[str, Any] | None = None,
    ) -> BillingCustomer:
        with self._lock:
            self._ensure_loaded()
            plan_code = self._require_valid_plan(plan)
            customer_id = f"cus_{uuid4().hex}"
            now = datetime.now(UTC)
            customer = BillingCustomer(
                customer_id=customer_id,
                email=email.strip().lower(),
                display_name=display_name.strip(),
                plan=plan_code,
                active=True,
                created_at=now,
                metadata=metadata or {},
            )
            payload: dict[str, Any] = {
                "customer_id": customer.customer_id,
                "email": customer.email,
                "display_name": customer.display_name,
                "plan": customer.plan,
                "active": customer.active,
                "created_at": customer.created_at.isoformat(),
                "metadata": customer.metadata,
            }
            try:
                self._store.insert(_CUSTOMERS_TABLE, payload)
            except Exception:
                logger.exception("billing: failed to persist customer %s", customer_id)
            self._customers[customer_id] = customer
            return customer

    def list_customers(self) -> list[BillingCustomer]:
        with self._lock:
            self._ensure_loaded()
            return list(self._customers.values())

    def get_customer(self, customer_id: str) -> BillingCustomer | None:
        with self._lock:
            self._ensure_loaded()
            return self._customers.get(customer_id)

    def deactivate_customer(self, customer_id: str) -> BillingCustomer:
        with self._lock:
            self._ensure_loaded()
            customer = self._customers.get(customer_id)
            if customer is None:
                raise KeyError(f"Unknown customer_id: {customer_id!r}")
            customer.active = False
            try:
                self._store.update(
                    _CUSTOMERS_TABLE,
                    {"active": False},
                    filters={"customer_id": customer_id},
                )
            except Exception:
                logger.exception(
                    "billing: failed to persist deactivation for customer %s",
                    customer_id,
                )
            self._cancel_all_active_subscriptions_unlocked(customer_id)
            return customer

    def create_subscription(
        self,
        *,
        customer_id: str,
        plan: str,
        status: str = "active",
        period_end: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> BillingSubscription:
        with self._lock:
            self._ensure_loaded()
            if customer_id not in self._customers:
                raise KeyError(f"Unknown customer_id: {customer_id!r}")

            plan_code = self._require_valid_plan(plan)
            subscription_id = f"sub_{uuid4().hex}"
            now = datetime.now(UTC)
            subscription = BillingSubscription(
                subscription_id=subscription_id,
                customer_id=customer_id,
                plan=plan_code,
                status=status,
                created_at=now,
                current_period_start=now,
                current_period_end=period_end if period_end is not None else now,
                units_consumed=0,
                metadata=metadata or {},
            )
            payload: dict[str, Any] = {
                "subscription_id": subscription.subscription_id,
                "customer_id": subscription.customer_id,
                "plan": subscription.plan,
                "status": subscription.status,
                "created_at": subscription.created_at.isoformat(),
                "current_period_start": subscription.current_period_start.isoformat(),
                "current_period_end": subscription.current_period_end.isoformat(),
                "units_consumed": subscription.units_consumed,
                "metadata": subscription.metadata,
            }
            try:
                self._store.insert(_SUBSCRIPTIONS_TABLE, payload)
            except Exception:
                logger.exception("billing: failed to persist subscription %s", subscription_id)
            self._subscriptions[subscription_id] = subscription
            self._customer_sub_index.setdefault(customer_id, []).append(subscription_id)
            return subscription

    def list_subscriptions(self) -> list[BillingSubscription]:
        with self._lock:
            self._ensure_loaded()
            return list(self._subscriptions.values())

    def get_active_subscription_for_customer(
        self,
        customer_id: str,
    ) -> BillingSubscription | None:
        with self._lock:
            self._ensure_loaded()
            return self._get_active_subscription_unlocked(customer_id)

    def cancel_subscription(self, subscription_id: str) -> BillingSubscription:
        with self._lock:
            self._ensure_loaded()
            sub = self._subscriptions.get(subscription_id)
            if sub is None:
                raise KeyError(f"Unknown subscription_id: {subscription_id!r}")
            sub.status = "cancelled"
            try:
                self._store.update(
                    _SUBSCRIPTIONS_TABLE,
                    {"status": "cancelled"},
                    filters={"subscription_id": subscription_id},
                )
            except Exception:
                logger.exception(
                    "billing: failed to persist cancellation for subscription %s",
                    subscription_id,
                )
            return sub

    def upgrade_plan(
        self,
        *,
        customer_id: str,
        new_plan: str,
    ) -> tuple[BillingCustomer, BillingSubscription]:
        """Change the active plan for a customer.

        Cancels the existing active subscription, updates the customer's
        plan field, and creates a new active subscription on the new plan.
        Raises KeyError if customer not found or no active subscription exists.
        """
        with self._lock:
            self._ensure_loaded()
            customer = self._customers.get(customer_id)
            if customer is None:
                raise KeyError(f"Unknown customer_id: {customer_id!r}")
            plan_code = self._require_valid_plan(new_plan)
            old_sub = self._get_active_subscription_unlocked(customer_id)
            if old_sub is not None:
                old_sub.status = "upgraded"
                try:
                    self._store.update(
                        _SUBSCRIPTIONS_TABLE,
                        {"status": "upgraded"},
                        filters={"subscription_id": old_sub.subscription_id},
                    )
                except Exception:
                    logger.exception(
                        "billing: failed to persist upgrade for subscription %s",
                        old_sub.subscription_id,
                    )
            customer.plan = plan_code
            try:
                self._store.update(
                    _CUSTOMERS_TABLE,
                    {"plan": plan_code},
                    filters={"customer_id": customer_id},
                )
            except Exception:
                logger.exception(
                    "billing: failed to persist plan upgrade for customer %s",
                    customer_id,
                )
        # create_subscription acquires its own lock
        new_sub = self.create_subscription(
            customer_id=customer_id,
            plan=plan_code,
            status="active",
        )
        return customer, new_sub

    def reset_period(
        self,
        *,
        subscription_id: str,
        new_period_end: datetime,
    ) -> BillingSubscription:
        """Reset units_consumed to zero and advance the billing period.

        Used by period rollover jobs. Raises KeyError if subscription not found.
        """
        with self._lock:
            self._ensure_loaded()
            sub = self._subscriptions.get(subscription_id)
            if sub is None:
                raise KeyError(f"Unknown subscription_id: {subscription_id!r}")
            now = datetime.now(UTC)
            sub.units_consumed = 0
            sub.current_period_start = now
            sub.current_period_end = new_period_end
            try:
                self._store.update(
                    _SUBSCRIPTIONS_TABLE,
                    {
                        "units_consumed": 0,
                        "current_period_start": now.isoformat(),
                        "current_period_end": new_period_end.isoformat(),
                    },
                    filters={"subscription_id": subscription_id},
                )
            except Exception:
                logger.exception(
                    "billing: failed to persist period reset for subscription %s",
                    subscription_id,
                )
            return sub

    def record_usage(
        self,
        *,
        customer_id: str,
        units: int,
    ) -> BillingSubscription:
        if units <= 0:
            raise ValueError("units must be positive")

        with self._lock:
            self._ensure_loaded()
            subscription = self._get_active_subscription_unlocked(customer_id)
            if subscription is None:
                raise KeyError(f"No active subscription for customer_id={customer_id!r}")

            projected = subscription.units_consumed + units
            if projected > subscription.unit_limit:
                raise BillingUsageError(
                    f"Usage would exceed plan limit: {projected} > {subscription.unit_limit}",
                    customer_id=customer_id,
                    subscription_id=subscription.subscription_id,
                    units_requested=units,
                    units_consumed=subscription.units_consumed,
                    unit_limit=subscription.unit_limit,
                )

            subscription.units_consumed = projected
            try:
                self._store.update(
                    _SUBSCRIPTIONS_TABLE,
                    {"units_consumed": projected},
                    filters={"subscription_id": subscription.subscription_id},
                )
            except Exception:
                logger.exception(
                    "billing: failed to persist usage update for subscription %s",
                    subscription.subscription_id,
                )
            return subscription

    def record_token_usage(
        self,
        *,
        customer_id: str,
        token_count: int,
    ) -> tuple[BillingSubscription, int]:
        required_units = units_required_for_tokens(token_count)
        subscription = self.record_usage(customer_id=customer_id, units=required_units)
        return subscription, required_units

    def can_consume(
        self,
        *,
        customer_id: str,
        units: int,
    ) -> bool:
        if units <= 0:
            return False

        with self._lock:
            self._ensure_loaded()
            subscription = self._get_active_subscription_unlocked(customer_id)
            if subscription is None:
                return False
            return subscription.units_consumed + units <= subscription.unit_limit

    def can_consume_tokens(
        self,
        *,
        customer_id: str,
        token_count: int,
    ) -> bool:
        required_units = units_required_for_tokens(token_count)
        return self.can_consume(customer_id=customer_id, units=required_units)

    def get_plan_definitions(self) -> dict[PlanCode, PlanDefinition]:
        return dict(PLAN_DEFINITIONS)


_billing_registry: BillingRegistry | None = None
_billing_registry_lock = Lock()


def get_billing_registry() -> BillingRegistry:
    global _billing_registry
    if _billing_registry is None:
        with _billing_registry_lock:
            if _billing_registry is None:
                _billing_registry = BillingRegistry()
    return _billing_registry
