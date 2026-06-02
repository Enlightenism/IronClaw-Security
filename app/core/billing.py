from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import logging
from threading import Lock
from typing import Any, Final, Literal, TypedDict
from uuid import uuid4

from app.persistencebootstrap import StoreType, build_store

logger = logging.getLogger(__name__)

PlanCode = Literal["starter-10k", "growth-50k", "scale-100k"]


class PlanDefinition(TypedDict):
    code: PlanCode
    name: str
    unit_limit: int
    price_usd: int


PLAN_DEFINITIONS: Final[dict[PlanCode, PlanDefinition]] = {
    "starter-10k": {
        "code": "starter-10k",
        "name": "Starter 10k",
        "unit_limit": 10_000,
        "price_usd": 20,
    },
    "growth-50k": {
        "code": "growth-50k",
        "name": "Growth 50k",
        "unit_limit": 50_000,
        "price_usd": 90,
    },
    "scale-100k": {
        "code": "scale-100k",
        "name": "Scale 100k",
        "unit_limit": 100_000,
        "price_usd": 150,
    },
}

_CUSTOMERS_TABLE = "billing_customers"
_SUBSCRIPTIONS_TABLE = "billing_subscriptions"


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
        # In-memory mirrors kept for fast reads and fallback coherence
        self._customers: dict[str, BillingCustomer] = {}
        self._subscriptions: dict[str, BillingSubscription] = {}
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
        except Exception:
            logger.exception("billing: failed to load from store; continuing with empty state")
        self._loaded = True

    def _require_valid_plan(self, plan: str) -> PlanCode:
        plan_code = plan.strip()
        if plan_code not in PLAN_DEFINITIONS:
            raise ValueError(f"Unknown plan code: {plan_code!r}. Valid codes: {list(PLAN_DEFINITIONS)}")
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

    def create_subscription(
        self,
        *,
        customer_id: str,
        plan: str,
        status: str = "active",
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
                current_period_end=now,
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
            ValueError: if units <= 0 or usage would exceed the plan limit.
            KeyError: if no active subscription exists.
        """
        if units <= 0:
            raise ValueError("units must be positive")

        with self._lock:
            self._ensure_loaded()
            subscription = self.get_active_subscription_for_customer(customer_id)
            if subscription is None:
                raise KeyError(f"No active subscription for customer_id={customer_id!r}")

            projected = subscription.units_consumed + units
            if projected > subscription.unit_limit:
                raise ValueError(
                    f"Usage would exceed plan limit: {projected} > {subscription.unit_limit}",
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

    def can_consume(
        self,
        *,
        customer_id: str,
        units: int,
    ) -> bool:
        """Check whether a customer can consume the requested units under their current plan."""
        if units <= 0:
            return False

        with self._lock:
            self._ensure_loaded()
            subscription = self.get_active_subscription_for_customer(customer_id)
            if subscription is None:
                return False
            return subscription.units_consumed + units <= subscription.unit_limit

    def get_plan_definitions(self) -> dict[PlanCode, PlanDefinition]:
        """Return the canonical plan definitions (read-only view)."""
        return dict(PLAN_DEFINITIONS)


_billing_registry = BillingRegistry()


def get_billing_registry() -> BillingRegistry:
    return _billing_registry
