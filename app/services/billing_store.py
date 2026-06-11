from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from threading import Lock
from typing import Any, Literal
from uuid import uuid4

PlanName = Literal["free", "pro", "enterprise"]
SubscriptionStatus = Literal["trialing", "active", "past_due", "canceled"]
MeterEventType = Literal["scan", "guard_request", "execution", "incident", "quarantine"]


def _utcnow() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class MeterEventRecord:
    event_id: str
    org_id: str
    event_type: MeterEventType
    quantity: int
    occurred_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["occurred_at"] = self.occurred_at.isoformat().replace("+00:00", "Z")
        return payload


@dataclass(slots=True)
class SubscriptionRecord:
    subscription_id: str
    org_id: str
    plan_name: PlanName
    status: SubscriptionStatus
    billing_email: str
    period_start: datetime
    period_end: datetime
    included_units: int
    used_units: int
    overage_units: int
    price_usd_monthly: int
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["period_start"] = self.period_start.isoformat().replace("+00:00", "Z")
        payload["period_end"] = self.period_end.isoformat().replace("+00:00", "Z")
        return payload


# ---------------------------------------------------------------------------
# SubscriptionMeterStore  (renamed from BillingStore to eliminate collision
# with billingstore.BillingStore — the two classes own completely different
# domains: this file owns subscriptions + metering; billingstore.py owns
# billing-transaction records / invoices / payments)
# ---------------------------------------------------------------------------


class SubscriptionMeterStore:
    def __init__(self) -> None:
        self._lock = Lock()
        self._subscriptions: list[SubscriptionRecord] = []
        self._meter_events: list[MeterEventRecord] = []

    # ------------------------------------------------------------------
    # Seeding
    # ------------------------------------------------------------------

    def seed_defaults(self) -> None:
        with self._lock:
            if self._subscriptions or self._meter_events:
                return

            now = _utcnow()
            period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            period_end = now.replace(day=28, hour=23, minute=59, second=59, microsecond=0)

            self._subscriptions.extend(
                [
                    SubscriptionRecord(
                        subscription_id=f"sub-{uuid4().hex[:12]}",
                        org_id="org-seed-001",
                        plan_name="enterprise",
                        status="active",
                        billing_email="billing@ironclaw.dev",
                        period_start=period_start,
                        period_end=period_end,
                        included_units=60_000,
                        used_units=28_440,
                        overage_units=0,
                        price_usd_monthly=2499,
                        metadata={"seeded": True},
                    ),
                    SubscriptionRecord(
                        subscription_id=f"sub-{uuid4().hex[:12]}",
                        org_id="org-seed-002",
                        plan_name="pro",
                        status="trialing",
                        billing_email="finance@sandbox.dev",
                        period_start=period_start,
                        period_end=period_end,
                        included_units=25_000,
                        used_units=2_140,
                        overage_units=0,
                        price_usd_monthly=299,
                        metadata={"seeded": True},
                    ),
                ]
            )

            self._meter_events.extend(
                [
                    MeterEventRecord(
                        event_id=f"mtr-{uuid4().hex[:12]}",
                        org_id="org-seed-001",
                        event_type="scan",
                        quantity=1200,
                        occurred_at=now,
                        metadata={"seeded": True},
                    ),
                    MeterEventRecord(
                        event_id=f"mtr-{uuid4().hex[:12]}",
                        org_id="org-seed-001",
                        event_type="guard_request",
                        quantity=420,
                        occurred_at=now,
                        metadata={"seeded": True},
                    ),
                    MeterEventRecord(
                        event_id=f"mtr-{uuid4().hex[:12]}",
                        org_id="org-seed-002",
                        event_type="execution",
                        quantity=84,
                        occurred_at=now,
                        metadata={"seeded": True},
                    ),
                ]
            )

    # ------------------------------------------------------------------
    # Subscriptions
    # ------------------------------------------------------------------

    def list_subscriptions(self, *, org_id: str | None = None) -> list[SubscriptionRecord]:
        with self._lock:
            items = list(self._subscriptions)
        if org_id is not None:
            items = [item for item in items if item.org_id == org_id]
        return items

    def get_subscription(self, subscription_id: str) -> SubscriptionRecord | None:
        with self._lock:
            for item in self._subscriptions:
                if item.subscription_id == subscription_id:
                    return item
        return None

    def create_subscription(
        self,
        *,
        org_id: str,
        plan_name: PlanName,
        status: SubscriptionStatus,
        billing_email: str,
        included_units: int,
        price_usd_monthly: int,
        metadata: dict[str, Any] | None = None,
    ) -> SubscriptionRecord:
        now = _utcnow()
        period_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        period_end = now.replace(day=28, hour=23, minute=59, second=59, microsecond=0)

        record = SubscriptionRecord(
            subscription_id=f"sub-{uuid4().hex[:12]}",
            org_id=org_id.strip(),
            plan_name=plan_name,
            status=status,
            billing_email=billing_email.strip(),
            period_start=period_start,
            period_end=period_end,
            included_units=included_units,
            used_units=0,
            overage_units=0,
            price_usd_monthly=price_usd_monthly,
            metadata=dict(metadata or {}),
        )
        with self._lock:
            self._subscriptions.append(record)
        return record

    def update_subscription(
        self,
        subscription_id: str,
        *,
        status: SubscriptionStatus,
        plan_name: PlanName | None = None,
        billing_email: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SubscriptionRecord | None:
        with self._lock:
            for index, item in enumerate(self._subscriptions):
                if item.subscription_id != subscription_id:
                    continue
                updated = SubscriptionRecord(
                    subscription_id=item.subscription_id,
                    org_id=item.org_id,
                    plan_name=plan_name if plan_name is not None else item.plan_name,
                    status=status,
                    billing_email=billing_email.strip() if billing_email is not None else item.billing_email,
                    period_start=item.period_start,
                    period_end=item.period_end,
                    included_units=item.included_units,
                    used_units=item.used_units,
                    overage_units=item.overage_units,
                    price_usd_monthly=item.price_usd_monthly,
                    metadata={**item.metadata, **dict(metadata or {})},
                )
                self._subscriptions[index] = updated
                return updated
        return None

    # ------------------------------------------------------------------
    # Metering
    # ------------------------------------------------------------------

    def list_meter_events(
        self,
        *,
        org_id: str | None = None,
        event_type: MeterEventType | None = None,
    ) -> list[MeterEventRecord]:
        with self._lock:
            items = list(self._meter_events)
        if org_id is not None:
            items = [item for item in items if item.org_id == org_id]
        if event_type is not None:
            items = [item for item in items if item.event_type == event_type]
        return items

    def record_meter_event(
        self,
        *,
        org_id: str,
        event_type: MeterEventType,
        quantity: int,
        metadata: dict[str, Any] | None = None,
    ) -> MeterEventRecord:
        event = MeterEventRecord(
            event_id=f"mtr-{uuid4().hex[:12]}",
            org_id=org_id.strip(),
            event_type=event_type,
            quantity=quantity,
            occurred_at=_utcnow(),
            metadata=dict(metadata or {}),
        )
        with self._lock:
            self._meter_events.append(event)
            for index, item in enumerate(self._subscriptions):
                if item.org_id != org_id:
                    continue
                used_units = item.used_units + quantity
                overage_units = max(0, used_units - item.included_units)
                self._subscriptions[index] = SubscriptionRecord(
                    subscription_id=item.subscription_id,
                    org_id=item.org_id,
                    plan_name=item.plan_name,
                    status=item.status,
                    billing_email=item.billing_email,
                    period_start=item.period_start,
                    period_end=item.period_end,
                    included_units=item.included_units,
                    used_units=used_units,
                    overage_units=overage_units,
                    price_usd_monthly=item.price_usd_monthly,
                    metadata=dict(item.metadata),
                )
        return event

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def reset(self) -> None:
        with self._lock:
            self._subscriptions.clear()
            self._meter_events.clear()

    def is_ready(self) -> bool:
        return True

    def as_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "subscriptions": len(self._subscriptions),
                "meter_events": len(self._meter_events),
                "ready": True,
            }


# ---------------------------------------------------------------------------
# Back-compat shim — any import of `BillingStore` from this module resolves
# to SubscriptionMeterStore so existing test references don't hard-break
# before the rename sweep is complete.  Remove after grep confirms no
# remaining consumers reference billing_store.BillingStore directly.
# ---------------------------------------------------------------------------
BillingStore = SubscriptionMeterStore


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_SUBSCRIPTION_METER_STORE = SubscriptionMeterStore()
_SUBSCRIPTION_METER_STORE.seed_defaults()


def get_subscription_meter_store() -> SubscriptionMeterStore:
    return _SUBSCRIPTION_METER_STORE


def reset_subscription_meter_store() -> None:
    _SUBSCRIPTION_METER_STORE.reset()
    _SUBSCRIPTION_METER_STORE.seed_defaults()


# Back-compat factory aliases — remove after consumer sweep
def get_billing_store() -> SubscriptionMeterStore:
    return _SUBSCRIPTION_METER_STORE


def reset_billing_store() -> None:
    reset_subscription_meter_store()
