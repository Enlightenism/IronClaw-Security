from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import RLock
from typing import TYPE_CHECKING, Any, Final, Literal

from app.core.install_key_formats import InstallKeyFormatRegistry
from app.core.supabase import SupabaseAPIError, SupabaseClientError, get_supabase_service_client

if TYPE_CHECKING:
    from app.core.install_keys import InstallKeyRegistry
    from app.core.unit_wallet import UnitWalletRegistry

__all__ = [
    "PlanName",
    "SubscriptionRecord",
    "MeterEventRecord",
    "SubscriptionMeterStore",
    "get_subscription_meter_store",
    "reset_subscription_meter_store",
    "get_billing_store",
    "reset_billing_store",
]


PlanName = Literal["starter", "team", "enterprise"]


def _normalize_status(value: str | None, *, default: str) -> str:
    normalized = str(value or "").strip().lower()
    return normalized or default


def _is_successful_checkout(payment_status: str | None, entitlements_status: str | None) -> bool:
    payment = _normalize_status(payment_status, default="pending")
    entitlements = _normalize_status(entitlements_status, default="not_active")
    successful_payment = payment in {"paid", "succeeded", "success", "complete", "completed", "active"}
    active_entitlement = entitlements in {"active", "paid", "enabled", "granted"}
    return successful_payment and active_entitlement


@dataclass(slots=True)
class SubscriptionRecord:
    subscription_id: str = ""
    owner_key: str | None = None
    org_id: str = ""
    plan_name: PlanName = "starter"
    customer_id: str = ""
    payment_status: str = "unpaid"
    entitlements_status: str = "not_active"
    purchase_complete: bool = False
    payment_id: str | None = None
    install_key_id: str | None = None
    install_key_status: str | None = None
    unit_balance: int = 0
    units_purchased: int = 0
    units_consumed: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)
    status: str = "unpaid"
    billing_email: str | None = None
    period_start: datetime | None = None
    period_end: datetime | None = None
    included_units: int = 0
    used_units: int = 0
    overage_units: int = 0
    price_usd_monthly: int | float = 0

    def __post_init__(self) -> None:
        if self.owner_key is not None:
            self.owner_key = str(self.owner_key).strip() or None
        if self.org_id:
            self.org_id = str(self.org_id).strip().lower()
        if not self.status or self.status == "unpaid" and self.payment_status not in {"paid", "succeeded", "success", "complete", "completed", "active"}:
            self.status = "active" if _is_successful_checkout(self.payment_status, self.entitlements_status) else self.payment_status or "unpaid"
        if self.billing_email is None and self.customer_id:
            self.billing_email = self.customer_id if "@" in self.customer_id else None
        if self.period_start is None:
            self.period_start = self.created_at
        if self.period_end is None:
            self.period_end = self.created_at
        if self.included_units == 0 and self.units_purchased > 0:
            self.included_units = self.units_purchased
        if self.used_units == 0:
            self.used_units = self.units_consumed
        if self.overage_units == 0 and self.used_units > self.included_units:
            self.overage_units = self.used_units - self.included_units
        if self.price_usd_monthly is None:
            self.price_usd_monthly = 0
        self.metadata.setdefault("owner_key", self.owner_key)
        self.metadata.setdefault("org_id", self.org_id)
        self.metadata.setdefault("subscription_id", self.subscription_id)
        self.metadata.setdefault("customer_id", self.customer_id)
        self.metadata.setdefault("plan_name", self.plan_name)
        self.metadata.setdefault("payment_status", self.payment_status)
        self.metadata.setdefault("entitlements_status", self.entitlements_status)
        self.metadata.setdefault("install_key_status", self.install_key_status)
        self.metadata.setdefault("purchase_complete", self.purchase_complete)

    def as_dict(self) -> dict[str, Any]:
        metadata = dict(self.metadata)
        metadata.update(
            {
                "owner_key": self.owner_key,
                "org_id": self.org_id,
                "subscription_id": self.subscription_id,
                "customer_id": self.customer_id,
                "plan_name": self.plan_name,
                "payment_status": self.payment_status,
                "entitlements_status": self.entitlements_status,
                "install_key_status": self.install_key_status,
                "purchase_complete": self.purchase_complete,
            }
        )
        return {
            "subscription_id": self.subscription_id,
            "owner_key": self.owner_key,
            "org_id": self.org_id,
            "plan_name": self.plan_name,
            "customer_id": self.customer_id,
            "payment_status": self.payment_status,
            "entitlements_status": self.entitlements_status,
            "purchase_complete": self.purchase_complete,
            "payment_id": self.payment_id,
            "install_key_id": self.install_key_id,
            "install_key_status": self.install_key_status,
            "unit_balance": self.unit_balance,
            "units_purchased": self.units_purchased,
            "units_consumed": self.units_consumed,
            "status": self.status,
            "billing_email": self.billing_email,
            "period_start": self.period_start.isoformat() if isinstance(self.period_start, datetime) else self.period_start,
            "period_end": self.period_end.isoformat() if isinstance(self.period_end, datetime) else self.period_end,
            "included_units": self.included_units,
            "used_units": self.used_units,
            "overage_units": self.overage_units,
            "price_usd_monthly": self.price_usd_monthly,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": metadata,
        }


@dataclass(slots=True)
class MeterEventRecord:
    event_id: str = ""
    subscription_id: str = ""
    org_id: str = ""
    action_type: str = "consume"
    units: int = 0
    recorded_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)
    event_type: str = ""
    quantity: int = 0
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not self.event_type:
            self.event_type = self.action_type
        if self.quantity == 0 and self.units:
            self.quantity = self.units
        if not self.action_type:
            self.action_type = self.event_type
        if self.units == 0 and self.quantity:
            self.units = self.quantity
        if self.occurred_at is None:
            self.occurred_at = self.recorded_at
        if self.recorded_at is None:
            self.recorded_at = self.occurred_at

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "subscription_id": self.subscription_id,
            "org_id": self.org_id,
            "action_type": self.action_type,
            "units": self.units,
            "recorded_at": self.recorded_at.isoformat(),
            "metadata": dict(self.metadata),
            "event_type": self.event_type,
            "quantity": self.quantity,
            "occurred_at": self.occurred_at.isoformat(),
        }

    def to_dict(self) -> dict[str, Any]:
        return self.as_dict()


_SUPPORTED_INSTALL_KEY_PROGRAMS: Final[tuple[str, ...]] = tuple(InstallKeyFormatRegistry.list_programs())


class SubscriptionMeterStore:
    _TABLE_SUBSCRIPTIONS: Final[str] = "subscriptions"
    _TABLE_METER_EVENTS: Final[str] = "meter_events"

    def __init__(self) -> None:
        self._lock = RLock()
        self._subscriptions: dict[str, SubscriptionRecord] = {}
        self._subscriptions_by_org: dict[str, str] = {}
        self._subscriptions_by_owner: dict[str, str] = {}
        self._events: list[MeterEventRecord] = []
        self._loaded = False
        self._install_key_registry: InstallKeyRegistry | None = None
        self._unit_wallet_registry: UnitWalletRegistry | None = None

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        try:
            client = get_supabase_service_client()
            subs_resp = client.table(self._TABLE_SUBSCRIPTIONS).select("*").execute()
            for row in subs_resp.data or []:
                record = SubscriptionRecord(
                    subscription_id=row["subscription_id"],
                    owner_key=row.get("owner_key") or (row.get("metadata") or {}).get("owner_key"),
                    org_id=row["org_id"],
                    plan_name=row["plan_name"],
                    customer_id=row["customer_id"],
                    payment_status=row.get("payment_status", "unpaid"),
                    entitlements_status=row.get("entitlements_status", "not_active"),
                    purchase_complete=bool(row.get("purchase_complete", False)),
                    payment_id=row.get("payment_id"),
                    install_key_id=row.get("install_key_id"),
                    install_key_status=row.get("install_key_status"),
                    unit_balance=row.get("unit_balance", 0),
                    units_purchased=row.get("units_purchased", 0),
                    units_consumed=row.get("units_consumed", 0),
                    created_at=datetime.fromisoformat(row["created_at"]) if row.get("created_at") else datetime.now(UTC),
                    updated_at=datetime.fromisoformat(row["updated_at"]) if row.get("updated_at") else datetime.now(UTC),
                    metadata=row.get("metadata") or {},
                )
                if record.owner_key:
                    record.metadata["owner_key"] = record.owner_key
                    self._subscriptions_by_owner[record.owner_key] = record.subscription_id
                self._subscriptions[record.subscription_id] = record
                self._subscriptions_by_org[record.org_id] = record.subscription_id
        except (SupabaseAPIError, SupabaseClientError, Exception):
            pass
        self._loaded = True

    def create_subscription(
        self,
        org_id: str,
        plan_name: PlanName,
        customer_id: str | None = None,
        subscription_id: str | None = None,
        *,
        status: str | None = None,
        billing_email: str | None = None,
        included_units: int = 0,
        price_usd_monthly: int | float = 0,
        owner_key: str | None = None,
    ) -> SubscriptionRecord:
        from uuid import uuid4

        with self._lock:
            self._ensure_loaded()
            normalized_org = org_id.strip().lower()
            existing_sub_id = self._subscriptions_by_org.get(normalized_org)
            if existing_sub_id is not None:
                return self._subscriptions[existing_sub_id]

            if subscription_id is None:
                subscription_id = f"sub_{uuid4().hex}"
            if customer_id is None:
                customer_id = billing_email or f"customer-{normalized_org}"

            record = SubscriptionRecord(
                subscription_id=subscription_id,
                owner_key=str(owner_key).strip() or None,
                org_id=normalized_org,
                plan_name=plan_name,
                customer_id=customer_id,
                status=status or "active",
                billing_email=billing_email,
                included_units=included_units,
                price_usd_monthly=price_usd_monthly,
            )
            record.payment_status = "paid" if record.status in {"active", "trialing", "pro", "free", "enterprise"} else record.payment_status
            record.entitlements_status = "active" if record.status in {"active", "trialing", "pro", "free", "enterprise"} else record.entitlements_status
            record.metadata.update(
                {
                    "owner_key": record.owner_key,
                    "org_id": record.org_id,
                    "subscription_id": record.subscription_id,
                    "customer_id": record.customer_id,
                    "plan_name": record.plan_name,
                    "payment_status": record.payment_status,
                    "entitlements_status": record.entitlements_status,
                    "install_key_status": record.install_key_status,
                    "purchase_complete": record.purchase_complete,
                }
            )
            if record.owner_key:
                self._subscriptions_by_owner[record.owner_key] = subscription_id
            self._subscriptions[subscription_id] = record
            self._subscriptions_by_org[record.org_id] = subscription_id

            try:
                client = get_supabase_service_client()
                client.table(self._TABLE_SUBSCRIPTIONS).insert(record.as_dict()).execute()
            except (SupabaseAPIError, SupabaseClientError, Exception):
                pass

            return record

    def list_subscriptions(self, org_id: str | None = None, owner_key: str | None = None) -> list[SubscriptionRecord]:
        with self._lock:
            self._ensure_loaded()
            subs = list(self._subscriptions.values())
            if org_id is not None:
                org_key = str(org_id).strip().lower()
                subs = [sub for sub in subs if sub.org_id == org_key]
            if owner_key is not None:
                owner_value = str(owner_key).strip()
                subs = [sub for sub in subs if (sub.owner_key or "") == owner_value]
            return subs

    def update_subscription(self, subscription_id: str, **updates: Any) -> SubscriptionRecord | None:
        with self._lock:
            self._ensure_loaded()
            record = self._subscriptions.get(subscription_id)
            if record is None:
                return None
            for key, value in updates.items():
                if value is None:
                    continue
                if hasattr(record, key):
                    setattr(record, key, value)
            record.updated_at = datetime.now(UTC)
            if record.status:
                record.payment_status = record.status if record.status in {"paid", "active", "trialing"} else record.payment_status
            if "owner_key" in updates:
                record.owner_key = str(updates["owner_key"]).strip() or None
                if record.owner_key:
                    self._subscriptions_by_owner[record.owner_key] = subscription_id
            if "billing_email" in updates:
                record.billing_email = updates["billing_email"]
            if "included_units" in updates:
                record.included_units = int(updates["included_units"])
            if "used_units" in updates:
                record.used_units = int(updates["used_units"])
            if "overage_units" in updates:
                record.overage_units = int(updates["overage_units"])
            if "period_start" in updates:
                record.period_start = updates["period_start"]
            if "period_end" in updates:
                record.period_end = updates["period_end"]
            if "price_usd_monthly" in updates:
                record.price_usd_monthly = updates["price_usd_monthly"]
            record.metadata.update(
                {
                    "owner_key": record.owner_key,
                    "org_id": record.org_id,
                    "subscription_id": record.subscription_id,
                    "customer_id": record.customer_id,
                    "plan_name": record.plan_name,
                    "payment_status": record.payment_status,
                    "entitlements_status": record.entitlements_status,
                    "install_key_status": record.install_key_status,
                    "purchase_complete": record.purchase_complete,
                }
            )
            return record

    def record_meter_event(
        self,
        *,
        org_id: str,
        event_type: str,
        quantity: int = 1,
        subscription_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        occurred_at: datetime | None = None,
    ) -> MeterEventRecord:
        with self._lock:
            self._ensure_loaded()
            record = self.get_subscription_by_org(org_id)
            if record is None:
                raise ValueError(f"subscription for org {org_id!r} not found")
            event = MeterEventRecord(
                event_id=f"mtr-{len(self._events) + 1}",
                subscription_id=subscription_id or record.subscription_id,
                org_id=record.org_id,
                action_type=event_type,
                units=int(quantity),
                occurred_at=occurred_at or datetime.now(UTC),
                metadata=metadata or {},
            )
            self._events.append(event)
            record.used_units += int(quantity)
            record.overage_units = max(0, record.used_units - record.included_units)
            record.updated_at = datetime.now(UTC)
            return event

    def get_subscription(self, subscription_id: str) -> SubscriptionRecord | None:
        with self._lock:
            self._ensure_loaded()
            return self._subscriptions.get(subscription_id)

    def get_subscription_by_org(self, org_id: str) -> SubscriptionRecord | None:
        with self._lock:
            self._ensure_loaded()
            sub_id = self._subscriptions_by_org.get(org_id.strip().lower())
            if sub_id is None:
                return None
            return self._subscriptions.get(sub_id)

    def get_subscription_by_owner(self, owner_key: str) -> SubscriptionRecord | None:
        with self._lock:
            self._ensure_loaded()
            sub_id = self._subscriptions_by_owner.get(str(owner_key).strip())
            if sub_id is None:
                return None
            return self._subscriptions.get(sub_id)

    def sync_checkout_result(
        self,
        subscription_id: str,
        *,
        payment_id: str | None,
        payment_status: str | None = "paid",
        entitlements_status: str | None = "active",
        customer_id: str | None = None,
        org_id: str | None = None,
        owner_key: str | None = None,
        install_key_id: str | None = None,
        install_key_status: str | None = None,
        unit_balance: int | None = None,
        purchase_complete: bool | None = None,
    ) -> SubscriptionRecord:
        with self._lock:
            self._ensure_loaded()
            record = self._subscriptions.get(subscription_id)
            if record is None:
                raise ValueError(f"subscription {subscription_id!r} not found")

            if customer_id is not None:
                record.customer_id = str(customer_id).strip()
            if org_id is not None:
                record.org_id = str(org_id).strip().lower()
            if owner_key is not None:
                normalized_owner = str(owner_key).strip() or None
                record.owner_key = normalized_owner
                if normalized_owner:
                    self._subscriptions_by_owner[normalized_owner] = subscription_id
            if payment_id is not None:
                record.payment_id = str(payment_id).strip() or None

            record.payment_status = _normalize_status(payment_status, default="pending")
            record.entitlements_status = _normalize_status(entitlements_status, default="not_active")
            checkout_success = _is_successful_checkout(record.payment_status, record.entitlements_status)

            if purchase_complete is None:
                record.purchase_complete = checkout_success
            else:
                record.purchase_complete = bool(purchase_complete) and checkout_success

            if not checkout_success:
                record.install_key_id = None
                record.install_key_status = None
            else:
                if install_key_id is not None:
                    record.install_key_id = str(install_key_id).strip() or None
                if install_key_status is not None:
                    record.install_key_status = str(install_key_status).strip() or None
                elif record.install_key_id is not None and record.install_key_status is None:
                    record.install_key_status = "active"

            if unit_balance is not None:
                record.unit_balance = max(0, int(unit_balance))

            record.metadata.update(
                {
                    "owner_key": record.owner_key,
                    "org_id": record.org_id,
                    "subscription_id": record.subscription_id,
                    "customer_id": record.customer_id,
                    "plan_name": record.plan_name,
                    "payment_status": record.payment_status,
                    "entitlements_status": record.entitlements_status,
                    "install_key_status": record.install_key_status,
                    "purchase_complete": record.purchase_complete,
                }
            )
            record.updated_at = datetime.now(UTC)

            try:
                client = get_supabase_service_client()
                client.table(self._TABLE_SUBSCRIPTIONS).update(record.as_dict()).eq("subscription_id", subscription_id).execute()
            except (SupabaseAPIError, SupabaseClientError, Exception):
                pass

            return record

    def mark_purchase_complete(
        self,
        subscription_id: str,
        *,
        payment_id: str,
        payment_status: str = "paid",
        entitlements_status: str = "active",
    ) -> SubscriptionRecord:
        return self.sync_checkout_result(
            subscription_id,
            payment_id=payment_id,
            payment_status=payment_status,
            entitlements_status=entitlements_status,
            purchase_complete=True,
        )

    def link_install_key(
        self,
        subscription_id: str,
        *,
        install_key_id: str,
        install_key_status: str = "active",
    ) -> SubscriptionRecord:
        with self._lock:
            self._ensure_loaded()
            record = self._subscriptions.get(subscription_id)
            if record is None:
                raise ValueError(f"subscription {subscription_id!r} not found")
            if not _is_successful_checkout(record.payment_status, record.entitlements_status):
                raise ValueError("install key can only be linked after successful payment confirmation and an active entitlement")

            record.install_key_id = str(install_key_id).strip() or None
            record.install_key_status = str(install_key_status).strip() or "active"
            record.purchase_complete = True
            record.metadata.update(
                {
                    "owner_key": record.owner_key,
                    "org_id": record.org_id,
                    "subscription_id": record.subscription_id,
                    "customer_id": record.customer_id,
                    "plan_name": record.plan_name,
                    "payment_status": record.payment_status,
                    "entitlements_status": record.entitlements_status,
                    "install_key_status": record.install_key_status,
                    "purchase_complete": record.purchase_complete,
                }
            )
            record.updated_at = datetime.now(UTC)

            try:
                client = get_supabase_service_client()
                client.table(self._TABLE_SUBSCRIPTIONS).update(record.as_dict()).eq("subscription_id", subscription_id).execute()
            except (SupabaseAPIError, SupabaseClientError, Exception):
                pass

            return record

    def credit_units(
        self,
        subscription_id: str,
        units: int,
    ) -> SubscriptionRecord:
        safe_units = max(0, int(units))
        with self._lock:
            self._ensure_loaded()
            record = self._subscriptions.get(subscription_id)
            if record is None:
                raise ValueError(f"subscription {subscription_id!r} not found")

            record.unit_balance += safe_units
            record.units_purchased += safe_units
            if record.install_key_id and record.install_key_status == "active":
                record.purchase_complete = record.purchase_complete or _is_successful_checkout(record.payment_status, record.entitlements_status)
            record.updated_at = datetime.now(UTC)

            try:
                client = get_supabase_service_client()
                client.table(self._TABLE_SUBSCRIPTIONS).update(
                    {
                        "unit_balance": record.unit_balance,
                        "units_purchased": record.units_purchased,
                        "updated_at": record.updated_at.isoformat(),
                    }
                ).eq("subscription_id", subscription_id).execute()
            except (SupabaseAPIError, SupabaseClientError, Exception):
                pass

            return record

    def debit_units(
        self,
        subscription_id: str,
        units: int,
        action_type: str = "consume",
        metadata: dict[str, Any] | None = None,
    ) -> tuple[SubscriptionRecord, MeterEventRecord]:
        safe_units = max(0, int(units))
        with self._lock:
            self._ensure_loaded()
            record = self._subscriptions.get(subscription_id)
            if record is None:
                raise ValueError(f"subscription {subscription_id!r} not found")

            if safe_units > record.unit_balance:
                raise ValueError("insufficient units for debit")

            record.unit_balance -= safe_units
            record.units_consumed += safe_units
            record.updated_at = datetime.now(UTC)

            from uuid import uuid4

            event = MeterEventRecord(
                event_id=f"evt_{uuid4().hex}",
                subscription_id=subscription_id,
                org_id=record.org_id,
                action_type=action_type,
                units=safe_units,
                metadata=metadata or {},
            )
            self._events.append(event)

            try:
                client = get_supabase_service_client()
                client.table(self._TABLE_SUBSCRIPTIONS).update(
                    {
                        "unit_balance": record.unit_balance,
                        "units_consumed": record.units_consumed,
                        "updated_at": record.updated_at.isoformat(),
                    }
                ).eq("subscription_id", subscription_id).execute()
                client.table(self._TABLE_METER_EVENTS).insert(event.as_dict()).execute()
            except (SupabaseAPIError, SupabaseClientError, Exception):
                pass

            return record, event

    def revoke_units(
        self,
        subscription_id: str,
        units: int,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[SubscriptionRecord, MeterEventRecord] | None:
        safe_units = max(0, int(units))
        event_key = str((metadata or {}).get("event_id") or "")
        with self._lock:
            self._ensure_loaded()
            record = self._subscriptions.get(subscription_id)
            if record is None:
                return None

            if event_key and any(item.action_type == "refund_revoke" and str(item.metadata.get("event_id") or "") == event_key for item in self._events):
                return None

            amount = min(safe_units, record.unit_balance)
            if amount <= 0:
                return None

            record.unit_balance -= amount
            record.updated_at = datetime.now(UTC)

            from uuid import uuid4

            event = MeterEventRecord(
                event_id=f"evt_{uuid4().hex}",
                subscription_id=subscription_id,
                org_id=record.org_id,
                action_type="refund_revoke",
                units=amount,
                metadata=metadata or {},
            )
            self._events.append(event)

            try:
                client = get_supabase_service_client()
                client.table(self._TABLE_SUBSCRIPTIONS).update(
                    {
                        "unit_balance": record.unit_balance,
                        "updated_at": record.updated_at.isoformat(),
                    }
                ).eq("subscription_id", subscription_id).execute()
                client.table(self._TABLE_METER_EVENTS).insert(event.as_dict()).execute()
            except (SupabaseAPIError, SupabaseClientError, Exception):
                pass

            return record, event

    def provision_install_key_on_purchase(
        self,
        subscription_id: str,
        program: str | None,
        owner_key: str,
        *,
        install_key_id: str | None = None,
        install_key_status: str | None = None,
    ) -> tuple[SubscriptionRecord, dict[str, Any]]:
        """Record billing truth for a purchase lifecycle without issuing install keys.

        The billing store only persists state for the completed checkout and active
        entitlement path. Actual install-key creation remains the responsibility of
        the canonical provisioning service, not this persistence layer.

        When a specific program is supplied, the returned payload remains backward
        compatible with the single-program shape. When no program is supplied, the
        payload is keyed by every supported install-key runtime so the purchase can
        be represented as a full install-key set for the same customer entitlement.
        """
        with self._lock:
            self._ensure_loaded()
            record = self._subscriptions.get(subscription_id)
            if record is None:
                raise ValueError(f"subscription {subscription_id!r} not found")

            if not _is_successful_checkout(record.payment_status, record.entitlements_status):
                raise ValueError("successful payment and active entitlement required before install key provisioning")

            record.purchase_complete = True
            if install_key_id is not None:
                record.install_key_id = str(install_key_id).strip() or None
            else:
                record.install_key_id = None

            if install_key_status is not None:
                record.install_key_status = str(install_key_status).strip() or None
            else:
                record.install_key_status = "pending"

            record.metadata.update(
                {
                    "owner_key": record.owner_key,
                    "org_id": record.org_id,
                    "subscription_id": record.subscription_id,
                    "customer_id": record.customer_id,
                    "plan_name": record.plan_name,
                    "payment_status": record.payment_status,
                    "entitlements_status": record.entitlements_status,
                    "install_key_status": record.install_key_status,
                    "purchase_complete": record.purchase_complete,
                    "program": program,
                }
            )
            record.updated_at = datetime.now(UTC)

            try:
                client = get_supabase_service_client()
                client.table(self._TABLE_SUBSCRIPTIONS).update(record.as_dict()).eq("subscription_id", subscription_id).execute()
            except (SupabaseAPIError, SupabaseClientError, Exception):
                pass

            def _base_payload(program_name: str) -> dict[str, Any]:
                entry = {
                    "subscription_id": subscription_id,
                    "owner_key": owner_key,
                    "program": program_name,
                    "active": record.install_key_status is not None and str(record.install_key_status).strip().lower() == "active",
                    "purchase_complete": record.purchase_complete,
                    "payment_status": record.payment_status,
                    "entitlements_status": record.entitlements_status,
                    "install_key_status": record.install_key_status,
                    "install_key_id": record.install_key_id,
                }
                return entry

            if program is None:
                payload: dict[str, Any] = {program_name: _base_payload(program_name) for program_name in _SUPPORTED_INSTALL_KEY_PROGRAMS}
            else:
                normalized_program = InstallKeyFormatRegistry.normalize_program(program)
                if normalized_program is None:
                    raise ValueError(f"Unsupported install key program: {program!r}")
                payload = _base_payload(normalized_program)

            return record, payload

    def list_events(self, subscription_id: str | None = None, limit: int = 100) -> list[MeterEventRecord]:
        with self._lock:
            self._ensure_loaded()
            events = self._events if subscription_id is None else [e for e in self._events if e.subscription_id == subscription_id]
            return list(events[-limit:])

    def list_meter_events(
        self,
        *,
        org_id: str | None = None,
        event_type: str | None = None,
        limit: int | None = None,
    ) -> list[MeterEventRecord]:
        with self._lock:
            self._ensure_loaded()
            events = list(self._events)
            if org_id is not None:
                org_key = str(org_id).strip().lower()
                events = [event for event in events if str(event.org_id).strip().lower() == org_key]
            if event_type is not None:
                events = [event for event in events if str(getattr(event, "event_type", getattr(event, "action_type", ""))).strip().lower() == str(event_type).strip().lower()]
            if limit is not None:
                events = list(events[-limit:])
            return events

    def seed_defaults(self) -> None:
        with self._lock:
            self._ensure_loaded()
            if self._subscriptions:
                return
            for org_id, plan_name, included_units, billing_email in [
                ("org-alpha", "pro", 25_000, "alpha@ironclaw.dev"),
                ("org-beta", "free", 5_000, "beta@ironclaw.dev"),
            ]:
                self.create_subscription(
                    org_id=org_id,
                    plan_name=plan_name,
                    customer_id=billing_email,
                    status="active",
                    billing_email=billing_email,
                    included_units=included_units,
                    price_usd_monthly=299 if plan_name == "pro" else 0,
                )
            if not self._events:
                self.record_meter_event(org_id="org-alpha", event_type="scan", quantity=120)
                self.record_meter_event(org_id="org-alpha", event_type="guard_request", quantity=30)
                self.record_meter_event(org_id="org-beta", event_type="scan", quantity=40)

    def reset(self) -> None:
        with self._lock:
            self._subscriptions.clear()
            self._subscriptions_by_org.clear()
            self._subscriptions_by_owner.clear()
            self._events.clear()
            self._loaded = True

    def is_ready(self) -> bool:
        return True

    def as_dict(self) -> dict[str, Any]:
        return {
            "subscriptions": len(self._subscriptions),
            "meter_events": len(self._events),
            "ready": True,
        }


_SUBSCRIPTION_METER_STORE: SubscriptionMeterStore | None = None
_subscription_meter_store_lock = RLock()


def get_subscription_meter_store() -> SubscriptionMeterStore:
    global _SUBSCRIPTION_METER_STORE
    if _SUBSCRIPTION_METER_STORE is None:
        with _subscription_meter_store_lock:
            if _SUBSCRIPTION_METER_STORE is None:
                _SUBSCRIPTION_METER_STORE = SubscriptionMeterStore()
    return _SUBSCRIPTION_METER_STORE


def reset_subscription_meter_store() -> None:
    global _SUBSCRIPTION_METER_STORE
    with _subscription_meter_store_lock:
        _SUBSCRIPTION_METER_STORE = None


def get_billing_store() -> SubscriptionMeterStore:
    return get_subscription_meter_store()


def reset_billing_store() -> None:
    reset_subscription_meter_store()
