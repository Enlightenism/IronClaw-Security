from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import logging
import math
from threading import Lock
from typing import Any, Final, Literal, TypedDict
from uuid import uuid4

from app.core.install_key_formats import InstallKeyFormatRegistry
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
from app.supabaseclient import (
    TOKENS_PER_UNIT as BILLING_TOKENS_PER_UNIT,
)

logger = logging.getLogger(__name__)


__all__ = [
    "BillingCustomer",
    "BillingRegistry",
    "BillingSubscription",
    "BillingUsageError",
    "PlanCode",
    "PlanDefinition",
    "UnitPackageEntry",
    "PLAN_DEFINITIONS",
    "PACKAGE_ALIASES",
    "FEATURED_PACKAGE_ID",
    "UNIT_PACKAGE_IDS",
    "TOKENS_PER_UNIT",
    "UNIT_PACKAGE_CATALOG",
    "resolve_plan_code",
    "resolve_package_id",
    "units_required_for_tokens",
    "get_billing_registry",
    "get_active_subscription_for_customer",
    "resolve_billing_owner",
    "resolve_authenticated_billing_owner",
    "_reset_billing_registry_for_testing",
]


TOKENS_PER_UNIT: Final[int] = BILLING_TOKENS_PER_UNIT
# Units do not expire in IronClaw. Period end is stored for DB completeness only
# and is not used to gate consumption. Set to 100 years as a non-expiring sentinel.
_DEFAULT_PERIOD_DAYS: Final[int] = 36500


def units_required_for_tokens(token_count: int) -> int:
    if token_count <= 0:
        return 0
    return math.ceil(token_count / TOKENS_PER_UNIT)


# ---------------------------------------------------------------------------
# Org wallet routing — single source of truth
# ---------------------------------------------------------------------------


def _normalize_owner_value(owner_key: str | None) -> str:
    """Normalize billing owner values to the canonical lowercase form.

    This keeps email owners and org wallet owners in the same lookup format so
    the billing registry can resolve a canonical owner key consistently across
    customer records, subscription checks, and install-key provisioning guards.
    """
    if owner_key is None:
        return ""
    normalized = str(owner_key).strip().lower()
    return normalized


def _looks_like_generic_platform_auth(value: str | None) -> bool:
    normalized = _normalize_owner_value(value)
    if not normalized:
        return False
    if normalized.startswith("ic_org_"):
        return False
    if normalized.startswith("ic_install_"):
        return False
    if normalized.startswith("ic_"):
        return True

    generic_prefixes = (
        "sk_",
        "pk_",
        "rk_",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "ghl_",
        "github_pat_",
        "pat_",
        "personal_access_token",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "xoxr-",
        "token_",
        "secret_",
        "api_",
        "api-key",
        "api_key",
        "platform-api-key",
        "platform_api_key",
        "system-api-key",
        "system_api_key",
        "internal-platform-api-key",
        "internal_platform_api_key",
        "bearer ",
        "x-api-key",
    )
    if normalized.startswith(generic_prefixes):
        return True

    return ("platform" in normalized and ("key" in normalized or "token" in normalized or "secret" in normalized)) or ("system" in normalized and ("key" in normalized or "token" in normalized or "secret" in normalized)) or ("api" in normalized and "key" in normalized)


def _is_org_owner_context(auth_ctx: Any) -> bool:
    """Return True only when the request is explicitly org-scoped.

    Generic auth identity, system API keys, and personal/session contexts must
    never be treated as the billing owner for paid install-key issuance. Only a
    real org-scoped auth context with an org_id is allowed to resolve to the
    shared org wallet.
    """
    if auth_ctx is None:
        return False

    key_type = str(getattr(auth_ctx, "key_type", "") or "").strip().lower()
    principal_type = str(getattr(auth_ctx, "principal_type", "") or "").strip().lower()
    org_id = getattr(auth_ctx, "org_id", None)
    normalized_org_id = _normalize_owner_value(org_id)

    if not normalized_org_id:
        return False
    if _looks_like_generic_platform_auth(normalized_org_id):
        return False
    if principal_type in {"platform", "system", "service"}:
        return False

    org_key_context = key_type in {"org", "org_key"}
    org_principal_context = principal_type in {"org", "org_key", "organization", "tenant"}
    return org_key_context or org_principal_context


def _is_real_billing_owner(value: str | None) -> bool:
    normalized = _normalize_owner_value(value)
    if not normalized:
        return False
    if normalized.startswith("ic_org_"):
        return True
    if normalized.startswith("ic_install_"):
        return False
    if _looks_like_generic_platform_auth(normalized):
        return False
    return not normalized.startswith("ic_")


def resolve_billing_owner(auth_ctx: Any, buyer_email: str) -> str:
    """Return the canonical wallet owner key for a billing operation.

    Only an explicit org-auth context can route to the shared org wallet via
    ``ic_org_{org_id}``. If the org identifier is already in canonical owner-key
    form, it is preserved exactly instead of being double-prefixed. Every other
    auth context resolves to the paid buyer's canonical email address, ensuring
    install-key generation follows the subscription owner path rather than a
    generic system or API identity.
    """
    normalized_email = _normalize_owner_value(buyer_email)
    if _is_org_owner_context(auth_ctx):
        org_id = getattr(auth_ctx, "org_id", None)
        normalized_org_id = _normalize_owner_value(org_id)
        if not normalized_org_id:
            return normalized_email if _is_real_billing_owner(normalized_email) else ""
        if normalized_org_id.startswith("ic_org_"):
            return normalized_org_id if _is_real_billing_owner(normalized_org_id) else normalized_email if _is_real_billing_owner(normalized_email) else ""
        if _looks_like_generic_platform_auth(normalized_org_id):
            return normalized_email if _is_real_billing_owner(normalized_email) else ""
        if not _is_real_billing_owner(normalized_org_id):
            return normalized_email if _is_real_billing_owner(normalized_email) else ""
        return f"ic_org_{normalized_org_id}"

    if not _is_real_billing_owner(normalized_email):
        return ""
    return normalized_email


def resolve_authenticated_billing_owner(auth_ctx: Any) -> str | None:
    """Resolve the billing owner from verified authentication context only."""
    if auth_ctx is None or getattr(auth_ctx, "authenticated", True) is False:
        return None

    metadata = getattr(auth_ctx, "metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}

    metadata_owner = str(metadata.get("owner_key") or "").strip()
    if metadata_owner:
        resolved_owner = resolve_billing_owner(auth_ctx, metadata_owner)
        if resolved_owner:
            return resolved_owner

    buyer_email = str(metadata.get("email") or getattr(auth_ctx, "email", "") or "").strip()
    if not buyer_email:
        principal_id = str(getattr(auth_ctx, "principal_id", "") or "").strip()
        if "@" in principal_id:
            buyer_email = principal_id

    resolved_owner = resolve_billing_owner(auth_ctx, buyer_email)
    return resolved_owner or None


PlanCode = Literal["starter-5k", "team-25k", "enterprise-60k"]


class PlanDefinition(TypedDict):
    code: PlanCode
    package_id: str
    aliases: tuple[str, ...]
    name: str
    unit_limit: int
    price_usd: int
    tokens_per_unit: int
    description: str
    featured: bool


PLAN_DEFINITIONS: Final[dict[PlanCode, PlanDefinition]] = {
    "starter-5k": {
        "code": "starter-5k",
        "package_id": "pkg_5000",
        "aliases": ("pkg5000", "starter"),
        "name": "Starter",
        "unit_limit": BILLING_TIER_5K_UNITS,
        "price_usd": BILLING_TIER_5K_PRICE_USD,
        "tokens_per_unit": TOKENS_PER_UNIT,
        "description": "Prepaid protection units for individual builders who want guarded prompt handling, tool-call review, source inspection, and safe response release.",
        "featured": False,
    },
    "team-25k": {
        "code": "team-25k",
        "package_id": "pkg_25000",
        "aliases": ("pkg25000", "team"),
        "name": "Team",
        "unit_limit": BILLING_TIER_25K_UNITS,
        "price_usd": BILLING_TIER_25K_PRICE_USD,
        "tokens_per_unit": TOKENS_PER_UNIT,
        "description": "Prepaid protection units for teams running higher volumes of AI-assisted development, research, and guarded agent workflows.",
        "featured": True,
    },
    "enterprise-60k": {
        "code": "enterprise-60k",
        "package_id": "pkg_60000",
        "aliases": ("pkg60000", "enterprise"),
        "name": "Enterprise",
        "unit_limit": BILLING_TIER_60K_UNITS,
        "price_usd": BILLING_TIER_60K_PRICE_USD,
        "tokens_per_unit": TOKENS_PER_UNIT,
        "description": "Prepaid protection units for organizations protecting large-scale agent operations, sensitive workflows, and high-frequency prompt activity.",
        "featured": False,
    },
}


def _build_plan_code_by_alias() -> dict[str, PlanCode]:
    aliases: dict[str, PlanCode] = {}
    for code, plan in PLAN_DEFINITIONS.items():
        for alias in (code, plan["package_id"], *plan["aliases"]):
            normalized = alias.strip().casefold()
            if normalized in aliases:
                raise ValueError(f"Duplicate billing package alias: {alias!r}")
            aliases[normalized] = code
    return aliases


_PLAN_CODE_BY_ALIAS: Final[dict[str, PlanCode]] = _build_plan_code_by_alias()
PACKAGE_ALIASES: Final[frozenset[str]] = frozenset(_PLAN_CODE_BY_ALIAS)


def resolve_plan_code(package_id: str) -> PlanCode | None:
    return _PLAN_CODE_BY_ALIAS.get(package_id.strip().casefold())


def resolve_package_id(package_id: str) -> str | None:
    plan_code = resolve_plan_code(package_id)
    if plan_code is None:
        return None
    return PLAN_DEFINITIONS[plan_code]["package_id"]


# ---------------------------------------------------------------------------
# Unit package catalog — ordered list used by purchase and UI surfaces.
# Entries are derived from PLAN_DEFINITIONS to keep package identifiers,
# pricing, unit amounts, and token coverage in one place.
# ---------------------------------------------------------------------------


class UnitPackageEntry(TypedDict):
    code: PlanCode
    package_id: str
    aliases: tuple[str, ...]
    name: str
    units: int
    price_usd: int
    tokens_per_unit: int
    token_coverage: int
    display_label: str
    description: str
    featured: bool


# Keep private alias for backward compat with any internal reference.
_UnitPackageEntry = UnitPackageEntry


def _build_unit_package_catalog() -> list[UnitPackageEntry]:
    catalog: list[UnitPackageEntry] = []
    for plan in PLAN_DEFINITIONS.values():
        units = plan["unit_limit"]
        price_usd = plan["price_usd"]
        tokens_per_unit = plan["tokens_per_unit"]
        catalog.append(
            {
                "code": plan["code"],
                "package_id": plan["package_id"],
                "aliases": plan["aliases"],
                "name": plan["name"],
                "units": units,
                "price_usd": price_usd,
                "tokens_per_unit": tokens_per_unit,
                "token_coverage": units * tokens_per_unit,
                "display_label": f"{units:,} units — ${price_usd:.2f}",
                "description": plan["description"],
                "featured": plan["featured"],
            },
        )
    return catalog


UNIT_PACKAGE_CATALOG: Final[list[UnitPackageEntry]] = _build_unit_package_catalog()
UNIT_PACKAGE_IDS: Final[tuple[str, ...]] = tuple(entry["package_id"] for entry in UNIT_PACKAGE_CATALOG)

_featured_package_ids = [entry["package_id"] for entry in UNIT_PACKAGE_CATALOG if entry["featured"]]
if len(_featured_package_ids) != 1:
    raise ValueError("Exactly one billing package must be featured")
FEATURED_PACKAGE_ID: Final[str] = _featured_package_ids[0]
del _featured_package_ids


_CUSTOMERS_TABLE = "billing_customers"
_SUBSCRIPTIONS_TABLE = "billing_subscriptions"


class BillingUsageError(Exception):
    """Raised when a usage record operation is rejected."""

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
        """Retained for DB introspection only. Not used to gate consumption."""
        now = datetime.now(UTC)
        return self.current_period_start <= now <= self.current_period_end

    @property
    def is_active(self) -> bool:
        """Units do not expire. Active is determined by status and remaining units only."""
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
    """Billing foundation for IronClaw agentic systems."""

    def __init__(
        self,
        *,
        store: StoreType | None = None,
        install_key_registry: Any | None = None,
    ) -> None:
        self._lock = Lock()
        self._store: StoreType = store if store is not None else build_store()
        self._customers: dict[str, BillingCustomer] = {}
        self._subscriptions: dict[str, BillingSubscription] = {}
        self._customer_sub_index: dict[str, list[str]] = {}
        self._loaded = False
        self._install_key_registry = install_key_registry

    def _get_install_key_registry(self) -> Any:
        if self._install_key_registry is not None:
            return self._install_key_registry
        from app.core.install_keys import get_install_key_registry  # local import to avoid circular

        return get_install_key_registry()

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
            resolved_period_end = period_end if period_end is not None else now + timedelta(days=_DEFAULT_PERIOD_DAYS)
            subscription = BillingSubscription(
                subscription_id=subscription_id,
                customer_id=customer_id,
                plan=plan_code,
                status=status,
                created_at=now,
                current_period_start=now,
                current_period_end=resolved_period_end,
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

    def _resolve_customer_for_owner_key(self, owner_key: str) -> BillingCustomer | None:
        normalized = _normalize_owner_value(owner_key)
        if not normalized or not _is_real_billing_owner(normalized):
            return None

        for customer in self._customers.values():
            if customer.customer_id and customer.customer_id.lower() == normalized:
                return customer
            if customer.email and customer.email.lower() == normalized:
                return customer

            metadata = customer.metadata or {}
            org_id = metadata.get("org_id") or metadata.get("organization_id") or metadata.get("customer_org_id")
            if org_id is not None:
                candidate = f"ic_org_{str(org_id).strip().lower()}"
                if candidate == normalized:
                    return customer

            if str(customer.customer_id).lower().startswith("ic_org_") and customer.customer_id.lower() == normalized:
                return customer

        return None

    def get_active_subscription_for_customer(
        self,
        owner_key: str,
    ) -> BillingSubscription | None:
        """Return the first active subscription for the canonical owner key.

        The caller passes the same owner_key used by resolve_billing_owner, which may
        be either a normalized email or an org wallet key like ic_org_{org_id}. This
        lookup must resolve through the customer record itself, not only a direct
        customer_id match.
        """
        with self._lock:
            self._ensure_loaded()
            customer = self._resolve_customer_for_owner_key(owner_key)
            if customer is None:
                return None
            return self._get_active_subscription_unlocked(customer.customer_id)

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

    def get_unit_package_catalog(self) -> list[UnitPackageEntry]:
        return list(UNIT_PACKAGE_CATALOG)

    # ---------------------------------------------------------------------------
    # has_active_subscription — gates install key generation
    # ---------------------------------------------------------------------------

    def has_active_subscription(self, owner_key: str) -> bool:
        """Return True only when the canonical owner has an active paid subscription.

        This is the real gate that controls install-key issuance. A customer may
        exist without a live subscription, or have a non-active subscription, but
        that must not permit paid install-key generation.
        """
        with self._lock:
            self._ensure_loaded()
            customer = self._resolve_customer_for_owner_key(owner_key)
            if customer is None or not customer.active:
                return False
            active_sub = self._get_active_subscription_unlocked(customer.customer_id)
            return active_sub is not None and active_sub.status == "active" and active_sub.remaining_units > 0

    # ---------------------------------------------------------------------------
    # provision_install_keys_on_purchase
    # ---------------------------------------------------------------------------

    def provision_install_keys_on_purchase(
        self,
        customer_id: str,
        subscription_id: str,
        owner_key: str,
    ) -> dict[str, Any]:
        """Validate purchasing ownership and entitlement before issuing install keys.

        This method is the billing-layer bridge that proves the canonical owner has
        an active subscription and then delegates actual key issuance to the
        install-key registry for the paid programs this customer is entitled to.
        """
        normalized_owner = _normalize_owner_value(owner_key)
        if not normalized_owner:
            raise ValueError("owner_key is required for billing provisioning")
        if not self.has_active_subscription(normalized_owner):
            raise ValueError(f"Cannot provision install keys: no active subscription found for owner {normalized_owner!r}")

        registry = self._get_install_key_registry()
        result: dict[str, Any] = {}
        for program in InstallKeyFormatRegistry.list_programs():
            metadata = {
                "customer_id": customer_id,
                "provisioned_by": "billing",
                "source": "billing_purchase",
                "purchase_reference": subscription_id,
                "checkout_session_id": subscription_id,
                "payment_status": "paid",
                "entitlements_status": "active",
                "issued_after_payment": True,
            }

            if hasattr(registry, "generate_for_paid_customer"):
                record = registry.generate_for_paid_customer(
                    normalized_owner,
                    subscription_id,
                    program,
                    customer_id=customer_id,
                    payment_status="paid",
                    entitlements_status="active",
                    issued_after_payment=True,
                    purchase_reference=subscription_id,
                    checkout_session_id=subscription_id,
                    label="auto-provisioned",
                    metadata=metadata,
                )
            elif hasattr(registry, "generate_install_key"):
                record = registry.generate_install_key(
                    normalized_owner,
                    subscription_id,
                    program,
                    label="auto-provisioned",
                    metadata=metadata,
                )
            else:
                raise AttributeError("Install key registry must expose generate_for_paid_customer() or generate_install_key().")
            result[program] = record

        logger.info(
            "billing_provisioning_gate_passed",
            extra={
                "customer_id": customer_id,
                "subscription_id": subscription_id,
                "owner_key": normalized_owner,
                "has_active_subscription": True,
                "programs": list(result),
            },
        )

        return result


_billing_registry: BillingRegistry | None = None
_billing_registry_lock = Lock()


def get_billing_registry() -> BillingRegistry:
    global _billing_registry
    if _billing_registry is None:
        with _billing_registry_lock:
            if _billing_registry is None:
                _billing_registry = BillingRegistry()
    return _billing_registry


def get_active_subscription_for_customer(owner_key: str) -> BillingSubscription | None:
    """Module-level convenience wrapper for get_dashboard_overview and other callers.

    Delegates to the singleton BillingRegistry so callers do not need to
    instantiate the registry themselves.
    """
    return get_billing_registry().get_active_subscription_for_customer(owner_key)


def _reset_billing_registry_for_testing() -> None:
    """Reset the module-level singleton. For use in pytest fixtures only."""
    global _billing_registry
    with _billing_registry_lock:
        _billing_registry = None
