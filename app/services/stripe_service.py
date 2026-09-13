from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from dataclasses import fields as dataclass_fields
from datetime import UTC, datetime
from enum import StrEnum
import logging
import math
from threading import Lock
import time
from typing import Any
from uuid import uuid4

from app.core.install_key_formats import InstallKeyFormatRegistry
from app.core.install_keys import _read_event_ledger_record, _write_event_ledger_record
from app.core.unit_wallet import get_unit_wallet_registry
from app.services.install_key_provisioning import InstallKeyProvisioningService
from app.services.secrets_vault import vault
from app.supabaseclient import (
    BILLING_TIER_5K_PRICE_USD,
    BILLING_TIER_5K_UNITS,
    BILLING_TIER_25K_PRICE_USD,
    BILLING_TIER_25K_UNITS,
    BILLING_TIER_60K_PRICE_USD,
    BILLING_TIER_60K_UNITS,
    TOKENS_PER_UNIT,
)


def provision_install_key_service(*, billing_registry: Any | None = None) -> InstallKeyProvisioningService:
    return InstallKeyProvisioningService(billing_registry=billing_registry)


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_STRIPE_API_BASE = "https://api.stripe.com/v1"
_STRIPE_TIMEOUT_SECONDS = 15
_METERED_USAGE_BUFFER_MAX = 500
_CHECKOUT_SESSION_TTL_SECONDS = 1800  # 30 min
_SCHEMA_VERSION = "1.0"
_INVOICE_CACHE_MAX = 200

# ---------------------------------------------------------------------------
# Billing tier catalogue — single source of truth imported from supabaseclient
# Starter   :  5,000 units → $20 USD
# Team      : 25,000 units → $90 USD
# Enterprise: 60,000 units → $180 USD
# Each protection unit covers up to 25,000 tokens.
# TOKENS_PER_UNIT = 25_000  (imported above)
# Scans are UNLIMITED — units auto-deduct in TOKENS_PER_UNIT chunks with no ceiling.
# ---------------------------------------------------------------------------

PACKAGE_CATALOGUE: dict[str, dict[str, Any]] = {
    "starter": {
        "label": "Starter",
        "units": BILLING_TIER_5K_UNITS,
        "price_usd": BILLING_TIER_5K_PRICE_USD,
        "tokens_per_unit": TOKENS_PER_UNIT,
        "notes": f"{BILLING_TIER_5K_UNITS:,} units · ${BILLING_TIER_5K_PRICE_USD} USD · each unit protects up to {TOKENS_PER_UNIT:,} tokens · no scan ceiling",
    },
    "team": {
        "label": "Team",
        "units": BILLING_TIER_25K_UNITS,
        "price_usd": BILLING_TIER_25K_PRICE_USD,
        "tokens_per_unit": TOKENS_PER_UNIT,
        "notes": f"{BILLING_TIER_25K_UNITS:,} units · ${BILLING_TIER_25K_PRICE_USD} USD · each unit protects up to {TOKENS_PER_UNIT:,} tokens · no scan ceiling",
    },
    "enterprise": {
        "label": "Enterprise",
        "units": BILLING_TIER_60K_UNITS,
        "price_usd": BILLING_TIER_60K_PRICE_USD,
        "tokens_per_unit": TOKENS_PER_UNIT,
        "notes": f"{BILLING_TIER_60K_UNITS:,} units · ${BILLING_TIER_60K_PRICE_USD} USD · each unit protects up to {TOKENS_PER_UNIT:,} tokens · no scan ceiling",
    },
}


def units_for_tokens(token_count: int) -> int:
    """
    Return the number of protection units required to cover token_count tokens.
    Each unit covers up to TOKENS_PER_UNIT (25,000) tokens.
    Partial chunks consume a full unit. No ceiling — scales to any token count.

    Examples:
        units_for_tokens(1)         → 1
        units_for_tokens(25_000)    → 1
        units_for_tokens(25_001)    → 2
        units_for_tokens(75_000)    → 3
        units_for_tokens(1_000_000) → 40
    """
    if token_count <= 0:
        return 0
    return math.ceil(token_count / TOKENS_PER_UNIT)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class StripeCheckoutMode(StrEnum):
    PAYMENT = "payment"
    SUBSCRIPTION = "subscription"
    SETUP = "setup"


class StripeBillingInterval(StrEnum):
    MONTHLY = "month"
    ANNUAL = "year"
    WEEKLY = "week"
    DAILY = "day"


class StripeSubscriptionStatus(StrEnum):
    ACTIVE = "active"
    TRIALING = "trialing"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    INCOMPLETE = "incomplete"
    INCOMPLETE_EXPIRED = "incomplete_expired"
    PAUSED = "paused"
    UNPAID = "unpaid"


class StripeUnitEventReason(StrEnum):
    CHECKOUT_COMPLETE = "checkout.complete"
    SUBSCRIPTION_RENEWED = "subscription.renewed"
    MANUAL_CREDIT = "manual.credit"
    METERED_SYNC = "metered.sync"
    REFUND = "refund"
    ADJUSTMENT = "adjustment"


class StripeWebhookEventType(StrEnum):
    CHECKOUT_SESSION_COMPLETED = "checkout.session.completed"
    CHECKOUT_SESSION_EXPIRED = "checkout.session.expired"
    CUSTOMER_SUBSCRIPTION_CREATED = "customer.subscription.created"
    CUSTOMER_SUBSCRIPTION_UPDATED = "customer.subscription.updated"
    CUSTOMER_SUBSCRIPTION_DELETED = "customer.subscription.deleted"
    INVOICE_PAID = "invoice.paid"
    INVOICE_PAYMENT_FAILED = "invoice.payment_failed"
    INVOICE_UPCOMING = "invoice.upcoming"
    CUSTOMER_CREATED = "customer.created"
    CUSTOMER_UPDATED = "customer.updated"
    CHARGE_REFUNDED = "charge.refunded"
    PAYMENT_INTENT_SUCCEEDED = "payment_intent.succeeded"
    PAYMENT_INTENT_PAYMENT_FAILED = "payment_intent.payment_failed"


# ---------------------------------------------------------------------------
# Internal dataclasses
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _CheckoutSessionRecord:
    session_id: str
    org_id: str
    customer_id: str | None
    mode: str
    price_id: str
    quantity: int
    unit_credits: int
    success_url: str
    cancel_url: str
    metadata: dict[str, Any]
    status: str
    created_at: str
    expires_at: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "org_id": self.org_id,
            "customer_id": self.customer_id,
            "mode": self.mode,
            "price_id": self.price_id,
            "quantity": self.quantity,
            "unit_credits": self.unit_credits,
            "status": self.status,
            "success_url": self.success_url,
            "cancel_url": self.cancel_url,
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }


@dataclass(slots=True)
class _SubscriptionRecord:
    subscription_id: str
    org_id: str
    customer_id: str
    price_id: str
    status: str
    billing_interval: str
    current_period_start: str
    current_period_end: str
    cancel_at_period_end: bool
    metered_price_id: str | None
    metadata: dict[str, Any]
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "subscription_id": self.subscription_id,
            "org_id": self.org_id,
            "customer_id": self.customer_id,
            "price_id": self.price_id,
            "status": self.status,
            "billing_interval": self.billing_interval,
            "current_period_start": self.current_period_start,
            "current_period_end": self.current_period_end,
            "cancel_at_period_end": self.cancel_at_period_end,
            "metered_price_id": self.metered_price_id,
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(slots=True)
class _MeteredUsageEntry:
    entry_id: str
    org_id: str
    subscription_id: str
    quantity: int
    action: str  # "increment" | "set"
    idempotency_key: str
    synced_at: str
    stripe_usage_record_id: str | None
    error: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "org_id": self.org_id,
            "subscription_id": self.subscription_id,
            "quantity": self.quantity,
            "action": self.action,
            "idempotency_key": self.idempotency_key,
            "synced_at": self.synced_at,
            "stripe_usage_record_id": self.stripe_usage_record_id,
            "error": self.error,
        }


@dataclass(slots=True)
class _UnitLedgerEntry:
    entry_id: str
    org_id: str
    delta: int
    reason: str
    reference_id: str | None
    balance_after: int
    recorded_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "org_id": self.org_id,
            "delta": self.delta,
            "reason": self.reason,
            "reference_id": self.reference_id,
            "balance_after": self.balance_after,
            "recorded_at": self.recorded_at,
        }


@dataclass(slots=True)
class _PaymentMethodRecord:
    """Internal record for a stored Stripe payment method."""

    payment_method_id: str
    customer_id: str
    type: str
    brand: str
    last4: str
    exp_month: int
    exp_year: int
    is_default: bool
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "payment_method_id": self.payment_method_id,
            "customer_id": self.customer_id,
            "type": self.type,
            "brand": self.brand,
            "last4": self.last4,
            "exp_month": self.exp_month,
            "exp_year": self.exp_year,
            "is_default": self.is_default,
            "created_at": self.created_at,
        }


# ---------------------------------------------------------------------------
# Public response shapes
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class CheckoutSessionResponse:
    session_id: str
    checkout_url: str
    org_id: str
    mode: str
    price_id: str
    quantity: int
    unit_credits: int
    expires_at: str | None
    metadata: dict[str, Any]
    created_at: str
    schema_version: str = _SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "checkout_url": self.checkout_url,
            "org_id": self.org_id,
            "mode": self.mode,
            "price_id": self.price_id,
            "quantity": self.quantity,
            "unit_credits": self.unit_credits,
            "expires_at": self.expires_at,
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
            "schema_version": self.schema_version,
        }


@dataclass(slots=True)
class SubscriptionResponse:
    subscription_id: str
    org_id: str
    customer_id: str
    price_id: str
    status: str
    billing_interval: str
    current_period_start: str
    current_period_end: str
    cancel_at_period_end: bool
    metered_price_id: str | None
    metadata: dict[str, Any]
    created_at: str
    updated_at: str
    schema_version: str = _SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "subscription_id": self.subscription_id,
            "org_id": self.org_id,
            "customer_id": self.customer_id,
            "price_id": self.price_id,
            "status": self.status,
            "billing_interval": self.billing_interval,
            "current_period_start": self.current_period_start,
            "current_period_end": self.current_period_end,
            "cancel_at_period_end": self.cancel_at_period_end,
            "metered_price_id": self.metered_price_id,
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "schema_version": self.schema_version,
        }


@dataclass(slots=True)
class MeteredSyncResponse:
    org_id: str
    subscription_id: str
    quantity: int
    action: str
    idempotency_key: str
    stripe_usage_record_id: str | None
    success: bool
    error: str | None
    synced_at: str
    schema_version: str = _SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "org_id": self.org_id,
            "subscription_id": self.subscription_id,
            "quantity": self.quantity,
            "action": self.action,
            "idempotency_key": self.idempotency_key,
            "stripe_usage_record_id": self.stripe_usage_record_id,
            "success": self.success,
            "error": self.error,
            "synced_at": self.synced_at,
            "schema_version": self.schema_version,
        }


@dataclass(slots=True)
class UnitBalanceResponse:
    org_id: str
    balance: int
    ledger_entries: list[dict[str, Any]]
    schema_version: str = _SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "org_id": self.org_id,
            "balance": self.balance,
            "ledger_entries": list(self.ledger_entries),
            "schema_version": self.schema_version,
        }


@dataclass(slots=True)
class WebhookVerifyResult:
    valid: bool
    event_type: str | None
    event_id: str | None
    error: str | None
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "event_type": self.event_type,
            "event_id": self.event_id,
            "error": self.error,
            "payload": dict(self.payload),
        }


@dataclass(slots=True)
class PaymentMethodResponse:
    """Public response shape for a stored payment method."""

    payment_method_id: str
    customer_id: str
    type: str
    brand: str
    last4: str
    exp_month: int
    exp_year: int
    is_default: bool
    created_at: str
    schema_version: str = _SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "payment_method_id": self.payment_method_id,
            "customer_id": self.customer_id,
            "type": self.type,
            "brand": self.brand,
            "last4": self.last4,
            "exp_month": self.exp_month,
            "exp_year": self.exp_year,
            "is_default": self.is_default,
            "created_at": self.created_at,
            "schema_version": self.schema_version,
        }


@dataclass(slots=True)
class InvoiceResponse:
    """Public response shape for a Stripe invoice record."""

    invoice_id: str
    org_id: str
    customer_id: str
    subscription_id: str | None
    amount_paid: int
    currency: str
    status: str
    created_at: str
    invoice_pdf: str | None = None
    hosted_invoice_url: str | None = None
    schema_version: str = _SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "invoice_id": self.invoice_id,
            "org_id": self.org_id,
            "customer_id": self.customer_id,
            "subscription_id": self.subscription_id,
            "amount_paid": self.amount_paid,
            "currency": self.currency,
            "status": self.status,
            "invoice_pdf": self.invoice_pdf,
            "hosted_invoice_url": self.hosted_invoice_url,
            "created_at": self.created_at,
            "schema_version": self.schema_version,
        }


# ---------------------------------------------------------------------------
# Internal HTTP transport (stdlib only — no stripe SDK import required)
# ---------------------------------------------------------------------------


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:16]}"


def _filter_to_dataclass_fields(dc_cls: type, raw: dict[str, Any]) -> dict[str, Any]:
    known = {f.name for f in dataclass_fields(dc_cls)}
    return {k: v for k, v in raw.items() if k in known}


def _normalize_stripe_invoice(raw: dict[str, Any], org_id: str, customer_id: str) -> dict[str, Any]:
    """
    Normalize a raw Stripe-shaped invoice dict (keys: id, customer, subscription,
    created, amount_paid, currency, status, invoice_pdf, hosted_invoice_url) into
    the InvoiceResponse field layout.  Safe to call on already-normalized dicts —
    if invoice_id is already present it is preserved.
    """
    if "invoice_id" in raw:
        return raw

    created_ts = raw.get("created", 0)
    try:
        created_iso = datetime.fromtimestamp(int(created_ts), tz=UTC).isoformat().replace("+00:00", "Z")
    except (ValueError, TypeError):
        created_iso = _utcnow_iso()

    return {
        "invoice_id": raw.get("id", ""),
        "org_id": org_id,
        "customer_id": raw.get("customer", customer_id),
        "subscription_id": raw.get("subscription"),
        "amount_paid": int(raw.get("amount_paid", 0)),
        "currency": raw.get("currency", "usd"),
        "status": raw.get("status", "unknown"),
        "invoice_pdf": raw.get("invoice_pdf"),
        "hosted_invoice_url": raw.get("hosted_invoice_url"),
        "created_at": created_iso,
        "schema_version": _SCHEMA_VERSION,
    }


class _StripeHTTPClient:
    """
    Minimal Stripe REST client using only stdlib urllib.
    Handles authentication, idempotency keys, and response parsing.
    No third-party stripe SDK dependency required.
    """

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def _headers(self, idempotency_key: str | None = None) -> dict[str, str]:
        import base64

        token = base64.b64encode(f"{self._api_key}:".encode()).decode()
        headers: dict[str, str] = {
            "Authorization": f"Basic {token}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Stripe-Version": "2024-04-10",
            "User-Agent": "IronClaw-Security/1.0",
        }
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        return headers

    def _encode_params(self, params: dict[str, Any]) -> bytes:
        from urllib.parse import urlencode

        flat: dict[str, str] = {}

        def _flatten(obj: Any, prefix: str = "") -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    _flatten(v, f"{prefix}[{k}]" if prefix else k)
            elif isinstance(obj, (list, tuple)):
                for i, v in enumerate(obj):
                    _flatten(v, f"{prefix}[{i}]")
            else:
                flat[prefix] = str(obj)

        _flatten(params)
        return urlencode(flat).encode("utf-8")

    def post(
        self,
        path: str,
        params: dict[str, Any],
        *,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        import json
        import urllib.error
        import urllib.request

        url = f"{_STRIPE_API_BASE}{path}"
        body = self._encode_params(params)
        req = urllib.request.Request(
            url,
            data=body,
            headers=self._headers(idempotency_key),
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=_STRIPE_TIMEOUT_SECONDS) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            try:
                err_body: dict[str, Any] = json.loads(raw)
            except Exception:  # noqa: BLE001
                err_body = {"raw": raw}
            raise StripeAPIError(
                message=err_body.get("error", {}).get("message", raw),
                http_status=exc.code,
                stripe_code=err_body.get("error", {}).get("code"),
                raw=err_body,
            ) from exc

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        import json
        import urllib.error
        from urllib.parse import urlencode
        import urllib.request

        url = f"{_STRIPE_API_BASE}{path}"
        if params:
            url = f"{url}?{urlencode(params)}"
        req = urllib.request.Request(url, headers=self._headers(), method="GET")
        try:
            with urllib.request.urlopen(req, timeout=_STRIPE_TIMEOUT_SECONDS) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            try:
                err_body: dict[str, Any] = json.loads(raw)
            except Exception:  # noqa: BLE001
                err_body = {"raw": raw}
            raise StripeAPIError(
                message=err_body.get("error", {}).get("message", raw),
                http_status=exc.code,
                stripe_code=err_body.get("error", {}).get("code"),
                raw=err_body,
            ) from exc

    def delete(self, path: str) -> dict[str, Any]:
        import json
        import urllib.error
        import urllib.request

        url = f"{_STRIPE_API_BASE}{path}"
        req = urllib.request.Request(url, headers=self._headers(), method="DELETE")
        try:
            with urllib.request.urlopen(req, timeout=_STRIPE_TIMEOUT_SECONDS) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            try:
                err_body: dict[str, Any] = json.loads(raw)
            except Exception:  # noqa: BLE001
                err_body = {"raw": raw}
            raise StripeAPIError(
                message=err_body.get("error", {}).get("message", raw),
                http_status=exc.code,
                stripe_code=err_body.get("error", {}).get("code"),
                raw=err_body,
            ) from exc


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class StripeServiceError(Exception):
    """Base for all StripeService errors."""


class StripeAPIError(StripeServiceError):
    """Wraps a Stripe HTTP API error."""

    def __init__(
        self,
        message: str,
        http_status: int = 0,
        stripe_code: str | None = None,
        raw: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.http_status = http_status
        self.stripe_code = stripe_code
        self.raw = raw or {}


class StripeConfigError(StripeServiceError):
    """Raised when required Stripe configuration is missing."""


class StripeWebhookSignatureError(StripeServiceError):
    """Raised when Stripe webhook signature verification fails."""


class StripeSessionNotFoundError(StripeServiceError):
    """Raised when a checkout session is not found."""


class StripeSubscriptionNotFoundError(StripeServiceError):
    """Raised when a subscription is not found."""

    def __init__(self, subscription_id: str) -> None:
        super().__init__(f"subscription not found: {subscription_id}")
        self.subscription_id = subscription_id


class StripeInsufficientUnitsError(StripeServiceError):
    """
    Raised when an org has insufficient unit balance for a debit.
    Callers may catch this to trigger an auto-purchase / top-up flow
    rather than hard-failing the scan. Scans themselves have no ceiling —
    units must simply be available (or topped up) before the debit.
    """

    def __init__(self, org_id: str, have: int, need: int) -> None:
        super().__init__(f"insufficient unit balance for org={org_id}: have={have} need={need}")
        self.org_id = org_id
        self.have = have
        self.need = need


class StripePaymentMethodNotFoundError(StripeServiceError):
    """Raised when a payment method is not found for the given ID or customer."""

    def __init__(self, payment_method_id: str) -> None:
        super().__init__(f"payment method not found: {payment_method_id}")
        self.payment_method_id = payment_method_id


class StripeIdempotencyError(StripeServiceError):
    """
    Raised when an idempotency key conflict is detected — a duplicate request
    with the same key but a different payload was submitted.
    """

    def __init__(self, idempotency_key: str, detail: str = "") -> None:
        super().__init__(f"idempotency key conflict for key={idempotency_key}" + (f": {detail}" if detail else ""))
        self.idempotency_key = idempotency_key


# ---------------------------------------------------------------------------
# StripeService
# ---------------------------------------------------------------------------


class StripeService:
    """
    IronClaw Payments / Billing integration layer.

    Responsibilities:
    - Create and track Stripe Checkout sessions (one-time payment + subscription).
    - Fulfill unit credits to org wallets after successful checkout.
    - Maintain in-memory subscription registry (synced from Stripe webhook events).
    - Report and sync metered usage (API calls, guard evaluations) to Stripe.
    - Verify and dispatch incoming Stripe webhook events with event-level idempotency.
    - Provide per-org unit balance ledger.
    - Attach, detach, list, and set-default payment methods per customer.
    - Cache and invalidate per-org invoice lists.
    - Thread-safe in-memory state with full reset for test isolation.

    Unit model:
    - Each protection unit covers up to TOKENS_PER_UNIT (25,000) tokens.
    - Scans are UNLIMITED — units auto-deduct in 25,000-token chunks with no ceiling.
    - Packages: Starter 5,000 units/$20 · Team 25,000 units/$90 · Enterprise 60,000 units/$180.
    - Use units_for_tokens(n) to convert a raw token count to required unit debit.
    - StripeInsufficientUnitsError is raised (not a generic error) so callers can
      trigger auto-purchase flows instead of hard-failing.

    All network calls are isolated through _StripeHTTPClient so they can be
    patched in tests without monkey-patching urllib directly.
    """

    def __init__(
        self,
        *,
        webhook_secret: str | None = None,
        on_insufficient_units: Callable[[str, int, int], None] | None = None,
    ) -> None:
        """
        Args:
            webhook_secret: Optional webhook secret override. When provided,
                verify_webhook_signature uses this value directly instead of
                reading from vault. Intended for test injection / stubbing.
            on_insufficient_units: Optional callback invoked when a debit would
                exceed the org's balance. Signature: (org_id, have, need) -> None.
                Useful for triggering auto-purchase / alerting pipelines without
                coupling billing logic to the calling layer.
        """
        self._lock = Lock()
        self._checkout_sessions: dict[str, _CheckoutSessionRecord] = {}
        self._subscriptions: dict[str, _SubscriptionRecord] = {}
        self._unit_balances: dict[str, int] = {}
        self._unit_ledger: dict[str, list[_UnitLedgerEntry]] = {}
        self._metered_usage_log: list[_MeteredUsageEntry] = []
        self._org_customer_map: dict[str, str] = {}
        self._customer_org_map: dict[str, str] = {}
        self._payment_methods: dict[str, _PaymentMethodRecord] = {}
        self._invoice_cache: dict[str, list[dict[str, Any]]] = {}
        self._idempotency_keys: dict[str, Any] = {}
        self._processed_event_ids: set[str] = set()
        self._wallet_registry = get_unit_wallet_registry()
        self._client: _StripeHTTPClient | None = None
        self._on_insufficient_units = on_insufficient_units
        # Injected webhook secret — takes precedence over vault when set.
        self._webhook_secret_override: str | None = webhook_secret

    @staticmethod
    def _canonical_org_owner_key(org_id: str) -> str:
        normalized = str(org_id).strip().lower()
        if not normalized:
            raise ValueError("org_id is required")
        if normalized.startswith("ic_org_"):
            return normalized
        return f"ic_org_{normalized}"

    def _sync_balances_from_wallet(self, org_id: str) -> UnitBalanceResponse:
        owner_key = self._canonical_org_owner_key(org_id)
        wallet = self._wallet_registry.get_wallet(owner_key)
        if wallet is None:
            with self._lock:
                self._unit_balances[org_id] = 0
                self._unit_ledger.setdefault(org_id, [])
            return UnitBalanceResponse(org_id=org_id, balance=0, ledger_entries=[])

        entries = self._wallet_registry.list_ledger_entries(owner_key=owner_key, limit=50)
        response_entries = []
        for entry in entries:
            response_entries.append(
                {
                    "entry_id": entry.entry_id,
                    "org_id": org_id,
                    "delta": int(entry.units) if entry.entry_type in {"credit", "refund"} else -int(entry.units),
                    "reason": str((entry.metadata or {}).get("stripe_reason") or entry.entry_type),
                    "reference_id": (entry.metadata or {}).get("reference_id"),
                    "balance_after": int(entry.balance_after),
                    "recorded_at": entry.created_at.isoformat().replace("+00:00", "Z"),
                }
            )

        with self._lock:
            self._unit_balances[org_id] = wallet.balance_units
            self._unit_ledger[org_id] = [
                _UnitLedgerEntry(
                    entry_id=e["entry_id"],
                    org_id=org_id,
                    delta=e["delta"],
                    reason=e["reason"],
                    reference_id=e["reference_id"],
                    balance_after=e["balance_after"],
                    recorded_at=e["recorded_at"],
                )
                for e in response_entries
            ]

        return UnitBalanceResponse(org_id=org_id, balance=wallet.balance_units, ledger_entries=response_entries)

    def _has_processed_event(self, event_id: str | None, *, purchase_reference: str | None = None, checkout_session_id: str | None = None) -> bool:
        if not event_id and not purchase_reference and not checkout_session_id:
            return False
        with self._lock:
            if event_id and event_id in self._processed_event_ids:
                return True
        if event_id:
            record = _read_event_ledger_record(event_id=event_id)
            if record:
                return True
        if purchase_reference:
            record = _read_event_ledger_record(purchase_reference=purchase_reference)
            if record:
                return True
        if checkout_session_id:
            record = _read_event_ledger_record(checkout_session_id=checkout_session_id)
            if record:
                return True
        return False

    def _mark_processed_event(
        self,
        *,
        event_id: str,
        event_type: str,
        purchase_reference: str | None = None,
        checkout_session_id: str | None = None,
        owner_key: str | None = None,
        customer_id: str | None = None,
        program: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        with self._lock:
            self._processed_event_ids.add(event_id)
        event_payload = payload or {}
        _write_event_ledger_record(
            event_id=event_id,
            event_type=event_type,
            purchase_reference=purchase_reference,
            checkout_session_id=checkout_session_id,
            owner_key=owner_key,
            customer_id=customer_id,
            program=program,
            payload=event_payload,
        )

    # ------------------------------------------------------------------
    # Config / client
    # ------------------------------------------------------------------

    def _get_api_key(self) -> str:
        key = vault.get("STRIPE_SECRET_KEY") or ""
        if not key:
            raise StripeConfigError("STRIPE_SECRET_KEY is not configured.")
        return key

    def _get_webhook_secret(self, *, override: str | None = None) -> str:
        """
        Return the webhook secret.

        Resolution order (first non-empty wins):
          1. ``override`` parameter (call-site injection — highest priority).
          2. ``self._webhook_secret_override`` (constructor injection — for test stubs).
          3. vault.get(\"STRIPE_WEBHOOK_SECRET\") read at call time (production path).

        Raises StripeConfigError when no source yields a non-empty value.
        """
        secret = override or self._webhook_secret_override or vault.get("STRIPE_WEBHOOK_SECRET") or ""
        if not secret:
            raise StripeConfigError("STRIPE_WEBHOOK_SECRET is not configured.")
        return secret

    def set_webhook_secret(self, secret: str) -> None:
        """
        Inject or replace the webhook secret at runtime without reconstructing
        the service. Intended for test isolation and runtime vault hot-reload.
        """
        self._webhook_secret_override = secret

    def _get_client(self) -> _StripeHTTPClient:
        if self._client is None:
            self._client = _StripeHTTPClient(self._get_api_key())
        return self._client

    def _override_client(self, client: _StripeHTTPClient) -> None:
        """Inject a mock client. Intended for test use only."""
        self._client = client

    # ------------------------------------------------------------------
    # Customer management
    # ------------------------------------------------------------------

    def get_or_create_stripe_customer(
        self,
        org_id: str,
        email: str | None = None,
        name: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """
        Return existing Stripe customer_id for org_id, or create a new one.
        Thread-safe; creates only once per org.
        """
        with self._lock:
            existing = self._org_customer_map.get(org_id)
        if existing:
            return existing

        params: dict[str, Any] = {
            "metadata[org_id]": org_id,
            "metadata[ironclaw_source]": "ironclaw-security",
        }
        if email:
            params["email"] = email
        if name:
            params["name"] = name
        if metadata:
            for k, v in metadata.items():
                params[f"metadata[{k}]"] = str(v)

        resp = self._get_client().post("/customers", params)
        customer_id: str = resp["id"]

        with self._lock:
            self._org_customer_map[org_id] = customer_id
            self._customer_org_map[customer_id] = org_id

        logger.info("stripe.customer_created org=%s customer=%s", org_id, customer_id)
        return customer_id

    def register_customer_mapping(self, org_id: str, customer_id: str) -> None:
        """
        Register an existing Stripe customer_id → org_id mapping.
        Used when the mapping is supplied from a webhook event rather than
        an in-process customer creation.
        """
        with self._lock:
            self._org_customer_map[org_id] = customer_id
            self._customer_org_map[customer_id] = org_id

    @staticmethod
    def _is_successful_payment_status(value: Any) -> bool:
        normalized = str(value).strip().lower() if value is not None else ""
        return normalized in {"paid", "succeeded", "success", "complete", "completed", "active"}

    def _resolve_owner_key_for_org(self, org_id: str) -> str:
        normalized = str(org_id).strip().lower()
        if not normalized:
            raise ValueError("org_id is required to resolve an owner key")
        return f"ic_org_{normalized}"

    def _issue_paid_install_keys_for_checkout(
        self,
        *,
        org_id: str,
        customer_id: str | None,
        session_id: str,
        unit_credits: int,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Issue the paid install-key entitlement only after a successful payment confirmation.

        This helper is intentionally narrow: it blocks unconfirmed / failed Stripe
        payment states, while broader entitlement validation is enforced by the
        webhook orchestration layer before it calls into this method.
        """
        payment_status = (metadata or {}).get("payment_status")
        if payment_status is None or not self._is_successful_payment_status(payment_status):
            logger.info(
                "stripe.checkout_install_keys_skipped org=%s session=%s reason=payment_status_not_confirmed payment_status=%s",
                org_id,
                session_id,
                payment_status,
            )
            return {}

        owner_key = self._resolve_owner_key_for_org(org_id)

        class _CheckoutEntitlementGuard:
            def has_active_subscription(self, candidate_owner_key: str) -> bool:
                normalized = str(candidate_owner_key).strip().lower()
                return normalized == owner_key.lower()

        provisioning_service = provision_install_key_service(
            billing_registry=_CheckoutEntitlementGuard(),
        )
        results: dict[str, dict[str, Any]] = {}
        base_metadata: dict[str, Any] = {
            "source": "stripe.checkout",
            "org_id": org_id,
            "customer_id": customer_id,
            "unit_credits": unit_credits,
            "checkout_session_id": session_id,
            "purchase_reference": session_id,
            "payment_status": "paid",
            "entitlements_status": "active",
            "issued_after_payment": True,
        }
        if metadata:
            base_metadata.update(metadata)

        supported_programs = tuple(InstallKeyFormatRegistry.list_programs())

        for program in supported_programs:
            issued = provisioning_service.provision_for_program(
                owner_key=owner_key,
                subscription_id=f"checkout:{session_id}",
                program=program,
                source="stripe.checkout",
                label=f"stripe-checkout:{session_id}",
                metadata={**base_metadata, "program": program},
                payment_status="paid",
                entitlements_status="active",
                issued_after_payment=True,
                checkout_session_id=session_id,
                purchase_reference=session_id,
                customer_id=customer_id,
                org_id=org_id,
                payment_confirmed=True,
            )
            record = issued.record
            results[program] = {
                "key_id": record.key_id,
                "owner_key": record.owner_key,
                "program": record.program,
                "active": record.active,
                "masked_key": record.masked_key,
                "subscription_id": record.subscription_id,
            }

        return results

    def resolve_org_from_customer(self, customer_id: str) -> str | None:
        with self._lock:
            return self._customer_org_map.get(customer_id)

    def resolve_customer_id(self, org_id: str) -> str | None:
        with self._lock:
            return self._org_customer_map.get(org_id)

    # ------------------------------------------------------------------
    # Payment methods
    # ------------------------------------------------------------------

    def attach_payment_method(
        self,
        customer_id: str,
        payment_method_id: str,
        *,
        set_as_default: bool = False,
    ) -> PaymentMethodResponse:
        """
        Attach a Stripe payment method to a customer via the API and cache locally.
        Optionally set as the customer's default payment method.
        Raises StripeIdempotencyError if the key is already registered with a
        different payload. Raises StripeAPIError on Stripe network failures.
        """
        idem_key = f"attach-pm-{customer_id}-{payment_method_id}"
        with self._lock:
            if idem_key in self._idempotency_keys:
                existing_pm_id = self._idempotency_keys[idem_key]
                if existing_pm_id != payment_method_id:
                    raise StripeIdempotencyError(idem_key, "conflicting payment_method_id")
                record = self._payment_methods.get(payment_method_id)
                if record:
                    return PaymentMethodResponse(**record.to_dict(), schema_version=_SCHEMA_VERSION)

        resp = self._get_client().post(
            f"/payment_methods/{payment_method_id}/attach",
            {"customer": customer_id},
        )

        card = resp.get("card", {})
        now = _utcnow_iso()
        record = _PaymentMethodRecord(
            payment_method_id=resp.get("id", payment_method_id),
            customer_id=customer_id,
            type=resp.get("type", "card"),
            brand=card.get("brand", "unknown"),
            last4=card.get("last4", "0000"),
            exp_month=int(card.get("exp_month", 0)),
            exp_year=int(card.get("exp_year", 0)),
            is_default=set_as_default,
            created_at=now,
        )

        with self._lock:
            self._payment_methods[record.payment_method_id] = record
            self._idempotency_keys[idem_key] = payment_method_id

        if set_as_default:
            self.set_default_payment_method(customer_id, record.payment_method_id)

        logger.info(
            "stripe.payment_method_attached customer=%s pm=%s default=%s",
            customer_id,
            record.payment_method_id,
            set_as_default,
        )
        return PaymentMethodResponse(**record.to_dict(), schema_version=_SCHEMA_VERSION)

    def detach_payment_method(self, payment_method_id: str) -> PaymentMethodResponse:
        """
        Detach a payment method from its customer via the Stripe API and remove
        from local cache.
        Raises StripePaymentMethodNotFoundError if not found locally.
        """
        with self._lock:
            record = self._payment_methods.get(payment_method_id)
        if record is None:
            raise StripePaymentMethodNotFoundError(payment_method_id)

        self._get_client().post(f"/payment_methods/{payment_method_id}/detach", {})

        with self._lock:
            self._payment_methods.pop(payment_method_id, None)

        logger.info("stripe.payment_method_detached pm=%s", payment_method_id)
        return PaymentMethodResponse(**record.to_dict(), schema_version=_SCHEMA_VERSION)

    def list_payment_methods(self, customer_id: str) -> list[PaymentMethodResponse]:
        """Return all locally cached payment methods for a customer."""
        with self._lock:
            records = [r for r in self._payment_methods.values() if r.customer_id == customer_id]
        return [PaymentMethodResponse(**r.to_dict(), schema_version=_SCHEMA_VERSION) for r in records]

    def set_default_payment_method(
        self,
        customer_id: str,
        payment_method_id: str,
    ) -> PaymentMethodResponse:
        """
        Set the specified payment method as the default for the customer.
        Local state is mutated first (always succeeds if pm exists); the Stripe
        network call follows and is best-effort — a StripeConfigError in test
        isolation (no API key) will not prevent the local state from being set.
        Raises StripePaymentMethodNotFoundError if the pm is not found locally.
        """
        with self._lock:
            record = self._payment_methods.get(payment_method_id)
            if record is None:
                raise StripePaymentMethodNotFoundError(payment_method_id)
            for pm_id, pm_record in self._payment_methods.items():
                if pm_record.customer_id == customer_id and pm_record.is_default:
                    updated = _PaymentMethodRecord(
                        payment_method_id=pm_record.payment_method_id,
                        customer_id=pm_record.customer_id,
                        type=pm_record.type,
                        brand=pm_record.brand,
                        last4=pm_record.last4,
                        exp_month=pm_record.exp_month,
                        exp_year=pm_record.exp_year,
                        is_default=False,
                        created_at=pm_record.created_at,
                    )
                    self._payment_methods[pm_id] = updated
            new_default = _PaymentMethodRecord(
                payment_method_id=record.payment_method_id,
                customer_id=record.customer_id,
                type=record.type,
                brand=record.brand,
                last4=record.last4,
                exp_month=record.exp_month,
                exp_year=record.exp_year,
                is_default=True,
                created_at=record.created_at,
            )
            self._payment_methods[payment_method_id] = new_default

        if self._client is not None:
            try:
                self._client.post(
                    f"/customers/{customer_id}",
                    {"invoice_settings[default_payment_method]": payment_method_id},
                )
            except Exception:  # noqa: BLE001
                logger.warning(
                    "stripe.set_default_payment_method network call failed customer=%s pm=%s",
                    customer_id,
                    payment_method_id,
                )

        logger.info("stripe.default_payment_method_set customer=%s pm=%s", customer_id, payment_method_id)
        return PaymentMethodResponse(**new_default.to_dict(), schema_version=_SCHEMA_VERSION)

    # ------------------------------------------------------------------
    # Invoices
    # ------------------------------------------------------------------

    def get_invoices_for_org(
        self,
        org_id: str,
        *,
        limit: int = 20,
        force_refresh: bool = False,
    ) -> list[InvoiceResponse]:
        """
        Return invoices for an org. Results are cached per org in _invoice_cache.
        Pass force_refresh=True to bypass the cache and re-fetch from Stripe.
        Cache entries stored as raw Stripe dicts are normalized through
        _normalize_stripe_invoice before reconstruction to guard against
        key-mapping mismatches when the cache was seeded with raw Stripe shapes.
        """
        with self._lock:
            if not force_refresh and org_id in self._invoice_cache:
                cached: list[dict[str, Any]] | None = list(self._invoice_cache[org_id])
            else:
                cached = None

        if cached is not None:
            with self._lock:
                customer_id = self._org_customer_map.get(org_id, "")
            normalized = [_normalize_stripe_invoice(r, org_id, customer_id) for r in cached]
            return [InvoiceResponse(**_filter_to_dataclass_fields(InvoiceResponse, r)) for r in normalized]

        with self._lock:
            customer_id = self._org_customer_map.get(org_id, "")
        if not customer_id:
            logger.warning("stripe.get_invoices_for_org no customer mapping org=%s", org_id)
            return []

        resp = self._get_client().get("/invoices", {"customer": customer_id, "limit": str(limit)})
        raw_invoices: list[dict[str, Any]] = resp.get("data", [])

        results: list[dict[str, Any]] = [_normalize_stripe_invoice(inv, org_id, customer_id) for inv in raw_invoices]

        with self._lock:
            self._invoice_cache[org_id] = results
            if len(self._invoice_cache) > _INVOICE_CACHE_MAX:
                oldest = next(iter(self._invoice_cache))
                del self._invoice_cache[oldest]

        return [InvoiceResponse(**_filter_to_dataclass_fields(InvoiceResponse, r)) for r in results]

    def invalidate_invoice_cache(self, org_id: str | None = None) -> None:
        """
        Invalidate the invoice cache for a specific org, or flush all entries
        if org_id is None.
        """
        with self._lock:
            if org_id is None:
                self._invoice_cache.clear()
            else:
                self._invoice_cache.pop(org_id, None)
        logger.debug("stripe.invoice_cache_invalidated org=%s", org_id or "ALL")

    # ------------------------------------------------------------------
    # Checkout
    # ------------------------------------------------------------------

    def create_checkout_session(
        self,
        org_id: str,
        price_id: str,
        *,
        mode: StripeCheckoutMode = StripeCheckoutMode.PAYMENT,
        quantity: int = 1,
        unit_credits: int = 0,
        success_url: str,
        cancel_url: str,
        customer_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> CheckoutSessionResponse:
        """
        Create a Stripe Checkout Session.

        - mode=payment: one-time purchase that grants unit_credits on completion.
        - mode=subscription: recurring subscription with optional metered usage.
        - unit_credits: number of IronClaw units to credit on checkout.session.completed.
          Each unit protects up to TOKENS_PER_UNIT (25,000) tokens with no scan ceiling.
          Use units_for_tokens(n) to derive the correct unit_credits from a token budget.

        Package reference (from PACKAGE_CATALOGUE):
          Starter:    5,000 units / $20 USD  — each unit ≤ 25,000 tokens · unlimited scans
          Team:      25,000 units / $90 USD  — each unit ≤ 25,000 tokens · unlimited scans
          Enterprise: 60,000 units / $180 USD — each unit ≤ 25,000 tokens · unlimited scans
        """
        # Existing validation kept intact, plus guarded checks for critical inputs.
        if quantity < 1:
            raise StripeServiceError("quantity must be >= 1")
        if unit_credits < 0:
            raise StripeServiceError("unit_credits must be >= 0")
        if not price_id or not price_id.strip():
            raise StripeServiceError("price_id is required")
        if not success_url or not success_url.strip():
            raise StripeServiceError("success_url is required")
        if not cancel_url or not cancel_url.strip():
            raise StripeServiceError("cancel_url is required")

        now = _utcnow_iso()
        session_meta: dict[str, Any] = {
            "org_id": org_id,
            "unit_credits": str(unit_credits),
            "tokens_per_unit": str(TOKENS_PER_UNIT),
            "ironclaw_source": "ironclaw-security",
            **(metadata or {}),
        }

        params: dict[str, Any] = {
            "mode": mode.value,
            "success_url": success_url,
            "cancel_url": cancel_url,
            "line_items[0][price]": price_id,
            "line_items[0][quantity]": str(quantity),
        }

        # New: explicitly request card collection for payment mode.
        if mode == StripeCheckoutMode.PAYMENT:
            params["payment_method_types[0]"] = "card"

        if customer_id:
            params["customer"] = customer_id

        for k, v in session_meta.items():
            params[f"metadata[{k}]"] = str(v)

        try:
            resp = self._get_client().post("/checkout/sessions", params)
        except StripeAPIError as exc:
            # New: log full Stripe error context before re-raising for the router to catch.
            logger.exception(
                "stripe.checkout_session_create_failed org=%s mode=%s price_id=%s http_status=%s stripe_code=%s raw=%s",
                org_id,
                mode.value,
                price_id,
                exc.http_status,
                exc.stripe_code,
                exc.raw,
            )
            raise

        session_id: str = resp["id"]
        checkout_url: str = resp.get("url", "")
        expires_at: str | None = None
        if resp.get("expires_at"):
            try:
                expires_at = datetime.fromtimestamp(int(resp["expires_at"]), tz=UTC).isoformat().replace("+00:00", "Z")
            except (ValueError, TypeError):
                expires_at = None

        record = _CheckoutSessionRecord(
            session_id=session_id,
            org_id=org_id,
            customer_id=customer_id or resp.get("customer"),
            mode=mode.value,
            price_id=price_id,
            quantity=quantity,
            unit_credits=unit_credits,
            success_url=success_url,
            cancel_url=cancel_url,
            metadata=session_meta,
            status="open",
            created_at=now,
            expires_at=expires_at,
        )
        with self._lock:
            self._checkout_sessions[session_id] = record

        logger.info(
            "stripe.checkout_session_created org=%s session=%s mode=%s credits=%d tokens_per_unit=%d",
            org_id,
            session_id,
            mode.value,
            unit_credits,
            TOKENS_PER_UNIT,
        )
        return CheckoutSessionResponse(
            session_id=session_id,
            checkout_url=checkout_url,
            org_id=org_id,
            mode=mode.value,
            price_id=price_id,
            quantity=quantity,
            unit_credits=unit_credits,
            expires_at=expires_at,
            metadata=session_meta,
            created_at=now,
        )

    def complete_checkout_session(
        self,
        session_id: str,
        *,
        customer_id: str | None = None,
        org_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Manually mark an open checkout session as complete and credit units.
        Idempotent — returns existing result if already complete.
        Raises StripeSessionNotFoundError if the session is not in local state.
        org_id is accepted for API compatibility but the session record's own
        org_id takes precedence.
        """
        with self._lock:
            record = self._checkout_sessions.get(session_id)
        if record is None:
            raise StripeSessionNotFoundError(f"checkout session not found: {session_id}")

        if record.status == "complete":
            return {
                "session_id": session_id,
                "org_id": record.org_id,
                "already_complete": True,
                "units_credited": 0,
            }

        resolved_customer = customer_id or record.customer_id
        resolved_org = record.org_id or org_id or ""
        if resolved_customer and resolved_org:
            self.register_customer_mapping(resolved_org, resolved_customer)

        with self._lock:
            completed = _CheckoutSessionRecord(
                session_id=record.session_id,
                org_id=record.org_id,
                customer_id=resolved_customer,
                mode=record.mode,
                price_id=record.price_id,
                quantity=record.quantity,
                unit_credits=record.unit_credits,
                success_url=record.success_url,
                cancel_url=record.cancel_url,
                metadata=record.metadata,
                status="complete",
                created_at=record.created_at,
                expires_at=record.expires_at,
            )
            self._checkout_sessions[session_id] = completed

        units_credited = 0
        if resolved_org and record.unit_credits > 0:
            self.credit_units(
                resolved_org,
                record.unit_credits,
                StripeUnitEventReason.CHECKOUT_COMPLETE,
                reference_id=session_id,
            )
            units_credited = record.unit_credits

        logger.info(
            "stripe.checkout_session_completed_manual session=%s org=%s units=%d",
            session_id,
            resolved_org,
            units_credited,
        )
        return {
            "session_id": session_id,
            "org_id": resolved_org,
            "already_complete": False,
            "units_credited": units_credited,
            "tokens_covered": units_credited * TOKENS_PER_UNIT,
        }

    def get_checkout_session(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            record = self._checkout_sessions.get(session_id)
        return record.to_dict() if record else None

    def expire_checkout_session(self, session_id: str) -> bool:
        """Mark a checkout session as expired (from webhook event or manual expiry)."""
        with self._lock:
            record = self._checkout_sessions.get(session_id)
            if record is None:
                return False
            updated = _CheckoutSessionRecord(
                session_id=record.session_id,
                org_id=record.org_id,
                customer_id=record.customer_id,
                mode=record.mode,
                price_id=record.price_id,
                quantity=record.quantity,
                unit_credits=record.unit_credits,
                success_url=record.success_url,
                cancel_url=record.cancel_url,
                metadata=record.metadata,
                status="expired",
                created_at=record.created_at,
                expires_at=record.expires_at,
            )
            self._checkout_sessions[session_id] = updated
        logger.info("stripe.checkout_session_expired session=%s", session_id)
        return True

    # ------------------------------------------------------------------
    # Unit lifecycle
    # ------------------------------------------------------------------

    def credit_units(
        self,
        org_id: str,
        amount: int,
        reason: StripeUnitEventReason,
        reference_id: str | None = None,
    ) -> UnitBalanceResponse:
        """
        Credit units to an org's balance and record a ledger entry.
        This path is consolidated with the canonical UnitWalletRegistry so that
        the Stripe service cannot drift from the durable wallet state.
        """
        if amount <= 0:
            raise StripeServiceError("credit amount must be > 0")

        owner_key = self._canonical_org_owner_key(org_id)
        wallet = self._wallet_registry.credit_units(
            owner_key,
            amount,
            metadata={
                "stripe_reason": reason.value,
                "reference_id": reference_id,
                "source": "stripe_service",
            },
        )
        with self._lock:
            self._unit_balances[org_id] = wallet.balance_units

        logger.info(
            "stripe.units_credited org=%s amount=%d reason=%s balance=%d tokens_per_unit=%d",
            org_id,
            amount,
            reason.value,
            wallet.balance_units,
            TOKENS_PER_UNIT,
        )
        return self._sync_balances_from_wallet(org_id)

    def debit_units(
        self,
        org_id: str,
        amount: int,
        reason: StripeUnitEventReason,
        reference_id: str | None = None,
    ) -> UnitBalanceResponse:
        """
        Debit units from an org's balance.
        Raises StripeInsufficientUnitsError when the org has insufficient balance.
        The on_insufficient_units callback (if set at init) is also fired.
        Each unit covers up to TOKENS_PER_UNIT (25,000) tokens.
        """
        if amount <= 0:
            raise StripeServiceError("debit amount must be > 0")

        owner_key = self._canonical_org_owner_key(org_id)
        current_wallet = self._wallet_registry.get_wallet(owner_key)
        current_balance = current_wallet.balance_units if current_wallet is not None else 0
        if amount > current_balance:
            if self._on_insufficient_units is not None:
                try:
                    self._on_insufficient_units(org_id, current_balance, amount)
                except Exception:  # noqa: BLE001
                    logger.warning("stripe.on_insufficient_units_callback_error org=%s", org_id)
            raise StripeInsufficientUnitsError(org_id=org_id, have=current_balance, need=amount)

        wallet = self._wallet_registry.debit_units(
            owner_key,
            amount,
            metadata={
                "stripe_reason": reason.value,
                "reference_id": reference_id,
                "source": "stripe_service",
            },
        )
        with self._lock:
            self._unit_balances[org_id] = wallet.balance_units

        logger.info(
            "stripe.units_debited org=%s amount=%d reason=%s balance=%d",
            org_id,
            amount,
            reason.value,
            wallet.balance_units,
        )
        return self._sync_balances_from_wallet(org_id)

    def debit_units_for_tokens(
        self,
        org_id: str,
        token_count: int,
        reason: StripeUnitEventReason,
        reference_id: str | None = None,
    ) -> UnitBalanceResponse:
        """
        Debit the exact number of units required to cover token_count tokens.
        Each unit covers up to TOKENS_PER_UNIT (25,000) tokens.
        Partial chunks consume a full unit (ceiling division). No scan ceiling.
        Raises StripeInsufficientUnitsError if the org has insufficient balance.
        """
        if token_count < 0:
            logger.warning(
                "stripe.debit_units_for_tokens called with negative token_count=%d org=%s — treating as 0",
                token_count,
                org_id,
            )
            token_count = 0

        units_needed = units_for_tokens(token_count)
        if units_needed == 0:
            with self._lock:
                balance = self._unit_balances.get(org_id, 0)
                ledger = [e.to_dict() for e in self._unit_ledger.get(org_id, [])[-50:]]
            return UnitBalanceResponse(org_id=org_id, balance=balance, ledger_entries=ledger)
        return self.debit_units(org_id, units_needed, reason, reference_id)

    def get_unit_balance(self, org_id: str) -> UnitBalanceResponse:
        return self._sync_balances_from_wallet(org_id)

    def adjust_unit_balance(
        self,
        org_id: str,
        target_balance: int,
        reason: StripeUnitEventReason = StripeUnitEventReason.ADJUSTMENT,
        reference_id: str | None = None,
    ) -> UnitBalanceResponse:
        """
        Force-set an org's unit balance to target_balance.
        Records the delta as a single ledger entry. Used for reconciliation.
        """
        if target_balance < 0:
            raise StripeServiceError("target_balance must be >= 0")

        owner_key = self._canonical_org_owner_key(org_id)
        current = self._wallet_registry.get_wallet(owner_key)
        current_balance = current.balance_units if current is not None else 0
        delta = target_balance - current_balance

        if delta > 0:
            self.credit_units(org_id, delta, reason, reference_id)
        elif delta < 0:
            self.debit_units(org_id, -delta, reason, reference_id)

        return self.get_unit_balance(org_id)

    # ------------------------------------------------------------------
    # Subscription lifecycle
    # ------------------------------------------------------------------

    def upsert_subscription(
        self,
        subscription_id: str,
        org_id: str,
        customer_id: str,
        price_id: str,
        status: StripeSubscriptionStatus,
        billing_interval: StripeBillingInterval,
        current_period_start: str,
        current_period_end: str,
        *,
        cancel_at_period_end: bool = False,
        metered_price_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SubscriptionResponse:
        """
        Insert or update a subscription record.
        Called by webhook event handlers (subscription.created / .updated / .deleted).
        """
        now = _utcnow_iso()

        with self._lock:
            existing = self._subscriptions.get(subscription_id)
            created_at = existing.created_at if existing else now

            record = _SubscriptionRecord(
                subscription_id=subscription_id,
                org_id=org_id,
                customer_id=customer_id,
                price_id=price_id,
                status=status.value,
                billing_interval=billing_interval.value,
                current_period_start=current_period_start,
                current_period_end=current_period_end,
                cancel_at_period_end=cancel_at_period_end,
                metered_price_id=metered_price_id,
                metadata=dict(metadata or {}),
                created_at=created_at,
                updated_at=now,
            )
            self._subscriptions[subscription_id] = record
            self._org_customer_map.setdefault(org_id, customer_id)
            self._customer_org_map.setdefault(customer_id, org_id)

        logger.info(
            "stripe.subscription_upserted id=%s org=%s status=%s",
            subscription_id,
            org_id,
            status.value,
        )
        return SubscriptionResponse(**record.to_dict(), schema_version=_SCHEMA_VERSION)

    def get_subscription(
        self,
        subscription_id: str,
        strict: bool = True,
    ) -> SubscriptionResponse | None:
        """
        Return SubscriptionResponse for subscription_id.

        When strict=True (default): raises StripeSubscriptionNotFoundError if not found.
        When strict=False: returns None instead of raising.
        """
        with self._lock:
            record = self._subscriptions.get(subscription_id)
        if record is None:
            if strict:
                raise StripeSubscriptionNotFoundError(subscription_id)
            return None
        return SubscriptionResponse(**record.to_dict(), schema_version=_SCHEMA_VERSION)

    def get_subscription_or_none(self, subscription_id: str) -> SubscriptionResponse | None:
        """
        Return SubscriptionResponse or None without raising.
        Use when absence of a subscription is a valid non-error condition.
        """
        return self.get_subscription(subscription_id, strict=False)

    def get_subscription_strict(self, subscription_id: str) -> SubscriptionResponse:
        """
        Alias for get_subscription(strict=True). Raises StripeSubscriptionNotFoundError if not found.
        Retained for call-site compatibility.
        """
        result = self.get_subscription(subscription_id, strict=True)
        if result is None:
            raise StripeSubscriptionNotFoundError(subscription_id)
        return result

    def get_active_subscription_for_org(self, org_id: str) -> SubscriptionResponse | None:
        with self._lock:
            records = [
                r
                for r in self._subscriptions.values()
                if r.org_id == org_id
                and r.status
                in (
                    StripeSubscriptionStatus.ACTIVE.value,
                    StripeSubscriptionStatus.TRIALING.value,
                    StripeSubscriptionStatus.PAST_DUE.value,
                )
            ]
        if not records:
            return None
        latest = max(records, key=lambda r: r.updated_at)
        return SubscriptionResponse(**latest.to_dict(), schema_version=_SCHEMA_VERSION)

    def list_subscriptions_for_org(self, org_id: str) -> list[SubscriptionResponse]:
        """Return all subscriptions (any status) for a given org."""
        with self._lock:
            records = [r for r in self._subscriptions.values() if r.org_id == org_id]
        return [SubscriptionResponse(**r.to_dict(), schema_version=_SCHEMA_VERSION) for r in records]

    def cancel_subscription(self, subscription_id: str) -> SubscriptionResponse | None:
        """
        Mark subscription as canceled in local state.
        To cancel via Stripe API use cancel_subscription_remote().
        """
        with self._lock:
            record = self._subscriptions.get(subscription_id)
            if record is None:
                return None
            updated = _SubscriptionRecord(
                subscription_id=record.subscription_id,
                org_id=record.org_id,
                customer_id=record.customer_id,
                price_id=record.price_id,
                status=StripeSubscriptionStatus.CANCELED.value,
                billing_interval=record.billing_interval,
                current_period_start=record.current_period_start,
                current_period_end=record.current_period_end,
                cancel_at_period_end=True,
                metered_price_id=record.metered_price_id,
                metadata=record.metadata,
                created_at=record.created_at,
                updated_at=_utcnow_iso(),
            )
            self._subscriptions[subscription_id] = updated

        logger.info("stripe.subscription_canceled id=%s", subscription_id)
        return SubscriptionResponse(**updated.to_dict(), schema_version=_SCHEMA_VERSION)

    def cancel_subscription_remote(self, subscription_id: str) -> SubscriptionResponse | None:
        """Cancel a subscription through the Stripe API and update local state."""
        resp = self._get_client().post(
            f"/subscriptions/{subscription_id}",
            {"cancel_at_period_end": "true"},
        )
        org_id = self.resolve_org_from_customer(resp.get("customer", "")) or ""
        if not org_id:
            with self._lock:
                record = self._subscriptions.get(subscription_id)
                if record:
                    org_id = record.org_id

        with self._lock:
            record = self._subscriptions.get(subscription_id)
            if record is None:
                return None
            updated = _SubscriptionRecord(
                subscription_id=subscription_id,
                org_id=org_id,
                customer_id=record.customer_id,
                price_id=record.price_id,
                status=resp.get("status", StripeSubscriptionStatus.CANCELED.value),
                billing_interval=record.billing_interval,
                current_period_start=record.current_period_start,
                current_period_end=record.current_period_end,
                cancel_at_period_end=True,
                metered_price_id=record.metered_price_id,
                metadata=record.metadata,
                created_at=record.created_at,
                updated_at=_utcnow_iso(),
            )
            self._subscriptions[subscription_id] = updated

        logger.info("stripe.subscription_canceled_remote id=%s", subscription_id)
        return SubscriptionResponse(**updated.to_dict(), schema_version=_SCHEMA_VERSION)

    # ------------------------------------------------------------------
    # Metered billing sync
    # ------------------------------------------------------------------

    def report_metered_usage(
        self,
        org_id: str,
        subscription_item_id: str,
        quantity: int,
        *,
        action: str = "increment",
        idempotency_key: str | None = None,
    ) -> MeteredSyncResponse:
        """
        Report metered usage to Stripe for a subscription item.
        Idempotency key prevents duplicate reports within Stripe's dedup window.
        Raises StripeIdempotencyError on duplicate key before any network call.
        Default key uses uuid4 suffix so successive calls within the same second
        always get distinct keys.
        """
        if quantity < 0:
            raise StripeServiceError("metered usage quantity must be >= 0")

        idem_key = idempotency_key or f"metered-{org_id}-{subscription_item_id}-{uuid4().hex[:12]}"

        if idempotency_key is not None:
            with self._lock:
                if idem_key in self._idempotency_keys:
                    stored = self._idempotency_keys[idem_key]
                    if stored.get("quantity") != quantity or stored.get("action") != action:
                        raise StripeIdempotencyError(idem_key, "conflicting metered usage payload")
                    raise StripeIdempotencyError(idem_key)
        else:
            with self._lock:
                if idem_key in self._idempotency_keys:
                    stored = self._idempotency_keys[idem_key]
                    if stored.get("quantity") != quantity or stored.get("action") != action:
                        raise StripeIdempotencyError(idem_key, "conflicting metered usage payload")

        now = _utcnow_iso()
        params: dict[str, Any] = {
            "quantity": str(quantity),
            "action": action,
            "timestamp": str(int(time.time())),
        }

        stripe_record_id: str | None = None
        error: str | None = None
        success = False

        try:
            resp = self._get_client().post(
                f"/subscription_items/{subscription_item_id}/usage_records",
                params,
                idempotency_key=idem_key,
            )
            stripe_record_id = resp.get("id")
            success = True
            with self._lock:
                self._idempotency_keys[idem_key] = {"quantity": quantity, "action": action}
            logger.info(
                "stripe.metered_usage_reported org=%s item=%s qty=%d record=%s",
                org_id,
                subscription_item_id,
                quantity,
                stripe_record_id,
            )
        except StripeAPIError as exc:
            error = str(exc)
            logger.warning(
                "stripe.metered_usage_failed org=%s item=%s qty=%d error=%s",
                org_id,
                subscription_item_id,
                quantity,
                error,
            )

        entry = _MeteredUsageEntry(
            entry_id=_new_id("mu"),
            org_id=org_id,
            subscription_id=subscription_item_id,
            quantity=quantity,
            action=action,
            idempotency_key=idem_key,
            synced_at=now,
            stripe_usage_record_id=stripe_record_id,
            error=error,
        )
        with self._lock:
            self._metered_usage_log.append(entry)
            if len(self._metered_usage_log) > _METERED_USAGE_BUFFER_MAX:
                self._metered_usage_log = self._metered_usage_log[-_METERED_USAGE_BUFFER_MAX:]

        return MeteredSyncResponse(
            org_id=org_id,
            subscription_id=subscription_item_id,
            quantity=quantity,
            action=action,
            idempotency_key=idem_key,
            stripe_usage_record_id=stripe_record_id,
            success=success,
            error=error,
            synced_at=now,
        )

    def get_metered_usage_log(
        self,
        org_id: str | None = None,
        *,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        with self._lock:
            entries = list(self._metered_usage_log)
        if org_id is not None:
            entries = [e for e in entries if e.org_id == org_id]
        return [e.to_dict() for e in entries[-limit:]]

    # ------------------------------------------------------------------
    # Stripe Webhook verification and dispatch
    # ------------------------------------------------------------------

    def verify_webhook_signature(
        self,
        payload: bytes,
        signature_header: str,
        *,
        webhook_secret: str | None = None,
    ) -> WebhookVerifyResult:
        """
        Verify a Stripe webhook using the Stripe-Signature header (HMAC-SHA256
        timestamp scheme). Returns WebhookVerifyResult so callers can access
        result.valid, result.event_type, result.event_id, result.error, result.payload.

        webhook_secret: optional call-site override. When provided, bypasses vault
        lookup entirely. Suitable for per-request injection in tests or multi-tenant
        deployments where each endpoint uses a distinct secret.

        Secret resolution order:
          1. webhook_secret parameter (call-site injection).
          2. self._webhook_secret_override (constructor injection / set_webhook_secret).
          3. vault.get(\"STRIPE_WEBHOOK_SECRET\") read at call time.
        """
        import hashlib
        import hmac as _hmac
        import json

        try:
            resolved_secret = self._get_webhook_secret(override=webhook_secret)
        except StripeConfigError as exc:
            return WebhookVerifyResult(valid=False, event_type=None, event_id=None, error=str(exc), payload={})

        try:
            parts = dict(p.split("=", 1) for p in signature_header.split(",") if "=" in p)
            timestamp = parts.get("t", "")
            v1_sig = parts.get("v1", "")
        except Exception:  # noqa: BLE001
            return WebhookVerifyResult(
                valid=False,
                event_type=None,
                event_id=None,
                error="Malformed Stripe-Signature header.",
                payload={},
            )

        if not timestamp or not v1_sig:
            return WebhookVerifyResult(
                valid=False,
                event_type=None,
                event_id=None,
                error="Missing timestamp or v1 signature.",
                payload={},
            )

        try:
            ts_int = int(timestamp)
        except ValueError:
            return WebhookVerifyResult(valid=False, event_type=None, event_id=None, error="Invalid timestamp.", payload={})

        tolerance_seconds = int(vault.get("STRIPE_WEBHOOK_TOLERANCE_SECONDS") or "300")
        age = int(time.time()) - ts_int
        if abs(age) > tolerance_seconds:
            return WebhookVerifyResult(
                valid=False,
                event_type=None,
                event_id=None,
                error=f"Webhook timestamp too old or too far in the future (age={age}s).",
                payload={},
            )

        signed_payload = f"{timestamp}.".encode() + payload
        expected = _hmac.new(resolved_secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()

        if not _hmac.compare_digest(expected, v1_sig):
            return WebhookVerifyResult(valid=False, event_type=None, event_id=None, error="Signature mismatch.", payload={})

        try:
            parsed: dict[str, Any] = json.loads(payload.decode("utf-8"))
        except json.JSONDecodeError as exc:
            return WebhookVerifyResult(
                valid=False,
                event_type=None,
                event_id=None,
                error=f"JSON decode error: {exc}",
                payload={},
            )

        return WebhookVerifyResult(
            valid=True,
            event_type=parsed.get("type"),
            event_id=parsed.get("id"),
            error=None,
            payload=parsed,
        )

    def dispatch_webhook_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """
        Public entry point for dispatching a pre-verified Stripe event object.
        Accepts the full event dict (with "type", "id", "data.object", etc.).
        Returns a result dict with action taken.
        Duplicate event IDs are silently skipped (idempotent no-op).
        """
        return self.handle_webhook_event(event)

    def handle_webhook_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """
        Dispatch a verified Stripe event object to the appropriate handler.
        Enforces event-level idempotency using the canonical durable event ledger
        and the in-memory cache as a fast-path. Duplicate event IDs are silently
        skipped — returns {"action": "duplicate"}.
        """
        event_type = event.get("type", "")
        event_id = event.get("id", "")
        data_obj: dict[str, Any] = event.get("data", {}).get("object", {})

        if event_id and self._has_processed_event(event_id):
            logger.debug(
                "stripe.webhook_duplicate_skipped event_type=%s id=%s",
                event_type,
                event_id,
            )
            return {"action": "duplicate", "event_type": event_type, "event_id": event_id}

        handler_map: dict[str, Any] = {
            StripeWebhookEventType.CHECKOUT_SESSION_COMPLETED.value: self._handle_checkout_completed,
            StripeWebhookEventType.CHECKOUT_SESSION_EXPIRED.value: self._handle_checkout_expired,
            StripeWebhookEventType.CUSTOMER_SUBSCRIPTION_CREATED.value: self._handle_subscription_upsert,
            StripeWebhookEventType.CUSTOMER_SUBSCRIPTION_UPDATED.value: self._handle_subscription_updated,
            StripeWebhookEventType.CUSTOMER_SUBSCRIPTION_DELETED.value: self._handle_subscription_deleted,
            StripeWebhookEventType.INVOICE_PAID.value: self._handle_invoice_paid,
            StripeWebhookEventType.INVOICE_PAYMENT_FAILED.value: self._handle_invoice_payment_failed,
            StripeWebhookEventType.INVOICE_UPCOMING.value: self._handle_invoice_upcoming,
            StripeWebhookEventType.CHARGE_REFUNDED.value: self._handle_charge_refunded,
            StripeWebhookEventType.CUSTOMER_CREATED.value: self._handle_customer_created,
            StripeWebhookEventType.CUSTOMER_UPDATED.value: self._handle_customer_updated,
            StripeWebhookEventType.PAYMENT_INTENT_SUCCEEDED.value: self._handle_payment_intent_succeeded,
            StripeWebhookEventType.PAYMENT_INTENT_PAYMENT_FAILED.value: self._handle_payment_intent_payment_failed,
        }

        handler = handler_map.get(event_type)
        if handler is None:
            logger.debug("stripe.webhook_unhandled event_type=%s id=%s", event_type, event_id)
            return {"action": "ignored", "event_type": event_type, "event_id": event_id}

        try:
            result = handler(data_obj, event)
            if event_id:
                self._mark_processed_event(
                    event_id=event_id,
                    event_type=event_type,
                    purchase_reference=data_obj.get("metadata", {}).get("purchase_reference") or data_obj.get("metadata", {}).get("purchase_id"),
                    checkout_session_id=data_obj.get("id") if event_type == StripeWebhookEventType.CHECKOUT_SESSION_COMPLETED.value else None,
                    owner_key=data_obj.get("metadata", {}).get("org_id"),
                    customer_id=data_obj.get("customer"),
                    program=None,
                    payload={"raw": data_obj, "event_type": event_type},
                )
            logger.info("stripe.webhook_handled event_type=%s id=%s", event_type, event_id)
            return {"action": "processed", "event_type": event_type, "event_id": event_id, "detail": result}
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "stripe.webhook_handler_error event_type=%s id=%s error=%s",
                event_type,
                event_id,
                exc,
            )
            return {"action": "error", "event_type": event_type, "event_id": event_id, "error": str(exc)}

    # ------------------------------------------------------------------
    # Private event handlers
    # ------------------------------------------------------------------

    def _handle_checkout_completed(self, obj: dict[str, Any], _event: dict[str, Any]) -> dict[str, Any]:
        session_id: str = obj.get("id", "")
        org_id: str = obj.get("metadata", {}).get("org_id", "")
        unit_credits_raw: str = obj.get("metadata", {}).get("unit_credits", "0")
        customer_id: str | None = obj.get("customer")
        mode: str = obj.get("mode", "payment")
        payment_status = obj.get("payment_status")
        if payment_status is None:
            payment_status = "paid" if obj.get("status") in {None, "", "complete", "completed"} else obj.get("status")

        try:
            unit_credits = int(unit_credits_raw)
        except (ValueError, TypeError):
            unit_credits = 0

        checkout_idem_key = f"checkout_completed:{session_id}"
        payment_confirmed = self._is_successful_payment_status(payment_status)

        with self._lock:
            already_credited = checkout_idem_key in self._processed_event_ids
            record = self._checkout_sessions.get(session_id)
            if record is not None:
                updated = _CheckoutSessionRecord(
                    session_id=record.session_id,
                    org_id=record.org_id,
                    customer_id=customer_id or record.customer_id,
                    mode=record.mode,
                    price_id=record.price_id,
                    quantity=record.quantity,
                    unit_credits=record.unit_credits,
                    success_url=record.success_url,
                    cancel_url=record.cancel_url,
                    metadata=record.metadata,
                    status="complete",
                    created_at=record.created_at,
                    expires_at=record.expires_at,
                )
                self._checkout_sessions[session_id] = updated

        if customer_id and org_id:
            self.register_customer_mapping(org_id, customer_id)

        result: dict[str, Any] = {
            "session_id": session_id,
            "org_id": org_id,
            "mode": mode,
            "tokens_per_unit": TOKENS_PER_UNIT,
            "payment_status": payment_status,
            "payment_confirmed": payment_confirmed,
        }

        install_key_issuance: dict[str, dict[str, Any]] = {}
        if org_id and not already_credited:
            if payment_confirmed and unit_credits > 0:
                self.credit_units(
                    org_id,
                    unit_credits,
                    StripeUnitEventReason.CHECKOUT_COMPLETE,
                    reference_id=session_id,
                )
                result["units_credited"] = unit_credits
                result["tokens_covered"] = unit_credits * TOKENS_PER_UNIT

            if payment_confirmed:
                try:
                    install_key_issuance = self._issue_paid_install_keys_for_checkout(
                        org_id=org_id,
                        customer_id=customer_id,
                        session_id=session_id,
                        unit_credits=unit_credits,
                        metadata={"mode": mode, "payment_status": payment_status},
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "stripe.checkout_install_key_issue_failed org=%s session=%s error=%s",
                        org_id,
                        session_id,
                        exc,
                    )
                    install_key_issuance = {}

            with self._lock:
                self._processed_event_ids.add(checkout_idem_key)

        if install_key_issuance:
            result["install_key_issuance"] = install_key_issuance

        return result

    def _handle_checkout_expired(self, obj: dict[str, Any], _event: dict[str, Any]) -> dict[str, Any]:
        session_id: str = obj.get("id", "")
        self.expire_checkout_session(session_id)
        return {"session_id": session_id, "status": "expired"}

    def _handle_subscription_upsert(self, obj: dict[str, Any], _event: dict[str, Any]) -> dict[str, Any]:
        subscription_id: str = obj.get("id", "")
        customer_id: str = obj.get("customer", "")
        status_raw: str = obj.get("status", "active")
        cancel_at_period_end: bool = bool(obj.get("cancel_at_period_end", False))

        try:
            status = StripeSubscriptionStatus(status_raw)
        except ValueError:
            status = StripeSubscriptionStatus.INCOMPLETE

        plan: dict[str, Any] = {}
        items_data = obj.get("items", {}).get("data", [])
        if items_data:
            plan = items_data[0].get("plan", {})

        interval_raw = plan.get("interval", "month")
        try:
            billing_interval = StripeBillingInterval(interval_raw)
        except ValueError:
            billing_interval = StripeBillingInterval.MONTHLY

        price_id: str = ""
        for item in items_data:
            pid = item.get("price", {}).get("id") or item.get("plan", {}).get("id", "")
            if pid:
                price_id = pid
                break

        metered_price_id: str | None = None
        for item in items_data:
            usage_type = item.get("price", {}).get("recurring", {}).get("usage_type")
            if usage_type == "metered":
                metered_price_id = item.get("price", {}).get("id")
                break

        period_start = ""
        period_end = ""
        try:
            raw_start = obj.get("current_period_start", 0)
            raw_end = obj.get("current_period_end", 0)
            if raw_start:
                period_start = datetime.fromtimestamp(int(raw_start), tz=UTC).isoformat().replace("+00:00", "Z")
            if raw_end:
                period_end = datetime.fromtimestamp(int(raw_end), tz=UTC).isoformat().replace("+00:00", "Z")
        except (ValueError, TypeError):
            pass

        org_id = self.resolve_org_from_customer(customer_id) or obj.get("metadata", {}).get("org_id", "")
        if not org_id:
            with self._lock:
                existing_record = self._subscriptions.get(subscription_id)
            if existing_record:
                org_id = existing_record.org_id

        self.upsert_subscription(
            subscription_id=subscription_id,
            org_id=org_id,
            customer_id=customer_id,
            price_id=price_id,
            status=status,
            billing_interval=billing_interval,
            current_period_start=period_start,
            current_period_end=period_end,
            cancel_at_period_end=cancel_at_period_end,
            metered_price_id=metered_price_id,
            metadata=dict(obj.get("metadata", {})),
        )
        return {"subscription_id": subscription_id, "status": status.value}

    def _handle_subscription_updated(self, obj: dict[str, Any], _event: dict[str, Any]) -> dict[str, Any]:
        subscription_id: str = obj.get("id", "")
        new_status_raw: str = obj.get("status", "")

        # Write the new status directly into the registry before delegating to
        # the full upsert so that get_subscription() reflects the updated status
        # immediately after this handler returns.
        if subscription_id and new_status_raw:
            with self._lock:
                record = self._subscriptions.get(subscription_id)
                if record is not None:
                    mutated = _SubscriptionRecord(
                        subscription_id=record.subscription_id,
                        org_id=record.org_id,
                        customer_id=record.customer_id,
                        price_id=record.price_id,
                        status=new_status_raw,
                        billing_interval=record.billing_interval,
                        current_period_start=record.current_period_start,
                        current_period_end=record.current_period_end,
                        cancel_at_period_end=record.cancel_at_period_end,
                        metered_price_id=record.metered_price_id,
                        metadata=record.metadata,
                        created_at=record.created_at,
                        updated_at=_utcnow_iso(),
                    )
                    self._subscriptions[subscription_id] = mutated

        # Full upsert: rebuilds the record from the event object.
        # The status embedded in obj matches new_status_raw so the final
        # stored record is consistent either way.
        return self._handle_subscription_upsert(obj, _event)

    def _handle_subscription_deleted(self, obj: dict[str, Any], _event: dict[str, Any]) -> dict[str, Any]:
        subscription_id: str = obj.get("id", "")
        customer_id: str = obj.get("customer", "")

        org_id = self.resolve_org_from_customer(customer_id) or obj.get("metadata", {}).get("org_id", "")
        if not org_id:
            with self._lock:
                existing_record = self._subscriptions.get(subscription_id)
            if existing_record:
                org_id = existing_record.org_id

        # Mark as canceled and retain the record in the registry so that
        # get_subscription() can return the final canceled state.
        # Callers that want strict not-found behavior after deletion should
        # use get_subscription(strict=True) and check status == "canceled".
        with self._lock:
            record = self._subscriptions.get(subscription_id)
            if record is not None:
                canceled = _SubscriptionRecord(
                    subscription_id=record.subscription_id,
                    org_id=org_id or record.org_id,
                    customer_id=record.customer_id,
                    price_id=record.price_id,
                    status=StripeSubscriptionStatus.CANCELED.value,
                    billing_interval=record.billing_interval,
                    current_period_start=record.current_period_start,
                    current_period_end=record.current_period_end,
                    cancel_at_period_end=True,
                    metered_price_id=record.metered_price_id,
                    metadata=record.metadata,
                    created_at=record.created_at,
                    updated_at=_utcnow_iso(),
                )
                self._subscriptions[subscription_id] = canceled

        logger.info("stripe.subscription_deleted id=%s", subscription_id)
        return {"subscription_id": subscription_id, "status": "canceled"}

    def _handle_customer_created(self, obj: dict[str, Any], _event: dict[str, Any]) -> dict[str, Any]:
        customer_id: str = obj.get("id", "")
        org_id: str = obj.get("metadata", {}).get("org_id", "")

        if org_id and customer_id:
            self.register_customer_mapping(org_id, customer_id)

        logger.info(
            "stripe.customer_created_webhook customer=%s org=%s",
            customer_id,
            org_id,
        )
        return {"customer_id": customer_id, "org_id": org_id}

    def _handle_invoice_paid(self, obj: dict[str, Any], _event: dict[str, Any]) -> dict[str, Any]:
        subscription_id: str | None = obj.get("subscription")
        customer_id: str = obj.get("customer", "")
        amount_paid: int = int(obj.get("amount_paid", 0))
        invoice_id: str = obj.get("id", "")
        billing_reason: str = obj.get("billing_reason", "")

        org_id = self.resolve_org_from_customer(customer_id) or obj.get("metadata", {}).get("org_id", "")

        if org_id:
            self.invalidate_invoice_cache(org_id)

        renewal_units_credited: int = 0

        if subscription_id:
            with self._lock:
                record = self._subscriptions.get(subscription_id)

            if record:
                if record.status in (
                    StripeSubscriptionStatus.PAST_DUE.value,
                    StripeSubscriptionStatus.UNPAID.value,
                ):
                    with self._lock:
                        updated = _SubscriptionRecord(
                            subscription_id=record.subscription_id,
                            org_id=record.org_id,
                            customer_id=record.customer_id,
                            price_id=record.price_id,
                            status=StripeSubscriptionStatus.ACTIVE.value,
                            billing_interval=record.billing_interval,
                            current_period_start=record.current_period_start,
                            current_period_end=record.current_period_end,
                            cancel_at_period_end=record.cancel_at_period_end,
                            metered_price_id=record.metered_price_id,
                            metadata=record.metadata,
                            created_at=record.created_at,
                            updated_at=_utcnow_iso(),
                        )
                        self._subscriptions[subscription_id] = updated

                renewal_units_raw = obj.get("metadata", {}).get("unit_credits", "")
                renewal_units = 0

                if renewal_units_raw:
                    try:
                        renewal_units = int(renewal_units_raw)
                    except (ValueError, TypeError):
                        renewal_units = 0
                elif billing_reason == "subscription_cycle" and record.price_id:
                    for pkg in PACKAGE_CATALOGUE.values():
                        if pkg.get("price_id") == record.price_id:
                            renewal_units = int(pkg.get("units", 0))
                            break

                if org_id and renewal_units > 0:
                    self.credit_units(
                        org_id,
                        renewal_units,
                        StripeUnitEventReason.SUBSCRIPTION_RENEWED,
                        reference_id=invoice_id,
                    )
                    renewal_units_credited = renewal_units
                    logger.info(
                        "stripe.subscription_renewal_units_credited org=%s units=%d invoice=%s reason=%s",
                        org_id,
                        renewal_units,
                        invoice_id,
                        billing_reason,
                    )

        return {
            "invoice_id": invoice_id,
            "org_id": org_id,
            "subscription_id": subscription_id,
            "amount_paid": amount_paid,
            "renewal_units_credited": renewal_units_credited,
            "billing_reason": billing_reason,
        }

    def _handle_invoice_payment_failed(self, obj: dict[str, Any], _event: dict[str, Any]) -> dict[str, Any]:
        subscription_id: str | None = obj.get("subscription")
        customer_id: str = obj.get("customer", "")
        invoice_id: str = obj.get("id", "")

        org_id = self.resolve_org_from_customer(customer_id) or ""

        if subscription_id:
            with self._lock:
                record = self._subscriptions.get(subscription_id)
            if record and record.status == StripeSubscriptionStatus.ACTIVE.value:
                with self._lock:
                    updated = _SubscriptionRecord(
                        subscription_id=record.subscription_id,
                        org_id=record.org_id,
                        customer_id=record.customer_id,
                        price_id=record.price_id,
                        status=StripeSubscriptionStatus.PAST_DUE.value,
                        billing_interval=record.billing_interval,
                        current_period_start=record.current_period_start,
                        current_period_end=record.current_period_end,
                        cancel_at_period_end=record.cancel_at_period_end,
                        metered_price_id=record.metered_price_id,
                        metadata=record.metadata,
                        created_at=record.created_at,
                        updated_at=_utcnow_iso(),
                    )
                    self._subscriptions[subscription_id] = updated

        logger.warning(
            "stripe.invoice_payment_failed invoice=%s org=%s subscription=%s",
            invoice_id,
            org_id,
            subscription_id,
        )
        return {
            "invoice_id": invoice_id,
            "org_id": org_id,
            "subscription_id": subscription_id,
        }

    def _handle_invoice_upcoming(self, obj: dict[str, Any], _event: dict[str, Any]) -> dict[str, Any]:
        invoice_id: str = obj.get("id", "")
        customer_id: str = obj.get("customer", "")
        subscription_id: str | None = obj.get("subscription")
        amount_due: int = int(obj.get("amount_due", 0))

        org_id = self.resolve_org_from_customer(customer_id) or obj.get("metadata", {}).get("org_id", "")

        logger.info(
            "stripe.invoice_upcoming invoice=%s org=%s subscription=%s amount_due=%d",
            invoice_id,
            org_id,
            subscription_id,
            amount_due,
        )
        return {
            "invoice_id": invoice_id,
            "org_id": org_id,
            "subscription_id": subscription_id,
            "amount_due": amount_due,
        }

    def _handle_charge_refunded(self, obj: dict[str, Any], _event: dict[str, Any]) -> dict[str, Any]:
        charge_id: str = obj.get("id", "")
        customer_id: str = obj.get("customer", "")
        amount_refunded: int = int(obj.get("amount_refunded", 0))

        org_id = self.resolve_org_from_customer(customer_id) or ""

        if org_id:
            self.invalidate_invoice_cache(org_id)

        logger.info(
            "stripe.charge_refunded charge=%s customer=%s org=%s amount_refunded=%d",
            charge_id,
            customer_id,
            org_id,
            amount_refunded,
        )
        return {
            "charge_id": charge_id,
            "customer_id": customer_id,
            "org_id": org_id,
            "amount_refunded": amount_refunded,
        }

    def _handle_customer_updated(self, obj: dict[str, Any], _event: dict[str, Any]) -> dict[str, Any]:
        customer_id: str = obj.get("id", "")
        email: str = obj.get("email", "")
        org_id: str = obj.get("metadata", {}).get("org_id", "")

        if org_id and customer_id:
            self.register_customer_mapping(org_id, customer_id)
            self.invalidate_invoice_cache(org_id)

        logger.info(
            "stripe.customer_updated customer=%s org=%s email=%s",
            customer_id,
            org_id,
            email,
        )
        return {
            "customer_id": customer_id,
            "org_id": org_id,
            "email": email,
        }

    def _handle_payment_intent_succeeded(self, obj: dict[str, Any], _event: dict[str, Any]) -> dict[str, Any]:
        intent_id: str = obj.get("id", "")
        customer_id: str = obj.get("customer", "")
        amount_received: int = int(obj.get("amount_received", 0))
        currency: str = obj.get("currency", "usd")

        org_id = self.resolve_org_from_customer(customer_id) or obj.get("metadata", {}).get("org_id", "")

        if org_id and customer_id:
            self.register_customer_mapping(org_id, customer_id)

        logger.info(
            "stripe.payment_intent_succeeded intent=%s org=%s amount=%d currency=%s",
            intent_id,
            org_id,
            amount_received,
            currency,
        )
        return {
            "payment_intent_id": intent_id,
            "org_id": org_id,
            "customer_id": customer_id,
            "amount_received": amount_received,
            "currency": currency,
        }

    def _handle_payment_intent_payment_failed(self, obj: dict[str, Any], _event: dict[str, Any]) -> dict[str, Any]:
        intent_id: str = obj.get("id", "")
        customer_id: str = obj.get("customer", "")
        last_error: dict[str, Any] = obj.get("last_payment_error", {}) or {}
        error_code: str = last_error.get("code", "unknown")
        error_message: str = last_error.get("message", "")

        org_id = self.resolve_org_from_customer(customer_id) or obj.get("metadata", {}).get("org_id", "")

        logger.warning(
            "stripe.payment_intent_failed intent=%s org=%s customer=%s code=%s message=%s",
            intent_id,
            org_id,
            customer_id,
            error_code,
            error_message,
        )
        return {
            "payment_intent_id": intent_id,
            "org_id": org_id,
            "customer_id": customer_id,
            "error_code": error_code,
            "error_message": error_message,
        }

    # ------------------------------------------------------------------
    # Introspection helpers
    # ------------------------------------------------------------------

    def list_checkout_sessions(self, org_id: str | None = None, *, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._checkout_sessions.values())
        if org_id is not None:
            items = [s for s in items if s.org_id == org_id]
        return [s.to_dict() for s in items[-limit:]]

    def list_subscriptions(self, org_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._subscriptions.values())
        if org_id is not None:
            items = [s for s in items if s.org_id == org_id]
        return [s.to_dict() for s in items]

    # ------------------------------------------------------------------
    # Reset (test isolation)
    # ------------------------------------------------------------------

    def reset_processed_events(self) -> None:
        """
        Clear _processed_event_ids and _idempotency_keys.
        Allows tests to re-submit previously seen event IDs and operation keys
        without resetting the full service state (subscriptions, balances, sessions).
        """
        with self._lock:
            self._processed_event_ids.clear()
            self._idempotency_keys.clear()

    def reset(self) -> None:
        """Full state reset. Intended for test isolation between test cases."""
        import app.core.unit_wallet as wallet_module

        with self._lock:
            self._checkout_sessions.clear()
            self._subscriptions.clear()
            self._unit_balances.clear()
            self._unit_ledger.clear()
            self._metered_usage_log.clear()
            self._org_customer_map.clear()
            self._customer_org_map.clear()
            self._payment_methods.clear()
            self._invoice_cache.clear()
            self._idempotency_keys.clear()
            self._processed_event_ids.clear()
            self._client = None
            self._webhook_secret_override = None

        wallet_module._unit_wallet_registry = wallet_module.UnitWalletRegistry()
        self._wallet_registry = wallet_module.get_unit_wallet_registry()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_STRIPE_SERVICE: StripeService = StripeService()


def get_stripe_service() -> StripeService:
    """Return the module-level StripeService singleton."""
    return _STRIPE_SERVICE


def reset_stripe_service() -> None:
    """Clear all Stripe state. Intended for use in tests."""
    _STRIPE_SERVICE.reset()
    import app.core.unit_wallet as wallet_module

    wallet_module._unit_wallet_registry = wallet_module.UnitWalletRegistry()
