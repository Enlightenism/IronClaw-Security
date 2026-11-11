from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from dataclasses import fields as dataclass_fields
from datetime import UTC, datetime
from enum import StrEnum
import hashlib
import hmac
import json
import logging
import math
import os
import re
from threading import Lock
import time
from typing import Any
from uuid import uuid4

from app.core.billing import PLAN_DEFINITIONS, TOKENS_PER_UNIT
from app.core.install_key_formats import InstallKeyFormatRegistry
from app.core.install_keys import (
    _read_event_ledger_record,
    _should_use_memory_fallback,
    _write_event_ledger_record,
    get_install_key_registry,
)
from app.core.supabase import get_supabase_service_client
from app.core.unit_wallet import get_unit_wallet_registry
from app.services.install_key_handoff import get_install_key_handoff_service
from app.services.install_key_provisioning import InstallKeyProvisioningService
from app.services.secrets_vault import vault


def provision_install_key_service(*, billing_registry: Any | None = None) -> InstallKeyProvisioningService:
    return InstallKeyProvisioningService(billing_registry=billing_registry)


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_STRIPE_API_BASE = "https://api.stripe.com/v1"
_STRIPE_TIMEOUT_SECONDS = 15
_STRIPE_CUSTOMER_LINKS_TABLE = "stripe_customer_links"
_CHECKOUT_CUSTOMER_LOOKUP_ERROR = "checkout_customer_lookup_unavailable"
_CHECKOUT_CUSTOMER_PERSIST_ERROR = "checkout_customer_persist_unavailable"
_CHECKOUT_FULFILLMENT_STORAGE_ERROR = "checkout_fulfillment_storage_unavailable"
_CHECKOUT_FULFILLMENT_PREFLIGHT_SESSION_ID = "cs_storage_preflight"
_METERED_USAGE_BUFFER_MAX = 500
_CHECKOUT_SESSION_TTL_SECONDS = 1800  # 30 min
_CHECKOUT_RECONCILE_PAGE_SIZE = 100
_CHECKOUT_RECONCILE_MAX_PAGES = 5
_CHECKOUT_EXPIRED_LOOKBACK_SECONDS = 24 * 60 * 60  # matches Stripe's default checkout expiry


def _customer_link_persistence_required() -> bool:
    persistence_mode = os.environ.get("IRONCLAW_PERSISTENCE_MODE", "").strip().lower()
    environment_name = (os.environ.get("IRONCLAW_ENV") or os.environ.get("APP_ENV") or os.environ.get("ENVIRONMENT", "")).strip().lower()
    return persistence_mode == "supabase" or environment_name in {"prod", "production"}


def _use_memory_customer_links() -> bool:
    use_memory = _should_use_memory_fallback()
    if use_memory and _customer_link_persistence_required():
        raise StripeServiceError("Stripe customer links require durable Supabase storage.")
    return use_memory


def _load_customer_link(*, org_id: str | None = None, customer_id: str | None = None) -> dict[str, Any] | None:
    if not (org_id or customer_id) or _use_memory_customer_links():
        return None
    try:
        query = get_supabase_service_client().table(_STRIPE_CUSTOMER_LINKS_TABLE).select("org_id,customer_id")
        query = query.eq("org_id", org_id) if org_id else query.eq("customer_id", customer_id)
        rows = query.limit(1).execute().data or []
        if isinstance(rows, dict):
            rows = [rows]
        return dict(rows[0]) if rows else None
    except Exception as exc:
        logger.warning(
            "stripe.customer_link_load_failed org=%s http_status=%s postgrest_code=%s",
            org_id or "",
            getattr(exc, "status_code", None),
            getattr(exc, "postgrest_code", None),
            exc_info=True,
        )
        if _customer_link_persistence_required():
            raise StripePersistenceError(
                "Stripe customer link could not be loaded from durable storage.",
                error_code=_CHECKOUT_CUSTOMER_LOOKUP_ERROR,
            ) from exc
        return None


def _persist_customer_link(org_id: str, customer_id: str) -> None:
    if _use_memory_customer_links():
        return
    try:
        get_supabase_service_client().table(_STRIPE_CUSTOMER_LINKS_TABLE).upsert(
            {"org_id": org_id, "customer_id": customer_id},
            on_conflict="org_id",
            returning="minimal",
        ).execute()
    except Exception as exc:
        logger.warning(
            "stripe.customer_link_persist_failed org=%s http_status=%s postgrest_code=%s",
            org_id,
            getattr(exc, "status_code", None),
            getattr(exc, "postgrest_code", None),
            exc_info=True,
        )
        if _customer_link_persistence_required():
            raise StripePersistenceError(
                "Stripe customer link could not be persisted to durable storage.",
                error_code=_CHECKOUT_CUSTOMER_PERSIST_ERROR,
            ) from exc


_SCHEMA_VERSION = "1.0"
_INVOICE_CACHE_MAX = 200
_STRIPE_CHECKOUT_SESSION_ID_PATTERN = re.compile(r"cs_[A-Za-z0-9_]{1,250}\Z")
_STRIPE_PAYMENT_INTENT_ID_PATTERN = re.compile(r"pi_[A-Za-z0-9_]{1,250}\Z")
_STRIPE_CHARGE_ID_PATTERN = re.compile(r"ch_[A-Za-z0-9_]{1,250}\Z")
_CHECKOUT_INTEGRITY_VERSION = "1"
_CHECKOUT_INTEGRITY_VERSION_KEY = "ironclaw_checkout_version"
_CHECKOUT_INTEGRITY_SIGNATURE_KEY = "ironclaw_checkout_signature"
_CHECKOUT_PRICE_ID_KEY = "ironclaw_checkout_price_id"
_CHECKOUT_QUANTITY_KEY = "ironclaw_checkout_quantity"
_CHECKOUT_MODE_KEY = "ironclaw_checkout_mode"

# ---------------------------------------------------------------------------
# Billing tier catalogue view derived from app.core.billing.PLAN_DEFINITIONS.
# ---------------------------------------------------------------------------

PACKAGE_CATALOGUE: dict[str, dict[str, Any]] = {
    plan["name"].casefold(): {
        "package_id": plan["package_id"],
        "aliases": list(plan["aliases"]),
        "label": plan["name"],
        "units": plan["unit_limit"],
        "price_usd": plan["price_usd"],
        "tokens_per_unit": plan["tokens_per_unit"],
        "token_coverage": plan["unit_limit"] * plan["tokens_per_unit"],
        "description": plan["description"],
        "featured": plan["featured"],
        "notes": f"{plan['unit_limit']:,} units · ${plan['price_usd']} USD · each unit protects up to {plan['tokens_per_unit']:,} tokens · no scan ceiling",
    }
    for plan in PLAN_DEFINITIONS.values()
}


def units_for_tokens(token_count: int) -> int:
    """
    Return the number of protection units required to cover token_count tokens.
    Each unit covers up to TOKENS_PER_UNIT tokens.
    Partial chunks consume a full unit. No ceiling — scales to any token count.

    Examples:
        units_for_tokens(1)                    → 1
        units_for_tokens(TOKENS_PER_UNIT)      → 1
        units_for_tokens(TOKENS_PER_UNIT + 1)  → 2
        units_for_tokens(3 * TOKENS_PER_UNIT)  → 3
        units_for_tokens(40 * TOKENS_PER_UNIT) → 40
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
    CHECKOUT_SESSION_ASYNC_PAYMENT_SUCCEEDED = "checkout.session.async_payment_succeeded"
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
            elif isinstance(obj, list | tuple):
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
        except (OSError, json.JSONDecodeError) as exc:
            raise StripeAPIError(
                message=f"Stripe request failed: {type(exc).__name__}",
                http_status=0,
                stripe_code=None,
                raw=None,
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
        except (OSError, json.JSONDecodeError) as exc:
            raise StripeAPIError(
                message=f"Stripe request failed: {type(exc).__name__}",
                http_status=0,
                stripe_code=None,
                raw=None,
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
        except (OSError, json.JSONDecodeError) as exc:
            raise StripeAPIError(
                message=f"Stripe request failed: {type(exc).__name__}",
                http_status=0,
                stripe_code=None,
                raw=None,
            ) from exc


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class StripeServiceError(Exception):
    """Base for all StripeService errors."""


class StripePersistenceError(StripeServiceError):
    """Raised when durable Stripe state cannot be read or written."""

    def __init__(self, message: str, *, error_code: str = "checkout_storage_unavailable") -> None:
        super().__init__(message)
        self.error_code = error_code


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


class StripeInstallKeyProvisioningError(StripeServiceError):
    """
    Raised when install-key issuance fails after the checkout's units were already credited.
    """


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
    - Each protection unit covers up to TOKENS_PER_UNIT tokens.
    - Scans are UNLIMITED — units auto-deduct in TOKENS_PER_UNIT chunks with no ceiling.
    - Package amounts and prices are sourced from the canonical package catalogue.
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

    def _resolve_wallet_owner_key(self, org_id: str, owner_key: str | None = None) -> str:
        if owner_key is None:
            return self._canonical_org_owner_key(org_id)
        normalized_owner_key = str(owner_key).strip().lower()
        if not normalized_owner_key:
            raise StripeServiceError("owner_key is required")
        return normalized_owner_key

    def _sync_balances_from_wallet(
        self,
        org_id: str,
        *,
        owner_key: str | None = None,
    ) -> UnitBalanceResponse:
        wallet_owner_key = self._resolve_wallet_owner_key(org_id, owner_key)
        wallet = self._wallet_registry.get_wallet(wallet_owner_key)
        if wallet is None:
            with self._lock:
                self._unit_balances[org_id] = 0
                self._unit_ledger.setdefault(org_id, [])
            return UnitBalanceResponse(org_id=org_id, balance=0, ledger_entries=[])

        entries = self._wallet_registry.list_ledger_entries(owner_key=wallet_owner_key, limit=50)
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
        existing = self.resolve_customer_id(org_id)
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

        idempotency_key = f"ironclaw-customer-{hashlib.sha256(org_id.strip().lower().encode()).hexdigest()}"
        resp = self._get_client().post("/customers", params, idempotency_key=idempotency_key)
        customer_id: str = resp["id"]

        _persist_customer_link(org_id, customer_id)
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
        _persist_customer_link(org_id, customer_id)
        with self._lock:
            self._org_customer_map[org_id] = customer_id
            self._customer_org_map[customer_id] = org_id

    @staticmethod
    def _is_successful_payment_status(value: Any) -> bool:
        normalized = str(value).strip().lower() if value is not None else ""
        return normalized in {"paid", "succeeded", "success"}

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
        payment_intent: str | None = None,
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

        candidate_owner_key = (metadata or {}).get("owner_key")
        owner_key = str(candidate_owner_key).strip() if candidate_owner_key else self._resolve_owner_key_for_org(org_id)
        if not owner_key:
            raise StripeServiceError("A verified billing owner is required to provision install keys.")

        class _CheckoutEntitlementGuard:
            def has_active_subscription(self, candidate_owner_key: str) -> bool:
                normalized = str(candidate_owner_key).strip().lower()
                return normalized == owner_key.lower()

        provisioning_service = provision_install_key_service(
            billing_registry=_CheckoutEntitlementGuard(),
        )
        results: dict[str, dict[str, Any]] = {}
        base_metadata: dict[str, Any] = dict(metadata or {})
        base_metadata.update(
            {
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
        )
        base_metadata["owner_key"] = owner_key
        if payment_intent:
            base_metadata["payment_intent"] = payment_intent

        supported_programs = tuple(InstallKeyFormatRegistry.list_programs())

        failed_programs: list[str] = []
        for program in supported_programs:
            try:
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
            except Exception as exc:  # noqa: BLE001
                failed_programs.append(program)
                logger.error(
                    "stripe.checkout_install_key_program_failed org=%s session=%s program=%s error_type=%s",
                    org_id,
                    session_id,
                    program,
                    type(exc).__name__,
                )
                continue
            record = issued.record
            results[program] = {
                "key_id": record.key_id,
                "owner_key": record.owner_key,
                "program": record.program,
                "active": record.active,
                "masked_key": record.masked_key,
                "subscription_id": record.subscription_id,
            }

        if failed_programs:
            raise StripeServiceError(f"Install key issuance failed for programs: {', '.join(failed_programs)}.")

        return results

    def resolve_org_from_customer(self, customer_id: str) -> str | None:
        with self._lock:
            org_id = self._customer_org_map.get(customer_id)
        if org_id:
            return org_id
        row = _load_customer_link(customer_id=customer_id)
        org_id = str(row.get("org_id") or "").strip() if row else ""
        if not org_id:
            return None
        self._remember_customer_link(org_id, customer_id)
        return org_id

    def resolve_customer_id(self, org_id: str) -> str | None:
        with self._lock:
            customer_id = self._org_customer_map.get(org_id)
        if customer_id:
            return customer_id
        row = _load_customer_link(org_id=org_id)
        customer_id = str(row.get("customer_id") or "").strip() if row else ""
        if not customer_id:
            return None
        self._remember_customer_link(org_id, customer_id)
        return customer_id

    def _remember_customer_link(self, org_id: str, customer_id: str) -> None:
        with self._lock:
            self._org_customer_map.setdefault(org_id, customer_id)
            self._customer_org_map.setdefault(customer_id, org_id)

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
        """Return the customer's current saved card methods from Stripe."""
        customer = self._get_client().get(f"/customers/{customer_id}")
        if not isinstance(customer, dict):
            raise StripeServiceError("Stripe returned an invalid customer response.")

        invoice_settings = customer.get("invoice_settings")
        if not isinstance(invoice_settings, dict):
            invoice_settings = {}
        default_method = invoice_settings.get("default_payment_method")
        default_method_id = default_method.get("id") if isinstance(default_method, dict) else default_method
        response = self._get_client().get(
            "/payment_methods",
            {"customer": customer_id, "type": "card", "limit": "100"},
        )
        raw_methods = response.get("data") if isinstance(response, dict) else None
        if not isinstance(raw_methods, list):
            raise StripeServiceError("Stripe returned an invalid payment-method list.")

        records: list[_PaymentMethodRecord] = []
        for raw_method in raw_methods:
            if not isinstance(raw_method, dict):
                raise StripeServiceError("Stripe returned an invalid saved payment method.")
            payment_method_id = str(raw_method.get("id") or "").strip()
            card = raw_method.get("card")
            if not payment_method_id or not isinstance(card, dict):
                raise StripeServiceError("Stripe returned an incomplete saved payment method.")
            raw_customer_id = raw_method.get("customer")
            if isinstance(raw_customer_id, dict):
                raw_customer_id = raw_customer_id.get("id")
            if raw_customer_id and str(raw_customer_id) != customer_id:
                raise StripeServiceError("Stripe returned a payment method for a different customer.")
            created = raw_method.get("created")
            if isinstance(created, int | float):
                created_at = datetime.fromtimestamp(created, UTC).isoformat()
            else:
                created_at = str(raw_method.get("created_at") or _utcnow_iso())
            records.append(
                _PaymentMethodRecord(
                    payment_method_id=payment_method_id,
                    customer_id=customer_id,
                    type=str(raw_method.get("type") or "card"),
                    brand=str(card.get("brand") or "unknown"),
                    last4=str(card.get("last4") or ""),
                    exp_month=int(card.get("exp_month") or 0),
                    exp_year=int(card.get("exp_year") or 0),
                    is_default=str(default_method_id or "") == payment_method_id,
                    created_at=created_at,
                )
            )

        with self._lock:
            self._payment_methods = {method_id: record for method_id, record in self._payment_methods.items() if record.customer_id != customer_id}
            self._payment_methods.update({record.payment_method_id: record for record in records})

        return [PaymentMethodResponse(**record.to_dict(), schema_version=_SCHEMA_VERSION) for record in records]

    def set_default_payment_method(
        self,
        customer_id: str,
        payment_method_id: str,
    ) -> PaymentMethodResponse:
        """
        Set the specified payment method as the Stripe customer default.
        Raises StripePaymentMethodNotFoundError if the method is not cached for
        this customer, and propagates Stripe API failures without changing cache.
        """
        with self._lock:
            record = self._payment_methods.get(payment_method_id)
            if record is None or record.customer_id != customer_id:
                raise StripePaymentMethodNotFoundError(payment_method_id)

        self._get_client().post(
            f"/customers/{customer_id}",
            {"invoice_settings[default_payment_method]": payment_method_id},
        )

        with self._lock:
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
            customer_id = self.resolve_customer_id(org_id) or ""
            normalized = [_normalize_stripe_invoice(r, org_id, customer_id) for r in cached]
            return [InvoiceResponse(**_filter_to_dataclass_fields(InvoiceResponse, r)) for r in normalized]

        customer_id = self.resolve_customer_id(org_id) or ""
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

    @staticmethod
    def _checkout_integrity_payload(metadata: dict[str, Any]) -> bytes:
        payload = {
            "version": str(metadata.get(_CHECKOUT_INTEGRITY_VERSION_KEY) or ""),
            "org_id": str(metadata.get("org_id") or ""),
            "owner_key": str(metadata.get("owner_key") or "").strip().lower(),
            "package_id": str(metadata.get("package_id") or ""),
            "price_id": str(metadata.get(_CHECKOUT_PRICE_ID_KEY) or ""),
            "quantity": str(metadata.get(_CHECKOUT_QUANTITY_KEY) or ""),
            "unit_credits": str(metadata.get("unit_credits") or ""),
            "mode": str(metadata.get(_CHECKOUT_MODE_KEY) or ""),
        }
        if "save_card" in metadata:
            payload["save_card"] = str(metadata.get("save_card") or "").lower()
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")

    def _sign_checkout_integrity_metadata(self, metadata: dict[str, Any]) -> str:
        secret = self._get_webhook_secret().encode("utf-8")
        return hmac.new(secret, self._checkout_integrity_payload(metadata), hashlib.sha256).hexdigest()

    def _verify_checkout_integrity_metadata(
        self,
        metadata: dict[str, Any],
        *,
        mode: str | None = None,
    ) -> dict[str, Any]:
        if metadata.get(_CHECKOUT_INTEGRITY_VERSION_KEY) != _CHECKOUT_INTEGRITY_VERSION:
            raise StripeServiceError("Checkout session is missing trusted IronClaw integrity metadata.")

        org_id = metadata.get("org_id")
        if not isinstance(org_id, str) or not org_id.strip():
            raise StripeServiceError("Checkout session is missing its trusted organization identity.")

        raw_unit_credits = metadata.get("unit_credits")
        try:
            unit_credits = int(raw_unit_credits)
        except (TypeError, ValueError) as exc:
            raise StripeServiceError("Checkout session contains invalid trusted unit metadata.") from exc
        if unit_credits < 0:
            raise StripeServiceError("Checkout session contains invalid trusted unit metadata.")

        raw_quantity = metadata.get(_CHECKOUT_QUANTITY_KEY)
        try:
            quantity = int(raw_quantity)
        except (TypeError, ValueError) as exc:
            raise StripeServiceError("Checkout session contains invalid trusted quantity metadata.") from exc
        if quantity < 1:
            raise StripeServiceError("Checkout session contains invalid trusted quantity metadata.")

        price_id = metadata.get(_CHECKOUT_PRICE_ID_KEY)
        if not isinstance(price_id, str) or not price_id.strip():
            raise StripeServiceError("Checkout session is missing its trusted Stripe price.")

        checkout_mode = metadata.get(_CHECKOUT_MODE_KEY)
        if not isinstance(checkout_mode, str) or checkout_mode not in {item.value for item in StripeCheckoutMode}:
            raise StripeServiceError("Checkout session contains an invalid trusted mode.")
        if mode is not None and mode != checkout_mode:
            raise StripeServiceError("Checkout session mode does not match its trusted metadata.")

        raw_owner_key = metadata.get("owner_key")
        if raw_owner_key is not None and (not isinstance(raw_owner_key, str) or not raw_owner_key.strip()):
            raise StripeServiceError("Checkout session contains an invalid trusted billing owner.")

        package_id = metadata.get("package_id")
        if package_id is not None and not isinstance(package_id, str):
            raise StripeServiceError("Checkout session contains an invalid trusted package.")

        raw_save_card = metadata.get("save_card")
        if raw_save_card not in {None, "true", "false"}:
            raise StripeServiceError("Checkout session contains invalid saved-payment-method consent metadata.")

        signature = metadata.get(_CHECKOUT_INTEGRITY_SIGNATURE_KEY)
        if not isinstance(signature, str) or not hmac.compare_digest(
            signature,
            self._sign_checkout_integrity_metadata(metadata),
        ):
            raise StripeServiceError("Checkout session integrity verification failed.")

        return {
            "org_id": org_id,
            "owner_key": raw_owner_key.strip().lower() if isinstance(raw_owner_key, str) else None,
            "package_id": package_id.strip() if isinstance(package_id, str) else "",
            "price_id": price_id.strip(),
            "quantity": quantity,
            "unit_credits": unit_credits,
            "mode": checkout_mode,
            "save_card": raw_save_card == "true",
        }

    def _is_payment_intent_refunded(self, payment_intent_id: str) -> bool:
        normalized_id = str(payment_intent_id or "").strip()
        if not _STRIPE_PAYMENT_INTENT_ID_PATTERN.fullmatch(normalized_id):
            raise StripeServiceError("Paid checkout contains an invalid PaymentIntent ID.")

        try:
            if self._wallet_registry.is_payment_refunded(normalized_id):
                return True
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "stripe.checkout_refund_marker_lookup_failed payment_intent=%s",
                hashlib.sha256(normalized_id.encode("utf-8")).hexdigest()[:12],
            )
            raise StripePersistenceError("The durable refund status is unavailable; checkout fulfillment was not applied.") from exc

        try:
            payment_intent = self._get_client().get(
                f"/payment_intents/{normalized_id}",
                params={"expand[]": "latest_charge"},
            )
        except StripeAPIError as exc:
            fingerprint = hashlib.sha256(normalized_id.encode("utf-8")).hexdigest()[:12]
            logger.warning(
                "stripe.checkout_refund_status_unavailable payment_intent=%s http_status=%s",
                fingerprint,
                exc.http_status,
            )
            raise StripeServiceError("Stripe could not verify the payment refund status; fulfillment was not applied.") from exc

        if payment_intent.get("id") != normalized_id:
            raise StripeServiceError("Stripe returned a mismatched PaymentIntent.")
        if payment_intent.get("status") != "succeeded":
            raise StripeServiceError("Stripe has not confirmed a successful PaymentIntent.")

        latest_charge = payment_intent.get("latest_charge")
        if isinstance(latest_charge, str):
            charge_id = latest_charge.strip()
            if not _STRIPE_CHARGE_ID_PATTERN.fullmatch(charge_id):
                raise StripeServiceError("Stripe returned an invalid charge for the PaymentIntent.")
            try:
                charge = self._get_client().get(f"/charges/{charge_id}")
            except StripeAPIError as exc:
                fingerprint = hashlib.sha256(normalized_id.encode("utf-8")).hexdigest()[:12]
                logger.warning(
                    "stripe.checkout_refund_status_unavailable payment_intent=%s http_status=%s",
                    fingerprint,
                    exc.http_status,
                )
                raise StripeServiceError("Stripe could not verify the payment refund status; fulfillment was not applied.") from exc
            if charge.get("id") != charge_id:
                raise StripeServiceError("Stripe returned a mismatched charge for the PaymentIntent.")
        elif isinstance(latest_charge, dict):
            charge = latest_charge
            charge_id = str(charge.get("id") or "").strip()
            if not _STRIPE_CHARGE_ID_PATTERN.fullmatch(charge_id):
                raise StripeServiceError("Stripe returned an invalid charge for the PaymentIntent.")
        else:
            raise StripeServiceError("Stripe did not return a charge for the PaymentIntent.")

        charge_payment_intent = charge.get("payment_intent")
        if isinstance(charge_payment_intent, dict):
            charge_payment_intent = charge_payment_intent.get("id")
        if charge_payment_intent != normalized_id:
            raise StripeServiceError("Stripe returned a charge for a different PaymentIntent.")

        refunded = charge.get("refunded")
        if not isinstance(refunded, bool):
            raise StripeServiceError("Stripe returned an invalid charge refund status.")
        try:
            amount_refunded = int(charge.get("amount_refunded", 0) or 0)
        except (TypeError, ValueError) as exc:
            raise StripeServiceError("Stripe returned an invalid refunded amount.") from exc
        if amount_refunded < 0:
            raise StripeServiceError("Stripe returned an invalid refunded amount.")

        if refunded or amount_refunded > 0:
            if amount_refunded <= 0:
                raise StripeServiceError("Stripe reported a refund without a positive refunded amount.")
            try:
                self._wallet_registry.mark_payment_refunded(
                    normalized_id,
                    charge_id=charge_id,
                    amount_refunded=amount_refunded,
                    reason="stripe_refund_status_confirmed",
                    metadata={"source": "payment_intent_verification"},
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception(
                    "stripe.checkout_refund_marker_write_failed payment_intent=%s",
                    hashlib.sha256(normalized_id.encode("utf-8")).hexdigest()[:12],
                )
                raise StripePersistenceError("Stripe confirmed a refund, but the durable refund marker could not be saved.") from exc
            return True

        return False

    def _record_checkout_fulfillment(
        self,
        *,
        session_id: str,
        org_id: str,
        owner_key: str,
        package_id: str,
        units: int,
        payment_intent: str | None,
        customer_id: str | None,
        save_card: bool,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        from app.services.billing_store import get_stripe_checkout_fulfillment_store

        try:
            return get_stripe_checkout_fulfillment_store().record_checkout(
                session_id=session_id,
                owner_key=owner_key,
                org_id=org_id,
                package_id=package_id,
                units=units,
                payment_intent=payment_intent,
                customer_id=customer_id,
                save_card=save_card,
                metadata=metadata,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("stripe.checkout_fulfillment_record_write_failed session=%s", session_id)
            raise StripePersistenceError(
                "The durable checkout fulfillment record could not be saved; retry or contact support.",
                error_code=_CHECKOUT_FULFILLMENT_STORAGE_ERROR,
            ) from exc

    def _verify_checkout_fulfillment_storage(self) -> None:
        from app.services.billing_store import get_stripe_checkout_fulfillment_store

        try:
            store = get_stripe_checkout_fulfillment_store()
            store.get_by_session(_CHECKOUT_FULFILLMENT_PREFLIGHT_SESSION_ID)
            store.verify_rpc_functions()
        except Exception as exc:  # noqa: BLE001
            logger.exception("stripe.checkout_fulfillment_preflight_failed")
            raise StripePersistenceError(
                "The durable checkout fulfillment storage is unavailable; no checkout session was created.",
                error_code=_CHECKOUT_FULFILLMENT_STORAGE_ERROR,
            ) from exc

    def _mark_checkout_fulfillment(
        self,
        session_id: str,
        *,
        status: str,
        units_credited: bool | None = None,
        install_keys_provisioned: bool | None = None,
        last_error: str | None = None,
    ) -> dict[str, Any]:
        from app.services.billing_store import get_stripe_checkout_fulfillment_store

        try:
            return get_stripe_checkout_fulfillment_store().mark(
                session_id,
                status=status,
                units_credited=units_credited,
                install_keys_provisioned=install_keys_provisioned,
                last_error=last_error,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("stripe.checkout_fulfillment_status_write_failed session=%s status=%s", session_id, status)
            raise StripePersistenceError("The durable checkout fulfillment status could not be saved; retry or contact support.") from exc

    def _get_checkout_fulfillment_by_payment_intent(self, payment_intent: str) -> dict[str, Any] | None:
        from app.services.billing_store import get_stripe_checkout_fulfillment_store

        try:
            return get_stripe_checkout_fulfillment_store().get_by_payment_intent(payment_intent)
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "stripe.checkout_fulfillment_lookup_failed payment_intent=%s",
                hashlib.sha256(payment_intent.encode("utf-8")).hexdigest()[:12],
            )
            raise StripePersistenceError("The durable checkout fulfillment record could not be loaded.") from exc

    def _revoke_checkout_entitlements_for_refund(
        self,
        *,
        session_id: str,
        payment_intent: str,
        owner_key: str,
    ) -> dict[str, int]:
        from app.core.install_keys import get_install_key_registry
        from app.services.billing_store import get_billing_store
        from app.services.install_key_handoff import get_install_key_handoff_service

        normalized_owner = str(owner_key or "").strip().lower()
        if not normalized_owner:
            raise StripeServiceError("A verified wallet owner is required to revoke refunded checkout entitlements.")

        revoked_keys = get_install_key_registry().revoke_keys_for_refund(
            checkout_session_ids={session_id},
            payment_intent=payment_intent,
        )
        revoked_units = self._wallet_registry.revoke_units_for_refund(
            [normalized_owner],
            payment_intent=payment_intent,
            checkout_session_id=session_id,
            reason="refund",
        )
        units_revoked = sum(revoked_units.values())
        for reference, amount in sorted(revoked_units.items()):
            get_billing_store().revoke_units(
                f"checkout:{reference}",
                amount,
                metadata={
                    "event_id": f"refund_revoke:{reference}",
                    "checkout_session_id": reference,
                    "payment_intent": payment_intent,
                    "reason": "refund",
                },
            )

        handoff_service = get_install_key_handoff_service()
        handoff_service.revoke_unredeemed_claims([record.key_id for record in revoked_keys])
        handoff_service.clear_claims_for_purchase(session_id)
        return {
            "install_keys_revoked": len(revoked_keys),
            "units_revoked": units_revoked,
        }

    def create_payment_method_setup_session(
        self,
        *,
        org_id: str,
        customer_id: str,
        success_url: str,
        cancel_url: str,
    ) -> dict[str, str]:
        normalized_org_id = str(org_id).strip()
        normalized_customer_id = str(customer_id).strip()
        if not normalized_org_id or not normalized_customer_id:
            raise StripeServiceError("org_id and customer_id are required for payment method setup")
        if not success_url.strip() or not cancel_url.strip():
            raise StripeServiceError("success_url and cancel_url are required")

        params = {
            "mode": StripeCheckoutMode.SETUP.value,
            "success_url": success_url.strip(),
            "cancel_url": cancel_url.strip(),
            "customer": normalized_customer_id,
            "payment_method_types[0]": "card",
            "metadata[org_id]": normalized_org_id,
            "metadata[ironclaw_source]": "ironclaw-security",
            "metadata[flow]": "saved_payment_method_setup",
        }
        try:
            response = self._get_client().post("/checkout/sessions", params)
        except StripeAPIError:
            logger.exception(
                "stripe.payment_method_setup_session_create_failed org=%s",
                normalized_org_id,
            )
            raise

        session_id = str(response.get("id") or "").strip()
        checkout_url = str(response.get("url") or "").strip()
        if not session_id or not checkout_url:
            raise StripeServiceError("Stripe returned an incomplete payment method setup session.")

        return {
            "session_id": session_id,
            "checkout_url": checkout_url,
            "org_id": normalized_org_id,
            "mode": StripeCheckoutMode.SETUP.value,
        }

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
        owner_key: str | None = None,
        metadata: dict[str, Any] | None = None,
        save_card: bool = False,
    ) -> CheckoutSessionResponse:
        """
        Create a Stripe Checkout Session.

        - mode=payment: one-time purchase that grants unit_credits on completion.
        - mode=subscription: recurring subscription with optional metered usage.
        - unit_credits: number of IronClaw units to credit on checkout.session.completed.
          Each unit protects up to TOKENS_PER_UNIT tokens with no scan ceiling.
          Use units_for_tokens(n) to derive the correct unit_credits from a token budget.
        - Checkout metadata is authenticated with the configured Stripe webhook secret so
          webhook fulfillment can reject client-influenced or legacy session metadata.

        Package amounts and prices are derived from PACKAGE_CATALOGUE.
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
        if mode == StripeCheckoutMode.PAYMENT and not str(org_id).strip():
            raise StripeServiceError("org_id is required for payment checkout")
        if mode == StripeCheckoutMode.PAYMENT and unit_credits > 0:
            if not owner_key or not str(owner_key).strip():
                raise StripeServiceError("An authenticated billing owner is required for unit package checkout")
            if not str((metadata or {}).get("package_id") or "").strip():
                raise StripeServiceError("A trusted package_id is required for unit package checkout")

        now = _utcnow_iso()
        price_id = price_id.strip()
        session_meta: dict[str, Any] = dict(metadata or {})
        session_meta.update(
            {
                "org_id": org_id,
                "unit_credits": str(unit_credits),
                "tokens_per_unit": str(TOKENS_PER_UNIT),
                "ironclaw_source": "ironclaw-security",
                _CHECKOUT_INTEGRITY_VERSION_KEY: _CHECKOUT_INTEGRITY_VERSION,
                _CHECKOUT_PRICE_ID_KEY: price_id,
                _CHECKOUT_QUANTITY_KEY: str(quantity),
                _CHECKOUT_MODE_KEY: mode.value,
            }
        )
        if owner_key is not None:
            normalized_owner_key = str(owner_key).strip().lower()
            if not normalized_owner_key:
                raise StripeServiceError("owner_key must be a non-empty authenticated billing identity")
            session_meta["owner_key"] = normalized_owner_key
        else:
            session_meta.pop("owner_key", None)
        if mode == StripeCheckoutMode.PAYMENT:
            session_meta["save_card"] = "true" if save_card else "false"
        else:
            session_meta.pop("save_card", None)
        session_meta[_CHECKOUT_INTEGRITY_SIGNATURE_KEY] = self._sign_checkout_integrity_metadata(session_meta)

        # Storage checks and the customer mapping run before the session POST so a storage failure
        # cannot leave an orphaned Stripe session behind. Failures raise StripePersistenceError here.
        if mode == StripeCheckoutMode.PAYMENT and unit_credits > 0:
            self._verify_checkout_fulfillment_storage()
        if not customer_id and org_id:
            customer_id = self.get_or_create_stripe_customer(org_id)

        params: dict[str, Any] = {
            "mode": mode.value,
            "success_url": success_url,
            "cancel_url": cancel_url,
            "line_items[0][price]": price_id,
            "line_items[0][quantity]": str(quantity),
        }

        if mode == StripeCheckoutMode.PAYMENT:
            params["payment_method_types[0]"] = "card"
            if save_card:
                params["payment_intent_data[setup_future_usage]"] = "off_session"
            if not customer_id:
                params["customer_creation"] = "always"

        # Carry the buyer's owner key onto the subscription so renewal credits land in the same wallet.
        if mode == StripeCheckoutMode.SUBSCRIPTION and session_meta.get("owner_key"):
            params["subscription_data[metadata][owner_key]"] = str(session_meta["owner_key"])

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
        checkout_customer_id = customer_id or resp.get("customer")
        expires_at: str | None = None
        if resp.get("expires_at"):
            try:
                expires_at = datetime.fromtimestamp(int(resp["expires_at"]), tz=UTC).isoformat().replace("+00:00", "Z")
            except (ValueError, TypeError):
                expires_at = None

        if mode == StripeCheckoutMode.PAYMENT and unit_credits > 0:
            payment_intent_raw = resp.get("payment_intent")
            if isinstance(payment_intent_raw, dict):
                payment_intent_raw = payment_intent_raw.get("id")
            payment_intent_id = str(payment_intent_raw or "").strip() or None
            self._record_checkout_fulfillment(
                session_id=session_id,
                org_id=org_id,
                owner_key=str(session_meta["owner_key"]),
                package_id=str(session_meta["package_id"]),
                units=unit_credits,
                payment_intent=payment_intent_id,
                customer_id=checkout_customer_id,
                save_card=save_card,
                metadata=session_meta,
            )

        record = _CheckoutSessionRecord(
            session_id=session_id,
            org_id=org_id,
            customer_id=checkout_customer_id,
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
        """Compatibility wrapper using verified Stripe state and canonical fulfillment."""
        del customer_id, org_id
        return self.reconcile_checkout_session(session_id)

    def get_checkout_session(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            record = self._checkout_sessions.get(session_id)
        return record.to_dict() if record else None

    def reconcile_checkout_session(self, session_id: str) -> dict[str, Any]:
        normalized_session_id = str(session_id).strip()
        if not _STRIPE_CHECKOUT_SESSION_ID_PATTERN.fullmatch(normalized_session_id):
            raise StripeSessionNotFoundError("checkout session not found")

        try:
            payload = self._get_client().get(f"/checkout/sessions/{normalized_session_id}")
        except StripeAPIError as exc:
            if exc.http_status == 404:
                raise StripeSessionNotFoundError("checkout session not found") from exc
            raise

        if payload.get("id") != normalized_session_id:
            raise StripeServiceError("Stripe returned a mismatched checkout session.")
        return self._handle_checkout_completed(payload, {})

    def reconcile_owner_checkout_sessions(self, owner_key: str) -> dict[str, Any]:
        normalized_owner = str(owner_key).strip().lower()
        if not normalized_owner:
            return {
                "status": "owner_unavailable",
                "pages_scanned": 0,
                "sessions_scanned": 0,
                "sessions_matched": 0,
                "sessions_reconciled": 0,
                "units_credited": 0,
                "sessions": [],
                "truncated": False,
            }

        pages_scanned = 0
        sessions_scanned = 0
        sessions_matched = 0
        sessions: list[dict[str, Any]] = []
        cursor: str | None = None
        has_more = False
        seen_cursors: set[str] = set()

        for _ in range(_CHECKOUT_RECONCILE_MAX_PAGES):
            params: dict[str, Any] = {
                "limit": _CHECKOUT_RECONCILE_PAGE_SIZE,
                "status": "complete",
            }
            if cursor:
                params["starting_after"] = cursor

            payload = self._get_client().get("/checkout/sessions", params=params)
            rows = payload.get("data") if isinstance(payload, dict) else None
            if not isinstance(rows, list):
                raise StripeServiceError("Stripe returned an invalid checkout session list.")
            has_more_value = payload.get("has_more", False)
            if not isinstance(has_more_value, bool):
                raise StripeServiceError("Stripe returned an invalid checkout session page status.")

            pages_scanned += 1
            sessions_scanned += len(rows)
            has_more = has_more_value

            for row in rows:
                if not isinstance(row, dict):
                    continue
                if row.get("mode") != StripeCheckoutMode.PAYMENT.value or row.get("payment_status") != "paid":
                    continue
                metadata = row.get("metadata")
                if not isinstance(metadata, dict) or str(metadata.get("owner_key") or "").strip().lower() != normalized_owner:
                    continue

                sessions_matched += 1
                session_id = row.get("id")
                try:
                    if not isinstance(session_id, str) or not _STRIPE_CHECKOUT_SESSION_ID_PATTERN.fullmatch(session_id):
                        raise StripeServiceError("Stripe returned an invalid checkout session ID.")
                    org_id = metadata.get("org_id")
                    if not isinstance(org_id, str) or not org_id.strip():
                        raise StripeServiceError("Checkout session is missing its trusted organization identity.")
                    integrity = self._verify_checkout_integrity_metadata(metadata, mode=row.get("mode"))
                    expected_units = int(integrity["unit_credits"])
                    units_before = self.get_checkout_units_credited(
                        session_id,
                        org_id,
                        owner_key=normalized_owner,
                    )
                    fulfillment = self._handle_checkout_completed(row, {})
                    if fulfillment.get("fulfillment_status") == "refunded":
                        sessions.append(
                            {
                                "session_id": session_id,
                                "status": "refunded",
                                "fulfillment_status": "refunded",
                                "units_credited": 0,
                                "action": "contact_support",
                                "support_reference": session_id,
                                "error": ("Stripe confirms this checkout payment was refunded; no active wallet credit or install keys remain."),
                            },
                        )
                        continue
                    if fulfillment.get("payment_confirmed") is not True:
                        raise StripeServiceError("Stripe has not confirmed payment for this checkout session.")

                    credited_units = self.get_checkout_units_credited(
                        session_id,
                        org_id,
                        owner_key=normalized_owner,
                    )
                    if credited_units != expected_units:
                        raise StripeServiceError(f"Stripe confirmed payment for {expected_units} units, but the wallet ledger shows {credited_units}.")
                    sessions.append(
                        {
                            "session_id": session_id,
                            "status": "fulfilled",
                            "fulfillment_status": "fulfilled",
                            "units_credited": credited_units,
                            "newly_credited_units": max(0, credited_units - units_before),
                            "action": "none",
                            "support_reference": session_id,
                        },
                    )
                except StripeServiceError as exc:
                    logger.warning(
                        "stripe.checkout_reconcile_failed session=%s error_type=%s",
                        session_id or "",
                        type(exc).__name__,
                    )
                    sessions.append(
                        {
                            "session_id": session_id,
                            "status": "failed",
                            "fulfillment_status": "failed",
                            "error": str(exc),
                            "action": "retry_sync",
                            "support_reference": session_id,
                        },
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.exception(
                        "stripe.checkout_reconcile_unexpected_error session=%s error_type=%s",
                        session_id or "",
                        type(exc).__name__,
                    )
                    sessions.append(
                        {
                            "session_id": session_id,
                            "status": "failed",
                            "fulfillment_status": "failed",
                            "error": "Checkout fulfillment failed unexpectedly. Retry or contact support.",
                            "action": "contact_support",
                            "support_reference": session_id,
                        },
                    )

            if not has_more:
                break
            if not rows:
                raise StripeServiceError("Stripe returned an empty checkout page while more sessions were available.")
            next_cursor = rows[-1].get("id") if isinstance(rows[-1], dict) else None
            if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen_cursors:
                raise StripeServiceError("Stripe returned an invalid checkout pagination cursor.")
            seen_cursors.add(next_cursor)
            cursor = next_cursor

        try:
            # Expired-session reporting is informational; a failure here must not block wallet reconciliation.
            expired_checkouts = self._list_owner_expired_checkouts(normalized_owner)
        except StripeServiceError:
            logger.warning("stripe.expired_checkout_scan_failed")
            expired_checkouts = []
        successful_sessions = [session for session in sessions if session["status"] == "fulfilled"]
        failed_sessions = [session for session in sessions if session["status"] != "fulfilled"]
        status_value = "partial" if failed_sessions or has_more else "complete"
        if sessions_matched == 0 and not has_more:
            status_value = "no_paid_sessions_found"
        return {
            "status": status_value,
            "pages_scanned": pages_scanned,
            "sessions_scanned": sessions_scanned,
            "sessions_matched": sessions_matched,
            "sessions_reconciled": len(successful_sessions),
            "units_credited": sum(int(session["units_credited"]) for session in successful_sessions),
            "newly_credited_units": sum(int(session["newly_credited_units"]) for session in successful_sessions),
            "sessions": sessions,
            "expired_checkouts": expired_checkouts,
            "truncated": has_more,
        }

    def _list_owner_expired_checkouts(self, owner_key: str) -> list[dict[str, Any]]:
        expired_checkouts: list[dict[str, Any]] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()

        for _ in range(_CHECKOUT_RECONCILE_MAX_PAGES):
            params: dict[str, Any] = {
                "limit": _CHECKOUT_RECONCILE_PAGE_SIZE,
                "status": "expired",
                "created[gte]": int(time.time()) - _CHECKOUT_EXPIRED_LOOKBACK_SECONDS,
            }
            if cursor:
                params["starting_after"] = cursor

            payload = self._get_client().get("/checkout/sessions", params=params)
            rows = payload.get("data") if isinstance(payload, dict) else None
            if not isinstance(rows, list):
                raise StripeServiceError("Stripe returned an invalid checkout session list.")
            has_more = payload.get("has_more", False)
            if not isinstance(has_more, bool):
                raise StripeServiceError("Stripe returned an invalid checkout session page status.")

            for row in rows:
                if not isinstance(row, dict):
                    continue
                if row.get("mode") != StripeCheckoutMode.PAYMENT.value or row.get("payment_status") == "paid":
                    continue
                metadata = row.get("metadata")
                if not isinstance(metadata, dict) or str(metadata.get("owner_key") or "").strip().lower() != owner_key:
                    continue
                session_id = row.get("id")
                if not isinstance(session_id, str) or not _STRIPE_CHECKOUT_SESSION_ID_PATTERN.fullmatch(session_id):
                    continue
                expired_checkouts.append(
                    {
                        "session_id": session_id,
                        "status": "expired",
                        "units_credited": 0,
                        "action": "none",
                    },
                )

            if not has_more:
                break
            next_cursor = rows[-1].get("id") if rows and isinstance(rows[-1], dict) else None
            if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen_cursors:
                raise StripeServiceError("Stripe returned an invalid checkout pagination cursor.")
            seen_cursors.add(next_cursor)
            cursor = next_cursor

        return expired_checkouts

    def retrieve_checkout_session(self, session_id: str) -> dict[str, Any]:
        normalized_session_id = str(session_id).strip()
        if not _STRIPE_CHECKOUT_SESSION_ID_PATTERN.fullmatch(normalized_session_id):
            raise StripeSessionNotFoundError("checkout session not found")

        try:
            payload = self._get_client().get(
                f"/checkout/sessions/{normalized_session_id}",
                params={"expand[]": "line_items"},
            )
        except StripeAPIError as exc:
            if exc.http_status == 404:
                raise StripeSessionNotFoundError("checkout session not found") from exc
            raise

        if payload.get("id") != normalized_session_id:
            raise StripeServiceError("Stripe returned a mismatched checkout session.")

        metadata_value = payload.get("metadata", {})
        metadata = metadata_value if isinstance(metadata_value, dict) else {}
        integrity = self._verify_checkout_integrity_metadata(metadata, mode=payload.get("mode"))
        unit_credits = integrity["unit_credits"]
        price_id = integrity["price_id"]
        quantity = integrity["quantity"]
        line_items_value = payload.get("line_items")
        if isinstance(line_items_value, dict):
            line_items = line_items_value.get("data")
            if line_items is not None and not isinstance(line_items, list):
                raise StripeServiceError("Stripe returned invalid checkout line-item metadata.")
        elif isinstance(line_items_value, list):
            line_items = line_items_value
        elif line_items_value is None:
            line_items = None
        else:
            raise StripeServiceError("Stripe returned invalid checkout line-item metadata.")

        if isinstance(line_items, list) and line_items:
            if len(line_items) != 1:
                raise StripeServiceError("Stripe returned an unexpected number of checkout line items.")
            first_item = line_items[0]
            if not isinstance(first_item, dict):
                raise StripeServiceError("Stripe returned invalid checkout line-item metadata.")
            price_value = first_item.get("price")
            actual_price_id = price_value.get("id") if isinstance(price_value, dict) else price_value
            try:
                actual_quantity = int(first_item.get("quantity"))
            except (TypeError, ValueError) as exc:
                raise StripeServiceError("Stripe returned invalid checkout line-item metadata.") from exc
            if not isinstance(actual_price_id, str) or actual_price_id != price_id or actual_quantity != quantity:
                raise StripeServiceError("Stripe checkout line items do not match trusted purchase metadata.")

        created_at = None
        raw_created_at = payload.get("created")
        if raw_created_at is not None:
            try:
                created_at = datetime.fromtimestamp(int(raw_created_at), tz=UTC).isoformat().replace("+00:00", "Z")
            except (OverflowError, OSError, TypeError, ValueError) as exc:
                raise StripeServiceError("Stripe returned an invalid checkout creation timestamp.") from exc

        expires_at = None
        raw_expires_at = payload.get("expires_at")
        if raw_expires_at is not None:
            try:
                expires_at = datetime.fromtimestamp(int(raw_expires_at), tz=UTC).isoformat().replace("+00:00", "Z")
            except (OverflowError, OSError, TypeError, ValueError) as exc:
                raise StripeServiceError("Stripe returned an invalid checkout expiration timestamp.") from exc

        return {
            "session_id": normalized_session_id,
            "org_id": str(metadata.get("org_id", "")),
            "customer_id": payload.get("customer"),
            "mode": payload.get("mode"),
            "price_id": price_id,
            "quantity": quantity,
            "unit_credits": unit_credits,
            "status": payload.get("status", "unknown"),
            "payment_status": payload.get("payment_status"),
            "url": payload.get("url"),
            "success_url": payload.get("success_url"),
            "cancel_url": payload.get("cancel_url"),
            "metadata": dict(metadata),
            "created_at": created_at,
            "expires_at": expires_at,
        }

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
        *,
        owner_key: str | None = None,
        package_id: str | None = None,
        payment_intent: str | None = None,
        invoice_id: str | None = None,
    ) -> UnitBalanceResponse:
        """
        Credit units to an org's balance and record a ledger entry.
        This path is consolidated with the canonical UnitWalletRegistry so that
        the Stripe service cannot drift from the durable wallet state.
        """
        if amount <= 0:
            raise StripeServiceError("credit amount must be > 0")

        wallet_owner_key = self._resolve_wallet_owner_key(org_id, owner_key)
        ledger_metadata: dict[str, Any] = {
            "stripe_reason": reason.value,
            "reference_id": reference_id,
            "source": "stripe_service",
            "event_id": (f"stripe:{reason.value}:{str(reference_id).strip()}" if reference_id and str(reference_id).strip() else None),
            "purchase_reference": str(reference_id).strip() if reference_id else None,
            "checkout_session_id": (str(reference_id).strip() if reference_id and reason == StripeUnitEventReason.CHECKOUT_COMPLETE else None),
        }
        if package_id:
            ledger_metadata["package_id"] = package_id
        # Lets a later charge.refunded map this credit back without a Stripe API call.
        if payment_intent:
            ledger_metadata["payment_intent"] = str(payment_intent).strip()
        if invoice_id:
            ledger_metadata["invoice_id"] = str(invoice_id).strip()
        wallet = self._wallet_registry.credit_units(
            wallet_owner_key,
            amount,
            metadata=ledger_metadata,
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
        return self._sync_balances_from_wallet(org_id, owner_key=wallet_owner_key)

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
        Each unit covers up to TOKENS_PER_UNIT tokens.
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
        Each unit covers up to TOKENS_PER_UNIT tokens.
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

    def get_unit_balance(self, org_id: str, *, owner_key: str | None = None) -> UnitBalanceResponse:
        return self._sync_balances_from_wallet(org_id, owner_key=owner_key)

    def get_checkout_units_credited(
        self,
        session_id: str,
        org_id: str,
        *,
        owner_key: str | None = None,
    ) -> int:
        """Return active checkout units, excluding any session with a durable refund marker."""
        wallet_owner_key = self._resolve_wallet_owner_key(org_id, owner_key)
        entries = self._wallet_registry.list_ledger_entries(
            owner_key=wallet_owner_key,
            limit=500,
            checkout_session_id=session_id,
        )
        for entry in entries:
            if entry.entry_type != "credit":
                continue
            payment_intent = str(entry.metadata.get("payment_intent") or "").strip()
            if payment_intent and self._wallet_registry.is_payment_refunded(payment_intent):
                return 0
        return sum(int(entry.units) for entry in entries if entry.entry_type == "credit")

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
            effective_customer_id = self._org_customer_map.setdefault(org_id, customer_id)
            self._customer_org_map.setdefault(customer_id, org_id)
        _persist_customer_link(org_id, effective_customer_id)

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
            StripeWebhookEventType.CHECKOUT_SESSION_ASYNC_PAYMENT_SUCCEEDED.value: self._handle_checkout_completed,
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
                    checkout_session_id=(
                        data_obj.get("id")
                        if event_type
                        in {
                            StripeWebhookEventType.CHECKOUT_SESSION_COMPLETED.value,
                            StripeWebhookEventType.CHECKOUT_SESSION_ASYNC_PAYMENT_SUCCEEDED.value,
                        }
                        else None
                    ),
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
        raw_metadata = obj.get("metadata")
        metadata = raw_metadata if isinstance(raw_metadata, dict) else {}
        mode_value = obj.get("mode")
        mode = str(mode_value) if mode_value is not None else ""
        if mode == StripeCheckoutMode.SETUP.value:
            if not session_id:
                raise StripeServiceError("Payment method setup session ID is required.")
            return {
                "session_id": session_id,
                "mode": mode,
                "payment_method_setup": "completed",
            }

        integrity = self._verify_checkout_integrity_metadata(metadata, mode=mode)
        org_id: str = integrity["org_id"]
        unit_credits: int = integrity["unit_credits"]
        owner_key: str = integrity["owner_key"] or self._resolve_wallet_owner_key(org_id, None)
        customer_id: str | None = obj.get("customer")
        payment_intent_raw = obj.get("payment_intent")
        if isinstance(payment_intent_raw, str):
            payment_intent = payment_intent_raw.strip() or None
        elif isinstance(payment_intent_raw, dict):
            payment_intent_id = payment_intent_raw.get("id")
            payment_intent = payment_intent_id.strip() if isinstance(payment_intent_id, str) and payment_intent_id.strip() else None
        else:
            payment_intent = None
        payment_status = obj.get("payment_status")
        if payment_status is None:
            payment_status = obj.get("status")

        payment_confirmed = self._is_successful_payment_status(payment_status)

        if payment_confirmed and not session_id:
            raise StripeServiceError("checkout session ID is required for payment fulfillment")
        if payment_confirmed and not org_id:
            raise StripeServiceError("checkout session is missing the organization identity")
        if payment_confirmed and mode != StripeCheckoutMode.PAYMENT.value:
            raise StripeServiceError("Only one-time unit package payments can fulfill checkout entitlements.")
        if payment_confirmed and unit_credits <= 0:
            raise StripeServiceError("Paid unit package checkout is missing its trusted unit amount.")
        if payment_confirmed and not integrity["package_id"]:
            raise StripeServiceError("Paid unit package checkout is missing its trusted package identity.")
        payment_intent_refunded = False
        fulfillment_record: dict[str, Any] | None = None
        if payment_confirmed:
            if payment_intent is None:
                raise StripeServiceError("Paid unit package checkout is missing its Stripe PaymentIntent.")
            fulfillment_record = self._record_checkout_fulfillment(
                session_id=session_id,
                org_id=org_id,
                owner_key=owner_key or "",
                package_id=integrity["package_id"],
                units=unit_credits,
                payment_intent=payment_intent,
                customer_id=customer_id,
                save_card=integrity["save_card"],
                metadata=metadata,
            )
            payment_intent_refunded = fulfillment_record.get("fulfillment_status") == "refunded"
            if not payment_intent_refunded:
                payment_intent_refunded = self._is_payment_intent_refunded(payment_intent)

        with self._lock:
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

        if payment_intent_refunded:
            self._mark_checkout_fulfillment(
                session_id,
                status="refunded",
                last_error="stripe_payment_refunded",
            )
            result.update(
                {
                    "fulfillment_status": "refunded",
                    "units_credited": 0,
                    "tokens_covered": 0,
                    "action": "contact_support",
                    "support_reference": session_id,
                }
            )
            return result

        install_key_issuance: dict[str, dict[str, Any]] = {}
        if org_id and payment_confirmed:
            payment_state = self._mark_checkout_fulfillment(
                session_id,
                status="payment_confirmed",
            )
            if payment_state.get("fulfillment_status") == "refunded":
                result.update(
                    {
                        "fulfillment_status": "refunded",
                        "units_credited": 0,
                        "tokens_covered": 0,
                        "action": "contact_support",
                        "support_reference": session_id,
                    }
                )
                return result

            self.credit_units(
                org_id,
                unit_credits,
                StripeUnitEventReason.CHECKOUT_COMPLETE,
                reference_id=session_id,
                owner_key=owner_key,
                package_id=integrity["package_id"],
                payment_intent=payment_intent,
            )
            result["units_credited"] = unit_credits
            result["tokens_covered"] = unit_credits * TOKENS_PER_UNIT

            wallet_state = self._mark_checkout_fulfillment(
                session_id,
                status="wallet_credited",
                units_credited=True,
            )
            if wallet_state.get("fulfillment_status") == "refunded" or self._wallet_registry.is_payment_refunded(payment_intent):
                revocation = self._revoke_checkout_entitlements_for_refund(
                    session_id=session_id,
                    payment_intent=payment_intent,
                    owner_key=owner_key or "",
                )
                result.update(
                    {
                        "fulfillment_status": "refunded",
                        "units_credited": 0,
                        "units_revoked": revocation["units_revoked"],
                        "tokens_covered": 0,
                        "action": "contact_support",
                        "support_reference": session_id,
                    }
                )
                return result

            try:
                install_key_issuance = self._issue_paid_install_keys_for_checkout(
                    org_id=org_id,
                    customer_id=customer_id,
                    session_id=session_id,
                    unit_credits=unit_credits,
                    metadata={
                        **metadata,
                        "mode": mode,
                        "payment_status": payment_status,
                    },
                    payment_intent=payment_intent,
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "stripe.checkout_install_key_issue_failed org=%s session=%s error_type=%s",
                    org_id,
                    session_id,
                    type(exc).__name__,
                )
                self._mark_checkout_fulfillment(
                    session_id,
                    status="failed",
                    units_credited=True,
                    last_error="install_key_provisioning_failed",
                )
                raise StripeInstallKeyProvisioningError("Install-key provisioning failed after units were credited.") from exc

            if self._wallet_registry.is_payment_refunded(payment_intent):
                revocation = self._revoke_checkout_entitlements_for_refund(
                    session_id=session_id,
                    payment_intent=payment_intent,
                    owner_key=owner_key or "",
                )
                result.update(
                    {
                        "fulfillment_status": "refunded",
                        "units_credited": 0,
                        "units_revoked": revocation["units_revoked"],
                        "install_keys_revoked": revocation["install_keys_revoked"],
                        "tokens_covered": 0,
                        "action": "contact_support",
                        "support_reference": session_id,
                    }
                )
                return result

            final_state = self._mark_checkout_fulfillment(
                session_id,
                status="fulfilled",
                units_credited=True,
                install_keys_provisioned=True,
            )
            if final_state.get("fulfillment_status") == "refunded":
                revocation = self._revoke_checkout_entitlements_for_refund(
                    session_id=session_id,
                    payment_intent=payment_intent,
                    owner_key=owner_key or "",
                )
                result.update(
                    {
                        "fulfillment_status": "refunded",
                        "units_credited": 0,
                        "units_revoked": revocation["units_revoked"],
                        "install_keys_revoked": revocation["install_keys_revoked"],
                        "tokens_covered": 0,
                        "action": "contact_support",
                        "support_reference": session_id,
                    }
                )
                return result

            result["fulfillment_status"] = "fulfilled"
            result["support_reference"] = session_id
            with self._lock:
                self._processed_event_ids.add(f"checkout_completed:{session_id}")

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
                    renewal_owner_key = str((record.metadata or {}).get("owner_key") or "").strip() or None
                    renewal_payment_intent = obj.get("payment_intent")
                    self.credit_units(
                        org_id,
                        renewal_units,
                        StripeUnitEventReason.SUBSCRIPTION_RENEWED,
                        reference_id=invoice_id,
                        owner_key=renewal_owner_key,
                        payment_intent=renewal_payment_intent if isinstance(renewal_payment_intent, str) else None,
                        invoice_id=invoice_id,
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

    def _attach_payment_intent_to_purchase(self, session_id: str, payment_intent: str | None) -> None:
        if not session_id or not payment_intent:
            return
        try:
            from app.api.routes.billing import _PURCHASE_REPOSITORY

            purchase = _PURCHASE_REPOSITORY.find_for_checkout(session_id=session_id)
            if purchase is not None:
                _PURCHASE_REPOSITORY.update_fields(purchase.purchase_id, {"stripe_payment_intent_id": payment_intent})
        except Exception:  # noqa: BLE001
            logger.warning("stripe.payment_intent_attach_failed session=%s", session_id, exc_info=True)

    def _handle_charge_refunded(self, obj: dict[str, Any], _event: dict[str, Any]) -> dict[str, Any]:
        from app.api.routes.billing import _PURCHASE_REPOSITORY
        from app.services.billing_store import get_billing_store

        charge_id: str = obj.get("id", "")
        customer_id: str = obj.get("customer", "") or ""
        amount_refunded: int = int(obj.get("amount_refunded", 0) or 0)
        payment_intent_raw = obj.get("payment_intent")
        if isinstance(payment_intent_raw, dict):
            payment_intent_raw = payment_intent_raw.get("id")
        payment_intent: str | None = payment_intent_raw.strip() if isinstance(payment_intent_raw, str) and payment_intent_raw.strip() else None
        invoice_raw = obj.get("invoice")
        invoice_id: str | None = invoice_raw.strip() if isinstance(invoice_raw, str) and invoice_raw.strip() else None

        if payment_intent and amount_refunded > 0:
            self._wallet_registry.mark_payment_refunded(
                payment_intent,
                charge_id=charge_id or None,
                amount_refunded=amount_refunded,
                reason="charge_refunded",
                metadata={"source": "stripe_webhook", "invoice_id": invoice_id},
            )
        checkout_fulfillment = self._get_checkout_fulfillment_by_payment_intent(payment_intent) if payment_intent else None
        org_id = self.resolve_org_from_customer(customer_id) or str((checkout_fulfillment or {}).get("org_id") or "")

        if org_id:
            self.invalidate_invoice_cache(org_id)

        logger.info(
            "stripe.charge_refunded charge=%s customer=%s org=%s amount_refunded=%d",
            charge_id,
            customer_id,
            org_id,
            amount_refunded,
        )
        result: dict[str, Any] = {
            "charge_id": charge_id,
            "customer_id": customer_id,
            "org_id": org_id,
            "amount_refunded": amount_refunded,
            "payment_intent_id": payment_intent,
            "install_keys_revoked": 0,
            "units_revoked": 0,
        }
        if not payment_intent or amount_refunded <= 0:
            result["status"] = "ignored"
            return result

        purchase = _PURCHASE_REPOSITORY.find_for_payment_intent(payment_intent)
        purchase_session_id = str((purchase.metadata or {}).get("checkout_session_id") or "").strip() if purchase else ""
        purchase_session_id = purchase_session_id or str((checkout_fulfillment or {}).get("session_id") or "").strip()

        revoked = get_install_key_registry().revoke_keys_for_refund(
            checkout_session_ids={purchase_session_id} if purchase_session_id else set(),
            payment_intent=payment_intent,
        )

        owner_candidates: list[str] = []
        if purchase is not None:
            owner_candidates.append(purchase.owner_key)
        fulfillment_owner = str((checkout_fulfillment or {}).get("owner_key") or "").strip()
        if fulfillment_owner:
            owner_candidates.append(fulfillment_owner)
        owner_candidates.extend(record.owner_key for record in revoked)
        if org_id:
            owner_candidates.append(self._resolve_wallet_owner_key(org_id, None))
        with self._lock:
            owner_candidates.extend(str((record.metadata or {}).get("owner_key") or "") for record in self._subscriptions.values() if customer_id and record.customer_id == customer_id)

        session_ids: set[str] = {purchase_session_id} if purchase_session_id else set()
        session_ids.update(record.checkout_session_id for record in revoked if record.checkout_session_id)

        wallet_registry = self._wallet_registry
        refunded_units: dict[str, int] = {}
        for session_value in sorted(session_ids) or [None]:
            for reference, revoked_units in wallet_registry.revoke_units_for_refund(
                owner_candidates,
                payment_intent=payment_intent,
                invoice_id=invoice_id,
                checkout_session_id=session_value,
                reason="refund",
            ).items():
                refunded_units[reference] = refunded_units.get(reference, 0) + revoked_units
        units_revoked = sum(refunded_units.values())
        for reference, revoked_units in sorted(refunded_units.items()):
            get_billing_store().revoke_units(
                f"checkout:{reference}",
                revoked_units,
                metadata={
                    "event_id": f"refund_revoke:{reference}",
                    "checkout_session_id": reference,
                    "payment_intent": payment_intent,
                    "reason": "refund",
                },
            )

        handoff_service = get_install_key_handoff_service()
        handoff_service.revoke_unredeemed_claims([record.key_id for record in revoked])
        for session_value in sorted(session_ids):
            handoff_service.clear_claims_for_purchase(session_value)

        purchase_was_already_refunded = purchase is not None and purchase.payment_status == "refunded"
        if purchase is not None and not purchase_was_already_refunded:
            _PURCHASE_REPOSITORY.update_fields(
                purchase.purchase_id,
                {
                    "payment_status": "refunded",
                    "refunded_at": datetime.now(UTC).isoformat(),
                    "refund_reason": "charge_refunded",
                },
            )

        result.update(
            {
                "status": "already_refunded" if purchase_was_already_refunded else "refunded",
                "purchase_id": purchase.purchase_id if purchase is not None else None,
                "install_keys_revoked": len(revoked),
                "units_revoked": units_revoked,
            }
        )
        logger.info(
            "stripe.charge_refunded_revoked charge=%s purchase=%s keys_revoked=%d units_revoked=%d",
            charge_id,
            result["purchase_id"],
            len(revoked),
            units_revoked,
        )
        return result

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
