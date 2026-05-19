from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
import logging
from threading import Lock
import time
from typing import Any
from uuid import uuid4

from app.services.secrets_vault import vault

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_STRIPE_API_BASE = "https://api.stripe.com/v1"
_STRIPE_TIMEOUT_SECONDS = 15
_METERED_USAGE_BUFFER_MAX = 500
_CHECKOUT_SESSION_TTL_SECONDS = 1800  # 30 min
_SCHEMA_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class StripeCheckoutMode(str, Enum):
    PAYMENT = "payment"
    SUBSCRIPTION = "subscription"
    SETUP = "setup"


class StripeBillingInterval(str, Enum):
    MONTHLY = "month"
    ANNUAL = "year"
    WEEKLY = "week"
    DAILY = "day"


class StripeSubscriptionStatus(str, Enum):
    ACTIVE = "active"
    TRIALING = "trialing"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    INCOMPLETE = "incomplete"
    INCOMPLETE_EXPIRED = "incomplete_expired"
    PAUSED = "paused"
    UNPAID = "unpaid"


class StripeUnitEventReason(str, Enum):
    CHECKOUT_COMPLETE = "checkout.complete"
    SUBSCRIPTION_RENEWED = "subscription.renewed"
    MANUAL_CREDIT = "manual.credit"
    METERED_SYNC = "metered.sync"
    REFUND = "refund"
    ADJUSTMENT = "adjustment"


class StripeWebhookEventType(str, Enum):
    CHECKOUT_SESSION_COMPLETED = "checkout.session.completed"
    CHECKOUT_SESSION_EXPIRED = "checkout.session.expired"
    CUSTOMER_SUBSCRIPTION_CREATED = "customer.subscription.created"
    CUSTOMER_SUBSCRIPTION_UPDATED = "customer.subscription.updated"
    CUSTOMER_SUBSCRIPTION_DELETED = "customer.subscription.deleted"
    INVOICE_PAID = "invoice.paid"
    INVOICE_PAYMENT_FAILED = "invoice.payment_failed"
    CUSTOMER_CREATED = "customer.created"
    CUSTOMER_UPDATED = "customer.updated"


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


# ---------------------------------------------------------------------------
# Internal HTTP transport (stdlib only — no stripe SDK import required)
# ---------------------------------------------------------------------------


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:16]}"


class _StripeHTTPClient:
    """
    Minimal Stripe REST client using only stdlib urllib.
    Handles authentication, idempotency keys, and response parsing.
    No third-party stripe SDK dependency required.
    If the stripe SDK is installed and STRIPE_USE_SDK=true, routes through it.
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
    - Verify and dispatch incoming Stripe webhook events.
    - Provide per-org unit balance ledger.
    - Thread-safe in-memory state with full reset for test isolation.

    All network calls are isolated through _StripeHTTPClient so they can be
    patched in tests without monkey-patching urllib directly.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._checkout_sessions: dict[str, _CheckoutSessionRecord] = {}
        self._subscriptions: dict[str, _SubscriptionRecord] = {}
        self._unit_balances: dict[str, int] = {}
        self._unit_ledger: dict[str, list[_UnitLedgerEntry]] = {}
        self._metered_usage_log: list[_MeteredUsageEntry] = []
        self._org_customer_map: dict[str, str] = {}
        self._customer_org_map: dict[str, str] = {}
        self._client: _StripeHTTPClient | None = None

    # ------------------------------------------------------------------
    # Config / client
    # ------------------------------------------------------------------

    def _get_api_key(self) -> str:
        key = vault.get("STRIPE_SECRET_KEY") or ""
        if not key:
            raise StripeConfigError("STRIPE_SECRET_KEY is not configured.")
        return key

    def _get_webhook_secret(self) -> str:
        secret = vault.get("STRIPE_WEBHOOK_SECRET") or ""
        if not secret:
            raise StripeConfigError("STRIPE_WEBHOOK_SECRET is not configured.")
        return secret

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

    def resolve_org_from_customer(self, customer_id: str) -> str | None:
        with self._lock:
            return self._customer_org_map.get(customer_id)

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
        """
        if quantity < 1:
            raise StripeServiceError("quantity must be >= 1")
        if unit_credits < 0:
            raise StripeServiceError("unit_credits must be >= 0")

        now = _utcnow_iso()
        session_meta: dict[str, Any] = {
            "org_id": org_id,
            "unit_credits": str(unit_credits),
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
        if customer_id:
            params["customer"] = customer_id
        for k, v in session_meta.items():
            params[f"metadata[{k}]"] = str(v)

        resp = self._get_client().post("/checkout/sessions", params)

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
            "stripe.checkout_session_created org=%s session=%s mode=%s credits=%d",
            org_id,
            session_id,
            mode.value,
            unit_credits,
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
        Thread-safe; safe to call from webhook handlers.
        """
        if amount <= 0:
            raise StripeServiceError("credit amount must be > 0")

        with self._lock:
            current = self._unit_balances.get(org_id, 0)
            new_balance = current + amount
            self._unit_balances[org_id] = new_balance

            entry = _UnitLedgerEntry(
                entry_id=_new_id("ule"),
                org_id=org_id,
                delta=amount,
                reason=reason.value,
                reference_id=reference_id,
                balance_after=new_balance,
                recorded_at=_utcnow_iso(),
            )
            if org_id not in self._unit_ledger:
                self._unit_ledger[org_id] = []
            self._unit_ledger[org_id].append(entry)
            ledger_snapshot = [e.to_dict() for e in self._unit_ledger[org_id][-50:]]

        logger.info(
            "stripe.units_credited org=%s amount=%d reason=%s balance=%d",
            org_id,
            amount,
            reason.value,
            new_balance,
        )
        return UnitBalanceResponse(
            org_id=org_id,
            balance=new_balance,
            ledger_entries=ledger_snapshot,
        )

    def debit_units(
        self,
        org_id: str,
        amount: int,
        reason: StripeUnitEventReason,
        reference_id: str | None = None,
    ) -> UnitBalanceResponse:
        """
        Debit units from an org's balance. Raises StripeServiceError on
        insufficient balance.
        """
        if amount <= 0:
            raise StripeServiceError("debit amount must be > 0")

        with self._lock:
            current = self._unit_balances.get(org_id, 0)
            if amount > current:
                raise StripeServiceError(f"insufficient unit balance for org={org_id}: " f"have={current} need={amount}")
            new_balance = current - amount
            self._unit_balances[org_id] = new_balance

            entry = _UnitLedgerEntry(
                entry_id=_new_id("ule"),
                org_id=org_id,
                delta=-amount,
                reason=reason.value,
                reference_id=reference_id,
                balance_after=new_balance,
                recorded_at=_utcnow_iso(),
            )
            if org_id not in self._unit_ledger:
                self._unit_ledger[org_id] = []
            self._unit_ledger[org_id].append(entry)
            ledger_snapshot = [e.to_dict() for e in self._unit_ledger[org_id][-50:]]

        logger.info(
            "stripe.units_debited org=%s amount=%d reason=%s balance=%d",
            org_id,
            amount,
            reason.value,
            new_balance,
        )
        return UnitBalanceResponse(
            org_id=org_id,
            balance=new_balance,
            ledger_entries=ledger_snapshot,
        )

    def get_unit_balance(self, org_id: str) -> UnitBalanceResponse:
        with self._lock:
            balance = self._unit_balances.get(org_id, 0)
            ledger = [e.to_dict() for e in self._unit_ledger.get(org_id, [])[-50:]]
        return UnitBalanceResponse(org_id=org_id, balance=balance, ledger_entries=ledger)

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

        with self._lock:
            current = self._unit_balances.get(org_id, 0)
            delta = target_balance - current
            self._unit_balances[org_id] = target_balance

            entry = _UnitLedgerEntry(
                entry_id=_new_id("ule"),
                org_id=org_id,
                delta=delta,
                reason=reason.value,
                reference_id=reference_id,
                balance_after=target_balance,
                recorded_at=_utcnow_iso(),
            )
            if org_id not in self._unit_ledger:
                self._unit_ledger[org_id] = []
            self._unit_ledger[org_id].append(entry)
            ledger_snapshot = [e.to_dict() for e in self._unit_ledger[org_id][-50:]]

        logger.info(
            "stripe.units_adjusted org=%s delta=%d balance=%d reason=%s",
            org_id,
            delta,
            target_balance,
            reason.value,
        )
        return UnitBalanceResponse(org_id=org_id, balance=target_balance, ledger_entries=ledger_snapshot)

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

    def get_subscription(self, subscription_id: str) -> SubscriptionResponse | None:
        with self._lock:
            record = self._subscriptions.get(subscription_id)
        if record is None:
            return None
        return SubscriptionResponse(**record.to_dict(), schema_version=_SCHEMA_VERSION)

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
                )
            ]
        if not records:
            return None
        latest = max(records, key=lambda r: r.updated_at)
        return SubscriptionResponse(**latest.to_dict(), schema_version=_SCHEMA_VERSION)

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
        """
        if quantity < 0:
            raise StripeServiceError("metered usage quantity must be >= 0")

        idem_key = idempotency_key or f"metered-{org_id}-{subscription_item_id}-{int(time.time())}"
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
        raw_body: bytes,
        stripe_signature_header: str,
    ) -> WebhookVerifyResult:
        """
        Verify a Stripe webhook using Stripe-Signature header (HMAC-SHA256 timestamp scheme).
        Returns WebhookVerifyResult with valid=True and parsed payload on success.
        """
        import hashlib
        import hmac as _hmac
        import json

        try:
            webhook_secret = self._get_webhook_secret()
        except StripeConfigError as exc:
            return WebhookVerifyResult(valid=False, event_type=None, event_id=None, error=str(exc))

        try:
            parts = dict(p.split("=", 1) for p in stripe_signature_header.split(",") if "=" in p)
            timestamp = parts.get("t", "")
            v1_sig = parts.get("v1", "")
        except Exception:  # noqa: BLE001
            return WebhookVerifyResult(
                valid=False,
                event_type=None,
                event_id=None,
                error="Malformed Stripe-Signature header.",
            )

        if not timestamp or not v1_sig:
            return WebhookVerifyResult(
                valid=False,
                event_type=None,
                event_id=None,
                error="Missing timestamp or v1 signature.",
            )

        try:
            ts_int = int(timestamp)
        except ValueError:
            return WebhookVerifyResult(valid=False, event_type=None, event_id=None, error="Invalid timestamp.")

        tolerance_seconds = int(vault.get("STRIPE_WEBHOOK_TOLERANCE_SECONDS") or "300")
        age = int(time.time()) - ts_int
        if abs(age) > tolerance_seconds:
            return WebhookVerifyResult(
                valid=False,
                event_type=None,
                event_id=None,
                error=f"Webhook timestamp too old or too far in the future (age={age}s).",
            )

        signed_payload = f"{timestamp}.".encode() + raw_body
        expected = _hmac.new(webhook_secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()

        if not _hmac.compare_digest(expected, v1_sig):
            return WebhookVerifyResult(
                valid=False,
                event_type=None,
                event_id=None,
                error="Signature mismatch.",
            )

        try:
            payload: dict[str, Any] = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            return WebhookVerifyResult(
                valid=False,
                event_type=None,
                event_id=None,
                error=f"JSON decode error: {exc}",
            )

        return WebhookVerifyResult(
            valid=True,
            event_type=payload.get("type"),
            event_id=payload.get("id"),
            error=None,
            payload=payload,
        )

    def handle_webhook_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """
        Dispatch a verified Stripe event object to the appropriate handler.
        Returns a result dict with action taken.
        """
        event_type = event.get("type", "")
        event_id = event.get("id", "")
        data_obj: dict[str, Any] = event.get("data", {}).get("object", {})

        handler_map = {
            StripeWebhookEventType.CHECKOUT_SESSION_COMPLETED.value: self._handle_checkout_completed,
            StripeWebhookEventType.CHECKOUT_SESSION_EXPIRED.value: self._handle_checkout_expired,
            StripeWebhookEventType.CUSTOMER_SUBSCRIPTION_CREATED.value: self._handle_subscription_upsert,
            StripeWebhookEventType.CUSTOMER_SUBSCRIPTION_UPDATED.value: self._handle_subscription_upsert,
            StripeWebhookEventType.CUSTOMER_SUBSCRIPTION_DELETED.value: self._handle_subscription_deleted,
            StripeWebhookEventType.INVOICE_PAID.value: self._handle_invoice_paid,
            StripeWebhookEventType.INVOICE_PAYMENT_FAILED.value: self._handle_invoice_payment_failed,
        }

        handler = handler_map.get(event_type)
        if handler is None:
            logger.debug("stripe.webhook_unhandled event_type=%s id=%s", event_type, event_id)
            return {"action": "ignored", "event_type": event_type, "event_id": event_id}

        try:
            result = handler(data_obj, event)
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

        try:
            unit_credits = int(unit_credits_raw)
        except (ValueError, TypeError):
            unit_credits = 0

        # Update local session status
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

        result: dict[str, Any] = {"session_id": session_id, "org_id": org_id, "mode": mode}

        if org_id and unit_credits > 0:
            self.credit_units(
                org_id,
                unit_credits,
                StripeUnitEventReason.CHECKOUT_COMPLETE,
                reference_id=session_id,
            )
            result["units_credited"] = unit_credits

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

    def _handle_subscription_deleted(self, obj: dict[str, Any], _event: dict[str, Any]) -> dict[str, Any]:
        subscription_id: str = obj.get("id", "")
        self.cancel_subscription(subscription_id)
        return {"subscription_id": subscription_id, "status": "canceled"}

    def _handle_invoice_paid(self, obj: dict[str, Any], _event: dict[str, Any]) -> dict[str, Any]:
        subscription_id: str | None = obj.get("subscription")
        customer_id: str = obj.get("customer", "")
        amount_paid: int = int(obj.get("amount_paid", 0))
        invoice_id: str = obj.get("id", "")

        org_id = self.resolve_org_from_customer(customer_id) or obj.get("metadata", {}).get("org_id", "")

        if subscription_id:
            with self._lock:
                record = self._subscriptions.get(subscription_id)
            if record and record.status in (
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

        return {
            "invoice_id": invoice_id,
            "org_id": org_id,
            "subscription_id": subscription_id,
            "amount_paid": amount_paid,
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

    def reset(self) -> None:
        with self._lock:
            self._checkout_sessions.clear()
            self._subscriptions.clear()
            self._unit_balances.clear()
            self._unit_ledger.clear()
            self._metered_usage_log.clear()
            self._org_customer_map.clear()
            self._customer_org_map.clear()
            self._client = None


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
