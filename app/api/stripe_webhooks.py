from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import hmac
import logging
import time
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel

from app.services.stripe_service import (
    StripeBillingInterval,
    StripeSubscriptionStatus,
    StripeUnitEventReason,
    StripeWebhookEventType,
    get_stripe_service,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Router — NO require_api_key dependency.
# Stripe webhooks are verified via HMAC signature, not API key.
# ---------------------------------------------------------------------------


router = APIRouter(
    prefix="/stripe",
    tags=["stripe-webhooks"],
)


_SCHEMA_VERSION = "1.0"
_STRIPE_SIGNATURE_HEADER = "stripe-signature"
_TIMESTAMP_TOLERANCE_SECONDS = 300  # 5 min — Stripe's own recommendation


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class StripeWebhookAck(BaseModel):
    received: bool = True
    event_id: str
    event_type: str
    processed: bool
    skipped: bool = False
    skip_reason: str | None = None
    org_id: str | None = None
    timestamp: str
    schema_version: str = _SCHEMA_VERSION


class StripeWebhookErrorResponse(BaseModel):
    error: str
    event_id: str | None = None
    timestamp: str
    schema_version: str = _SCHEMA_VERSION


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _verify_stripe_signature(
    payload: bytes,
    sig_header: str,
    webhook_secret: str,
    tolerance: int = _TIMESTAMP_TOLERANCE_SECONDS,
) -> None:
    """
    Validate Stripe-Signature header.
    Raises HTTPException 400 on any verification failure.
    Stripe signature format: t=<timestamp>,v1=<hmac_sha256_hex>[,v1=...]
    """
    try:
        parts: dict[str, list[str]] = {}
        for item in sig_header.split(","):
            if "=" not in item:
                continue
            key, _, value = item.partition("=")
            parts.setdefault(key.strip(), []).append(value.strip())
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed Stripe-Signature header.",
        ) from None

    timestamps = parts.get("t", [])
    v1_signatures = parts.get("v1", [])

    if not timestamps or not v1_signatures:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Stripe-Signature missing required t= or v1= components.",
        )

    try:
        event_timestamp = int(timestamps[0])
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Stripe-Signature timestamp is not a valid integer.",
        ) from None

    now = int(time.time())
    if abs(now - event_timestamp) > tolerance:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(f"Stripe webhook timestamp is outside tolerance window ({tolerance}s). Possible replay attack."),
        )

    signed_payload = f"{event_timestamp}.".encode() + payload
    expected_sig = hmac.new(
        webhook_secret.encode("utf-8"),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()

    matched = any(hmac.compare_digest(expected_sig, received_sig) for received_sig in v1_signatures)
    if not matched:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Stripe-Signature HMAC verification failed. Rejecting event.",
        )


def _extract_org_id(event_data: dict[str, Any]) -> str | None:
    """
    Pull org_id from the canonical locations Stripe embeds it.
    Priority: event.metadata.org_id → data.object.metadata.org_id →
              data.object.client_reference_id
    """
    top_meta = event_data.get("metadata") or {}
    if isinstance(top_meta, dict) and top_meta.get("org_id"):
        return str(top_meta["org_id"])

    data_obj = (event_data.get("data") or {}).get("object") or {}

    obj_meta = data_obj.get("metadata") or {}
    if isinstance(obj_meta, dict) and obj_meta.get("org_id"):
        return str(obj_meta["org_id"])

    client_ref = data_obj.get("client_reference_id")
    if client_ref:
        return str(client_ref)

    return None


def _safe_event_type(raw: Any) -> str | None:
    if not isinstance(raw, str):
        return None
    return raw.strip() or None


def _epoch_to_iso(epoch: Any) -> str:
    if epoch is None:
        return _utc_now_iso()
    try:
        return datetime.fromtimestamp(int(epoch), tz=UTC).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OSError):
        return _utc_now_iso()


# ---------------------------------------------------------------------------
# In-process event deduplication store
# ---------------------------------------------------------------------------

_PROCESSED_EVENTS: set[str] = set()
_PROCESSED_EVENT_META: dict[str, dict[str, Any]] = {}


def _is_event_processed(event_id: str) -> bool:
    return event_id in _PROCESSED_EVENTS


def _record_event_seen(
    event_id: str,
    event_type: str,
    org_id: str | None,
    processed: bool,
) -> None:
    _PROCESSED_EVENTS.add(event_id)
    _PROCESSED_EVENT_META[event_id] = {
        "event_type": event_type,
        "org_id": org_id,
        "processed": processed,
        "recorded_at": _utc_now_iso(),
    }


def reset_processed_events() -> None:
    """Test isolation helper — clears in-process event dedup state."""
    _PROCESSED_EVENTS.clear()
    _PROCESSED_EVENT_META.clear()


# ---------------------------------------------------------------------------
# Service bridge — delegates to StripeService public API
# ---------------------------------------------------------------------------


def _svc_get_webhook_secret(svc: Any) -> str:
    """
    Pull webhook secret from service. StripeService._get_webhook_secret is
    private; we call it via the public vault path using the same guard logic.
    Falls back gracefully — returns "" if not configured so caller can warn
    rather than crash.
    """
    try:
        return svc._get_webhook_secret()  # noqa: SLF001
    except Exception:
        return ""


def _svc_handle_checkout_completed(
    svc: Any,
    *,
    session_id: str,
    org_id: str | None,
    amount_total: int,
    currency: str,
    mode: str,
    unit_credits: int,
    metadata: dict[str, Any],
    raw_event_id: str,
) -> None:
    """Credit units on checkout.session.completed via StripeService.credit_units."""
    if org_id and unit_credits > 0:
        svc.credit_units(
            org_id=org_id,
            amount=unit_credits,
            reason=StripeUnitEventReason.CHECKOUT_COMPLETE,
            reference_id=session_id,
        )
    logger.info(
        "stripe_bridge: checkout_completed session=%s org=%s units=%d amount=%d %s",
        session_id,
        org_id,
        unit_credits,
        amount_total,
        currency,
    )


def _svc_handle_checkout_expired(
    svc: Any,
    *,
    session_id: str,
    org_id: str | None,
    raw_event_id: str,
) -> None:
    """Mark checkout session as expired via StripeService.expire_checkout_session."""
    svc.expire_checkout_session(session_id)
    logger.info(
        "stripe_bridge: checkout_expired session=%s org=%s",
        session_id,
        org_id,
    )


def _svc_handle_subscription_created(
    svc: Any,
    *,
    subscription_id: str,
    org_id: str | None,
    customer_id: str,
    price_id: str,
    metered_price_id: str | None,
    status: str,
    billing_interval: str,
    current_period_start: str,
    current_period_end: str,
    cancel_at_period_end: bool,
    metadata: dict[str, Any],
    raw_event_id: str,
) -> None:
    _resolved_org = org_id or (svc.resolve_org_from_customer(customer_id) if customer_id else None)
    try:
        sub_status = StripeSubscriptionStatus(status)
    except ValueError:
        sub_status = StripeSubscriptionStatus.INCOMPLETE
    try:
        interval = StripeBillingInterval(billing_interval)
    except ValueError:
        interval = StripeBillingInterval.MONTHLY

    svc.upsert_subscription(
        subscription_id=subscription_id,
        org_id=_resolved_org or "",
        customer_id=customer_id,
        price_id=price_id,
        status=sub_status,
        billing_interval=interval,
        current_period_start=current_period_start,
        current_period_end=current_period_end,
        cancel_at_period_end=cancel_at_period_end,
        metered_price_id=metered_price_id,
        metadata=metadata,
    )
    if customer_id and _resolved_org:
        svc.register_customer_mapping(_resolved_org, customer_id)


def _svc_handle_subscription_updated(
    svc: Any,
    *,
    subscription_id: str,
    org_id: str | None,
    status: str,
    cancel_at_period_end: bool,
    current_period_start: str,
    current_period_end: str,
    metadata: dict[str, Any],
    raw_event_id: str,
) -> None:
    existing = svc.get_subscription(subscription_id)
    if existing is None:
        logger.warning(
            "stripe_bridge: subscription_updated for unknown sub=%s — skipping upsert",
            subscription_id,
        )
        return
    try:
        sub_status = StripeSubscriptionStatus(status)
    except ValueError:
        sub_status = StripeSubscriptionStatus.INCOMPLETE
    try:
        interval = StripeBillingInterval(existing.get("billing_interval", "month"))
    except ValueError:
        interval = StripeBillingInterval.MONTHLY

    _resolved_org = org_id or existing.get("org_id") or ""

    svc.upsert_subscription(
        subscription_id=subscription_id,
        org_id=_resolved_org,
        customer_id=existing.get("customer_id", ""),
        price_id=existing.get("price_id", ""),
        status=sub_status,
        billing_interval=interval,
        current_period_start=current_period_start,
        current_period_end=current_period_end,
        cancel_at_period_end=cancel_at_period_end,
        metered_price_id=existing.get("metered_price_id"),
        metadata=metadata,
    )

    # If subscription renewed and metadata carries unit_credits, credit them
    unit_credits_raw = metadata.get("unit_credits") or metadata.get("units")
    if sub_status == StripeSubscriptionStatus.ACTIVE and unit_credits_raw is not None and _resolved_org:
        try:
            units = int(unit_credits_raw)
            if units > 0:
                svc.credit_units(
                    org_id=_resolved_org,
                    amount=units,
                    reason=StripeUnitEventReason.SUBSCRIPTION_RENEWED,
                    reference_id=subscription_id,
                )
        except (TypeError, ValueError):
            pass


def _svc_handle_subscription_deleted(
    svc: Any,
    *,
    subscription_id: str,
    org_id: str | None,
    raw_event_id: str,
) -> None:
    existing = svc.get_subscription(subscription_id)
    if existing is None:
        logger.warning(
            "stripe_bridge: subscription_deleted for unknown sub=%s — no-op",
            subscription_id,
        )
        return
    _resolved_org = org_id or existing.get("org_id") or ""
    try:
        interval = StripeBillingInterval(existing.get("billing_interval", "month"))
    except ValueError:
        interval = StripeBillingInterval.MONTHLY

    svc.upsert_subscription(
        subscription_id=subscription_id,
        org_id=_resolved_org,
        customer_id=existing.get("customer_id", ""),
        price_id=existing.get("price_id", ""),
        status=StripeSubscriptionStatus.CANCELED,
        billing_interval=interval,
        current_period_start=existing.get("current_period_start", _utc_now_iso()),
        current_period_end=existing.get("current_period_end", _utc_now_iso()),
        cancel_at_period_end=True,
        metered_price_id=existing.get("metered_price_id"),
        metadata=existing.get("metadata", {}),
    )


def _svc_handle_invoice_paid(
    svc: Any,
    *,
    invoice_id: str,
    subscription_id: str | None,
    org_id: str | None,
    amount_paid: int,
    currency: str,
    billing_reason: str,
    unit_credits: int,
    metadata: dict[str, Any],
    raw_event_id: str,
) -> None:
    _resolved_org = org_id
    if not _resolved_org and subscription_id:
        existing = svc.get_subscription(subscription_id)
        if existing:
            _resolved_org = existing.get("org_id")

    if _resolved_org and unit_credits > 0 and billing_reason in ("subscription_cycle", "subscription_create", "subscription_update"):
        svc.credit_units(
            org_id=_resolved_org,
            amount=unit_credits,
            reason=StripeUnitEventReason.SUBSCRIPTION_RENEWED,
            reference_id=invoice_id,
        )

    logger.info(
        "stripe_bridge: invoice_paid invoice=%s sub=%s org=%s units=%d reason=%s amount=%d %s",
        invoice_id,
        subscription_id,
        _resolved_org,
        unit_credits,
        billing_reason,
        amount_paid,
        currency,
    )


def _svc_handle_invoice_payment_failed(
    svc: Any,
    *,
    invoice_id: str,
    subscription_id: str | None,
    org_id: str | None,
    attempt_count: int,
    next_payment_attempt: str,
    metadata: dict[str, Any],
    raw_event_id: str,
) -> None:
    logger.warning(
        "stripe_bridge: invoice_payment_failed invoice=%s sub=%s org=%s attempt=%d next=%s",
        invoice_id,
        subscription_id,
        org_id,
        attempt_count,
        next_payment_attempt,
    )


def _svc_handle_customer_created(
    svc: Any,
    *,
    customer_id: str,
    org_id: str | None,
    email: str,
    metadata: dict[str, Any],
    raw_event_id: str,
) -> None:
    if org_id and customer_id:
        svc.register_customer_mapping(org_id, customer_id)
    logger.info(
        "stripe_bridge: customer_created cust=%s org=%s email=%s",
        customer_id,
        org_id,
        email,
    )


def _svc_handle_customer_updated(
    svc: Any,
    *,
    customer_id: str,
    org_id: str | None,
    email: str,
    metadata: dict[str, Any],
    raw_event_id: str,
) -> None:
    if not org_id and customer_id:
        org_id = svc.resolve_org_from_customer(customer_id)
    if org_id and customer_id:
        svc.register_customer_mapping(org_id, customer_id)
    logger.info(
        "stripe_bridge: customer_updated cust=%s org=%s email=%s",
        customer_id,
        org_id,
        email,
    )


# ---------------------------------------------------------------------------
# Event handlers — one private function per Stripe event type
# ---------------------------------------------------------------------------


def _handle_checkout_session_completed(
    event_id: str,
    event_data: dict[str, Any],
    org_id: str | None,
    svc: Any,
) -> bool:
    """
    checkout.session.completed
    Credit the org with units from the completed checkout session.
    """
    data_obj = (event_data.get("data") or {}).get("object") or {}
    session_id = data_obj.get("id") or event_id
    amount_total = data_obj.get("amount_total") or 0
    currency = (data_obj.get("currency") or "usd").lower()
    payment_status = data_obj.get("payment_status", "")
    mode = data_obj.get("mode", "")

    if payment_status != "paid":
        logger.info(
            "stripe_webhooks: checkout.session.completed skipped — payment_status=%s session=%s",
            payment_status,
            session_id,
        )
        return False

    metadata: dict[str, Any] = data_obj.get("metadata") or {}
    unit_credits: int = 0
    raw_credits = metadata.get("unit_credits") or metadata.get("units")
    if raw_credits is not None:
        try:
            unit_credits = int(raw_credits)
        except (TypeError, ValueError):
            unit_credits = 0

    _svc_handle_checkout_completed(
        svc,
        session_id=session_id,
        org_id=org_id,
        amount_total=amount_total,
        currency=currency,
        mode=mode,
        unit_credits=unit_credits,
        metadata=metadata,
        raw_event_id=event_id,
    )
    logger.info(
        "stripe_webhooks: checkout.session.completed processed — session=%s org=%s units=%d",
        session_id,
        org_id,
        unit_credits,
    )
    return True


def _handle_checkout_session_expired(
    event_id: str,
    event_data: dict[str, Any],
    org_id: str | None,
    svc: Any,
) -> bool:
    data_obj = (event_data.get("data") or {}).get("object") or {}
    session_id = data_obj.get("id") or event_id
    _svc_handle_checkout_expired(
        svc,
        session_id=session_id,
        org_id=org_id,
        raw_event_id=event_id,
    )
    logger.info(
        "stripe_webhooks: checkout.session.expired processed — session=%s org=%s",
        session_id,
        org_id,
    )
    return True


def _handle_subscription_created(
    event_id: str,
    event_data: dict[str, Any],
    org_id: str | None,
    svc: Any,
) -> bool:
    data_obj = (event_data.get("data") or {}).get("object") or {}
    subscription_id = data_obj.get("id") or event_id
    customer_id = data_obj.get("customer") or ""
    status_val = data_obj.get("status") or StripeSubscriptionStatus.INCOMPLETE
    items_data = (data_obj.get("items") or {}).get("data") or []
    price_id = ""
    metered_price_id: str | None = None
    billing_interval = "month"

    for item in items_data:
        price = item.get("price") or {}
        pid = price.get("id") or ""
        usage_type = price.get("recurring", {}).get("usage_type", "licensed")
        interval = price.get("recurring", {}).get("interval", "month")
        if usage_type == "metered":
            metered_price_id = pid
        else:
            price_id = pid
            billing_interval = interval

    current_period_start = _epoch_to_iso(data_obj.get("current_period_start"))
    current_period_end = _epoch_to_iso(data_obj.get("current_period_end"))
    metadata: dict[str, Any] = data_obj.get("metadata") or {}

    _svc_handle_subscription_created(
        svc,
        subscription_id=subscription_id,
        org_id=org_id,
        customer_id=customer_id,
        price_id=price_id,
        metered_price_id=metered_price_id,
        status=status_val,
        billing_interval=billing_interval,
        current_period_start=current_period_start,
        current_period_end=current_period_end,
        cancel_at_period_end=bool(data_obj.get("cancel_at_period_end", False)),
        metadata=metadata,
        raw_event_id=event_id,
    )
    logger.info(
        "stripe_webhooks: customer.subscription.created processed — sub=%s org=%s status=%s",
        subscription_id,
        org_id,
        status_val,
    )
    return True


def _handle_subscription_updated(
    event_id: str,
    event_data: dict[str, Any],
    org_id: str | None,
    svc: Any,
) -> bool:
    data_obj = (event_data.get("data") or {}).get("object") or {}
    subscription_id = data_obj.get("id") or event_id
    status_val = data_obj.get("status") or ""
    cancel_at_period_end = bool(data_obj.get("cancel_at_period_end", False))
    current_period_start = _epoch_to_iso(data_obj.get("current_period_start"))
    current_period_end = _epoch_to_iso(data_obj.get("current_period_end"))
    metadata: dict[str, Any] = data_obj.get("metadata") or {}

    _svc_handle_subscription_updated(
        svc,
        subscription_id=subscription_id,
        org_id=org_id,
        status=status_val,
        cancel_at_period_end=cancel_at_period_end,
        current_period_start=current_period_start,
        current_period_end=current_period_end,
        metadata=metadata,
        raw_event_id=event_id,
    )
    logger.info(
        "stripe_webhooks: customer.subscription.updated processed — sub=%s org=%s status=%s",
        subscription_id,
        org_id,
        status_val,
    )
    return True


def _handle_subscription_deleted(
    event_id: str,
    event_data: dict[str, Any],
    org_id: str | None,
    svc: Any,
) -> bool:
    data_obj = (event_data.get("data") or {}).get("object") or {}
    subscription_id = data_obj.get("id") or event_id

    _svc_handle_subscription_deleted(
        svc,
        subscription_id=subscription_id,
        org_id=org_id,
        raw_event_id=event_id,
    )
    logger.info(
        "stripe_webhooks: customer.subscription.deleted processed — sub=%s org=%s",
        subscription_id,
        org_id,
    )
    return True


def _handle_invoice_paid(
    event_id: str,
    event_data: dict[str, Any],
    org_id: str | None,
    svc: Any,
) -> bool:
    """
    invoice.paid
    Renewal path: credit units if this invoice is for a subscription renewal
    and carries a unit_credits metadata value.
    """
    data_obj = (event_data.get("data") or {}).get("object") or {}
    invoice_id = data_obj.get("id") or event_id
    subscription_id = data_obj.get("subscription") or None
    amount_paid = data_obj.get("amount_paid") or 0
    currency = (data_obj.get("currency") or "usd").lower()
    billing_reason = data_obj.get("billing_reason") or ""
    metadata: dict[str, Any] = data_obj.get("metadata") or {}

    unit_credits: int = 0
    raw_credits = metadata.get("unit_credits") or metadata.get("units")
    if raw_credits is not None:
        try:
            unit_credits = int(raw_credits)
        except (TypeError, ValueError):
            unit_credits = 0

    _svc_handle_invoice_paid(
        svc,
        invoice_id=invoice_id,
        subscription_id=subscription_id,
        org_id=org_id,
        amount_paid=amount_paid,
        currency=currency,
        billing_reason=billing_reason,
        unit_credits=unit_credits,
        metadata=metadata,
        raw_event_id=event_id,
    )
    logger.info(
        "stripe_webhooks: invoice.paid processed — invoice=%s sub=%s org=%s units=%d billing_reason=%s",
        invoice_id,
        subscription_id,
        org_id,
        unit_credits,
        billing_reason,
    )
    return True


def _handle_invoice_payment_failed(
    event_id: str,
    event_data: dict[str, Any],
    org_id: str | None,
    svc: Any,
) -> bool:
    data_obj = (event_data.get("data") or {}).get("object") or {}
    invoice_id = data_obj.get("id") or event_id
    subscription_id = data_obj.get("subscription") or None
    attempt_count = data_obj.get("attempt_count") or 1
    next_payment_attempt = _epoch_to_iso(data_obj.get("next_payment_attempt"))
    metadata: dict[str, Any] = data_obj.get("metadata") or {}

    _svc_handle_invoice_payment_failed(
        svc,
        invoice_id=invoice_id,
        subscription_id=subscription_id,
        org_id=org_id,
        attempt_count=attempt_count,
        next_payment_attempt=next_payment_attempt,
        metadata=metadata,
        raw_event_id=event_id,
    )
    logger.warning(
        "stripe_webhooks: invoice.payment_failed — invoice=%s sub=%s org=%s attempt=%d",
        invoice_id,
        subscription_id,
        org_id,
        attempt_count,
    )
    return True


def _handle_customer_created(
    event_id: str,
    event_data: dict[str, Any],
    org_id: str | None,
    svc: Any,
) -> bool:
    data_obj = (event_data.get("data") or {}).get("object") or {}
    customer_id = data_obj.get("id") or ""
    email = data_obj.get("email") or ""
    metadata: dict[str, Any] = data_obj.get("metadata") or {}

    _svc_handle_customer_created(
        svc,
        customer_id=customer_id,
        org_id=org_id,
        email=email,
        metadata=metadata,
        raw_event_id=event_id,
    )
    logger.info(
        "stripe_webhooks: customer.created processed — cust=%s org=%s",
        customer_id,
        org_id,
    )
    return True


def _handle_customer_updated(
    event_id: str,
    event_data: dict[str, Any],
    org_id: str | None,
    svc: Any,
) -> bool:
    data_obj = (event_data.get("data") or {}).get("object") or {}
    customer_id = data_obj.get("id") or ""
    email = data_obj.get("email") or ""
    metadata: dict[str, Any] = data_obj.get("metadata") or {}

    _svc_handle_customer_updated(
        svc,
        customer_id=customer_id,
        org_id=org_id,
        email=email,
        metadata=metadata,
        raw_event_id=event_id,
    )
    logger.info(
        "stripe_webhooks: customer.updated processed — cust=%s org=%s",
        customer_id,
        org_id,
    )
    return True


# ---------------------------------------------------------------------------
# Dispatch table — maps event_type string → handler function
# ---------------------------------------------------------------------------

_EVENT_HANDLERS: dict[str, Any] = {
    StripeWebhookEventType.CHECKOUT_SESSION_COMPLETED: _handle_checkout_session_completed,
    StripeWebhookEventType.CHECKOUT_SESSION_EXPIRED: _handle_checkout_session_expired,
    StripeWebhookEventType.CUSTOMER_SUBSCRIPTION_CREATED: _handle_subscription_created,
    StripeWebhookEventType.CUSTOMER_SUBSCRIPTION_UPDATED: _handle_subscription_updated,
    StripeWebhookEventType.CUSTOMER_SUBSCRIPTION_DELETED: _handle_subscription_deleted,
    StripeWebhookEventType.INVOICE_PAID: _handle_invoice_paid,
    StripeWebhookEventType.INVOICE_PAYMENT_FAILED: _handle_invoice_payment_failed,
    StripeWebhookEventType.CUSTOMER_CREATED: _handle_customer_created,
    StripeWebhookEventType.CUSTOMER_UPDATED: _handle_customer_updated,
}


# ---------------------------------------------------------------------------
# Primary ingestion endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/webhook",
    response_model=StripeWebhookAck,
    status_code=status.HTTP_200_OK,
    summary="Stripe event ingestion endpoint",
    description=("Receives and processes Stripe webhook events. Validates HMAC-SHA256 signature before processing. Returns HTTP 200 for all valid events to prevent Stripe retries. Returns HTTP 400 only for signature failures."),
)
async def stripe_webhook_ingest(
    request: Request,
    stripe_signature: str | None = Header(default=None, alias=_STRIPE_SIGNATURE_HEADER),
) -> StripeWebhookAck:
    raw_body: bytes = await request.body()

    svc = get_stripe_service()
    webhook_secret = _svc_get_webhook_secret(svc)

    if not webhook_secret:
        logger.warning("stripe_webhooks: STRIPE_WEBHOOK_SECRET not configured. Accepting event without signature verification (setup mode).")
    else:
        if not stripe_signature:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing Stripe-Signature header.",
            )
        _verify_stripe_signature(
            payload=raw_body,
            sig_header=stripe_signature,
            webhook_secret=webhook_secret,
        )

    try:
        import json as _json

        event_data: dict[str, Any] = _json.loads(raw_body)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Stripe webhook body is not valid JSON.",
        ) from None

    event_id: str = event_data.get("id") or f"evt_unknown_{int(time.time())}"
    raw_event_type = _safe_event_type(event_data.get("type"))

    if raw_event_type is None:
        logger.warning("stripe_webhooks: received event with missing type — id=%s", event_id)
        return StripeWebhookAck(
            event_id=event_id,
            event_type="unknown",
            processed=False,
            skipped=True,
            skip_reason="Missing event type.",
            org_id=None,
            timestamp=_utc_now_iso(),
        )

    if _is_event_processed(event_id):
        logger.info(
            "stripe_webhooks: duplicate event suppressed — id=%s type=%s",
            event_id,
            raw_event_type,
        )
        return StripeWebhookAck(
            event_id=event_id,
            event_type=raw_event_type,
            processed=False,
            skipped=True,
            skip_reason="Duplicate event — already processed.",
            org_id=None,
            timestamp=_utc_now_iso(),
        )

    org_id = _extract_org_id(event_data)

    handler = _EVENT_HANDLERS.get(raw_event_type)
    processed = False

    if handler is None:
        logger.info(
            "stripe_webhooks: unhandled event type=%s id=%s — acking to Stripe",
            raw_event_type,
            event_id,
        )
        _record_event_seen(event_id, raw_event_type, org_id, processed=False)
        return StripeWebhookAck(
            event_id=event_id,
            event_type=raw_event_type,
            processed=False,
            skipped=True,
            skip_reason=f"Unhandled event type: {raw_event_type}",
            org_id=org_id,
            timestamp=_utc_now_iso(),
        )

    try:
        processed = bool(handler(event_id, event_data, org_id, svc))
    except Exception as exc:
        logger.exception(
            "stripe_webhooks: handler error — event_id=%s type=%s org=%s error=%s",
            event_id,
            raw_event_type,
            org_id,
            str(exc),
        )
        _record_event_seen(event_id, raw_event_type, org_id, processed=False)
        return StripeWebhookAck(
            event_id=event_id,
            event_type=raw_event_type,
            processed=False,
            skipped=True,
            skip_reason=f"Handler raised an internal error: {type(exc).__name__}",
            org_id=org_id,
            timestamp=_utc_now_iso(),
        )

    _record_event_seen(event_id, raw_event_type, org_id, processed=processed)

    return StripeWebhookAck(
        event_id=event_id,
        event_type=raw_event_type,
        processed=processed,
        skipped=False,
        org_id=org_id,
        timestamp=_utc_now_iso(),
    )


# ---------------------------------------------------------------------------
# Health probe — unauthenticated, used by Stripe to verify endpoint is live
# ---------------------------------------------------------------------------


@router.get(
    "/webhook/health",
    status_code=status.HTTP_200_OK,
    summary="Stripe webhook endpoint health probe",
    include_in_schema=False,
)
def stripe_webhook_health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "IronClaw-Stripe-Webhook",
        "timestamp": _utc_now_iso(),
    }
