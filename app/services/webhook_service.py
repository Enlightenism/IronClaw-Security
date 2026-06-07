from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
import hashlib
import hmac
import json
import logging
import os
from typing import Any
import uuid

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_WEBHOOK_DELIVERY_TABLE = "webhook_delivery_log"
_WEBHOOK_SUBSCRIPTIONS_TABLE = "webhook_subscriptions"

_MAX_ATTEMPTS: int = 5
_RETRY_BACKOFF_BASE: float = 2.0
_DELIVERY_TIMEOUT_SECONDS: float = 10.0
_EDGE_DISPATCH_TIMEOUT_SECONDS: float = 15.0
_SIGNATURE_HEADER = "X-IronClaw-Signature-256"
_DELIVERY_ID_HEADER = "X-IronClaw-Delivery"
_EVENT_HEADER = "X-IronClaw-Event"
_TIMESTAMP_HEADER = "X-IronClaw-Timestamp"

# Edge Function name — matches the deployed Supabase function name exactly.
_EDGE_FUNCTION_NAME = "ironclaw-webhook-dispatch"

# ---------------------------------------------------------------------------
# Enums / types
# ---------------------------------------------------------------------------


class WebhookDeliveryStatus(str, Enum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    EXHAUSTED = "exhausted"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WebhookSubscription:
    id: str
    tenant_id: str
    target_url: str
    events: list[str]
    secret_hash: str
    active: bool = True
    max_attempts: int = _MAX_ATTEMPTS
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> WebhookSubscription:
        return cls(
            id=row["id"],
            tenant_id=row["tenant_id"],
            target_url=row["target_url"],
            events=row.get("events") or [],
            secret_hash=row["secret_hash"],
            active=row.get("active", True),
            max_attempts=row.get("max_attempts", _MAX_ATTEMPTS),
            metadata=row.get("metadata") or {},
            created_at=row.get("created_at", datetime.now(UTC).isoformat()),
        )


@dataclass(frozen=True)
class WebhookDeliveryRecord:
    id: str
    subscription_id: str
    tenant_id: str
    event_type: str
    payload_json: str
    status: WebhookDeliveryStatus
    attempts: int
    http_status: int | None
    response_body: str | None
    error_detail: str | None
    delivered_at: str | None
    next_attempt_at: str | None
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "subscription_id": self.subscription_id,
            "tenant_id": self.tenant_id,
            "event_type": self.event_type,
            "payload_json": self.payload_json,
            "status": self.status.value if isinstance(self.status, WebhookDeliveryStatus) else self.status,
            "attempts": self.attempts,
            "http_status": self.http_status,
            "response_body": self.response_body,
            "error_detail": self.error_detail,
            "delivered_at": self.delivered_at,
            "next_attempt_at": self.next_attempt_at,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class WebhookDispatchResult:
    delivery_id: str
    subscription_id: str
    tenant_id: str
    event_type: str
    status: WebhookDeliveryStatus
    http_status: int | None
    attempts: int
    error_detail: str | None
    delivered_at: str | None

    @property
    def succeeded(self) -> bool:
        return self.status == WebhookDeliveryStatus.SUCCESS

    @property
    def exhausted(self) -> bool:
        return self.status == WebhookDeliveryStatus.EXHAUSTED

    def to_dict(self) -> dict[str, Any]:
        return {
            "delivery_id": self.delivery_id,
            "subscription_id": self.subscription_id,
            "tenant_id": self.tenant_id,
            "event_type": self.event_type,
            "status": self.status.value if isinstance(self.status, WebhookDeliveryStatus) else self.status,
            "http_status": self.http_status,
            "attempts": self.attempts,
            "error_detail": self.error_detail,
            "delivered_at": self.delivered_at,
        }


@dataclass(frozen=True)
class EdgeDispatchResult:
    """Result of a POST to the ironclaw-webhook-dispatch Edge Function."""

    event_type: str
    tenant_id: str
    http_status: int | None
    succeeded: bool
    error_detail: str | None
    dispatched_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "tenant_id": self.tenant_id,
            "http_status": self.http_status,
            "succeeded": self.succeeded,
            "error_detail": self.error_detail,
            "dispatched_at": self.dispatched_at,
        }


# ---------------------------------------------------------------------------
# HMAC-SHA256 signature
# ---------------------------------------------------------------------------


def _compute_signature(secret_hash: str, body: bytes, timestamp: str) -> str:
    signing_payload = f"{timestamp}.".encode() + body
    digest = hmac.new(
        secret_hash.encode("utf-8"),
        signing_payload,
        hashlib.sha256,
    ).hexdigest()
    return f"sha256={digest}"


def verify_webhook_signature(
    secret_hash: str,
    body: bytes,
    timestamp: str,
    received_signature: str,
) -> bool:
    expected = _compute_signature(secret_hash, body, timestamp)
    return hmac.compare_digest(expected, received_signature)


# ---------------------------------------------------------------------------
# Supabase service-role client accessor (canonical — delegates to app.core.supabase)
# ---------------------------------------------------------------------------


def _get_service_role_client() -> Any:
    try:
        from app.core.supabase import get_supabase_service_client  # type: ignore[import]

        return get_supabase_service_client()
    except ImportError:
        # Fallback: construct directly when core module is unavailable (e.g. isolated tests)
        from supabase import create_client  # type: ignore[import]

        url = os.environ["SUPABASE_URL"]
        key = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
        return create_client(url, key)


# ---------------------------------------------------------------------------
# Edge Function URL builder
# ---------------------------------------------------------------------------


def _edge_function_url(function_name: str) -> str:
    """
    Constructs the Supabase Edge Function URL:
      {SUPABASE_URL}/functions/v1/{function_name}

    Raises ValueError if SUPABASE_URL is not set.
    """
    base = os.environ.get("SUPABASE_URL", "").rstrip("/")
    if not base:
        raise ValueError("SUPABASE_URL environment variable is not set.")
    return f"{base}/functions/v1/{function_name}"


# ---------------------------------------------------------------------------
# Edge Function caller — POST verdict event to ironclaw-webhook-dispatch
# ---------------------------------------------------------------------------


def dispatch_verdict_to_edge(
    event_type: str,
    payload: dict[str, Any],
    tenant_id: str,
    *,
    timeout: float = _EDGE_DISPATCH_TIMEOUT_SECONDS,
) -> EdgeDispatchResult:
    """
    POST {event_type, payload, tenant_id} to the ironclaw-webhook-dispatch
    Supabase Edge Function using the service-role Bearer token.

    Called after every verdict is issued. Failures are logged and returned
    as a failed EdgeDispatchResult — they never raise so the verdict path
    is never blocked.
    """
    service_role_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    if not service_role_key:
        logger.error("webhook_service | dispatch_verdict_to_edge | SUPABASE_SERVICE_ROLE_KEY not set")
        return EdgeDispatchResult(
            event_type=event_type,
            tenant_id=tenant_id,
            http_status=None,
            succeeded=False,
            error_detail="SUPABASE_SERVICE_ROLE_KEY not configured",
            dispatched_at=datetime.now(UTC).isoformat(),
        )

    try:
        url = _edge_function_url(_EDGE_FUNCTION_NAME)
    except ValueError as exc:
        logger.error("webhook_service | dispatch_verdict_to_edge | url build error | %s", exc)
        return EdgeDispatchResult(
            event_type=event_type,
            tenant_id=tenant_id,
            http_status=None,
            succeeded=False,
            error_detail=str(exc),
            dispatched_at=datetime.now(UTC).isoformat(),
        )

    body: dict[str, Any] = {
        "event_type": event_type,
        "payload": payload,
        "tenant_id": tenant_id,
        "dispatched_at": datetime.now(UTC).isoformat(),
    }
    body_bytes = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {service_role_key}",
        "User-Agent": "IronClaw-Security/1.0",
    }

    dispatched_at = datetime.now(UTC).isoformat()

    try:
        with httpx.Client(timeout=timeout) as http:
            response = http.post(url, content=body_bytes, headers=headers)

        if response.is_success:
            logger.info(
                "webhook_service | dispatch_verdict_to_edge | event_type=%s tenant_id=%s http=%d",
                event_type,
                tenant_id,
                response.status_code,
            )
            return EdgeDispatchResult(
                event_type=event_type,
                tenant_id=tenant_id,
                http_status=response.status_code,
                succeeded=True,
                error_detail=None,
                dispatched_at=dispatched_at,
            )

        error_detail = f"Non-2xx from edge function: HTTP {response.status_code} — {response.text[:512]}"
        logger.warning(
            "webhook_service | dispatch_verdict_to_edge | event_type=%s tenant_id=%s http=%d detail=%s",
            event_type,
            tenant_id,
            response.status_code,
            error_detail,
        )
        return EdgeDispatchResult(
            event_type=event_type,
            tenant_id=tenant_id,
            http_status=response.status_code,
            succeeded=False,
            error_detail=error_detail,
            dispatched_at=dispatched_at,
        )

    except httpx.TimeoutException as exc:
        detail = f"Timeout after {timeout}s contacting edge function: {exc}"
        logger.warning(
            "webhook_service | dispatch_verdict_to_edge | event_type=%s tenant_id=%s timeout",
            event_type,
            tenant_id,
        )
        return EdgeDispatchResult(
            event_type=event_type,
            tenant_id=tenant_id,
            http_status=None,
            succeeded=False,
            error_detail=detail,
            dispatched_at=dispatched_at,
        )

    except Exception as exc:  # noqa: BLE001
        detail = f"HTTP error contacting edge function: {exc}"
        logger.error(
            "webhook_service | dispatch_verdict_to_edge | event_type=%s tenant_id=%s error=%s",
            event_type,
            tenant_id,
            exc,
        )
        return EdgeDispatchResult(
            event_type=event_type,
            tenant_id=tenant_id,
            http_status=None,
            succeeded=False,
            error_detail=detail,
            dispatched_at=dispatched_at,
        )


# ---------------------------------------------------------------------------
# Subscription queries
# ---------------------------------------------------------------------------


def _query_subscriptions_for_event(
    tenant_id: str,
    event_type: str,
    *,
    client: Any = None,
) -> list[WebhookSubscription]:
    sb = client or _get_service_role_client()
    try:
        resp = sb.table(_WEBHOOK_SUBSCRIPTIONS_TABLE).select("*").eq("tenant_id", tenant_id).eq("active", True).filter("events", "cs", json.dumps([event_type])).execute()
        rows: list[dict[str, Any]] = resp.data or []
        return [WebhookSubscription.from_row(r) for r in rows]
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "webhook_service | query_subscriptions | tenant_id=%s event_type=%s error=%s",
            tenant_id,
            event_type,
            exc,
        )
        return []


# ---------------------------------------------------------------------------
# Delivery log writes (service_role)
# ---------------------------------------------------------------------------


def _write_delivery_log(
    record: WebhookDeliveryRecord,
    *,
    client: Any = None,
    upsert: bool = False,
) -> None:
    sb = client or _get_service_role_client()
    try:
        row = record.to_dict()
        if upsert:
            sb.table(_WEBHOOK_DELIVERY_TABLE).upsert(row).execute()
        else:
            sb.table(_WEBHOOK_DELIVERY_TABLE).insert(row).execute()
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "webhook_service | write_delivery_log | delivery_id=%s error=%s",
            record.id,
            exc,
        )


def _update_delivery_log_attempt(
    delivery_id: str,
    *,
    status: WebhookDeliveryStatus,
    attempts: int,
    http_status: int | None,
    response_body: str | None,
    error_detail: str | None,
    delivered_at: str | None,
    next_attempt_at: str | None,
    client: Any = None,
) -> None:
    sb = client or _get_service_role_client()
    try:
        sb.table(_WEBHOOK_DELIVERY_TABLE).update(
            {
                "status": status.value,
                "attempts": attempts,
                "http_status": http_status,
                "response_body": response_body[:4096] if response_body else None,
                "error_detail": error_detail,
                "delivered_at": delivered_at,
                "next_attempt_at": next_attempt_at,
            }
        ).eq("id", delivery_id).execute()
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "webhook_service | update_delivery_log | delivery_id=%s error=%s",
            delivery_id,
            exc,
        )


# ---------------------------------------------------------------------------
# HTTP dispatch (synchronous, single attempt)
# ---------------------------------------------------------------------------


def _dispatch_http_post(
    subscription: WebhookSubscription,
    delivery_id: str,
    event_type: str,
    payload: dict[str, Any],
    *,
    attempt: int,
    timeout: float = _DELIVERY_TIMEOUT_SECONDS,
) -> tuple[int | None, str | None, str | None]:
    body_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    signature = _compute_signature(subscription.secret_hash, body_bytes, timestamp)

    headers = {
        "Content-Type": "application/json",
        _SIGNATURE_HEADER: signature,
        _DELIVERY_ID_HEADER: delivery_id,
        _EVENT_HEADER: event_type,
        _TIMESTAMP_HEADER: timestamp,
        "User-Agent": "IronClaw-Security/1.0",
    }

    try:
        with httpx.Client(timeout=timeout) as http:
            response = http.post(
                subscription.target_url,
                content=body_bytes,
                headers=headers,
            )
        resp_text = response.text[:4096] if response.text else None
        if response.is_success:
            logger.info(
                "webhook_service | dispatch | delivery_id=%s subscription_id=%s attempt=%d http=%d",
                delivery_id,
                subscription.id,
                attempt,
                response.status_code,
            )
            return response.status_code, resp_text, None
        error_detail = f"Non-2xx response: HTTP {response.status_code}"
        logger.warning(
            "webhook_service | dispatch | delivery_id=%s subscription_id=%s attempt=%d http=%d detail=%s",
            delivery_id,
            subscription.id,
            attempt,
            response.status_code,
            error_detail,
        )
        return response.status_code, resp_text, error_detail

    except httpx.TimeoutException as exc:
        detail = f"Timeout after {timeout}s: {exc}"
        logger.warning(
            "webhook_service | dispatch | delivery_id=%s subscription_id=%s attempt=%d timeout",
            delivery_id,
            subscription.id,
            attempt,
        )
        return None, None, detail

    except Exception as exc:  # noqa: BLE001
        detail = f"HTTP error: {exc}"
        logger.error(
            "webhook_service | dispatch | delivery_id=%s subscription_id=%s attempt=%d error=%s",
            delivery_id,
            subscription.id,
            attempt,
            exc,
        )
        return None, None, detail


# ---------------------------------------------------------------------------
# Retry logic
# ---------------------------------------------------------------------------


def _next_attempt_iso(attempt: int) -> str:
    delay_seconds = min(int(_RETRY_BACKOFF_BASE**attempt), 3600)
    next_at = datetime.now(UTC) + timedelta(seconds=delay_seconds)
    return next_at.isoformat()


def _should_retry(http_status: int | None) -> bool:
    if http_status is None:
        return True
    if http_status == 429:
        return True
    if 500 <= http_status < 600:
        return True
    return False


# ---------------------------------------------------------------------------
# Core delivery logic — one subscription, with retry tracking
# ---------------------------------------------------------------------------


def deliver_webhook(
    subscription: WebhookSubscription,
    event_type: str,
    payload: dict[str, Any],
    *,
    existing_delivery_id: str | None = None,
    current_attempts: int = 0,
    client: Any = None,
) -> WebhookDispatchResult:
    delivery_id = existing_delivery_id or str(uuid.uuid4())
    attempt_number = current_attempts + 1
    now_iso = datetime.now(UTC).isoformat()

    envelope: dict[str, Any] = {
        "ironclaw_event": event_type,
        "delivery_id": delivery_id,
        "subscription_id": subscription.id,
        "tenant_id": subscription.tenant_id,
        "attempt": attempt_number,
        "timestamp": now_iso,
        "data": payload,
    }

    if current_attempts == 0:
        initial_record = WebhookDeliveryRecord(
            id=delivery_id,
            subscription_id=subscription.id,
            tenant_id=subscription.tenant_id,
            event_type=event_type,
            payload_json=json.dumps(envelope, separators=(",", ":"), ensure_ascii=False),
            status=WebhookDeliveryStatus.PENDING,
            attempts=0,
            http_status=None,
            response_body=None,
            error_detail=None,
            delivered_at=None,
            next_attempt_at=None,
            created_at=now_iso,
        )
        _write_delivery_log(initial_record, client=client)

    http_status, response_body, error_detail = _dispatch_http_post(
        subscription,
        delivery_id,
        event_type,
        envelope,
        attempt=attempt_number,
    )

    success = error_detail is None and http_status is not None and (200 <= http_status < 300)

    if success:
        final_status = WebhookDeliveryStatus.SUCCESS
        delivered_at = datetime.now(UTC).isoformat()
        next_attempt_at = None
    elif attempt_number >= subscription.max_attempts or not _should_retry(http_status):
        final_status = WebhookDeliveryStatus.EXHAUSTED
        delivered_at = None
        next_attempt_at = None
    else:
        final_status = WebhookDeliveryStatus.FAILED
        delivered_at = None
        next_attempt_at = _next_attempt_iso(attempt_number)

    _update_delivery_log_attempt(
        delivery_id,
        status=final_status,
        attempts=attempt_number,
        http_status=http_status,
        response_body=response_body,
        error_detail=error_detail,
        delivered_at=delivered_at,
        next_attempt_at=next_attempt_at,
        client=client,
    )

    logger.info(
        "webhook_service | deliver_webhook | delivery_id=%s subscription_id=%s event=%s attempt=%d status=%s",
        delivery_id,
        subscription.id,
        event_type,
        attempt_number,
        final_status.value,
    )

    return WebhookDispatchResult(
        delivery_id=delivery_id,
        subscription_id=subscription.id,
        tenant_id=subscription.tenant_id,
        event_type=event_type,
        status=final_status,
        http_status=http_status,
        attempts=attempt_number,
        error_detail=error_detail,
        delivered_at=delivered_at,
    )


# ---------------------------------------------------------------------------
# Fan-out: dispatch event to all matching subscriptions for a tenant
# AND fire the ironclaw-webhook-dispatch Edge Function
# ---------------------------------------------------------------------------


def dispatch_event(
    tenant_id: str,
    event_type: str,
    payload: dict[str, Any],
    *,
    client: Any = None,
    fire_edge_function: bool = True,
) -> list[WebhookDispatchResult]:
    """
    Fan-out webhook delivery to all active subscriptions for this tenant/event,
    then POST to the ironclaw-webhook-dispatch Edge Function so that server-side
    downstream consumers (alerting, SIEM, realtime channels) are notified.

    `fire_edge_function=False` disables the edge call for tests or environments
    where the Edge Function is not deployed.
    """
    subscriptions = _query_subscriptions_for_event(tenant_id, event_type, client=client)

    if not subscriptions:
        logger.debug(
            "webhook_service | dispatch_event | no subscriptions | tenant_id=%s event_type=%s",
            tenant_id,
            event_type,
        )

    results: list[WebhookDispatchResult] = []
    for sub in subscriptions:
        result = deliver_webhook(sub, event_type, payload, client=client)
        results.append(result)

    succeeded = sum(1 for r in results if r.succeeded)
    failed = len(results) - succeeded
    logger.info(
        "webhook_service | dispatch_event | tenant_id=%s event_type=%s subscriptions=%d succeeded=%d failed=%d",
        tenant_id,
        event_type,
        len(subscriptions),
        succeeded,
        failed,
    )

    # Fire the ironclaw-webhook-dispatch Edge Function after every verdict fan-out.
    # This is non-blocking to the verdict path: failures are logged only.
    if fire_edge_function:
        edge_result = dispatch_verdict_to_edge(
            event_type=event_type,
            payload=payload,
            tenant_id=tenant_id,
        )
        if not edge_result.succeeded:
            logger.warning(
                "webhook_service | dispatch_event | edge_dispatch_failed | tenant_id=%s event_type=%s detail=%s",
                tenant_id,
                event_type,
                edge_result.error_detail,
            )

    return results


# ---------------------------------------------------------------------------
# Retry runner — for background task / queue-driven retries
# ---------------------------------------------------------------------------


def retry_failed_delivery(
    delivery_id: str,
    subscription_id: str,
    tenant_id: str,
    event_type: str,
    payload_json: str,
    current_attempts: int,
    *,
    client: Any = None,
) -> WebhookDispatchResult:
    sb = client or _get_service_role_client()

    try:
        resp = sb.table(_WEBHOOK_SUBSCRIPTIONS_TABLE).select("*").eq("id", subscription_id).eq("tenant_id", tenant_id).eq("active", True).limit(1).execute()
        rows: list[dict[str, Any]] = resp.data or []
        if not rows:
            error_msg = f"Subscription {subscription_id} not found or inactive for retry."
            logger.warning("webhook_service | retry_failed_delivery | %s", error_msg)
            return WebhookDispatchResult(
                delivery_id=delivery_id,
                subscription_id=subscription_id,
                tenant_id=tenant_id,
                event_type=event_type,
                status=WebhookDeliveryStatus.EXHAUSTED,
                http_status=None,
                attempts=current_attempts,
                error_detail=error_msg,
                delivered_at=None,
            )
        sub = WebhookSubscription.from_row(rows[0])
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "webhook_service | retry_failed_delivery | subscription fetch error | delivery_id=%s error=%s",
            delivery_id,
            exc,
        )
        return WebhookDispatchResult(
            delivery_id=delivery_id,
            subscription_id=subscription_id,
            tenant_id=tenant_id,
            event_type=event_type,
            status=WebhookDeliveryStatus.EXHAUSTED,
            http_status=None,
            attempts=current_attempts,
            error_detail=str(exc),
            delivered_at=None,
        )

    try:
        payload = json.loads(payload_json)
    except Exception:  # noqa: BLE001
        payload = {"raw": payload_json}

    return deliver_webhook(
        sub,
        event_type,
        payload.get("data", payload),
        existing_delivery_id=delivery_id,
        current_attempts=current_attempts,
        client=client,
    )


# ---------------------------------------------------------------------------
# Delivery log query helpers (read-only, service_role)
# ---------------------------------------------------------------------------


def get_delivery_log(
    delivery_id: str,
    *,
    client: Any = None,
) -> dict[str, Any] | None:
    sb = client or _get_service_role_client()
    try:
        resp = sb.table(_WEBHOOK_DELIVERY_TABLE).select("*").eq("id", delivery_id).limit(1).execute()
        rows = resp.data or []
        return rows[0] if rows else None
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "webhook_service | get_delivery_log | delivery_id=%s error=%s",
            delivery_id,
            exc,
        )
        return None


def list_delivery_logs_for_tenant(
    tenant_id: str,
    *,
    event_type: str | None = None,
    status: WebhookDeliveryStatus | str | None = None,
    limit: int = 100,
    client: Any = None,
) -> list[dict[str, Any]]:
    sb = client or _get_service_role_client()
    try:
        query = sb.table(_WEBHOOK_DELIVERY_TABLE).select("*").eq("tenant_id", tenant_id).order("created_at", desc=True).limit(limit)
        if event_type:
            query = query.eq("event_type", event_type)
        if status is not None:
            status_val = status.value if isinstance(status, WebhookDeliveryStatus) else status
            query = query.eq("status", status_val)
        resp = query.execute()
        return resp.data or []
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "webhook_service | list_delivery_logs | tenant_id=%s error=%s",
            tenant_id,
            exc,
        )
        return []


def list_retryable_deliveries(
    *,
    limit: int = 50,
    client: Any = None,
) -> list[dict[str, Any]]:
    """
    Returns delivery log rows with status='failed' and next_attempt_at <= now.
    Consumed by the webhooks router retry worker only.
    """
    sb = client or _get_service_role_client()
    now_iso = datetime.now(UTC).isoformat()
    try:
        resp = sb.table(_WEBHOOK_DELIVERY_TABLE).select("*").eq("status", WebhookDeliveryStatus.FAILED.value).lte("next_attempt_at", now_iso).order("next_attempt_at", desc=False).limit(limit).execute()
        return resp.data or []
    except Exception as exc:  # noqa: BLE001
        logger.error("webhook_service | list_retryable_deliveries | error=%s", exc)
        return []
