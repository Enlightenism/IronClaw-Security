from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json
import logging
import os
from typing import Any
import uuid

import httpx

from app.models.webhook import WebhookDeliveryStatus
from app.persistencebootstrap import PersistenceStore

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

_EDGE_FUNCTION_NAME = "ironclaw-webhook-dispatch"


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
            id=str(row["id"]),
            tenant_id=str(row["tenant_id"]),
            target_url=str(row["target_url"]),
            events=list(row.get("events") or []),
            secret_hash=str(row["secret_hash"]),
            active=bool(row.get("active", True)),
            max_attempts=int(row.get("max_attempts") or _MAX_ATTEMPTS),
            metadata=dict(row.get("metadata") or {}),
            created_at=str(row.get("created_at") or datetime.now(UTC).isoformat()),
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
# Persistence adapter — single canonical path, no raw Supabase client access
# ---------------------------------------------------------------------------


def _get_persistence_store() -> PersistenceStore:
    try:
        from app.persistencebootstrap import get_persistence_store  # type: ignore[import]

        return get_persistence_store()
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "webhook_service | _get_persistence_store | bootstrap unavailable: %s",
            exc,
        )
        raise


# ---------------------------------------------------------------------------
# Edge Function URL builder
# ---------------------------------------------------------------------------


def _edge_function_url(function_name: str) -> str:
    base = os.environ.get("SUPABASE_URL", "").rstrip("/")
    if not base:
        raise ValueError("SUPABASE_URL environment variable is not set.")
    return f"{base}/functions/v1/{function_name}"


# ---------------------------------------------------------------------------
# Canonical HTTP hooks
# ---------------------------------------------------------------------------


def _post_json_with_httpx(
    *,
    url: str,
    body_bytes: bytes,
    headers: dict[str, str],
    timeout: float,
) -> tuple[int | None, str | None, str | None]:
    try:
        with httpx.Client(timeout=timeout) as http:
            response = http.post(url, content=body_bytes, headers=headers)

        response_text = response.text[:4096] if response.text else None
        if response.is_success:
            return response.status_code, response_text, None
        return response.status_code, response_text, f"Non-2xx response: HTTP {response.status_code}"
    except httpx.TimeoutException as exc:
        return None, None, f"Timeout after {timeout}s: {exc}"
    except Exception as exc:  # noqa: BLE001
        return None, None, f"HTTP error: {exc}"


def _dispatch_http_post_impl(
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

    http_status, response_body, error_detail = _post_json_with_httpx(
        url=subscription.target_url,
        body_bytes=body_bytes,
        headers=headers,
        timeout=timeout,
    )

    if error_detail is None and http_status is not None:
        logger.info(
            "webhook_service | dispatch | delivery_id=%s subscription_id=%s attempt=%d http=%d",
            delivery_id,
            subscription.id,
            attempt,
            http_status,
        )
    elif http_status is not None:
        logger.warning(
            "webhook_service | dispatch | delivery_id=%s subscription_id=%s attempt=%d http=%d detail=%s",
            delivery_id,
            subscription.id,
            attempt,
            http_status,
            error_detail,
        )
    elif error_detail and error_detail.startswith("Timeout after"):
        logger.warning(
            "webhook_service | dispatch | delivery_id=%s subscription_id=%s attempt=%d timeout",
            delivery_id,
            subscription.id,
            attempt,
        )
    else:
        logger.error(
            "webhook_service | dispatch | delivery_id=%s subscription_id=%s attempt=%d error=%s",
            delivery_id,
            subscription.id,
            attempt,
            error_detail,
        )

    return http_status, response_body, error_detail


def _dispatch_http_post(
    subscription: WebhookSubscription,
    delivery_id: str,
    event_type: str,
    payload: dict[str, Any],
    *,
    attempt: int,
    timeout: float = _DELIVERY_TIMEOUT_SECONDS,
) -> tuple[int | None, str | None, str | None]:
    return _dispatch_http_post_impl(
        subscription,
        delivery_id,
        event_type,
        payload,
        attempt=attempt,
        timeout=timeout,
    )


def dispatch_http_post(
    subscription: WebhookSubscription,
    delivery_id: str,
    event_type: str,
    payload: dict[str, Any],
    *,
    attempt: int,
    timeout: float = _DELIVERY_TIMEOUT_SECONDS,
) -> tuple[int | None, str | None, str | None]:
    return _dispatch_http_post(
        subscription,
        delivery_id,
        event_type,
        payload,
        attempt=attempt,
        timeout=timeout,
    )


dispatchhttppost = dispatch_http_post


# ---------------------------------------------------------------------------
# Edge Function caller
# ---------------------------------------------------------------------------


def _dispatch_verdict_to_edge_impl(
    event_type: str,
    payload: dict[str, Any],
    tenant_id: str,
    *,
    timeout: float = _EDGE_DISPATCH_TIMEOUT_SECONDS,
) -> EdgeDispatchResult:
    service_role_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    dispatched_at = datetime.now(UTC).isoformat()

    if not service_role_key:
        logger.error(
            "webhook_service | dispatch_verdict_to_edge | SUPABASE_SERVICE_ROLE_KEY not set",
        )
        return EdgeDispatchResult(
            event_type=event_type,
            tenant_id=tenant_id,
            http_status=None,
            succeeded=False,
            error_detail="SUPABASE_SERVICE_ROLE_KEY not configured",
            dispatched_at=dispatched_at,
        )

    try:
        url = _edge_function_url(_EDGE_FUNCTION_NAME)
    except ValueError as exc:
        logger.error(
            "webhook_service | dispatch_verdict_to_edge | url build error | %s",
            exc,
        )
        return EdgeDispatchResult(
            event_type=event_type,
            tenant_id=tenant_id,
            http_status=None,
            succeeded=False,
            error_detail=str(exc),
            dispatched_at=dispatched_at,
        )

    body: dict[str, Any] = {
        "event_type": event_type,
        "payload": payload,
        "tenant_id": tenant_id,
        "dispatched_at": dispatched_at,
    }
    body_bytes = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {service_role_key}",
        "User-Agent": "IronClaw-Security/1.0",
    }

    http_status, response_body, error_detail = _post_json_with_httpx(
        url=url,
        body_bytes=body_bytes,
        headers=headers,
        timeout=timeout,
    )

    if error_detail is None and http_status is not None:
        logger.info(
            "webhook_service | dispatch_verdict_to_edge | event_type=%s tenant_id=%s http=%d",
            event_type,
            tenant_id,
            http_status,
        )
        return EdgeDispatchResult(
            event_type=event_type,
            tenant_id=tenant_id,
            http_status=http_status,
            succeeded=True,
            error_detail=None,
            dispatched_at=dispatched_at,
        )

    normalized_error = error_detail
    if http_status is not None and response_body is not None:
        normalized_error = f"Non-2xx from edge function: HTTP {http_status} — {response_body[:512]}"
        logger.warning(
            "webhook_service | dispatch_verdict_to_edge | event_type=%s tenant_id=%s http=%d detail=%s",
            event_type,
            tenant_id,
            http_status,
            normalized_error,
        )
    elif normalized_error and normalized_error.startswith("Timeout after"):
        logger.warning(
            "webhook_service | dispatch_verdict_to_edge | event_type=%s tenant_id=%s timeout",
            event_type,
            tenant_id,
        )
    else:
        logger.error(
            "webhook_service | dispatch_verdict_to_edge | event_type=%s tenant_id=%s error=%s",
            event_type,
            tenant_id,
            normalized_error,
        )

    return EdgeDispatchResult(
        event_type=event_type,
        tenant_id=tenant_id,
        http_status=http_status,
        succeeded=False,
        error_detail=normalized_error,
        dispatched_at=dispatched_at,
    )


def dispatch_verdict_to_edge(
    event_type: str,
    payload: dict[str, Any],
    tenant_id: str,
    *,
    timeout: float = _EDGE_DISPATCH_TIMEOUT_SECONDS,
) -> EdgeDispatchResult:
    return _dispatch_verdict_to_edge_impl(
        event_type=event_type,
        payload=payload,
        tenant_id=tenant_id,
        timeout=timeout,
    )


dispatchverdicttoedge = dispatch_verdict_to_edge


# ---------------------------------------------------------------------------
# Subscription queries — via persistence adapter
# ---------------------------------------------------------------------------


def _query_subscriptions_for_event(
    tenant_id: str,
    event_type: str,
    *,
    store: PersistenceStore | None = None,
) -> list[WebhookSubscription]:
    ps = store or _get_persistence_store()
    try:
        rows = ps.select(
            _WEBHOOK_SUBSCRIPTIONS_TABLE,
            filters={"tenant_id": tenant_id, "active": True},
        )
        matching = [row for row in rows if event_type in (row.get("events") or [])]
        return [WebhookSubscription.from_row(row) for row in matching]
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "webhook_service | query_subscriptions | tenant_id=%s event_type=%s error=%s",
            tenant_id,
            event_type,
            exc,
        )
        return []


# ---------------------------------------------------------------------------
# Delivery log writes — via persistence adapter
# ---------------------------------------------------------------------------


def _write_delivery_log(
    record: WebhookDeliveryRecord,
    *,
    store: PersistenceStore | None = None,
) -> None:
    ps = store or _get_persistence_store()
    try:
        ps.insert(_WEBHOOK_DELIVERY_TABLE, record.to_dict())
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
    store: PersistenceStore | None = None,
) -> None:
    ps = store or _get_persistence_store()
    try:
        ps.update(
            _WEBHOOK_DELIVERY_TABLE,
            {
                "status": status.value,
                "attempts": attempts,
                "http_status": http_status,
                "response_body": response_body[:4096] if response_body else None,
                "error_detail": error_detail,
                "delivered_at": delivered_at,
                "next_attempt_at": next_attempt_at,
            },
            filters={"id": delivery_id},
        )
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "webhook_service | update_delivery_log | delivery_id=%s error=%s",
            delivery_id,
            exc,
        )


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
# Core delivery logic
# ---------------------------------------------------------------------------


def deliver_webhook(
    subscription: WebhookSubscription,
    event_type: str,
    payload: dict[str, Any],
    *,
    existing_delivery_id: str | None = None,
    current_attempts: int = 0,
    store: PersistenceStore | None = None,
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
        _write_delivery_log(initial_record, store=store)

    http_status, response_body, error_detail = dispatch_http_post(
        subscription,
        delivery_id,
        event_type,
        envelope,
        attempt=attempt_number,
    )

    success = error_detail is None and http_status is not None and 200 <= http_status < 300

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
        store=store,
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
# Fan-out dispatch
# ---------------------------------------------------------------------------


def dispatch_event(
    tenant_id: str,
    event_type: str,
    payload: dict[str, Any],
    *,
    store: PersistenceStore | None = None,
    fire_edge_function: bool = True,
) -> list[WebhookDispatchResult]:
    subscriptions = _query_subscriptions_for_event(tenant_id, event_type, store=store)

    if not subscriptions:
        logger.debug(
            "webhook_service | dispatch_event | no subscriptions | tenant_id=%s event_type=%s",
            tenant_id,
            event_type,
        )

    results: list[WebhookDispatchResult] = []
    for subscription in subscriptions:
        try:
            results.append(deliver_webhook(subscription, event_type, payload, store=store))
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "webhook_service | dispatch_event | subscription_delivery_error | subscription_id=%s tenant_id=%s event_type=%s error=%s",
                subscription.id,
                tenant_id,
                event_type,
                exc,
            )
            results.append(
                WebhookDispatchResult(
                    delivery_id=str(uuid.uuid4()),
                    subscription_id=subscription.id,
                    tenant_id=subscription.tenant_id,
                    event_type=event_type,
                    status=WebhookDeliveryStatus.FAILED,
                    http_status=None,
                    attempts=0,
                    error_detail=str(exc),
                    delivered_at=None,
                )
            )

    succeeded = sum(1 for result in results if result.succeeded)
    failed = len(results) - succeeded
    logger.info(
        "webhook_service | dispatch_event | tenant_id=%s event_type=%s subscriptions=%d succeeded=%d failed=%d",
        tenant_id,
        event_type,
        len(subscriptions),
        succeeded,
        failed,
    )

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
# Retry runner
# ---------------------------------------------------------------------------


def retry_failed_delivery(
    delivery_id: str,
    subscription_id: str,
    tenant_id: str,
    event_type: str,
    payload_json: str,
    current_attempts: int,
    *,
    store: PersistenceStore | None = None,
) -> WebhookDispatchResult:
    ps = store or _get_persistence_store()

    try:
        rows = ps.select(
            _WEBHOOK_SUBSCRIPTIONS_TABLE,
            filters={"id": subscription_id, "tenant_id": tenant_id, "active": True},
            limit=1,
        )
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
        subscription = WebhookSubscription.from_row(rows[0])
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
        subscription,
        event_type,
        payload.get("data", payload),
        existing_delivery_id=delivery_id,
        current_attempts=current_attempts,
        store=store,
    )


# ---------------------------------------------------------------------------
# Delivery log query helpers (read-only)
# ---------------------------------------------------------------------------


def get_delivery_log(
    delivery_id: str,
    *,
    store: PersistenceStore | None = None,
) -> dict[str, Any] | None:
    ps = store or _get_persistence_store()
    try:
        rows = ps.select(
            _WEBHOOK_DELIVERY_TABLE,
            filters={"id": delivery_id},
            limit=1,
        )
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
    store: PersistenceStore | None = None,
) -> list[dict[str, Any]]:
    ps = store or _get_persistence_store()
    try:
        filters: dict[str, Any] = {"tenant_id": tenant_id}
        if event_type:
            filters["event_type"] = event_type
        if status is not None:
            filters["status"] = status.value if isinstance(status, WebhookDeliveryStatus) else status
        return ps.select(_WEBHOOK_DELIVERY_TABLE, filters=filters, limit=limit)
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
    store: PersistenceStore | None = None,
) -> list[dict[str, Any]]:
    ps = store or _get_persistence_store()
    try:
        rows = ps.select(
            _WEBHOOK_DELIVERY_TABLE,
            filters={"status": WebhookDeliveryStatus.FAILED.value},
            limit=limit,
        )
        now_iso = datetime.now(UTC).isoformat()
        return [row for row in rows if row.get("next_attempt_at") and row["next_attempt_at"] <= now_iso]
    except Exception as exc:  # noqa: BLE001
        logger.error("webhook_service | list_retryable_deliveries | error=%s", exc)
        return []


__all__ = [
    "WebhookSubscription",
    "WebhookDeliveryRecord",
    "WebhookDispatchResult",
    "EdgeDispatchResult",
    "verify_webhook_signature",
    "deliver_webhook",
    "dispatch_event",
    "retry_failed_delivery",
    "get_delivery_log",
    "list_delivery_logs_for_tenant",
    "list_retryable_deliveries",
    "_dispatch_http_post",
    "dispatch_http_post",
    "dispatchhttppost",
    "dispatch_verdict_to_edge",
    "dispatchverdicttoedge",
]
