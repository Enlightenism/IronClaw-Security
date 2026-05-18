from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import hmac
import json
import logging
from threading import Lock
import time
from typing import Any
import urllib.error
import urllib.request
from uuid import uuid4

from app.models.webhook import (
    WebhookCreateRequest,
    WebhookDeliveryAttempt,
    WebhookDeliveryStatus,
    WebhookEventPayload,
    WebhookEventType,
    WebhookFilterRequest,
    WebhookResponse,
    WebhookRotateSecretResponse,
    WebhookSigningAlgorithm,
    WebhookStatus,
    WebhookStatusUpdateResponse,
    WebhookSummaryResponse,
    WebhookTestResponse,
    WebhookUpdateRequest,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_DEAD_LETTER_SIZE = 500
_RETRY_BACKOFF_BASE_SECONDS = 2.0
_DEFAULT_MAX_RETRIES = 3
_DEFAULT_TIMEOUT_SECONDS = 10
_HIGH_FAILURE_THRESHOLD = 5
_SIGNATURE_HEADER_256 = "X-IronClaw-Signature-256"
_SIGNATURE_HEADER_512 = "X-IronClaw-Signature-512"
_DELIVERY_ID_HEADER = "X-IronClaw-Delivery"
_EVENT_TYPE_HEADER = "X-IronClaw-Event"
_WEBHOOK_AGENT_HEADER = "User-Agent"
_WEBHOOK_AGENT_VALUE = "IronClaw-Webhook/1.0"


# ---------------------------------------------------------------------------
# Internal webhook record (stores secret, never exposed outside service)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _WebhookRecord:
    webhook_id: str
    name: str
    target_url: str
    secret: str
    event_types: list[str]
    org_id: str | None
    signing_algorithm: str
    status: str
    active: bool
    max_retries: int
    timeout_seconds: int
    failure_count: int
    last_triggered_at: str | None
    metadata: dict[str, Any]
    created_at: str
    updated_at: str

    def to_response(self) -> WebhookResponse:
        return WebhookResponse(
            webhook_id=self.webhook_id,
            name=self.name,
            target_url=self.target_url,
            event_types=list(self.event_types),
            org_id=self.org_id,
            signing_algorithm=self.signing_algorithm,
            status=WebhookStatus(self.status),
            active=self.active,
            max_retries=self.max_retries,
            timeout_seconds=self.timeout_seconds,
            failure_count=self.failure_count,
            last_triggered_at=self.last_triggered_at,
            metadata=dict(self.metadata),
            created_at=self.created_at,
            updated_at=self.updated_at,
        )

    def to_summary(self) -> WebhookSummaryResponse:
        return WebhookSummaryResponse(
            webhook_id=self.webhook_id,
            name=self.name,
            target_url=self.target_url,
            status=WebhookStatus(self.status),
            active=self.active,
            event_type_count=len(self.event_types),
            org_id=self.org_id,
            failure_count=self.failure_count,
            created_at=self.created_at,
        )


# ---------------------------------------------------------------------------
# Dead-letter entry
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class DeadLetterEntry:
    delivery_id: str
    webhook_id: str
    event_type: str
    payload_json: str
    payload_hash: str
    error_message: str
    attempt_count: int
    queued_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "delivery_id": self.delivery_id,
            "webhook_id": self.webhook_id,
            "event_type": self.event_type,
            "payload_hash": self.payload_hash,
            "error_message": self.error_message,
            "attempt_count": self.attempt_count,
            "queued_at": self.queued_at,
        }


# ---------------------------------------------------------------------------
# Signing helpers
# ---------------------------------------------------------------------------


def _sign_payload(payload_bytes: bytes, secret: str, algorithm: str) -> str:
    key = secret.encode("utf-8")
    if algorithm == WebhookSigningAlgorithm.HMAC_SHA512:
        digest = hmac.new(key, payload_bytes, hashlib.sha512).hexdigest()
        return f"sha512={digest}"
    digest = hmac.new(key, payload_bytes, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _hash_payload(payload_bytes: bytes) -> str:
    return hashlib.sha256(payload_bytes).hexdigest()


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# WebhookDispatcher
# ---------------------------------------------------------------------------


class WebhookDispatcher:
    """
    Delivery engine for IronClaw webhooks.

    Responsibilities:
    - Register / update / delete webhook registrations.
    - Sign payloads with HMAC-SHA256 or HMAC-SHA512.
    - Deliver events with configurable retry + exponential back-off.
    - Track per-webhook delivery attempts (in-memory, capped).
    - Route failed deliveries exceeding max_retries to the dead-letter queue.
    - Mark webhooks as FAILING after _HIGH_FAILURE_THRESHOLD consecutive failures.
    - Provide dead-letter queue inspection and replay.
    - Filter subscriptions by event_type and org_id scope.
    """

    def __init__(self, *, max_dead_letter: int = _MAX_DEAD_LETTER_SIZE) -> None:
        self._lock = Lock()
        self._webhooks: dict[str, _WebhookRecord] = {}
        # delivery_id → list[WebhookDeliveryAttempt], capped per webhook
        self._delivery_log: dict[str, list[WebhookDeliveryAttempt]] = {}
        self._dead_letter: deque[DeadLetterEntry] = deque(maxlen=max_dead_letter)

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, request: WebhookCreateRequest) -> WebhookResponse:
        now = _utcnow_iso()
        webhook_id = f"wh-{uuid4().hex[:16]}"
        record = _WebhookRecord(
            webhook_id=webhook_id,
            name=request.name,
            target_url=str(request.target_url),
            secret=request.secret,
            event_types=[str(e) for e in request.event_types],
            org_id=request.org_id,
            signing_algorithm=str(request.signing_algorithm),
            status=WebhookStatus.ACTIVE if request.active else WebhookStatus.DISABLED,
            active=request.active,
            max_retries=request.max_retries,
            timeout_seconds=request.timeout_seconds,
            failure_count=0,
            last_triggered_at=None,
            metadata=dict(request.metadata),
            created_at=now,
            updated_at=now,
        )
        with self._lock:
            self._webhooks[webhook_id] = record
            self._delivery_log[webhook_id] = []
        logger.info("webhook.registered id=%s name=%s", webhook_id, request.name)
        return record.to_response()

    def update(self, webhook_id: str, request: WebhookUpdateRequest) -> WebhookResponse | None:
        with self._lock:
            record = self._webhooks.get(webhook_id)
            if record is None:
                return None

            new_name = request.name if request.name is not None else record.name
            new_url = str(request.target_url) if request.target_url is not None else record.target_url
            new_secret = request.secret if request.secret is not None else record.secret
            new_events = [str(e) for e in request.event_types] if request.event_types is not None else record.event_types
            new_org = request.org_id if request.org_id is not None else record.org_id
            new_algo = str(request.signing_algorithm) if request.signing_algorithm is not None else record.signing_algorithm
            new_active = request.active if request.active is not None else record.active
            new_max_retries = request.max_retries if request.max_retries is not None else record.max_retries
            new_timeout = request.timeout_seconds if request.timeout_seconds is not None else record.timeout_seconds
            new_meta = {**record.metadata, **request.metadata} if request.metadata is not None else record.metadata

            if new_active and record.status == WebhookStatus.DISABLED:
                new_status = WebhookStatus.ACTIVE
            elif not new_active:
                new_status = WebhookStatus.DISABLED
            else:
                new_status = record.status

            updated = _WebhookRecord(
                webhook_id=record.webhook_id,
                name=new_name,
                target_url=new_url,
                secret=new_secret,
                event_types=new_events,
                org_id=new_org,
                signing_algorithm=new_algo,
                status=new_status,
                active=new_active,
                max_retries=new_max_retries,
                timeout_seconds=new_timeout,
                failure_count=record.failure_count,
                last_triggered_at=record.last_triggered_at,
                metadata=new_meta,
                created_at=record.created_at,
                updated_at=_utcnow_iso(),
            )
            self._webhooks[webhook_id] = updated

        logger.info("webhook.updated id=%s", webhook_id)
        return updated.to_response()

    def delete(self, webhook_id: str) -> bool:
        with self._lock:
            if webhook_id not in self._webhooks:
                return False
            del self._webhooks[webhook_id]
            self._delivery_log.pop(webhook_id, None)
        logger.info("webhook.deleted id=%s", webhook_id)
        return True

    def get(self, webhook_id: str) -> WebhookResponse | None:
        with self._lock:
            record = self._webhooks.get(webhook_id)
        return record.to_response() if record else None

    def list_webhooks(self, filter_req: WebhookFilterRequest | None = None) -> list[WebhookSummaryResponse]:
        with self._lock:
            records = list(self._webhooks.values())

        if filter_req is not None:
            if filter_req.org_id is not None:
                records = [r for r in records if r.org_id == filter_req.org_id]
            if filter_req.status is not None:
                records = [r for r in records if r.status == str(filter_req.status)]
            if filter_req.active is not None:
                records = [r for r in records if r.active == filter_req.active]
            if filter_req.event_type is not None:
                et = str(filter_req.event_type)
                records = [r for r in records if et in r.event_types or WebhookEventType.ALL in r.event_types]

        return [r.to_summary() for r in records]

    # ------------------------------------------------------------------
    # Secret rotation
    # ------------------------------------------------------------------

    def rotate_secret(self, webhook_id: str, new_secret: str) -> WebhookRotateSecretResponse | None:
        with self._lock:
            record = self._webhooks.get(webhook_id)
            if record is None:
                return None
            updated = _WebhookRecord(
                webhook_id=record.webhook_id,
                name=record.name,
                target_url=record.target_url,
                secret=new_secret,
                event_types=record.event_types,
                org_id=record.org_id,
                signing_algorithm=record.signing_algorithm,
                status=record.status,
                active=record.active,
                max_retries=record.max_retries,
                timeout_seconds=record.timeout_seconds,
                failure_count=record.failure_count,
                last_triggered_at=record.last_triggered_at,
                metadata=record.metadata,
                created_at=record.created_at,
                updated_at=_utcnow_iso(),
            )
            self._webhooks[webhook_id] = updated

        logger.info("webhook.secret_rotated id=%s", webhook_id)
        return WebhookRotateSecretResponse(
            webhook_id=webhook_id,
            signing_algorithm=updated.signing_algorithm,
        )

    # ------------------------------------------------------------------
    # Status toggle
    # ------------------------------------------------------------------

    def set_active(self, webhook_id: str, *, active: bool) -> WebhookStatusUpdateResponse | None:
        with self._lock:
            record = self._webhooks.get(webhook_id)
            if record is None:
                return None
            new_status = WebhookStatus.ACTIVE if active else WebhookStatus.DISABLED
            updated = _WebhookRecord(
                webhook_id=record.webhook_id,
                name=record.name,
                target_url=record.target_url,
                secret=record.secret,
                event_types=record.event_types,
                org_id=record.org_id,
                signing_algorithm=record.signing_algorithm,
                status=new_status,
                active=active,
                max_retries=record.max_retries,
                timeout_seconds=record.timeout_seconds,
                failure_count=record.failure_count,
                last_triggered_at=record.last_triggered_at,
                metadata=record.metadata,
                created_at=record.created_at,
                updated_at=_utcnow_iso(),
            )
            self._webhooks[webhook_id] = updated

        return WebhookStatusUpdateResponse(
            webhook_id=webhook_id,
            active=active,
            status=new_status,
        )

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def dispatch_event(
        self,
        event_type: str,
        data: dict[str, Any],
        *,
        org_id: str | None = None,
    ) -> list[WebhookDeliveryAttempt]:
        """
        Dispatch an event to all matching, active webhook subscriptions.
        Returns the list of final delivery attempt records.
        """
        with self._lock:
            candidates = [r for r in self._webhooks.values() if r.active and r.status != WebhookStatus.DISABLED and self._matches_event(r, event_type, org_id)]

        results: list[WebhookDeliveryAttempt] = []
        for record in candidates:
            attempt = self._deliver_with_retry(record, event_type, data, org_id=org_id)
            results.append(attempt)

        return results

    def _matches_event(
        self,
        record: _WebhookRecord,
        event_type: str,
        org_id: str | None,
    ) -> bool:
        if record.org_id is not None and record.org_id != org_id:
            return False
        subscribed = record.event_types
        return WebhookEventType.ALL in subscribed or event_type in subscribed

    def _build_payload(
        self,
        record: _WebhookRecord,
        event_type: str,
        data: dict[str, Any],
        delivery_id: str,
        org_id: str | None,
    ) -> tuple[bytes, str]:
        envelope = WebhookEventPayload(
            ironclaw_delivery_id=delivery_id,
            webhook_id=record.webhook_id,
            event_type=event_type,
            org_id=org_id,
            data=data,
        )
        payload_bytes = json.dumps(envelope.model_dump(), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        payload_hash = _hash_payload(payload_bytes)
        return payload_bytes, payload_hash

    def _deliver_with_retry(
        self,
        record: _WebhookRecord,
        event_type: str,
        data: dict[str, Any],
        *,
        org_id: str | None,
    ) -> WebhookDeliveryAttempt:
        delivery_id = f"dlv-{uuid4().hex[:20]}"
        payload_bytes, payload_hash = self._build_payload(record, event_type, data, delivery_id, org_id)
        signature = _sign_payload(payload_bytes, record.secret, record.signing_algorithm)

        last_attempt: WebhookDeliveryAttempt | None = None
        max_attempts = record.max_retries + 1

        for attempt_num in range(1, max_attempts + 1):
            if attempt_num > 1:
                backoff = _RETRY_BACKOFF_BASE_SECONDS * (2 ** (attempt_num - 2))
                time.sleep(min(backoff, 30.0))

            last_attempt = self._send_once(
                record=record,
                delivery_id=delivery_id,
                payload_bytes=payload_bytes,
                payload_hash=payload_hash,
                signature=signature,
                event_type=event_type,
                attempt_number=attempt_num,
                max_attempts=max_attempts,
            )

            if last_attempt.status == WebhookDeliveryStatus.SUCCESS:
                self._record_success(record.webhook_id, last_attempt)
                return last_attempt

        # All attempts exhausted
        assert last_attempt is not None
        final = WebhookDeliveryAttempt(
            attempt_id=last_attempt.attempt_id,
            webhook_id=record.webhook_id,
            event_type=event_type,
            payload_hash=payload_hash,
            status=WebhookDeliveryStatus.FAILED,
            http_status_code=last_attempt.http_status_code,
            response_body_snippet=last_attempt.response_body_snippet,
            attempt_number=last_attempt.attempt_number,
            duration_ms=last_attempt.duration_ms,
            error_message=last_attempt.error_message,
            attempted_at=last_attempt.attempted_at,
        )
        self._record_failure(record.webhook_id, final, payload_bytes, event_type)
        return final

    def _send_once(
        self,
        *,
        record: _WebhookRecord,
        delivery_id: str,
        payload_bytes: bytes,
        payload_hash: str,
        signature: str,
        event_type: str,
        attempt_number: int,
        max_attempts: int,
    ) -> WebhookDeliveryAttempt:
        attempt_id = f"att-{uuid4().hex[:16]}"
        attempted_at = _utcnow_iso()
        start_ns = time.monotonic_ns()

        sig_header = _SIGNATURE_HEADER_512 if record.signing_algorithm == WebhookSigningAlgorithm.HMAC_SHA512 else _SIGNATURE_HEADER_256

        headers = {
            "Content-Type": "application/json",
            sig_header: signature,
            _DELIVERY_ID_HEADER: delivery_id,
            _EVENT_TYPE_HEADER: event_type,
            _WEBHOOK_AGENT_HEADER: _WEBHOOK_AGENT_VALUE,
        }

        http_status: int | None = None
        response_snippet: str | None = None
        error_message: str | None = None
        status = WebhookDeliveryStatus.FAILED

        try:
            req = urllib.request.Request(
                record.target_url,
                data=payload_bytes,
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=record.timeout_seconds) as resp:
                http_status = resp.status
                raw_body = resp.read(512)
                response_snippet = raw_body.decode("utf-8", errors="replace")

            if 200 <= http_status < 300:
                status = WebhookDeliveryStatus.SUCCESS
            else:
                error_message = f"Non-2xx HTTP status: {http_status}"
                status = WebhookDeliveryStatus.RETRYING if attempt_number < max_attempts else WebhookDeliveryStatus.FAILED

        except urllib.error.HTTPError as exc:
            http_status = exc.code
            error_message = f"HTTPError {exc.code}: {exc.reason}"
            status = WebhookDeliveryStatus.RETRYING if attempt_number < max_attempts else WebhookDeliveryStatus.FAILED
        except urllib.error.URLError as exc:
            error_message = f"URLError: {exc.reason}"
            status = WebhookDeliveryStatus.RETRYING if attempt_number < max_attempts else WebhookDeliveryStatus.FAILED
        except TimeoutError:
            error_message = f"Delivery timed out after {record.timeout_seconds}s"
            status = WebhookDeliveryStatus.RETRYING if attempt_number < max_attempts else WebhookDeliveryStatus.FAILED
        except Exception as exc:  # noqa: BLE001
            error_message = f"Unexpected error: {exc}"
            status = WebhookDeliveryStatus.RETRYING if attempt_number < max_attempts else WebhookDeliveryStatus.FAILED

        elapsed_ms = (time.monotonic_ns() - start_ns) // 1_000_000

        return WebhookDeliveryAttempt(
            attempt_id=attempt_id,
            webhook_id=record.webhook_id,
            event_type=event_type,
            payload_hash=payload_hash,
            status=status,
            http_status_code=http_status,
            response_body_snippet=response_snippet,
            attempt_number=attempt_number,
            duration_ms=int(elapsed_ms),
            error_message=error_message,
            attempted_at=attempted_at,
        )

    # ------------------------------------------------------------------
    # Post-delivery bookkeeping
    # ------------------------------------------------------------------

    def _record_success(self, webhook_id: str, attempt: WebhookDeliveryAttempt) -> None:
        with self._lock:
            record = self._webhooks.get(webhook_id)
            if record is None:
                return
            updated = _WebhookRecord(
                webhook_id=record.webhook_id,
                name=record.name,
                target_url=record.target_url,
                secret=record.secret,
                event_types=record.event_types,
                org_id=record.org_id,
                signing_algorithm=record.signing_algorithm,
                status=WebhookStatus.ACTIVE,
                active=record.active,
                max_retries=record.max_retries,
                timeout_seconds=record.timeout_seconds,
                failure_count=0,
                last_triggered_at=attempt.attempted_at,
                metadata=record.metadata,
                created_at=record.created_at,
                updated_at=_utcnow_iso(),
            )
            self._webhooks[webhook_id] = updated
            self._delivery_log[webhook_id] = (self._delivery_log.get(webhook_id, []) + [attempt])[-200:]

        logger.debug(
            "webhook.delivered id=%s attempt=%d status=%d",
            webhook_id,
            attempt.attempt_number,
            attempt.http_status_code or 0,
        )

    def _record_failure(
        self,
        webhook_id: str,
        attempt: WebhookDeliveryAttempt,
        payload_bytes: bytes,
        event_type: str,
    ) -> None:
        with self._lock:
            record = self._webhooks.get(webhook_id)
            if record is None:
                return

            new_failures = record.failure_count + 1
            new_status = WebhookStatus.FAILING if new_failures >= _HIGH_FAILURE_THRESHOLD else record.status

            updated = _WebhookRecord(
                webhook_id=record.webhook_id,
                name=record.name,
                target_url=record.target_url,
                secret=record.secret,
                event_types=record.event_types,
                org_id=record.org_id,
                signing_algorithm=record.signing_algorithm,
                status=new_status,
                active=record.active,
                max_retries=record.max_retries,
                timeout_seconds=record.timeout_seconds,
                failure_count=new_failures,
                last_triggered_at=record.last_triggered_at,
                metadata=record.metadata,
                created_at=record.created_at,
                updated_at=_utcnow_iso(),
            )
            self._webhooks[webhook_id] = updated
            self._delivery_log[webhook_id] = (self._delivery_log.get(webhook_id, []) + [attempt])[-200:]

            self._dead_letter.append(
                DeadLetterEntry(
                    delivery_id=attempt.attempt_id,
                    webhook_id=webhook_id,
                    event_type=event_type,
                    payload_json=payload_bytes.decode("utf-8", errors="replace"),
                    payload_hash=attempt.payload_hash,
                    error_message=attempt.error_message or "unknown",
                    attempt_count=attempt.attempt_number,
                    queued_at=_utcnow_iso(),
                )
            )

        logger.warning(
            "webhook.failed id=%s failures=%d error=%s",
            webhook_id,
            new_failures,
            attempt.error_message,
        )

    # ------------------------------------------------------------------
    # Delivery log
    # ------------------------------------------------------------------

    def get_delivery_log(self, webhook_id: str, *, limit: int = 50) -> list[WebhookDeliveryAttempt]:
        with self._lock:
            log = list(self._delivery_log.get(webhook_id, []))
        return log[-limit:]

    # ------------------------------------------------------------------
    # Dead-letter queue
    # ------------------------------------------------------------------

    def list_dead_letter(self, *, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._dead_letter)
        return [e.to_dict() for e in items[-limit:]]

    def replay_dead_letter(self, delivery_id: str) -> WebhookDeliveryAttempt | None:
        """
        Re-attempt delivery of a single dead-letter entry by delivery_id.
        Removes the entry from the dead-letter queue on successful replay.
        """
        with self._lock:
            entry: DeadLetterEntry | None = None
            for item in self._dead_letter:
                if item.delivery_id == delivery_id:
                    entry = item
                    break

        if entry is None:
            return None

        with self._lock:
            record = self._webhooks.get(entry.webhook_id)
        if record is None:
            return None

        try:
            data: dict[str, Any] = json.loads(entry.payload_json).get("data", {})
        except (json.JSONDecodeError, AttributeError):
            data = {}

        result = self._deliver_with_retry(record, entry.event_type, data, org_id=record.org_id)

        if result.status == WebhookDeliveryStatus.SUCCESS:
            with self._lock:
                for i, item in enumerate(self._dead_letter):
                    if item.delivery_id == delivery_id:
                        del self._dead_letter[i]  # type: ignore[attr-defined]
                        break
            logger.info("webhook.dead_letter_replayed id=%s", delivery_id)

        return result

    def purge_dead_letter(self) -> int:
        with self._lock:
            count = len(self._dead_letter)
            self._dead_letter.clear()
        logger.info("webhook.dead_letter_purged count=%d", count)
        return count

    # ------------------------------------------------------------------
    # Test delivery
    # ------------------------------------------------------------------

    def send_test(
        self,
        webhook_id: str,
        event_type: str = WebhookEventType.GUARD_ALLOW,
    ) -> WebhookTestResponse:
        with self._lock:
            record = self._webhooks.get(webhook_id)

        if record is None:
            return WebhookTestResponse(
                webhook_id=webhook_id,
                event_type=event_type,
                delivery_status=WebhookDeliveryStatus.FAILED,
                error_message="Webhook not found",
            )

        test_data: dict[str, Any] = {
            "test": True,
            "message": "IronClaw webhook connectivity test",
        }
        delivery_id = f"test-{uuid4().hex[:20]}"
        payload_bytes, payload_hash = self._build_payload(record, event_type, test_data, delivery_id, record.org_id)
        signature = _sign_payload(payload_bytes, record.secret, record.signing_algorithm)

        attempt = self._send_once(
            record=record,
            delivery_id=delivery_id,
            payload_bytes=payload_bytes,
            payload_hash=payload_hash,
            signature=signature,
            event_type=event_type,
            attempt_number=1,
            max_attempts=1,
        )

        return WebhookTestResponse(
            webhook_id=webhook_id,
            event_type=event_type,
            delivery_status=attempt.status,
            http_status_code=attempt.http_status_code,
            duration_ms=attempt.duration_ms,
            error_message=attempt.error_message,
        )

    # ------------------------------------------------------------------
    # Reset (test isolation)
    # ------------------------------------------------------------------

    def reset(self) -> None:
        with self._lock:
            self._webhooks.clear()
            self._delivery_log.clear()
            self._dead_letter.clear()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_WEBHOOK_DISPATCHER = WebhookDispatcher()


def get_webhook_dispatcher() -> WebhookDispatcher:
    """Return the module-level WebhookDispatcher singleton."""
    return _WEBHOOK_DISPATCHER


def reset_webhook_dispatcher() -> None:
    """Clear all webhook state. Intended for use in tests."""
    _WEBHOOK_DISPATCHER.reset()
