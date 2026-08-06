from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import hmac
import json
import logging
from threading import Lock
from time import sleep as _sleep
from typing import Any, Protocol
from uuid import uuid4

import httpx
from pydantic import SecretStr

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
_AUTO_DISABLE_FAILURE_THRESHOLD = 10
_MAX_DELIVERY_LOG_PER_WEBHOOK = 200
_SIGNATURE_HEADER_256 = "X-IronClaw-Signature-256"
_SIGNATURE_HEADER_512 = "X-IronClaw-Signature-512"
_DELIVERY_ID_HEADER = "X-IronClaw-Delivery"
_EVENT_TYPE_HEADER = "X-IronClaw-Event"
_WEBHOOK_AGENT_HEADER = "User-Agent"
_WEBHOOK_AGENT_VALUE = "IronClaw-Webhook/2.0"


# ---------------------------------------------------------------------------
# Internal webhook record (stores secret, never exposed outside service)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _WebhookRecord:
    webhook_id: str
    name: str
    target_url: str
    secret: SecretStr
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
    org_id: str | None
    event_type: str
    payload_json: str
    payload_hash: str
    error_message: str
    attempt_count: int
    queued_at: str
    last_attempt_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "delivery_id": self.delivery_id,
            "webhook_id": self.webhook_id,
            "org_id": self.org_id,
            "event_type": self.event_type,
            "payload_hash": self.payload_hash,
            "error_message": self.error_message,
            "attempt_count": self.attempt_count,
            "queued_at": self.queued_at,
            "last_attempt_id": self.last_attempt_id,
        }


# ---------------------------------------------------------------------------
# Persistence abstraction
# ---------------------------------------------------------------------------


class WebhookDispatcherRepository(Protocol):
    def save_webhook(self, record: _WebhookRecord) -> None: ...
    def get_webhook(self, webhook_id: str) -> _WebhookRecord | None: ...
    def delete_webhook(self, webhook_id: str) -> bool: ...
    def list_webhooks(self) -> list[_WebhookRecord]: ...
    def append_delivery_attempt(self, webhook_id: str, attempt: WebhookDeliveryAttempt) -> None: ...
    def get_delivery_log(self, webhook_id: str) -> list[WebhookDeliveryAttempt]: ...
    def append_dead_letter(self, entry: DeadLetterEntry) -> None: ...
    def list_dead_letter(self) -> list[DeadLetterEntry]: ...
    def remove_dead_letter(self, delivery_id: str, *, org_id: str | None) -> bool: ...
    def clear_dead_letter(self, *, org_id: str | None = None) -> int: ...
    def reset(self) -> None: ...


class InMemoryWebhookDispatcherRepository:
    def __init__(self, *, max_dead_letter: int = _MAX_DEAD_LETTER_SIZE) -> None:
        self._lock = Lock()
        self._webhooks: dict[str, _WebhookRecord] = {}
        self._delivery_log: dict[str, list[WebhookDeliveryAttempt]] = {}
        self._dead_letter: deque[DeadLetterEntry] = deque(maxlen=max_dead_letter)

    def save_webhook(self, record: _WebhookRecord) -> None:
        with self._lock:
            self._webhooks[record.webhook_id] = record
            self._delivery_log.setdefault(record.webhook_id, [])

    def get_webhook(self, webhook_id: str) -> _WebhookRecord | None:
        with self._lock:
            return self._webhooks.get(webhook_id)

    def delete_webhook(self, webhook_id: str) -> bool:
        with self._lock:
            if webhook_id not in self._webhooks:
                return False
            del self._webhooks[webhook_id]
            self._delivery_log.pop(webhook_id, None)
            retained = deque(
                (entry for entry in self._dead_letter if entry.webhook_id != webhook_id),
                maxlen=self._dead_letter.maxlen,
            )
            self._dead_letter = retained
            return True

    def list_webhooks(self) -> list[_WebhookRecord]:
        with self._lock:
            return list(self._webhooks.values())

    def append_delivery_attempt(self, webhook_id: str, attempt: WebhookDeliveryAttempt) -> None:
        with self._lock:
            history = self._delivery_log.setdefault(webhook_id, [])
            history.append(attempt)
            if len(history) > _MAX_DELIVERY_LOG_PER_WEBHOOK:
                del history[:-_MAX_DELIVERY_LOG_PER_WEBHOOK]

    def get_delivery_log(self, webhook_id: str) -> list[WebhookDeliveryAttempt]:
        with self._lock:
            return list(self._delivery_log.get(webhook_id, []))

    def append_dead_letter(self, entry: DeadLetterEntry) -> None:
        with self._lock:
            self._dead_letter.append(entry)

    def list_dead_letter(self) -> list[DeadLetterEntry]:
        with self._lock:
            return list(self._dead_letter)

    def remove_dead_letter(self, delivery_id: str, *, org_id: str | None) -> bool:
        with self._lock:
            for idx, item in enumerate(self._dead_letter):
                if item.delivery_id == delivery_id and item.org_id == org_id:
                    del self._dead_letter[idx]  # type: ignore[attr-defined]
                    return True
        return False

    def clear_dead_letter(self, *, org_id: str | None = None) -> int:
        with self._lock:
            if org_id is None:
                count = len(self._dead_letter)
                self._dead_letter.clear()
                return count
            retained = [entry for entry in self._dead_letter if entry.org_id != org_id]
            removed = len(self._dead_letter) - len(retained)
            self._dead_letter = deque(retained, maxlen=self._dead_letter.maxlen)
            return removed

    def reset(self) -> None:
        with self._lock:
            self._webhooks.clear()
            self._delivery_log.clear()
            self._dead_letter.clear()


# ---------------------------------------------------------------------------
# Signing helpers
# ---------------------------------------------------------------------------


def _sign_payload(payload_bytes: bytes, secret: SecretStr | str, algorithm: str) -> str:
    secret_value = secret.get_secret_value() if isinstance(secret, SecretStr) else secret
    key = secret_value.encode("utf-8")
    if algorithm == WebhookSigningAlgorithm.HMAC_SHA512:
        digest = hmac.new(key, payload_bytes, hashlib.sha512).hexdigest()
        return f"sha512={digest}"
    digest = hmac.new(key, payload_bytes, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _hash_payload(payload_bytes: bytes) -> str:
    return hashlib.sha256(payload_bytes).hexdigest()


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _coerce_secret(secret: SecretStr | str) -> SecretStr:
    return secret if isinstance(secret, SecretStr) else SecretStr(secret)


# ---------------------------------------------------------------------------
# WebhookDispatcher
# ---------------------------------------------------------------------------


class WebhookDispatcher:
    """
    Delivery engine for IronClaw webhooks.

    Responsibilities:
    - Register / update / delete webhook registrations.
    - Persist registrations, delivery attempts, and dead-letter state through a repository abstraction.
    - Sign payloads with HMAC-SHA256 or HMAC-SHA512.
    - Deliver events with configurable retry + exponential back-off.
    - Track per-webhook delivery attempts.
    - Route failed deliveries exceeding max_retries to the dead-letter queue.
    - Mark webhooks as FAILING after repeated failures and auto-disable after sustained failure.
    - Provide org-scoped dead-letter queue inspection and replay.
    - Filter subscriptions by event_type and org_id scope.
    """

    def __init__(
        self,
        *,
        repository: WebhookDispatcherRepository | None = None,
        http_client: httpx.Client | None = None,
        max_dead_letter: int = _MAX_DEAD_LETTER_SIZE,
        failure_threshold: int = _HIGH_FAILURE_THRESHOLD,
        auto_disable_failure_threshold: int = _AUTO_DISABLE_FAILURE_THRESHOLD,
        sleep_fn: Any | None = None,
    ) -> None:
        self._lock = Lock()
        self._repository = repository or InMemoryWebhookDispatcherRepository(max_dead_letter=max_dead_letter)
        self._http_client = http_client or httpx.Client(follow_redirects=False)
        self._owns_http_client = http_client is None
        self._failure_threshold = max(1, failure_threshold)
        self._auto_disable_failure_threshold = max(self._failure_threshold, auto_disable_failure_threshold)
        self._sleep = sleep_fn or _sleep

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
            secret=_coerce_secret(request.secret),
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
        self._repository.save_webhook(record)
        logger.info("webhook.registered id=%s name=%s", webhook_id, request.name)
        return record.to_response()

    def update(self, webhook_id: str, request: WebhookUpdateRequest) -> WebhookResponse | None:
        with self._lock:
            record = self._repository.get_webhook(webhook_id)
            if record is None:
                return None

            new_name = request.name if request.name is not None else record.name
            new_url = str(request.target_url) if request.target_url is not None else record.target_url
            new_secret = _coerce_secret(request.secret) if request.secret is not None else record.secret
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
            self._repository.save_webhook(updated)

        logger.info("webhook.updated id=%s", webhook_id)
        return updated.to_response()

    def delete(self, webhook_id: str) -> bool:
        deleted = self._repository.delete_webhook(webhook_id)
        if deleted:
            logger.info("webhook.deleted id=%s", webhook_id)
        return deleted

    def get(self, webhook_id: str) -> WebhookResponse | None:
        record = self._repository.get_webhook(webhook_id)
        return record.to_response() if record else None

    def list_webhooks(self, filter_req: WebhookFilterRequest | None = None) -> list[WebhookSummaryResponse]:
        records = self._repository.list_webhooks()

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
            record = self._repository.get_webhook(webhook_id)
            if record is None:
                return None
            updated = _WebhookRecord(
                webhook_id=record.webhook_id,
                name=record.name,
                target_url=record.target_url,
                secret=SecretStr(new_secret),
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
            self._repository.save_webhook(updated)

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
            record = self._repository.get_webhook(webhook_id)
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
            self._repository.save_webhook(updated)

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
        records = self._repository.list_webhooks()
        candidates = [r for r in records if r.active and r.status != WebhookStatus.DISABLED and self._matches_event(r, event_type, org_id)]

        results: list[WebhookDeliveryAttempt] = []
        for record in candidates:
            attempt = self._deliver_with_retry(record, event_type, data, org_id=org_id, is_test=False)
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
        payload_bytes = json.dumps(
            envelope.model_dump(),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        payload_hash = _hash_payload(payload_bytes)
        return payload_bytes, payload_hash

    def _deliver_with_retry(
        self,
        record: _WebhookRecord,
        event_type: str,
        data: dict[str, Any],
        *,
        org_id: str | None,
        is_test: bool,
        delivery_id: str | None = None,
        payload_bytes_override: bytes | None = None,
        payload_hash_override: str | None = None,
    ) -> WebhookDeliveryAttempt:
        effective_delivery_id = delivery_id or f"dlv-{uuid4().hex[:20]}"
        if payload_bytes_override is None:
            payload_bytes, payload_hash = self._build_payload(record, event_type, data, effective_delivery_id, org_id)
        else:
            payload_bytes = payload_bytes_override
            payload_hash = payload_hash_override or _hash_payload(payload_bytes)

        signature = _sign_payload(payload_bytes, record.secret, record.signing_algorithm)

        last_attempt: WebhookDeliveryAttempt | None = None
        max_attempts = max(1, record.max_retries + 1)

        for attempt_num in range(1, max_attempts + 1):
            if attempt_num > 1:
                backoff = _RETRY_BACKOFF_BASE_SECONDS * (2 ** (attempt_num - 2))
                self._sleep(min(backoff, 30.0))

            last_attempt = self._send_once(
                record=record,
                delivery_id=effective_delivery_id,
                payload_bytes=payload_bytes,
                payload_hash=payload_hash,
                signature=signature,
                event_type=event_type,
                attempt_number=attempt_num,
                max_attempts=max_attempts,
            )
            self._repository.append_delivery_attempt(record.webhook_id, last_attempt)

            if last_attempt.status == WebhookDeliveryStatus.SUCCESS:
                self._record_success(record.webhook_id, last_attempt, is_test=is_test)
                return last_attempt

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
        self._record_failure(
            record.webhook_id,
            final,
            payload_bytes,
            event_type,
            delivery_id=effective_delivery_id,
            org_id=record.org_id,
            is_test=is_test,
        )
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
        start_ns = datetime.now(UTC).timestamp()

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
            response = self._http_client.post(
                record.target_url,
                content=payload_bytes,
                headers=headers,
                timeout=record.timeout_seconds,
            )
            http_status = response.status_code
            response_snippet = response.text[:512]
            if 200 <= response.status_code < 300:
                status = WebhookDeliveryStatus.SUCCESS
            else:
                error_message = f"Non-2xx HTTP status: {response.status_code}"
                status = WebhookDeliveryStatus.RETRYING if attempt_number < max_attempts else WebhookDeliveryStatus.FAILED
        except httpx.TimeoutException:
            error_message = f"Delivery timed out after {record.timeout_seconds}s"
            status = WebhookDeliveryStatus.RETRYING if attempt_number < max_attempts else WebhookDeliveryStatus.FAILED
        except httpx.RequestError as exc:
            error_message = f"RequestError: {exc}"
            status = WebhookDeliveryStatus.RETRYING if attempt_number < max_attempts else WebhookDeliveryStatus.FAILED
        except Exception as exc:  # noqa: BLE001
            error_message = f"Unexpected error: {exc}"
            status = WebhookDeliveryStatus.RETRYING if attempt_number < max_attempts else WebhookDeliveryStatus.FAILED

        elapsed_ms = int((datetime.now(UTC).timestamp() - start_ns) * 1000)

        return WebhookDeliveryAttempt(
            attempt_id=attempt_id,
            webhook_id=record.webhook_id,
            event_type=event_type,
            payload_hash=payload_hash,
            status=status,
            http_status_code=http_status,
            response_body_snippet=response_snippet,
            attempt_number=attempt_number,
            duration_ms=elapsed_ms,
            error_message=error_message,
            attempted_at=attempted_at,
        )

    # ------------------------------------------------------------------
    # Post-delivery bookkeeping
    # ------------------------------------------------------------------

    def _record_success(
        self,
        webhook_id: str,
        attempt: WebhookDeliveryAttempt,
        *,
        is_test: bool,
    ) -> None:
        with self._lock:
            record = self._repository.get_webhook(webhook_id)
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
            self._repository.save_webhook(updated)

        logger.debug(
            "webhook.delivered id=%s attempt=%d status=%d test=%s",
            webhook_id,
            attempt.attempt_number,
            attempt.http_status_code or 0,
            is_test,
        )

    def _record_failure(
        self,
        webhook_id: str,
        attempt: WebhookDeliveryAttempt,
        payload_bytes: bytes,
        event_type: str,
        *,
        delivery_id: str,
        org_id: str | None,
        is_test: bool,
    ) -> None:
        with self._lock:
            record = self._repository.get_webhook(webhook_id)
            if record is None:
                return

            new_failures = record.failure_count + 1
            new_status = record.status
            new_active = record.active

            if new_failures >= self._auto_disable_failure_threshold:
                new_status = WebhookStatus.DISABLED
                new_active = False
            elif new_failures >= self._failure_threshold:
                new_status = WebhookStatus.FAILING

            updated = _WebhookRecord(
                webhook_id=record.webhook_id,
                name=record.name,
                target_url=record.target_url,
                secret=record.secret,
                event_types=record.event_types,
                org_id=record.org_id,
                signing_algorithm=record.signing_algorithm,
                status=new_status,
                active=new_active,
                max_retries=record.max_retries,
                timeout_seconds=record.timeout_seconds,
                failure_count=new_failures,
                last_triggered_at=record.last_triggered_at,
                metadata=record.metadata,
                created_at=record.created_at,
                updated_at=_utcnow_iso(),
            )
            self._repository.save_webhook(updated)
            self._repository.append_dead_letter(
                DeadLetterEntry(
                    delivery_id=delivery_id,
                    webhook_id=webhook_id,
                    org_id=org_id,
                    event_type=event_type,
                    payload_json=payload_bytes.decode("utf-8", errors="replace"),
                    payload_hash=attempt.payload_hash,
                    error_message=attempt.error_message or "unknown",
                    attempt_count=attempt.attempt_number,
                    queued_at=_utcnow_iso(),
                    last_attempt_id=attempt.attempt_id,
                )
            )

        logger.warning(
            "webhook.failed id=%s failures=%d error=%s test=%s",
            webhook_id,
            new_failures,
            attempt.error_message,
            is_test,
        )

    # ------------------------------------------------------------------
    # Delivery log
    # ------------------------------------------------------------------

    def get_delivery_log(self, webhook_id: str, *, limit: int = 50) -> list[WebhookDeliveryAttempt]:
        log = self._repository.get_delivery_log(webhook_id)
        return log[-limit:]

    # ------------------------------------------------------------------
    # Dead-letter queue
    # ------------------------------------------------------------------

    def list_dead_letter(
        self,
        *,
        org_id: str,
        limit: int = 100,
        allow_global: bool = False,
    ) -> list[dict[str, Any]]:
        if not org_id and not allow_global:
            return []

        items = self._repository.list_dead_letter()
        if allow_global:
            scoped = items
        else:
            scoped = [entry for entry in items if entry.org_id == org_id]
        return [entry.to_dict() for entry in scoped[-limit:]]

    def replay_dead_letter(
        self,
        delivery_id: str,
        *,
        org_id: str,
        allow_global: bool = False,
    ) -> WebhookDeliveryAttempt | None:
        entry: DeadLetterEntry | None = None
        for item in self._repository.list_dead_letter():
            if item.delivery_id != delivery_id:
                continue
            if allow_global or item.org_id == org_id:
                entry = item
                break

        if entry is None:
            return None

        record = self._repository.get_webhook(entry.webhook_id)
        if record is None:
            return None
        if not allow_global and record.org_id != org_id:
            return None

        try:
            payload_bytes = entry.payload_json.encode("utf-8")
            payload_obj = json.loads(entry.payload_json)
            data = payload_obj.get("data", {}) if isinstance(payload_obj, dict) else {}
        except (UnicodeEncodeError, json.JSONDecodeError, AttributeError):
            payload_bytes = entry.payload_json.encode("utf-8", errors="replace")
            data = {}

        result = self._deliver_with_retry(
            record,
            entry.event_type,
            data,
            org_id=record.org_id,
            is_test=False,
            delivery_id=entry.delivery_id,
            payload_bytes_override=payload_bytes,
            payload_hash_override=entry.payload_hash,
        )

        if result.status == WebhookDeliveryStatus.SUCCESS:
            self._repository.remove_dead_letter(entry.delivery_id, org_id=entry.org_id)
            logger.info("webhook.dead_letter_replayed delivery_id=%s org_id=%s", delivery_id, entry.org_id)

        return result

    def purge_dead_letter(self, *, org_id: str, allow_global: bool = False) -> int:
        removed = self._repository.clear_dead_letter(org_id=None if allow_global else org_id)
        logger.info("webhook.dead_letter_purged count=%d org_id=%s global=%s", removed, org_id, allow_global)
        return removed

    # ------------------------------------------------------------------
    # Test delivery
    # ------------------------------------------------------------------

    def send_test(
        self,
        webhook_id: str,
        event_type: str = WebhookEventType.GUARD_ALLOW,
    ) -> WebhookTestResponse:
        record = self._repository.get_webhook(webhook_id)

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
        attempt = self._deliver_with_retry(
            record,
            event_type,
            test_data,
            org_id=record.org_id,
            is_test=True,
            delivery_id=f"test-{uuid4().hex[:20]}",
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
        self._repository.reset()

    def close(self) -> None:
        if self._owns_http_client:
            self._http_client.close()


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
