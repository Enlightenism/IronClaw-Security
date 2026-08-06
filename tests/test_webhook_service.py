from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import os
from typing import Any
from unittest.mock import patch
import uuid

import httpx

from app.models.webhook import WebhookDeliveryStatus
from app.persistencebootstrap import InMemoryPersistenceStore
from app.services import webhook_service as webhook_service_module
from app.services.webhook_service import (
    EdgeDispatchResult,
    WebhookDeliveryRecord,
    WebhookDispatchResult,
    WebhookSubscription,
    _compute_signature,
    _next_attempt_iso,
    _query_subscriptions_for_event,
    _should_retry,
    _update_delivery_log_attempt,
    _write_delivery_log,
    deliver_webhook,
    dispatch_event,
    get_delivery_log,
    list_delivery_logs_for_tenant,
    list_retryable_deliveries,
    retry_failed_delivery,
    verify_webhook_signature,
)


def _resolve_webhook_http_dispatch_name() -> str:
    for name in ("dispatch_http_post", "_dispatch_http_post", "dispatchhttppost"):
        if hasattr(webhook_service_module, name):
            return name
    raise AssertionError("No webhook HTTP dispatch function found on webhook_service module.")


def _resolve_edge_dispatch_name() -> str:
    for name in ("dispatch_verdict_to_edge", "dispatchverdicttoedge"):
        if hasattr(webhook_service_module, name):
            return name
    raise AssertionError("No edge dispatch function found on webhook_service module.")


_WEBHOOK_HTTP_DISPATCH_NAME = _resolve_webhook_http_dispatch_name()
_EDGE_DISPATCH_NAME = _resolve_edge_dispatch_name()


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_WEBHOOK_DELIVERY_TABLE = "webhook_delivery_log"
_WEBHOOK_SUBSCRIPTIONS_TABLE = "webhook_subscriptions"

_SECRET = "ironclaw-test-secret-abc123"
_TENANT_ID = "tenant-test-001"
_SUB_ID = "sub-test-001"
_EVENT_TYPE = "verdict.block"
_TARGET_URL = "https://hooks.example.com/ironclaw"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_store() -> InMemoryPersistenceStore:
    return InMemoryPersistenceStore()


def _make_subscription(
    *,
    sub_id: str = _SUB_ID,
    tenant_id: str = _TENANT_ID,
    events: list[str] | None = None,
    active: bool = True,
    max_attempts: int = 3,
    secret_hash: str = _SECRET,
    target_url: str = _TARGET_URL,
) -> WebhookSubscription:
    return WebhookSubscription(
        id=sub_id,
        tenant_id=tenant_id,
        target_url=target_url,
        events=events if events is not None else [_EVENT_TYPE],
        secret_hash=secret_hash,
        active=active,
        max_attempts=max_attempts,
        metadata={},
        created_at=datetime.now(UTC).isoformat(),
    )


def _make_delivery_record(
    *,
    delivery_id: str | None = None,
    subscription_id: str = _SUB_ID,
    tenant_id: str = _TENANT_ID,
    event_type: str = _EVENT_TYPE,
    status: WebhookDeliveryStatus = WebhookDeliveryStatus.PENDING,
    attempts: int = 0,
) -> WebhookDeliveryRecord:
    now = datetime.now(UTC).isoformat()
    return WebhookDeliveryRecord(
        id=delivery_id or str(uuid.uuid4()),
        subscription_id=subscription_id,
        tenant_id=tenant_id,
        event_type=event_type,
        payload_json=json.dumps({"ironclaw_event": event_type, "data": {}}),
        status=status,
        attempts=attempts,
        http_status=None,
        response_body=None,
        error_detail=None,
        delivered_at=None,
        next_attempt_at=None,
        created_at=now,
    )


def _seed_subscription(store: InMemoryPersistenceStore, sub: WebhookSubscription) -> None:
    store.insert(
        _WEBHOOK_SUBSCRIPTIONS_TABLE,
        {
            "id": sub.id,
            "tenant_id": sub.tenant_id,
            "target_url": sub.target_url,
            "events": sub.events,
            "secret_hash": sub.secret_hash,
            "active": sub.active,
            "max_attempts": sub.max_attempts,
            "metadata": sub.metadata,
            "created_at": sub.created_at,
        },
    )


# ---------------------------------------------------------------------------
# _compute_signature / verify_webhook_signature
# ---------------------------------------------------------------------------


class TestSignature:
    def test_compute_signature_produces_sha256_prefix(self) -> None:
        body = b'{"event":"test"}'
        ts = "20260101T000000Z"
        sig = _compute_signature(_SECRET, body, ts)
        assert sig.startswith("sha256=")

    def test_compute_signature_deterministic(self) -> None:
        body = b'{"key":"value"}'
        ts = "20260608T120000Z"
        assert _compute_signature(_SECRET, body, ts) == _compute_signature(_SECRET, body, ts)

    def test_compute_signature_changes_with_body(self) -> None:
        ts = "20260608T120000Z"
        sig_a = _compute_signature(_SECRET, b"body_a", ts)
        sig_b = _compute_signature(_SECRET, b"body_b", ts)
        assert sig_a != sig_b

    def test_compute_signature_changes_with_timestamp(self) -> None:
        body = b"same body"
        sig_a = _compute_signature(_SECRET, body, "20260608T120000Z")
        sig_b = _compute_signature(_SECRET, body, "20260608T130000Z")
        assert sig_a != sig_b

    def test_compute_signature_changes_with_secret(self) -> None:
        body = b"test"
        ts = "20260608T120000Z"
        sig_a = _compute_signature("secret-one", body, ts)
        sig_b = _compute_signature("secret-two", body, ts)
        assert sig_a != sig_b

    def test_verify_webhook_signature_valid(self) -> None:
        body = b'{"data":"ok"}'
        ts = "20260608T120000Z"
        sig = _compute_signature(_SECRET, body, ts)
        assert verify_webhook_signature(_SECRET, body, ts, sig) is True

    def test_verify_webhook_signature_invalid_signature(self) -> None:
        body = b'{"data":"ok"}'
        ts = "20260608T120000Z"
        assert verify_webhook_signature(_SECRET, body, ts, "sha256=badhex") is False

    def test_verify_webhook_signature_tampered_body(self) -> None:
        ts = "20260608T120000Z"
        original_body = b'{"data":"original"}'
        tampered_body = b'{"data":"injected"}'
        sig = _compute_signature(_SECRET, original_body, ts)
        assert verify_webhook_signature(_SECRET, tampered_body, ts, sig) is False

    def test_verify_webhook_signature_wrong_secret(self) -> None:
        body = b'{"data":"ok"}'
        ts = "20260608T120000Z"
        sig = _compute_signature(_SECRET, body, ts)
        assert verify_webhook_signature("wrong-secret", body, ts, sig) is False

    def test_verify_webhook_signature_uses_hmac_compare_digest(self) -> None:
        body = b"test"
        ts = "20260608T000000Z"
        assert verify_webhook_signature(_SECRET, body, ts, "sha256=short") is False
        assert verify_webhook_signature(_SECRET, body, ts, "") is False


# ---------------------------------------------------------------------------
# _query_subscriptions_for_event
# ---------------------------------------------------------------------------


class TestQuerySubscriptionsForEvent:
    def test_returns_matching_subscription(self) -> None:
        store = _make_store()
        sub = _make_subscription()
        _seed_subscription(store, sub)
        results = _query_subscriptions_for_event(_TENANT_ID, _EVENT_TYPE, store=store)
        assert len(results) == 1
        assert results[0].id == _SUB_ID

    def test_excludes_inactive_subscription(self) -> None:
        store = _make_store()
        sub = _make_subscription(active=False)
        _seed_subscription(store, sub)
        results = _query_subscriptions_for_event(_TENANT_ID, _EVENT_TYPE, store=store)
        assert results == []

    def test_excludes_wrong_event(self) -> None:
        store = _make_store()
        sub = _make_subscription(events=["verdict.allow"])
        _seed_subscription(store, sub)
        results = _query_subscriptions_for_event(_TENANT_ID, "verdict.block", store=store)
        assert results == []

    def test_excludes_wrong_tenant(self) -> None:
        store = _make_store()
        sub = _make_subscription(tenant_id="other-tenant")
        _seed_subscription(store, sub)
        results = _query_subscriptions_for_event(_TENANT_ID, _EVENT_TYPE, store=store)
        assert results == []

    def test_returns_multiple_matching_subscriptions(self) -> None:
        store = _make_store()
        for i in range(3):
            _seed_subscription(store, _make_subscription(sub_id=f"sub-{i}"))
        results = _query_subscriptions_for_event(_TENANT_ID, _EVENT_TYPE, store=store)
        assert len(results) == 3

    def test_returns_empty_on_no_subscriptions(self) -> None:
        store = _make_store()
        results = _query_subscriptions_for_event(_TENANT_ID, _EVENT_TYPE, store=store)
        assert results == []

    def test_subscription_with_multiple_events_matches(self) -> None:
        store = _make_store()
        sub = _make_subscription(events=["verdict.allow", "verdict.block", "verdict.warn"])
        _seed_subscription(store, sub)
        results = _query_subscriptions_for_event(_TENANT_ID, "verdict.warn", store=store)
        assert len(results) == 1

    def test_returns_empty_list_on_store_error(self) -> None:
        broken_store = _make_store()

        def _bad_select(*_a: Any, **_kw: Any) -> Any:
            raise RuntimeError("db exploded")

        broken_store.select = _bad_select  # type: ignore[method-assign]
        results = _query_subscriptions_for_event(_TENANT_ID, _EVENT_TYPE, store=broken_store)
        assert results == []


# ---------------------------------------------------------------------------
# _write_delivery_log
# ---------------------------------------------------------------------------


class TestWriteDeliveryLog:
    def test_insert_creates_row(self) -> None:
        store = _make_store()
        record = _make_delivery_record()
        _write_delivery_log(record, store=store)
        rows = store.select(_WEBHOOK_DELIVERY_TABLE, filters={"id": record.id})
        assert len(rows) == 1
        assert rows[0]["id"] == record.id

    def test_insert_persists_status(self) -> None:
        store = _make_store()
        record = _make_delivery_record(status=WebhookDeliveryStatus.PENDING)
        _write_delivery_log(record, store=store)
        rows = store.select(_WEBHOOK_DELIVERY_TABLE, filters={"id": record.id})
        assert rows[0]["status"] == WebhookDeliveryStatus.PENDING.value

    def test_rewrite_existing_row_via_update_delivery_log_attempt(self) -> None:
        store = _make_store()
        delivery_id = str(uuid.uuid4())
        record = _make_delivery_record(delivery_id=delivery_id, status=WebhookDeliveryStatus.PENDING)
        _write_delivery_log(record, store=store)

        delivered_at = datetime.now(UTC).isoformat()
        _update_delivery_log_attempt(
            delivery_id,
            status=WebhookDeliveryStatus.SUCCESS,
            attempts=1,
            http_status=200,
            response_body="ok",
            error_detail=None,
            delivered_at=delivered_at,
            next_attempt_at=None,
            store=store,
        )

        rows = store.select(_WEBHOOK_DELIVERY_TABLE, filters={"id": delivery_id})
        assert len(rows) == 1
        assert rows[0]["status"] == WebhookDeliveryStatus.SUCCESS.value
        assert rows[0]["http_status"] == 200
        assert rows[0]["response_body"] == "ok"
        assert rows[0]["delivered_at"] == delivered_at

    def test_does_not_raise_on_store_error(self) -> None:
        store = _make_store()

        def _bad_insert(*_a: Any, **_kw: Any) -> Any:
            raise RuntimeError("insert failed")

        store.insert = _bad_insert  # type: ignore[method-assign]
        record = _make_delivery_record()
        _write_delivery_log(record, store=store)


# ---------------------------------------------------------------------------
# _update_delivery_log_attempt
# ---------------------------------------------------------------------------


class TestUpdateDeliveryLogAttempt:
    def test_updates_status_and_attempts(self) -> None:
        store = _make_store()
        delivery_id = str(uuid.uuid4())
        record = _make_delivery_record(delivery_id=delivery_id)
        _write_delivery_log(record, store=store)

        _update_delivery_log_attempt(
            delivery_id,
            status=WebhookDeliveryStatus.SUCCESS,
            attempts=1,
            http_status=200,
            response_body="ok",
            error_detail=None,
            delivered_at=datetime.now(UTC).isoformat(),
            next_attempt_at=None,
            store=store,
        )
        rows = store.select(_WEBHOOK_DELIVERY_TABLE, filters={"id": delivery_id})
        assert rows[0]["status"] == WebhookDeliveryStatus.SUCCESS.value
        assert rows[0]["attempts"] == 1
        assert rows[0]["http_status"] == 200

    def test_sets_next_attempt_at_on_failure(self) -> None:
        store = _make_store()
        delivery_id = str(uuid.uuid4())
        _write_delivery_log(_make_delivery_record(delivery_id=delivery_id), store=store)
        next_at = (datetime.now(UTC) + timedelta(seconds=60)).isoformat()

        _update_delivery_log_attempt(
            delivery_id,
            status=WebhookDeliveryStatus.FAILED,
            attempts=1,
            http_status=503,
            response_body=None,
            error_detail="server error",
            delivered_at=None,
            next_attempt_at=next_at,
            store=store,
        )
        rows = store.select(_WEBHOOK_DELIVERY_TABLE, filters={"id": delivery_id})
        assert rows[0]["next_attempt_at"] == next_at
        assert rows[0]["error_detail"] == "server error"

    def test_truncates_response_body_to_4096(self) -> None:
        store = _make_store()
        delivery_id = str(uuid.uuid4())
        _write_delivery_log(_make_delivery_record(delivery_id=delivery_id), store=store)
        long_body = "x" * 9000

        _update_delivery_log_attempt(
            delivery_id,
            status=WebhookDeliveryStatus.SUCCESS,
            attempts=1,
            http_status=200,
            response_body=long_body,
            error_detail=None,
            delivered_at=datetime.now(UTC).isoformat(),
            next_attempt_at=None,
            store=store,
        )
        rows = store.select(_WEBHOOK_DELIVERY_TABLE, filters={"id": delivery_id})
        assert len(rows[0]["response_body"]) == 4096

    def test_does_not_raise_on_store_error(self) -> None:
        store = _make_store()

        def _bad_update(*_a: Any, **_kw: Any) -> Any:
            raise RuntimeError("update failed")

        store.update = _bad_update  # type: ignore[method-assign]
        _update_delivery_log_attempt(
            str(uuid.uuid4()),
            status=WebhookDeliveryStatus.FAILED,
            attempts=1,
            http_status=None,
            response_body=None,
            error_detail="boom",
            delivered_at=None,
            next_attempt_at=None,
            store=store,
        )


# ---------------------------------------------------------------------------
# _should_retry / _next_attempt_iso
# ---------------------------------------------------------------------------


class TestRetryHelpers:
    def test_retry_on_none_status(self) -> None:
        assert _should_retry(None) is True

    def test_retry_on_429(self) -> None:
        assert _should_retry(429) is True

    def test_retry_on_5xx(self) -> None:
        for code in (500, 502, 503, 504):
            assert _should_retry(code) is True

    def test_no_retry_on_2xx(self) -> None:
        assert _should_retry(200) is False
        assert _should_retry(204) is False

    def test_no_retry_on_4xx_non_429(self) -> None:
        assert _should_retry(400) is False
        assert _should_retry(401) is False
        assert _should_retry(403) is False
        assert _should_retry(404) is False

    def test_next_attempt_iso_is_future(self) -> None:
        before = datetime.now(UTC)
        result = _next_attempt_iso(1)
        after = datetime.fromisoformat(result)
        assert after > before

    def test_next_attempt_iso_caps_at_3600(self) -> None:
        far_future = _next_attempt_iso(30)
        at = datetime.fromisoformat(far_future)
        delta = (at - datetime.now(UTC)).total_seconds()
        assert delta <= 3601


# ---------------------------------------------------------------------------
# deliver_webhook
# ---------------------------------------------------------------------------


class TestDeliverWebhook:
    def test_success_outcome(self) -> None:
        store = _make_store()
        sub = _make_subscription(max_attempts=3)

        def _mock_post(
            subscription: WebhookSubscription,
            delivery_id: str,
            event_type: str,
            payload: dict[str, Any],
            *,
            attempt: int,
            timeout: float = 10.0,
        ) -> tuple[int | None, str | None, str | None]:
            return 200, "ok", None

        with patch.object(webhook_service_module, _WEBHOOK_HTTP_DISPATCH_NAME, side_effect=_mock_post):
            result = deliver_webhook(sub, _EVENT_TYPE, {"action": "scan"}, store=store)

        assert result.succeeded is True
        assert result.status == WebhookDeliveryStatus.SUCCESS
        assert result.http_status == 200
        assert result.attempts == 1
        assert result.error_detail is None
        assert result.delivered_at is not None

        rows = store.select(_WEBHOOK_DELIVERY_TABLE, filters={"id": result.delivery_id})
        assert rows[0]["status"] == WebhookDeliveryStatus.SUCCESS.value

    def test_retry_scheduled_outcome(self) -> None:
        store = _make_store()
        sub = _make_subscription(max_attempts=3)

        def _mock_post(*_a: Any, **_kw: Any) -> tuple[int | None, str | None, str | None]:
            return 503, "server error", "Non-2xx response: HTTP 503"

        with patch.object(webhook_service_module, _WEBHOOK_HTTP_DISPATCH_NAME, side_effect=_mock_post):
            result = deliver_webhook(sub, _EVENT_TYPE, {"action": "scan"}, store=store)

        assert result.status == WebhookDeliveryStatus.FAILED
        assert result.succeeded is False
        assert result.exhausted is False

        rows = store.select(_WEBHOOK_DELIVERY_TABLE, filters={"id": result.delivery_id})
        assert rows[0]["next_attempt_at"] is not None

    def test_exhausted_outcome_on_max_attempts(self) -> None:
        store = _make_store()
        sub = _make_subscription(max_attempts=1)

        def _mock_post(*_a: Any, **_kw: Any) -> tuple[int | None, str | None, str | None]:
            return 503, None, "Non-2xx response: HTTP 503"

        with patch.object(webhook_service_module, _WEBHOOK_HTTP_DISPATCH_NAME, side_effect=_mock_post):
            result = deliver_webhook(sub, _EVENT_TYPE, {"action": "scan"}, store=store)

        assert result.status == WebhookDeliveryStatus.EXHAUSTED
        assert result.exhausted is True

        rows = store.select(_WEBHOOK_DELIVERY_TABLE, filters={"id": result.delivery_id})
        assert rows[0]["status"] == WebhookDeliveryStatus.EXHAUSTED.value
        assert rows[0]["next_attempt_at"] is None

    def test_no_retry_on_4xx(self) -> None:
        store = _make_store()
        sub = _make_subscription(max_attempts=5)

        def _mock_post(*_a: Any, **_kw: Any) -> tuple[int | None, str | None, str | None]:
            return 404, None, "Non-2xx response: HTTP 404"

        with patch.object(webhook_service_module, _WEBHOOK_HTTP_DISPATCH_NAME, side_effect=_mock_post):
            result = deliver_webhook(sub, _EVENT_TYPE, {}, store=store)

        assert result.status == WebhookDeliveryStatus.EXHAUSTED

    def test_existing_delivery_id_is_preserved(self) -> None:
        store = _make_store()
        sub = _make_subscription()
        fixed_id = str(uuid.uuid4())

        def _mock_post(*_a: Any, **_kw: Any) -> tuple[int | None, str | None, str | None]:
            return 200, "ok", None

        with patch.object(webhook_service_module, _WEBHOOK_HTTP_DISPATCH_NAME, side_effect=_mock_post):
            result = deliver_webhook(
                sub,
                _EVENT_TYPE,
                {},
                existing_delivery_id=fixed_id,
                store=store,
            )

        assert result.delivery_id == fixed_id

    def test_initial_record_not_duplicated_on_retry(self) -> None:
        store = _make_store()
        sub = _make_subscription()
        fixed_id = str(uuid.uuid4())

        store.insert(
            _WEBHOOK_DELIVERY_TABLE,
            {
                "id": fixed_id,
                "subscription_id": sub.id,
                "tenant_id": sub.tenant_id,
                "event_type": _EVENT_TYPE,
                "payload_json": "{}",
                "status": WebhookDeliveryStatus.FAILED.value,
                "attempts": 1,
                "http_status": None,
                "response_body": None,
                "error_detail": "first fail",
                "delivered_at": None,
                "next_attempt_at": None,
                "created_at": datetime.now(UTC).isoformat(),
            },
        )

        def _mock_post(*_a: Any, **_kw: Any) -> tuple[int | None, str | None, str | None]:
            return 200, "ok", None

        with patch.object(webhook_service_module, _WEBHOOK_HTTP_DISPATCH_NAME, side_effect=_mock_post):
            deliver_webhook(
                sub,
                _EVENT_TYPE,
                {},
                existing_delivery_id=fixed_id,
                current_attempts=1,
                store=store,
            )

        rows = store.select(_WEBHOOK_DELIVERY_TABLE, filters={"id": fixed_id})
        assert len(rows) == 1


# ---------------------------------------------------------------------------
# dispatch_event
# ---------------------------------------------------------------------------


class TestDispatchEvent:
    def test_zero_subscriptions_returns_empty_list(self) -> None:
        store = _make_store()
        results = dispatch_event(
            _TENANT_ID,
            _EVENT_TYPE,
            {"action": "test"},
            store=store,
            fire_edge_function=False,
        )
        assert results == []

    def test_single_subscription_dispatch(self) -> None:
        store = _make_store()
        sub = _make_subscription()
        _seed_subscription(store, sub)

        def _mock_post(*_a: Any, **_kw: Any) -> tuple[int | None, str | None, str | None]:
            return 200, "ok", None

        with patch.object(webhook_service_module, _WEBHOOK_HTTP_DISPATCH_NAME, side_effect=_mock_post):
            results = dispatch_event(
                _TENANT_ID,
                _EVENT_TYPE,
                {"data": "payload"},
                store=store,
                fire_edge_function=False,
            )

        assert len(results) == 1
        assert results[0].succeeded is True
        assert results[0].tenant_id == _TENANT_ID

    def test_multiple_subscriptions_fan_out(self) -> None:
        store = _make_store()
        for i in range(4):
            _seed_subscription(store, _make_subscription(sub_id=f"sub-fan-{i}"))

        def _mock_post(*_a: Any, **_kw: Any) -> tuple[int | None, str | None, str | None]:
            return 200, "ok", None

        with patch.object(webhook_service_module, _WEBHOOK_HTTP_DISPATCH_NAME, side_effect=_mock_post):
            results = dispatch_event(
                _TENANT_ID,
                _EVENT_TYPE,
                {},
                store=store,
                fire_edge_function=False,
            )

        assert len(results) == 4
        assert all(r.succeeded for r in results)

    def test_fire_edge_function_false_skips_edge(self) -> None:
        store = _make_store()

        with patch.object(webhook_service_module, _EDGE_DISPATCH_NAME) as mock_edge:
            dispatch_event(
                _TENANT_ID,
                _EVENT_TYPE,
                {},
                store=store,
                fire_edge_function=False,
            )
            mock_edge.assert_not_called()

    def test_fire_edge_function_true_calls_edge(self) -> None:
        store = _make_store()

        with patch.object(
            webhook_service_module,
            _EDGE_DISPATCH_NAME,
            return_value=EdgeDispatchResult(
                event_type=_EVENT_TYPE,
                tenant_id=_TENANT_ID,
                http_status=200,
                succeeded=True,
                error_detail=None,
                dispatched_at=datetime.now(UTC).isoformat(),
            ),
        ) as mock_edge:
            dispatch_event(
                _TENANT_ID,
                _EVENT_TYPE,
                {},
                store=store,
                fire_edge_function=True,
            )
            mock_edge.assert_called_once_with(
                event_type=_EVENT_TYPE,
                payload={},
                tenant_id=_TENANT_ID,
            )

    def test_partial_failure_does_not_abort_others(self) -> None:
        store = _make_store()
        for i in range(3):
            _seed_subscription(store, _make_subscription(sub_id=f"sub-partial-{i}"))

        call_count = 0

        def _mock_post(*_a: Any, **_kw: Any) -> tuple[int | None, str | None, str | None]:
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                return 500, None, "server error"
            return 200, "ok", None

        with patch.object(webhook_service_module, _WEBHOOK_HTTP_DISPATCH_NAME, side_effect=_mock_post):
            results = dispatch_event(
                _TENANT_ID,
                _EVENT_TYPE,
                {},
                store=store,
                fire_edge_function=False,
            )

        assert len(results) == 3
        succeeded = sum(1 for r in results if r.succeeded)
        assert succeeded == 2


# ---------------------------------------------------------------------------
# retry_failed_delivery
# ---------------------------------------------------------------------------


class TestRetryFailedDelivery:
    def test_retry_with_active_subscription_succeeds(self) -> None:
        store = _make_store()
        sub = _make_subscription(max_attempts=5)
        _seed_subscription(store, sub)
        delivery_id = str(uuid.uuid4())
        payload_json = json.dumps({"ironclaw_event": _EVENT_TYPE, "data": {"retry": True}})

        def _mock_post(*_a: Any, **_kw: Any) -> tuple[int | None, str | None, str | None]:
            return 200, "ok", None

        with patch.object(webhook_service_module, _WEBHOOK_HTTP_DISPATCH_NAME, side_effect=_mock_post):
            result = retry_failed_delivery(
                delivery_id=delivery_id,
                subscription_id=sub.id,
                tenant_id=_TENANT_ID,
                event_type=_EVENT_TYPE,
                payload_json=payload_json,
                current_attempts=1,
                store=store,
            )

        assert result.succeeded is True
        assert result.delivery_id == delivery_id
        assert result.attempts == 2

    def test_retry_with_missing_subscription_returns_exhausted(self) -> None:
        store = _make_store()
        delivery_id = str(uuid.uuid4())

        result = retry_failed_delivery(
            delivery_id=delivery_id,
            subscription_id="sub-does-not-exist",
            tenant_id=_TENANT_ID,
            event_type=_EVENT_TYPE,
            payload_json=json.dumps({}),
            current_attempts=1,
            store=store,
        )

        assert result.status == WebhookDeliveryStatus.EXHAUSTED
        assert result.error_detail is not None

    def test_retry_with_inactive_subscription_returns_exhausted(self) -> None:
        store = _make_store()
        sub = _make_subscription(active=False)
        _seed_subscription(store, sub)
        delivery_id = str(uuid.uuid4())

        result = retry_failed_delivery(
            delivery_id=delivery_id,
            subscription_id=sub.id,
            tenant_id=_TENANT_ID,
            event_type=_EVENT_TYPE,
            payload_json=json.dumps({}),
            current_attempts=1,
            store=store,
        )

        assert result.status == WebhookDeliveryStatus.EXHAUSTED

    def test_retry_handles_invalid_payload_json_gracefully(self) -> None:
        store = _make_store()
        sub = _make_subscription()
        _seed_subscription(store, sub)

        def _mock_post(*_a: Any, **_kw: Any) -> tuple[int | None, str | None, str | None]:
            return 200, "ok", None

        with patch.object(webhook_service_module, _WEBHOOK_HTTP_DISPATCH_NAME, side_effect=_mock_post):
            result = retry_failed_delivery(
                delivery_id=str(uuid.uuid4()),
                subscription_id=sub.id,
                tenant_id=_TENANT_ID,
                event_type=_EVENT_TYPE,
                payload_json="not-valid-json",
                current_attempts=1,
                store=store,
            )

        assert result.succeeded is True


# ---------------------------------------------------------------------------
# get_delivery_log / list_delivery_logs_for_tenant / list_retryable_deliveries
# ---------------------------------------------------------------------------


class TestDeliveryLogQueries:
    def test_get_delivery_log_returns_row(self) -> None:
        store = _make_store()
        delivery_id = str(uuid.uuid4())
        record = _make_delivery_record(delivery_id=delivery_id)
        _write_delivery_log(record, store=store)
        row = get_delivery_log(delivery_id, store=store)
        assert row is not None
        assert row["id"] == delivery_id

    def test_get_delivery_log_returns_none_when_missing(self) -> None:
        store = _make_store()
        assert get_delivery_log("nonexistent-id", store=store) is None

    def test_get_delivery_log_returns_none_on_store_error(self) -> None:
        store = _make_store()

        def _bad_select(*_a: Any, **_kw: Any) -> Any:
            raise RuntimeError("select failed")

        store.select = _bad_select  # type: ignore[method-assign]
        assert get_delivery_log("any-id", store=store) is None

    def test_list_delivery_logs_for_tenant_returns_all(self) -> None:
        store = _make_store()
        for i in range(5):
            _write_delivery_log(
                _make_delivery_record(delivery_id=f"d-{i}"),
                store=store,
            )
        rows = list_delivery_logs_for_tenant(_TENANT_ID, store=store)
        assert len(rows) == 5

    def test_list_delivery_logs_filters_by_event_type(self) -> None:
        store = _make_store()
        _write_delivery_log(_make_delivery_record(event_type="verdict.block"), store=store)
        _write_delivery_log(_make_delivery_record(event_type="verdict.allow"), store=store)

        rows = list_delivery_logs_for_tenant(
            _TENANT_ID,
            event_type="verdict.block",
            store=store,
        )
        assert len(rows) == 1
        assert rows[0]["event_type"] == "verdict.block"

    def test_list_delivery_logs_filters_by_status(self) -> None:
        store = _make_store()
        _write_delivery_log(
            _make_delivery_record(status=WebhookDeliveryStatus.SUCCESS),
            store=store,
        )
        _write_delivery_log(
            _make_delivery_record(status=WebhookDeliveryStatus.FAILED),
            store=store,
        )

        rows = list_delivery_logs_for_tenant(
            _TENANT_ID,
            status=WebhookDeliveryStatus.SUCCESS,
            store=store,
        )
        assert len(rows) == 1
        assert rows[0]["status"] == WebhookDeliveryStatus.SUCCESS.value

    def test_list_delivery_logs_returns_empty_on_store_error(self) -> None:
        store = _make_store()

        def _bad_select(*_a: Any, **_kw: Any) -> Any:
            raise RuntimeError("select failed")

        store.select = _bad_select  # type: ignore[method-assign]
        rows = list_delivery_logs_for_tenant(_TENANT_ID, store=store)
        assert rows == []

    def test_list_retryable_deliveries_returns_overdue_failed_rows(self) -> None:
        store = _make_store()
        past_iso = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
        future_iso = (datetime.now(UTC) + timedelta(minutes=5)).isoformat()

        overdue = _make_delivery_record(status=WebhookDeliveryStatus.FAILED)
        not_due_yet = _make_delivery_record(status=WebhookDeliveryStatus.FAILED)
        succeeded = _make_delivery_record(status=WebhookDeliveryStatus.SUCCESS)

        store.insert(
            _WEBHOOK_DELIVERY_TABLE,
            {**overdue.to_dict(), "status": WebhookDeliveryStatus.FAILED.value, "next_attempt_at": past_iso},
        )
        store.insert(
            _WEBHOOK_DELIVERY_TABLE,
            {**not_due_yet.to_dict(), "status": WebhookDeliveryStatus.FAILED.value, "next_attempt_at": future_iso},
        )
        store.insert(
            _WEBHOOK_DELIVERY_TABLE,
            {**succeeded.to_dict(), "status": WebhookDeliveryStatus.SUCCESS.value, "next_attempt_at": past_iso},
        )

        retryable = list_retryable_deliveries(store=store)
        assert len(retryable) == 1
        assert retryable[0]["id"] == overdue.id

    def test_list_retryable_deliveries_returns_empty_on_store_error(self) -> None:
        store = _make_store()

        def _bad_select(*_a: Any, **_kw: Any) -> Any:
            raise RuntimeError("select failed")

        store.select = _bad_select  # type: ignore[method-assign]
        assert list_retryable_deliveries(store=store) == []


# ---------------------------------------------------------------------------
# edge dispatch
# ---------------------------------------------------------------------------


class TestDispatchVerdictToEdge:
    def _set_env(self, *, url: str = "https://supabase.example.com", key: str = "test-service-key") -> None:
        os.environ["SUPABASE_URL"] = url
        os.environ["SUPABASE_SERVICE_ROLE_KEY"] = key

    def _clear_env(self) -> None:
        os.environ["SUPABASE_URL"] = ""
        os.environ["SUPABASE_SERVICE_ROLE_KEY"] = ""

    def test_missing_service_role_key_returns_failed_result(self) -> None:
        self._clear_env()
        edge_dispatch = getattr(webhook_service_module, _EDGE_DISPATCH_NAME)
        result = edge_dispatch(
            event_type=_EVENT_TYPE,
            payload={"data": "x"},
            tenant_id=_TENANT_ID,
        )
        assert result.succeeded is False
        assert result.http_status is None
        assert "SUPABASE_SERVICE_ROLE_KEY" in (result.error_detail or "")

    def test_missing_supabase_url_returns_failed_result(self) -> None:
        os.environ["SUPABASE_URL"] = ""
        os.environ["SUPABASE_SERVICE_ROLE_KEY"] = "some-key"
        edge_dispatch = getattr(webhook_service_module, _EDGE_DISPATCH_NAME)
        result = edge_dispatch(
            event_type=_EVENT_TYPE,
            payload={},
            tenant_id=_TENANT_ID,
        )
        assert result.succeeded is False
        self._clear_env()

    def test_http_success_returns_succeeded_result(self) -> None:
        self._set_env()
        edge_dispatch = getattr(webhook_service_module, _EDGE_DISPATCH_NAME)

        with patch("httpx.Client") as mock_client_class:
            mock_client = mock_client_class.return_value.__enter__.return_value
            mock_client.post.return_value = httpx.Response(200, json={"received": True})

            result = edge_dispatch(
                event_type=_EVENT_TYPE,
                payload={"verdict": "block"},
                tenant_id=_TENANT_ID,
            )

        assert result.succeeded is True
        assert result.http_status == 200
        assert result.event_type == _EVENT_TYPE
        self._clear_env()

    def test_non_2xx_returns_failed_result_with_detail(self) -> None:
        self._set_env()
        edge_dispatch = getattr(webhook_service_module, _EDGE_DISPATCH_NAME)

        with patch("httpx.Client") as mock_client_class:
            mock_client = mock_client_class.return_value.__enter__.return_value
            mock_client.post.return_value = httpx.Response(502, text="Bad Gateway")

            result = edge_dispatch(
                event_type=_EVENT_TYPE,
                payload={},
                tenant_id=_TENANT_ID,
            )

        assert result.succeeded is False
        assert result.http_status == 502
        assert "502" in (result.error_detail or "")
        self._clear_env()

    def test_timeout_returns_failed_result(self) -> None:
        self._set_env()
        edge_dispatch = getattr(webhook_service_module, _EDGE_DISPATCH_NAME)

        with patch("httpx.Client") as mock_client_class:
            mock_client = mock_client_class.return_value.__enter__.return_value
            mock_client.post.side_effect = httpx.TimeoutException("timed out")

            result = edge_dispatch(
                event_type=_EVENT_TYPE,
                payload={},
                tenant_id=_TENANT_ID,
            )

        assert result.succeeded is False
        assert result.http_status is None
        assert "Timeout" in (result.error_detail or "") or "timed out" in (result.error_detail or "")
        self._clear_env()

    def test_generic_exception_returns_failed_result(self) -> None:
        self._set_env()
        edge_dispatch = getattr(webhook_service_module, _EDGE_DISPATCH_NAME)

        with patch("httpx.Client") as mock_client_class:
            mock_client = mock_client_class.return_value.__enter__.return_value
            mock_client.post.side_effect = ConnectionError("network unreachable")

            result = edge_dispatch(
                event_type=_EVENT_TYPE,
                payload={},
                tenant_id=_TENANT_ID,
            )

        assert result.succeeded is False
        assert result.http_status is None
        self._clear_env()

    def test_result_contains_dispatched_at_timestamp(self) -> None:
        self._set_env()
        edge_dispatch = getattr(webhook_service_module, _EDGE_DISPATCH_NAME)

        with patch("httpx.Client") as mock_client_class:
            mock_client = mock_client_class.return_value.__enter__.return_value
            mock_client.post.return_value = httpx.Response(200)

            result = edge_dispatch(
                event_type=_EVENT_TYPE,
                payload={},
                tenant_id=_TENANT_ID,
            )

        assert result.dispatched_at is not None
        datetime.fromisoformat(result.dispatched_at)
        self._clear_env()


# ---------------------------------------------------------------------------
# WebhookSubscription.from_row
# ---------------------------------------------------------------------------


class TestWebhookSubscriptionFromRow:
    def test_from_row_builds_correctly(self) -> None:
        row = {
            "id": _SUB_ID,
            "tenant_id": _TENANT_ID,
            "target_url": _TARGET_URL,
            "events": [_EVENT_TYPE],
            "secret_hash": _SECRET,
            "active": True,
            "max_attempts": 3,
            "metadata": {"source": "test"},
            "created_at": datetime.now(UTC).isoformat(),
        }
        sub = WebhookSubscription.from_row(row)
        assert sub.id == _SUB_ID
        assert sub.events == [_EVENT_TYPE]
        assert sub.max_attempts == 3

    def test_from_row_defaults_none_events_to_empty_list(self) -> None:
        row = {
            "id": _SUB_ID,
            "tenant_id": _TENANT_ID,
            "target_url": _TARGET_URL,
            "events": None,
            "secret_hash": _SECRET,
        }
        sub = WebhookSubscription.from_row(row)
        assert sub.events == []

    def test_from_row_defaults_none_metadata_to_empty_dict(self) -> None:
        row = {
            "id": _SUB_ID,
            "tenant_id": _TENANT_ID,
            "target_url": _TARGET_URL,
            "events": [],
            "secret_hash": _SECRET,
            "metadata": None,
        }
        sub = WebhookSubscription.from_row(row)
        assert sub.metadata == {}


# ---------------------------------------------------------------------------
# WebhookDispatchResult helpers
# ---------------------------------------------------------------------------


class TestWebhookDispatchResultHelpers:
    def _make_result(self, status: WebhookDeliveryStatus) -> WebhookDispatchResult:
        return WebhookDispatchResult(
            delivery_id=str(uuid.uuid4()),
            subscription_id=_SUB_ID,
            tenant_id=_TENANT_ID,
            event_type=_EVENT_TYPE,
            status=status,
            http_status=200 if status == WebhookDeliveryStatus.SUCCESS else None,
            attempts=1,
            error_detail=None,
            delivered_at=datetime.now(UTC).isoformat() if status == WebhookDeliveryStatus.SUCCESS else None,
        )

    def test_succeeded_property(self) -> None:
        assert self._make_result(WebhookDeliveryStatus.SUCCESS).succeeded is True
        assert self._make_result(WebhookDeliveryStatus.FAILED).succeeded is False

    def test_exhausted_property(self) -> None:
        assert self._make_result(WebhookDeliveryStatus.EXHAUSTED).exhausted is True
        assert self._make_result(WebhookDeliveryStatus.SUCCESS).exhausted is False

    def test_to_dict_contains_expected_keys(self) -> None:
        result = self._make_result(WebhookDeliveryStatus.SUCCESS)
        d = result.to_dict()
        for key in ("delivery_id", "subscription_id", "tenant_id", "event_type", "status", "http_status", "attempts"):
            assert key in d
