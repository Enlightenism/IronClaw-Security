from __future__ import annotations

from collections.abc import Iterator
import json
from types import SimpleNamespace

import httpx
from pydantic import SecretStr
import pytest

from app.models.webhook import (
    WebhookCreateRequest,
    WebhookDeliveryStatus,
    WebhookEventType,
    WebhookFilterRequest,
    WebhookSigningAlgorithm,
    WebhookStatus,
    WebhookUpdateRequest,
)
from app.services.webhook_dispatcher import (
    _DEFAULT_MAX_RETRIES,
    _DEFAULT_TIMEOUT_SECONDS,
    _DELIVERY_ID_HEADER,
    _EVENT_TYPE_HEADER,
    _HIGH_FAILURE_THRESHOLD,
    _SIGNATURE_HEADER_256,
    _SIGNATURE_HEADER_512,
    _WEBHOOK_AGENT_HEADER,
    _WEBHOOK_AGENT_VALUE,
    DeadLetterEntry,
    InMemoryWebhookDispatcherRepository,
    WebhookDispatcher,
    _hash_payload,
    _sign_payload,
    _utcnow_iso,
    _WebhookRecord,
    get_webhook_dispatcher,
    reset_webhook_dispatcher,
)

TEST_URL = "https://example.test/webhook"
TEST_SECRET = "super-secret-webhook-key"
TEST_EVENT = WebhookEventType.GUARD_BLOCK
TEST_ORG_ID = "org-test-001"


def _create_request(
    *,
    name: str = "Primary webhook",
    target_url: str = TEST_URL,
    secret: str = TEST_SECRET,
    event_types: list[WebhookEventType] | None = None,
    org_id: str | None = TEST_ORG_ID,
    signing_algorithm: WebhookSigningAlgorithm = WebhookSigningAlgorithm.HMAC_SHA256,
    active: bool = True,
    max_retries: int = _DEFAULT_MAX_RETRIES,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    metadata: dict[str, object] | None = None,
) -> WebhookCreateRequest:
    return WebhookCreateRequest(
        name=name,
        target_url=target_url,
        secret=secret,
        event_types=event_types or [TEST_EVENT],
        org_id=org_id,
        signing_algorithm=signing_algorithm,
        active=active,
        max_retries=max_retries,
        timeout_seconds=timeout_seconds,
        metadata=metadata or {},
    )


def _make_wildcard_record(
    *,
    webhook_id: str = "wh-wildcard",
    name: str = "Wildcard webhook",
    org_id: str | None = TEST_ORG_ID,
    active: bool = True,
    status: WebhookStatus = WebhookStatus.ACTIVE,
    signing_algorithm: WebhookSigningAlgorithm = WebhookSigningAlgorithm.HMAC_SHA256,
) -> _WebhookRecord:
    now = _utcnow_iso()
    return _WebhookRecord(
        webhook_id=webhook_id,
        name=name,
        target_url=TEST_URL,
        secret=SecretStr(TEST_SECRET),
        event_types=[str(WebhookEventType.ALL)],
        org_id=org_id,
        signing_algorithm=str(signing_algorithm),
        status=str(status),
        active=active,
        max_retries=_DEFAULT_MAX_RETRIES,
        timeout_seconds=_DEFAULT_TIMEOUT_SECONDS,
        failure_count=0,
        last_triggered_at=None,
        metadata={},
        created_at=now,
        updated_at=now,
    )


class _MockResponse:
    def __init__(self, *, status_code: int = 200, text: str = "ok") -> None:
        self.status_code = status_code
        self.text = text


@pytest.fixture(autouse=True)
def _reset_singleton() -> Iterator[None]:
    reset_webhook_dispatcher()
    yield
    reset_webhook_dispatcher()


@pytest.fixture()
def dispatcher() -> WebhookDispatcher:
    return WebhookDispatcher()


class TestSigningHelpers:
    def test_sign_payload_uses_sha256_prefix(self) -> None:
        payload = b'{"event":"guard.block"}'

        signature = _sign_payload(
            payload,
            TEST_SECRET,
            WebhookSigningAlgorithm.HMAC_SHA256,
        )

        assert signature.startswith("sha256=")

    def test_sign_payload_uses_sha512_prefix(self) -> None:
        payload = b'{"event":"guard.block"}'

        signature = _sign_payload(
            payload,
            SecretStr(TEST_SECRET),
            WebhookSigningAlgorithm.HMAC_SHA512,
        )

        assert signature.startswith("sha512=")

    def test_hash_payload_is_stable(self) -> None:
        payload = b'{"event":"guard.block","value":1}'

        first = _hash_payload(payload)
        second = _hash_payload(payload)

        assert first == second
        assert len(first) == 64


class TestRepository:
    def test_repository_remove_dead_letter_matches_delivery_id_and_org(self) -> None:
        repo = InMemoryWebhookDispatcherRepository()
        entry = DeadLetterEntry(
            delivery_id="dlv-1",
            webhook_id="wh-1",
            org_id="org-a",
            event_type=str(TEST_EVENT),
            payload_json="{}",
            payload_hash="hash",
            error_message="boom",
            attempt_count=1,
            queued_at="2026-01-01T00:00:00Z",
            last_attempt_id="att-1",
        )
        repo.append_dead_letter(entry)

        removed = repo.remove_dead_letter("dlv-1", org_id="org-a")

        assert removed is True
        assert repo.list_dead_letter() == []

    def test_repository_clear_dead_letter_by_org(self) -> None:
        repo = InMemoryWebhookDispatcherRepository()
        repo.append_dead_letter(
            DeadLetterEntry(
                delivery_id="dlv-1",
                webhook_id="wh-1",
                org_id="org-a",
                event_type=str(TEST_EVENT),
                payload_json="{}",
                payload_hash="hash-1",
                error_message="boom",
                attempt_count=1,
                queued_at="2026-01-01T00:00:00Z",
                last_attempt_id="att-1",
            ),
        )
        repo.append_dead_letter(
            DeadLetterEntry(
                delivery_id="dlv-2",
                webhook_id="wh-2",
                org_id="org-b",
                event_type=str(TEST_EVENT),
                payload_json="{}",
                payload_hash="hash-2",
                error_message="boom",
                attempt_count=1,
                queued_at="2026-01-01T00:00:00Z",
                last_attempt_id="att-2",
            ),
        )

        removed = repo.clear_dead_letter(org_id="org-a")

        assert removed == 1
        remaining = repo.list_dead_letter()
        assert len(remaining) == 1
        assert remaining[0].org_id == "org-b"


class TestRegistration:
    def test_register_returns_active_response(self, dispatcher: WebhookDispatcher) -> None:
        result = dispatcher.register(_create_request(metadata={"source": "test"}))

        assert result.name == "Primary webhook"
        assert result.target_url == TEST_URL
        assert result.org_id == TEST_ORG_ID
        assert result.status == WebhookStatus.ACTIVE
        assert result.active is True
        assert result.failure_count == 0
        assert result.metadata == {"source": "test"}

    def test_register_disabled_webhook_sets_disabled_status(self, dispatcher: WebhookDispatcher) -> None:
        result = dispatcher.register(_create_request(active=False))

        assert result.active is False
        assert result.status == WebhookStatus.DISABLED

    def test_get_returns_registered_webhook(self, dispatcher: WebhookDispatcher) -> None:
        created = dispatcher.register(_create_request())

        found = dispatcher.get(created.webhook_id)

        assert found is not None
        assert found.webhook_id == created.webhook_id

    def test_get_returns_none_when_missing(self, dispatcher: WebhookDispatcher) -> None:
        assert dispatcher.get("missing-webhook") is None

    def test_update_applies_partial_changes(self, dispatcher: WebhookDispatcher) -> None:
        created = dispatcher.register(_create_request())

        updated = dispatcher.update(
            created.webhook_id,
            WebhookUpdateRequest(
                name="Renamed webhook",
                active=False,
                metadata={"updated": True},
            ),
        )

        assert updated is not None
        assert updated.name == "Renamed webhook"
        assert updated.active is False
        assert updated.status == WebhookStatus.DISABLED
        assert updated.metadata == {"updated": True}

    def test_update_returns_none_when_missing(self, dispatcher: WebhookDispatcher) -> None:
        result = dispatcher.update("missing-webhook", WebhookUpdateRequest(name="Nope"))

        assert result is None

    def test_delete_removes_webhook(self, dispatcher: WebhookDispatcher) -> None:
        created = dispatcher.register(_create_request())

        deleted = dispatcher.delete(created.webhook_id)

        assert deleted is True
        assert dispatcher.get(created.webhook_id) is None

    def test_delete_returns_false_when_missing(self, dispatcher: WebhookDispatcher) -> None:
        assert dispatcher.delete("missing-webhook") is False

    def test_rotate_secret_updates_secret_response(self, dispatcher: WebhookDispatcher) -> None:
        created = dispatcher.register(_create_request())

        result = dispatcher.rotate_secret(created.webhook_id, "replacement-secret-123")

        assert result is not None
        assert result.webhook_id == created.webhook_id
        assert result.signing_algorithm == WebhookSigningAlgorithm.HMAC_SHA256

    def test_rotate_secret_returns_none_when_missing(self, dispatcher: WebhookDispatcher) -> None:
        assert dispatcher.rotate_secret("missing-webhook", "replacement-secret-123") is None

    def test_set_active_true_enables_webhook(self, dispatcher: WebhookDispatcher) -> None:
        created = dispatcher.register(_create_request(active=False))

        result = dispatcher.set_active(created.webhook_id, active=True)

        assert result is not None
        assert result.active is True
        assert result.status == WebhookStatus.ACTIVE

    def test_set_active_false_disables_webhook(self, dispatcher: WebhookDispatcher) -> None:
        created = dispatcher.register(_create_request(active=True))

        result = dispatcher.set_active(created.webhook_id, active=False)

        assert result is not None
        assert result.active is False
        assert result.status == WebhookStatus.DISABLED

    def test_set_active_returns_none_when_missing(self, dispatcher: WebhookDispatcher) -> None:
        assert dispatcher.set_active("missing-webhook", active=True) is None


class TestListingAndFiltering:
    def test_list_webhooks_returns_all_when_unfiltered(self, dispatcher: WebhookDispatcher) -> None:
        dispatcher.register(_create_request(name="one", org_id="org-a"))
        dispatcher.register(_create_request(name="two", org_id="org-b"))

        results = dispatcher.list_webhooks()

        assert len(results) == 2

    def test_list_webhooks_filters_by_org_id(self, dispatcher: WebhookDispatcher) -> None:
        dispatcher.register(_create_request(name="one", org_id="org-a"))
        dispatcher.register(_create_request(name="two", org_id="org-b"))

        results = dispatcher.list_webhooks(WebhookFilterRequest(org_id="org-a"))

        assert len(results) == 1
        assert results[0].org_id == "org-a"

    def test_list_webhooks_filters_by_active(self, dispatcher: WebhookDispatcher) -> None:
        dispatcher.register(_create_request(name="enabled", active=True))
        dispatcher.register(_create_request(name="disabled", active=False))

        results = dispatcher.list_webhooks(WebhookFilterRequest(active=False))

        assert len(results) == 1
        assert results[0].active is False

    def test_list_webhooks_filters_by_status(self, dispatcher: WebhookDispatcher) -> None:
        dispatcher.register(_create_request(name="enabled", active=True))
        dispatcher.register(_create_request(name="disabled", active=False))

        results = dispatcher.list_webhooks(
            WebhookFilterRequest(status=WebhookStatus.DISABLED),
        )

        assert len(results) == 1
        assert results[0].status == WebhookStatus.DISABLED

    def test_list_webhooks_filters_by_event_type(self, dispatcher: WebhookDispatcher) -> None:
        dispatcher.register(
            _create_request(
                name="warn-hook",
                event_types=[WebhookEventType.GUARD_WARN],
            ),
        )
        dispatcher.register(
            _create_request(
                name="block-hook",
                event_types=[WebhookEventType.GUARD_BLOCK],
            ),
        )

        results = dispatcher.list_webhooks(
            WebhookFilterRequest(event_type=WebhookEventType.GUARD_BLOCK),
        )

        assert len(results) == 1
        assert results[0].name == "block-hook"

    def test_list_webhooks_matches_all_subscription(self, dispatcher: WebhookDispatcher) -> None:
        dispatcher._repository.save_webhook(
            _make_wildcard_record(webhook_id="wh-all", name="wildcard"),
        )

        results = dispatcher.list_webhooks(
            WebhookFilterRequest(event_type=WebhookEventType.GUARD_ALLOW),
        )

        assert len(results) == 1
        assert results[0].webhook_id == "wh-all"


class TestDispatchAndMatching:
    def test_dispatch_event_fans_out_to_matching_active_webhooks(self, dispatcher: WebhookDispatcher) -> None:
        one = dispatcher.register(_create_request(name="one", org_id="org-a"))
        two = dispatcher.register(_create_request(name="two", org_id="org-a"))
        dispatcher.register(_create_request(name="three", org_id="org-b"))

        expected_one = SimpleNamespace(
            webhook_id=one.webhook_id,
            status=WebhookDeliveryStatus.SUCCESS,
        )
        expected_two = SimpleNamespace(
            webhook_id=two.webhook_id,
            status=WebhookDeliveryStatus.SUCCESS,
        )

        original = dispatcher._deliver_with_retry
        dispatcher._deliver_with_retry = lambda *args, **kwargs: expected_one if args[0].webhook_id == one.webhook_id else expected_two
        try:
            results = dispatcher.dispatch_event(
                str(TEST_EVENT),
                {"decision": "block"},
                org_id="org-a",
            )
        finally:
            dispatcher._deliver_with_retry = original

        assert len(results) == 2

    def test_dispatch_event_skips_disabled_webhooks(self, dispatcher: WebhookDispatcher) -> None:
        dispatcher.register(_create_request(name="enabled", active=True))
        dispatcher.register(_create_request(name="disabled", active=False))

        original = dispatcher._deliver_with_retry
        dispatcher._deliver_with_retry = lambda *args, **kwargs: SimpleNamespace(
            status=WebhookDeliveryStatus.SUCCESS,
        )
        try:
            results = dispatcher.dispatch_event(
                str(TEST_EVENT),
                {"decision": "block"},
                org_id=TEST_ORG_ID,
            )
        finally:
            dispatcher._deliver_with_retry = original

        assert len(results) == 1

    def test_matches_event_rejects_wrong_org(self, dispatcher: WebhookDispatcher) -> None:
        created = dispatcher.register(_create_request(org_id="org-a"))
        record = dispatcher._repository.get_webhook(created.webhook_id)

        assert record is not None
        assert dispatcher._matches_event(record, str(TEST_EVENT), "org-b") is False

    def test_matches_event_accepts_matching_org_and_event(self, dispatcher: WebhookDispatcher) -> None:
        created = dispatcher.register(_create_request(org_id="org-a"))
        record = dispatcher._repository.get_webhook(created.webhook_id)

        assert record is not None
        assert dispatcher._matches_event(record, str(TEST_EVENT), "org-a") is True

    def test_matches_event_accepts_all_event_subscription(self, dispatcher: WebhookDispatcher) -> None:
        record = _make_wildcard_record(webhook_id="wh-all-match", org_id="org-a")

        assert (
            dispatcher._matches_event(
                record,
                str(WebhookEventType.GUARD_ALLOW),
                "org-a",
            )
            is True
        )

    def test_build_payload_contains_expected_fields(self, dispatcher: WebhookDispatcher) -> None:
        created = dispatcher.register(_create_request())
        record = dispatcher._repository.get_webhook(created.webhook_id)

        assert record is not None
        payload_bytes, payload_hash_value = dispatcher._build_payload(
            record,
            str(TEST_EVENT),
            {"decision": "block"},
            "dlv-test-123",
            TEST_ORG_ID,
        )

        payload = json.loads(payload_bytes.decode("utf-8"))

        assert payload["ironclaw_delivery_id"] == "dlv-test-123"
        assert payload["webhook_id"] == created.webhook_id
        assert payload["event_type"] == str(TEST_EVENT)
        assert payload["org_id"] == TEST_ORG_ID
        assert payload["data"] == {"decision": "block"}
        assert payload_hash_value == _hash_payload(payload_bytes)


class TestSendOnce:
    def test_send_once_success_sets_expected_headers_for_sha256(self) -> None:
        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["headers"] = dict(request.headers)
            captured["url"] = str(request.url)
            captured["body"] = request.content
            return httpx.Response(200, text="accepted")

        client = httpx.Client(transport=httpx.MockTransport(handler))
        dispatcher = WebhookDispatcher(http_client=client)
        created = dispatcher.register(
            _create_request(signing_algorithm=WebhookSigningAlgorithm.HMAC_SHA256),
        )
        record = dispatcher._repository.get_webhook(created.webhook_id)

        assert record is not None
        attempt = dispatcher._send_once(
            record=record,
            delivery_id="dlv-1",
            payload_bytes=b'{"ok":true}',
            payload_hash=_hash_payload(b'{"ok":true}'),
            signature="sha256=testsig",
            event_type=str(TEST_EVENT),
            attempt_number=1,
            max_attempts=3,
        )

        headers = captured["headers"]
        assert attempt.status == WebhookDeliveryStatus.SUCCESS
        assert attempt.http_status_code == 200
        assert headers[_SIGNATURE_HEADER_256.lower()] == "sha256=testsig"
        assert headers[_DELIVERY_ID_HEADER.lower()] == "dlv-1"
        assert headers[_EVENT_TYPE_HEADER.lower()] == str(TEST_EVENT)
        assert headers[_WEBHOOK_AGENT_HEADER.lower()] == _WEBHOOK_AGENT_VALUE

    def test_send_once_success_sets_expected_headers_for_sha512(self) -> None:
        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["headers"] = dict(request.headers)
            return httpx.Response(204, text="")

        client = httpx.Client(transport=httpx.MockTransport(handler))
        dispatcher = WebhookDispatcher(http_client=client)
        created = dispatcher.register(
            _create_request(signing_algorithm=WebhookSigningAlgorithm.HMAC_SHA512),
        )
        record = dispatcher._repository.get_webhook(created.webhook_id)

        assert record is not None
        attempt = dispatcher._send_once(
            record=record,
            delivery_id="dlv-2",
            payload_bytes=b"{}",
            payload_hash=_hash_payload(b"{}"),
            signature="sha512=testsig",
            event_type=str(TEST_EVENT),
            attempt_number=1,
            max_attempts=1,
        )

        headers = captured["headers"]
        assert attempt.status == WebhookDeliveryStatus.SUCCESS
        assert headers[_SIGNATURE_HEADER_512.lower()] == "sha512=testsig"

    def test_send_once_non_2xx_retries_before_final_attempt(self) -> None:
        client = httpx.Client(
            transport=httpx.MockTransport(lambda request: httpx.Response(502, text="bad gateway")),
        )
        dispatcher = WebhookDispatcher(http_client=client)
        created = dispatcher.register(_create_request())
        record = dispatcher._repository.get_webhook(created.webhook_id)

        assert record is not None
        attempt = dispatcher._send_once(
            record=record,
            delivery_id="dlv-3",
            payload_bytes=b"{}",
            payload_hash=_hash_payload(b"{}"),
            signature="sha256=testsig",
            event_type=str(TEST_EVENT),
            attempt_number=1,
            max_attempts=3,
        )

        assert attempt.status == WebhookDeliveryStatus.RETRYING
        assert attempt.http_status_code == 502
        assert attempt.error_message == "Non-2xx HTTP status: 502"

    def test_send_once_non_2xx_fails_on_final_attempt(self) -> None:
        client = httpx.Client(
            transport=httpx.MockTransport(lambda request: httpx.Response(400, text="bad request")),
        )
        dispatcher = WebhookDispatcher(http_client=client)
        created = dispatcher.register(_create_request())
        record = dispatcher._repository.get_webhook(created.webhook_id)

        assert record is not None
        attempt = dispatcher._send_once(
            record=record,
            delivery_id="dlv-4",
            payload_bytes=b"{}",
            payload_hash=_hash_payload(b"{}"),
            signature="sha256=testsig",
            event_type=str(TEST_EVENT),
            attempt_number=3,
            max_attempts=3,
        )

        assert attempt.status == WebhookDeliveryStatus.FAILED
        assert attempt.http_status_code == 400

    def test_send_once_timeout_error_is_captured(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("timed out")

        client = httpx.Client(transport=httpx.MockTransport(handler))
        dispatcher = WebhookDispatcher(http_client=client)
        created = dispatcher.register(_create_request(timeout_seconds=7))
        record = dispatcher._repository.get_webhook(created.webhook_id)

        assert record is not None
        attempt = dispatcher._send_once(
            record=record,
            delivery_id="dlv-5",
            payload_bytes=b"{}",
            payload_hash=_hash_payload(b"{}"),
            signature="sha256=testsig",
            event_type=str(TEST_EVENT),
            attempt_number=1,
            max_attempts=1,
        )

        assert attempt.status == WebhookDeliveryStatus.FAILED
        assert attempt.error_message == "Delivery timed out after 7s"

    def test_send_once_request_error_is_captured(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("network unreachable", request=request)

        client = httpx.Client(transport=httpx.MockTransport(handler))
        dispatcher = WebhookDispatcher(http_client=client)
        created = dispatcher.register(_create_request())
        record = dispatcher._repository.get_webhook(created.webhook_id)

        assert record is not None
        attempt = dispatcher._send_once(
            record=record,
            delivery_id="dlv-6",
            payload_bytes=b"{}",
            payload_hash=_hash_payload(b"{}"),
            signature="sha256=testsig",
            event_type=str(TEST_EVENT),
            attempt_number=2,
            max_attempts=2,
        )

        assert attempt.status == WebhookDeliveryStatus.FAILED
        assert "RequestError:" in (attempt.error_message or "")

    def test_send_once_unexpected_error_is_captured(self) -> None:
        class BoomTransport(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                raise RuntimeError("boom")

        client = httpx.Client(transport=BoomTransport())
        dispatcher = WebhookDispatcher(http_client=client)
        created = dispatcher.register(_create_request())
        record = dispatcher._repository.get_webhook(created.webhook_id)

        assert record is not None
        attempt = dispatcher._send_once(
            record=record,
            delivery_id="dlv-7",
            payload_bytes=b"{}",
            payload_hash=_hash_payload(b"{}"),
            signature="sha256=testsig",
            event_type=str(TEST_EVENT),
            attempt_number=1,
            max_attempts=1,
        )

        assert attempt.status == WebhookDeliveryStatus.FAILED
        assert attempt.error_message == "Unexpected error: boom"


class TestRetryFlow:
    def test_deliver_with_retry_returns_success_on_first_attempt(self, dispatcher: WebhookDispatcher) -> None:
        created = dispatcher.register(_create_request())
        record = dispatcher._repository.get_webhook(created.webhook_id)

        assert record is not None
        success_attempt = SimpleNamespace(
            attempt_id="att-1",
            webhook_id=created.webhook_id,
            event_type=str(TEST_EVENT),
            payload_hash="hash-1",
            status=WebhookDeliveryStatus.SUCCESS,
            http_status_code=200,
            response_body_snippet="ok",
            attempt_number=1,
            duration_ms=5,
            error_message=None,
            attempted_at="2026-01-01T00:00:00Z",
        )

        original = dispatcher._send_once
        dispatcher._send_once = lambda **kwargs: success_attempt
        try:
            result = dispatcher._deliver_with_retry(
                record,
                str(TEST_EVENT),
                {"decision": "block"},
                org_id=TEST_ORG_ID,
                is_test=False,
            )
        finally:
            dispatcher._send_once = original

        assert result.status == WebhookDeliveryStatus.SUCCESS

    def test_deliver_with_retry_records_dead_letter_on_failure(self, dispatcher: WebhookDispatcher) -> None:
        created = dispatcher.register(_create_request(max_retries=0))
        record = dispatcher._repository.get_webhook(created.webhook_id)

        assert record is not None
        failed_attempt = SimpleNamespace(
            attempt_id="att-final",
            webhook_id=created.webhook_id,
            event_type=str(TEST_EVENT),
            payload_hash="hash-final",
            status=WebhookDeliveryStatus.FAILED,
            http_status_code=503,
            response_body_snippet=None,
            attempt_number=1,
            duration_ms=12,
            error_message="Non-2xx HTTP status: 503",
            attempted_at="2026-01-01T00:00:00Z",
        )

        original = dispatcher._send_once
        dispatcher._send_once = lambda **kwargs: failed_attempt
        try:
            result = dispatcher._deliver_with_retry(
                record,
                str(TEST_EVENT),
                {"decision": "block"},
                org_id=TEST_ORG_ID,
                is_test=False,
            )
        finally:
            dispatcher._send_once = original

        assert result.status == WebhookDeliveryStatus.FAILED
        dead = dispatcher.list_dead_letter(org_id=TEST_ORG_ID, limit=10)
        assert len(dead) == 1
        assert dead[0]["webhook_id"] == created.webhook_id

    def test_record_success_resets_failure_count(self, dispatcher: WebhookDispatcher) -> None:
        created = dispatcher.register(_create_request())

        dispatcher._record_failure(
            created.webhook_id,
            SimpleNamespace(
                attempt_id="att-1",
                payload_hash="hash",
                attempt_number=1,
                error_message="boom",
                attempted_at="2026-01-01T00:00:00Z",
            ),
            b"{}",
            str(TEST_EVENT),
            delivery_id="dlv-1",
            org_id=TEST_ORG_ID,
            is_test=False,
        )

        dispatcher._record_success(
            created.webhook_id,
            SimpleNamespace(
                attempted_at="2026-01-02T00:00:00Z",
                attempt_number=1,
                http_status_code=200,
            ),
            is_test=False,
        )

        updated = dispatcher.get(created.webhook_id)
        assert updated is not None
        assert updated.failure_count == 0
        assert updated.last_triggered_at == "2026-01-02T00:00:00Z"
        assert updated.status == WebhookStatus.ACTIVE

    def test_record_failure_increments_failure_count(self, dispatcher: WebhookDispatcher) -> None:
        created = dispatcher.register(_create_request())

        dispatcher._record_failure(
            created.webhook_id,
            SimpleNamespace(
                attempt_id="att-1",
                payload_hash="hash",
                attempt_number=1,
                error_message="boom",
                attempted_at="2026-01-01T00:00:00Z",
            ),
            b'{"x":1}',
            str(TEST_EVENT),
            delivery_id="dlv-1",
            org_id=TEST_ORG_ID,
            is_test=False,
        )

        updated = dispatcher.get(created.webhook_id)
        assert updated is not None
        assert updated.failure_count == 1
        dead = dispatcher.list_dead_letter(org_id=TEST_ORG_ID, limit=10)
        assert len(dead) == 1

    def test_record_failure_marks_webhook_failing_at_threshold(self, dispatcher: WebhookDispatcher) -> None:
        created = dispatcher.register(_create_request())

        for idx in range(_HIGH_FAILURE_THRESHOLD):
            dispatcher._record_failure(
                created.webhook_id,
                SimpleNamespace(
                    attempt_id=f"att-{idx}",
                    payload_hash=f"hash-{idx}",
                    attempt_number=1,
                    error_message="boom",
                    attempted_at="2026-01-01T00:00:00Z",
                ),
                b'{"x":1}',
                str(TEST_EVENT),
                delivery_id=f"dlv-{idx}",
                org_id=TEST_ORG_ID,
                is_test=False,
            )

        updated = dispatcher.get(created.webhook_id)
        assert updated is not None
        assert updated.failure_count == _HIGH_FAILURE_THRESHOLD
        assert updated.status == WebhookStatus.FAILING

    def test_get_delivery_log_returns_limited_entries(self, dispatcher: WebhookDispatcher) -> None:
        created = dispatcher.register(_create_request())

        for idx in range(3):
            attempt = SimpleNamespace(
                attempt_id=f"att-{idx}",
                webhook_id=created.webhook_id,
                event_type=str(TEST_EVENT),
                payload_hash=f"hash-{idx}",
                status=WebhookDeliveryStatus.FAILED,
                http_status_code=500,
                response_body_snippet=None,
                attempt_number=idx + 1,
                duration_ms=10,
                error_message="boom",
                attempted_at=f"2026-01-0{idx + 1}T00:00:00Z",
            )
            dispatcher._repository.append_delivery_attempt(created.webhook_id, attempt)

        results = dispatcher.get_delivery_log(created.webhook_id, limit=2)

        assert len(results) == 2
        assert results[0].attempt_id == "att-1"
        assert results[1].attempt_id == "att-2"


class TestDeadLetter:
    def test_list_dead_letter_requires_org_without_global(self, dispatcher: WebhookDispatcher) -> None:
        assert dispatcher.list_dead_letter(org_id="", allow_global=False) == []

    def test_list_dead_letter_respects_limit(self, dispatcher: WebhookDispatcher) -> None:
        created = dispatcher.register(_create_request())

        for idx in range(3):
            dispatcher._record_failure(
                created.webhook_id,
                SimpleNamespace(
                    attempt_id=f"att-{idx}",
                    payload_hash=f"hash-{idx}",
                    attempt_number=idx + 1,
                    error_message="boom",
                    attempted_at="2026-01-01T00:00:00Z",
                ),
                json.dumps({"idx": idx}).encode("utf-8"),
                str(TEST_EVENT),
                delivery_id=f"dlv-{idx}",
                org_id=TEST_ORG_ID,
                is_test=False,
            )

        results = dispatcher.list_dead_letter(org_id=TEST_ORG_ID, limit=2)

        assert len(results) == 2

    def test_replay_dead_letter_returns_none_when_missing(self, dispatcher: WebhookDispatcher) -> None:
        assert dispatcher.replay_dead_letter("missing-delivery", org_id=TEST_ORG_ID) is None

    def test_replay_dead_letter_returns_none_when_webhook_missing(self, dispatcher: WebhookDispatcher) -> None:
        dispatcher._repository.append_dead_letter(
            DeadLetterEntry(
                delivery_id="dead-1",
                webhook_id="missing-webhook",
                org_id=TEST_ORG_ID,
                event_type=str(TEST_EVENT),
                payload_json='{"data":{"x":1}}',
                payload_hash="hash",
                error_message="boom",
                attempt_count=1,
                queued_at="2026-01-01T00:00:00Z",
                last_attempt_id="att-1",
            ),
        )

        assert dispatcher.replay_dead_letter("dead-1", org_id=TEST_ORG_ID) is None

    def test_replay_dead_letter_replays_and_removes_on_success(self, dispatcher: WebhookDispatcher) -> None:
        created = dispatcher.register(_create_request())
        dispatcher._repository.append_dead_letter(
            DeadLetterEntry(
                delivery_id="dead-2",
                webhook_id=created.webhook_id,
                org_id=TEST_ORG_ID,
                event_type=str(TEST_EVENT),
                payload_json='{"data":{"x":1}}',
                payload_hash="hash",
                error_message="boom",
                attempt_count=1,
                queued_at="2026-01-01T00:00:00Z",
                last_attempt_id="att-1",
            ),
        )

        original = dispatcher._deliver_with_retry
        dispatcher._deliver_with_retry = lambda *args, **kwargs: SimpleNamespace(
            status=WebhookDeliveryStatus.SUCCESS,
        )
        try:
            result = dispatcher.replay_dead_letter("dead-2", org_id=TEST_ORG_ID)
        finally:
            dispatcher._deliver_with_retry = original

        assert result is not None
        assert result.status == WebhookDeliveryStatus.SUCCESS
        assert dispatcher.list_dead_letter(org_id=TEST_ORG_ID, limit=10) == []

    def test_replay_dead_letter_keeps_entry_on_failure(self, dispatcher: WebhookDispatcher) -> None:
        created = dispatcher.register(_create_request())
        dispatcher._repository.append_dead_letter(
            DeadLetterEntry(
                delivery_id="dead-3",
                webhook_id=created.webhook_id,
                org_id=TEST_ORG_ID,
                event_type=str(TEST_EVENT),
                payload_json='{"data":{"x":1}}',
                payload_hash="hash",
                error_message="boom",
                attempt_count=1,
                queued_at="2026-01-01T00:00:00Z",
                last_attempt_id="att-1",
            ),
        )

        original = dispatcher._deliver_with_retry
        dispatcher._deliver_with_retry = lambda *args, **kwargs: SimpleNamespace(
            status=WebhookDeliveryStatus.FAILED,
        )
        try:
            result = dispatcher.replay_dead_letter("dead-3", org_id=TEST_ORG_ID)
        finally:
            dispatcher._deliver_with_retry = original

        assert result is not None
        assert result.status == WebhookDeliveryStatus.FAILED
        assert len(dispatcher.list_dead_letter(org_id=TEST_ORG_ID, limit=10)) == 1

    def test_purge_dead_letter_by_org(self, dispatcher: WebhookDispatcher) -> None:
        dispatcher._repository.append_dead_letter(
            DeadLetterEntry(
                delivery_id="dead-a",
                webhook_id="wh-a",
                org_id="org-a",
                event_type=str(TEST_EVENT),
                payload_json="{}",
                payload_hash="hash-a",
                error_message="boom",
                attempt_count=1,
                queued_at="2026-01-01T00:00:00Z",
                last_attempt_id="att-a",
            ),
        )
        dispatcher._repository.append_dead_letter(
            DeadLetterEntry(
                delivery_id="dead-b",
                webhook_id="wh-b",
                org_id="org-b",
                event_type=str(TEST_EVENT),
                payload_json="{}",
                payload_hash="hash-b",
                error_message="boom",
                attempt_count=1,
                queued_at="2026-01-01T00:00:00Z",
                last_attempt_id="att-b",
            ),
        )

        removed = dispatcher.purge_dead_letter(org_id="org-a")

        assert removed == 1
        remaining = dispatcher.list_dead_letter(org_id="org-b", limit=10)
        assert len(remaining) == 1

    def test_purge_dead_letter_global(self, dispatcher: WebhookDispatcher) -> None:
        dispatcher._repository.append_dead_letter(
            DeadLetterEntry(
                delivery_id="dead-a",
                webhook_id="wh-a",
                org_id="org-a",
                event_type=str(TEST_EVENT),
                payload_json="{}",
                payload_hash="hash-a",
                error_message="boom",
                attempt_count=1,
                queued_at="2026-01-01T00:00:00Z",
                last_attempt_id="att-a",
            ),
        )
        dispatcher._repository.append_dead_letter(
            DeadLetterEntry(
                delivery_id="dead-b",
                webhook_id="wh-b",
                org_id="org-b",
                event_type=str(TEST_EVENT),
                payload_json="{}",
                payload_hash="hash-b",
                error_message="boom",
                attempt_count=1,
                queued_at="2026-01-01T00:00:00Z",
                last_attempt_id="att-b",
            ),
        )

        removed = dispatcher.purge_dead_letter(org_id="", allow_global=True)

        assert removed == 2


class TestSendTest:
    def test_send_test_returns_failure_when_webhook_missing(self, dispatcher: WebhookDispatcher) -> None:
        result = dispatcher.send_test("missing-webhook")

        assert result.webhook_id == "missing-webhook"
        assert result.delivery_status == WebhookDeliveryStatus.FAILED
        assert result.error_message == "Webhook not found"

    def test_send_test_returns_attempt_result(self, dispatcher: WebhookDispatcher) -> None:
        created = dispatcher.register(_create_request())

        original = dispatcher._deliver_with_retry
        dispatcher._deliver_with_retry = lambda *args, **kwargs: SimpleNamespace(
            status=WebhookDeliveryStatus.SUCCESS,
            http_status_code=200,
            duration_ms=15,
            error_message=None,
        )
        try:
            result = dispatcher.send_test(created.webhook_id)
        finally:
            dispatcher._deliver_with_retry = original

        assert result.webhook_id == created.webhook_id
        assert result.delivery_status == WebhookDeliveryStatus.SUCCESS
        assert result.http_status_code == 200
        assert result.duration_ms == 15


class TestSingletonHelpers:
    def test_get_webhook_dispatcher_returns_singleton(self) -> None:
        first = get_webhook_dispatcher()
        second = get_webhook_dispatcher()

        assert first is second

    def test_reset_webhook_dispatcher_clears_singleton_state(self) -> None:
        dispatcher = get_webhook_dispatcher()
        created = dispatcher.register(_create_request())

        assert dispatcher.get(created.webhook_id) is not None

        reset_webhook_dispatcher()

        assert dispatcher.get(created.webhook_id) is None
