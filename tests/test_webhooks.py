from __future__ import annotations

from collections.abc import Generator
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import threading
from typing import Any
from unittest.mock import patch

import pytest

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("IRONCLAW_API_KEY", "test-api-key")
os.environ.setdefault("AUTH_REQUIRED", "true")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "")
os.environ.setdefault("SUPABASE_KEY", "")
os.environ.setdefault("SUPABASE_ANON_KEY", "")

from fastapi.testclient import TestClient

from app.main import app
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
    WebhookDispatcher,
    _hash_payload,
    _sign_payload,
    reset_webhook_dispatcher,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TEST_ORG = "org-test-001"
_TEST_SECRET = "supersecretvalue1234567890abcdef"
_TEST_URL = "https://example.com/hook"
_AUTH_HEADERS = {"X-API-Key": "test-api-key", "X-Organization-Id": _TEST_ORG}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _create_request(
    *,
    name: str = "test-hook",
    url: str = _TEST_URL,
    secret: str = _TEST_SECRET,
    event_types: list[str] | None = None,
    org_id: str | None = None,
    active: bool = True,
    max_retries: int = 0,
    timeout_seconds: int = 5,
    signing_algorithm: str = WebhookSigningAlgorithm.HMAC_SHA256,
    metadata: dict[str, Any] | None = None,
) -> WebhookCreateRequest:
    return WebhookCreateRequest(
        name=name,
        target_url=url,  # type: ignore[arg-type]
        secret=secret,
        event_types=[WebhookEventType(e) for e in (event_types or ["guard.allow"])],
        org_id=org_id,
        active=active,
        max_retries=max_retries,
        timeout_seconds=timeout_seconds,
        signing_algorithm=WebhookSigningAlgorithm(signing_algorithm),
        metadata=metadata or {},
    )


def _fresh_dispatcher() -> WebhookDispatcher:
    return WebhookDispatcher()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_dispatcher() -> Generator[None, None, None]:
    reset_webhook_dispatcher()
    yield
    reset_webhook_dispatcher()


@pytest.fixture()
def dispatcher() -> WebhookDispatcher:
    return _fresh_dispatcher()


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture()
def registered(dispatcher: WebhookDispatcher) -> Any:
    req = _create_request()
    return dispatcher.register(req)


# ---------------------------------------------------------------------------
# Tiny local HTTP server for live delivery tests
# ---------------------------------------------------------------------------


class _RecordingHandler(BaseHTTPRequestHandler):
    received: list[dict[str, Any]] = []
    response_code: int = 200

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        _RecordingHandler.received.append(
            {
                "path": self.path,
                "body": body,
                "headers": dict(self.headers),
            }
        )
        self.send_response(_RecordingHandler.response_code)
        self.end_headers()

    def log_message(self, *args: Any) -> None:  # suppress noise
        pass


@pytest.fixture()
def local_server() -> Generator[tuple[HTTPServer, int], None, None]:
    _RecordingHandler.received = []
    _RecordingHandler.response_code = 200
    server = HTTPServer(("127.0.0.1", 0), _RecordingHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, port
    server.shutdown()


# ===========================================================================
# Section 1 — Model validation
# ===========================================================================


class TestWebhookModelValidation:
    def test_create_requires_https(self) -> None:
        with pytest.raises(ValueError):
            WebhookCreateRequest(
                name="bad",
                target_url="http://example.com/hook",  # type: ignore[arg-type]
                secret=_TEST_SECRET,
                event_types=[WebhookEventType.GUARD_ALLOW],
            )

    def test_create_secret_min_length(self) -> None:
        with pytest.raises(ValueError):
            WebhookCreateRequest(
                name="bad",
                target_url=_TEST_URL,  # type: ignore[arg-type]
                secret="short",
                event_types=[WebhookEventType.GUARD_ALLOW],
            )

    def test_create_deduplicates_event_types(self) -> None:
        req = WebhookCreateRequest(
            name="dedup",
            target_url=_TEST_URL,  # type: ignore[arg-type]
            secret=_TEST_SECRET,
            event_types=[WebhookEventType.GUARD_ALLOW, WebhookEventType.GUARD_ALLOW],
        )
        assert len(req.event_types) == 1

    def test_wildcard_exclusive(self) -> None:
        with pytest.raises(ValueError):
            WebhookCreateRequest(
                name="wild",
                target_url=_TEST_URL,  # type: ignore[arg-type]
                secret=_TEST_SECRET,
                event_types=[WebhookEventType.ALL, WebhookEventType.GUARD_ALLOW],
            )

    def test_wildcard_alone_ok(self) -> None:
        req = WebhookCreateRequest(
            name="wild-ok",
            target_url=_TEST_URL,  # type: ignore[arg-type]
            secret=_TEST_SECRET,
            event_types=[WebhookEventType.ALL],
        )
        assert "*" in [str(e) for e in req.event_types]

    def test_event_types_required_non_empty(self) -> None:
        with pytest.raises(ValueError):
            WebhookCreateRequest(
                name="empty",
                target_url=_TEST_URL,  # type: ignore[arg-type]
                secret=_TEST_SECRET,
                event_types=[],
            )

    def test_max_retries_bounds(self) -> None:
        with pytest.raises(ValueError):
            WebhookCreateRequest(
                name="retry-oob",
                target_url=_TEST_URL,  # type: ignore[arg-type]
                secret=_TEST_SECRET,
                event_types=[WebhookEventType.GUARD_ALLOW],
                max_retries=99,
            )

    def test_timeout_bounds(self) -> None:
        with pytest.raises(ValueError):
            WebhookCreateRequest(
                name="timeout-oob",
                target_url=_TEST_URL,  # type: ignore[arg-type]
                secret=_TEST_SECRET,
                event_types=[WebhookEventType.GUARD_ALLOW],
                timeout_seconds=0,
            )

    def test_update_request_all_optional(self) -> None:
        req = WebhookUpdateRequest()
        assert req.name is None
        assert req.active is None

    def test_update_request_https_enforced(self) -> None:
        with pytest.raises(ValueError):
            WebhookUpdateRequest(target_url="http://bad.example.com")  # type: ignore[arg-type]

    def test_update_request_deduplicates_events(self) -> None:
        req = WebhookUpdateRequest(event_types=[WebhookEventType.GUARD_ALLOW, WebhookEventType.GUARD_ALLOW])
        assert req.event_types is not None
        assert len(req.event_types) == 1


# ===========================================================================
# Section 2 — Dispatcher unit tests (no network)
# ===========================================================================


class TestWebhookDispatcherUnit:
    def test_register_returns_response(self, dispatcher: WebhookDispatcher) -> None:
        req = _create_request()
        resp = dispatcher.register(req)
        assert resp.webhook_id.startswith("wh-")
        assert resp.name == req.name
        assert resp.active is True
        assert resp.status == WebhookStatus.ACTIVE

    def test_register_inactive_sets_disabled_status(self, dispatcher: WebhookDispatcher) -> None:
        req = _create_request(active=False)
        resp = dispatcher.register(req)
        assert resp.active is False
        assert resp.status == WebhookStatus.DISABLED

    def test_get_existing(self, dispatcher: WebhookDispatcher) -> None:
        req = _create_request()
        created = dispatcher.register(req)
        fetched = dispatcher.get(created.webhook_id)
        assert fetched is not None
        assert fetched.webhook_id == created.webhook_id

    def test_get_missing_returns_none(self, dispatcher: WebhookDispatcher) -> None:
        assert dispatcher.get("nonexistent-id") is None

    def test_delete_existing(self, dispatcher: WebhookDispatcher) -> None:
        req = _create_request()
        created = dispatcher.register(req)
        result = dispatcher.delete(created.webhook_id)
        assert result is True
        assert dispatcher.get(created.webhook_id) is None

    def test_delete_nonexistent_returns_false(self, dispatcher: WebhookDispatcher) -> None:
        assert dispatcher.delete("ghost-id") is False

    def test_update_name(self, dispatcher: WebhookDispatcher) -> None:
        req = _create_request()
        created = dispatcher.register(req)
        updated = dispatcher.update(created.webhook_id, WebhookUpdateRequest(name="renamed"))
        assert updated is not None
        assert updated.name == "renamed"
        assert updated.webhook_id == created.webhook_id

    def test_update_nonexistent_returns_none(self, dispatcher: WebhookDispatcher) -> None:
        result = dispatcher.update("ghost-id", WebhookUpdateRequest(name="x"))
        assert result is None

    def test_update_merges_metadata(self, dispatcher: WebhookDispatcher) -> None:
        req = _create_request(metadata={"env": "prod"})
        created = dispatcher.register(req)
        updated = dispatcher.update(created.webhook_id, WebhookUpdateRequest(metadata={"region": "us"}))
        assert updated is not None
        assert updated.metadata.get("env") == "prod"
        assert updated.metadata.get("region") == "us"

    def test_update_active_false_sets_disabled(self, dispatcher: WebhookDispatcher) -> None:
        req = _create_request(active=True)
        created = dispatcher.register(req)
        updated = dispatcher.update(created.webhook_id, WebhookUpdateRequest(active=False))
        assert updated is not None
        assert updated.active is False
        assert updated.status == WebhookStatus.DISABLED

    def test_list_webhooks_all(self, dispatcher: WebhookDispatcher) -> None:
        for i in range(3):
            dispatcher.register(_create_request(name=f"hook-{i}"))
        results = dispatcher.list_webhooks()
        assert len(results) == 3

    def test_list_webhooks_filter_active(self, dispatcher: WebhookDispatcher) -> None:
        dispatcher.register(_create_request(active=True))
        dispatcher.register(_create_request(name="inactive", active=False))
        active_results = dispatcher.list_webhooks(WebhookFilterRequest(active=True))
        assert all(r.active for r in active_results)

    def test_list_webhooks_filter_org(self, dispatcher: WebhookDispatcher) -> None:
        dispatcher.register(_create_request(org_id="org-a"))
        dispatcher.register(_create_request(name="b", org_id="org-b"))
        results = dispatcher.list_webhooks(WebhookFilterRequest(org_id="org-a"))
        assert len(results) == 1
        assert results[0].org_id == "org-a"

    def test_list_webhooks_filter_event_type(self, dispatcher: WebhookDispatcher) -> None:
        dispatcher.register(_create_request(event_types=["guard.allow"]))
        dispatcher.register(_create_request(name="review-hook", event_types=["review.submitted"]))
        results = dispatcher.list_webhooks(WebhookFilterRequest(event_type=WebhookEventType.REVIEW_SUBMITTED))
        assert len(results) == 1

    def test_list_webhooks_wildcard_matches_any_event(self, dispatcher: WebhookDispatcher) -> None:
        dispatcher.register(_create_request(event_types=["*"]))
        results = dispatcher.list_webhooks(WebhookFilterRequest(event_type=WebhookEventType.ALERT_CREATED))
        assert len(results) == 1

    def test_set_active_enable(self, dispatcher: WebhookDispatcher) -> None:
        req = _create_request(active=False)
        created = dispatcher.register(req)
        result = dispatcher.set_active(created.webhook_id, active=True)
        assert result is not None
        assert result.active is True
        assert result.status == WebhookStatus.ACTIVE

    def test_set_active_disable(self, dispatcher: WebhookDispatcher) -> None:
        req = _create_request(active=True)
        created = dispatcher.register(req)
        result = dispatcher.set_active(created.webhook_id, active=False)
        assert result is not None
        assert result.active is False
        assert result.status == WebhookStatus.DISABLED

    def test_set_active_nonexistent_returns_none(self, dispatcher: WebhookDispatcher) -> None:
        assert dispatcher.set_active("ghost-id", active=True) is None

    def test_rotate_secret(self, dispatcher: WebhookDispatcher) -> None:
        req = _create_request()
        created = dispatcher.register(req)
        new_secret = "a" * 32
        result = dispatcher.rotate_secret(created.webhook_id, new_secret)
        assert result is not None
        assert result.webhook_id == created.webhook_id
        assert result.signing_algorithm == WebhookSigningAlgorithm.HMAC_SHA256

    def test_rotate_secret_nonexistent_returns_none(self, dispatcher: WebhookDispatcher) -> None:
        assert dispatcher.rotate_secret("ghost-id", "a" * 32) is None

    def test_reset_clears_all_state(self, dispatcher: WebhookDispatcher) -> None:
        dispatcher.register(_create_request())
        dispatcher.reset()
        assert dispatcher.list_webhooks() == []
        assert dispatcher.list_dead_letter() == []

    def test_thread_safety_concurrent_registers(self, dispatcher: WebhookDispatcher) -> None:
        errors: list[Exception] = []

        def _reg(i: int) -> None:
            try:
                dispatcher.register(_create_request(name=f"concurrent-{i}"))
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=_reg, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert len(dispatcher.list_webhooks()) == 20


# ===========================================================================
# Section 3 — Signing helpers
# ===========================================================================


class TestSigningHelpers:
    def test_hmac_sha256_prefix(self) -> None:
        sig = _sign_payload(b"hello", "secret123", WebhookSigningAlgorithm.HMAC_SHA256)
        assert sig.startswith("sha256=")

    def test_hmac_sha512_prefix(self) -> None:
        sig = _sign_payload(b"hello", "secret123", WebhookSigningAlgorithm.HMAC_SHA512)
        assert sig.startswith("sha512=")

    def test_sha256_correct_digest(self) -> None:
        payload = b"ironclaw-test"
        secret = "mysecretpassword"
        sig = _sign_payload(payload, secret, WebhookSigningAlgorithm.HMAC_SHA256)
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        assert sig == f"sha256={expected}"

    def test_sha512_correct_digest(self) -> None:
        payload = b"ironclaw-512"
        secret = "mysecretpassword"
        sig = _sign_payload(payload, secret, WebhookSigningAlgorithm.HMAC_SHA512)
        expected = hmac.new(secret.encode(), payload, hashlib.sha512).hexdigest()
        assert sig == f"sha512={expected}"

    def test_different_secrets_produce_different_sigs(self) -> None:
        payload = b"payload"
        sig1 = _sign_payload(payload, "secret-aaa-111-000", WebhookSigningAlgorithm.HMAC_SHA256)
        sig2 = _sign_payload(payload, "secret-bbb-222-999", WebhookSigningAlgorithm.HMAC_SHA256)
        assert sig1 != sig2

    def test_hash_payload_sha256(self) -> None:
        data = b"ironclaw"
        result = _hash_payload(data)
        expected = hashlib.sha256(data).hexdigest()
        assert result == expected

    def test_hash_payload_deterministic(self) -> None:
        data = b"repeat"
        assert _hash_payload(data) == _hash_payload(data)


# ===========================================================================
# Section 4 — Delivery tests (mocked network)
# ===========================================================================


class TestWebhookDeliveryMocked:
    def _make_mock_response(self, status_code: int = 200) -> Any:
        class _Resp:
            status = status_code

            def read(self, n: int) -> bytes:
                return b"ok"

            def __enter__(self) -> _Resp:
                return self

            def __exit__(self, *args: Any) -> None:
                pass

        return _Resp()

    def test_dispatch_delivers_to_matching_webhook(self, dispatcher: WebhookDispatcher) -> None:
        req = _create_request(event_types=["guard.allow"])
        dispatcher.register(req)

        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = self._make_mock_response(200)
            results = dispatcher.dispatch_event("guard.allow", {"score": 0.9})

        assert len(results) == 1
        assert results[0].status == WebhookDeliveryStatus.SUCCESS
        assert results[0].http_status_code == 200

    def test_dispatch_skips_inactive_webhook(self, dispatcher: WebhookDispatcher) -> None:
        req = _create_request(active=False)
        dispatcher.register(req)

        with patch("urllib.request.urlopen") as mock_open:
            results = dispatcher.dispatch_event("guard.allow", {})

        assert results == []
        mock_open.assert_not_called()

    def test_dispatch_skips_wrong_event_type(self, dispatcher: WebhookDispatcher) -> None:
        req = _create_request(event_types=["review.submitted"])
        dispatcher.register(req)

        with patch("urllib.request.urlopen") as mock_open:
            results = dispatcher.dispatch_event("guard.allow", {})

        assert results == []
        mock_open.assert_not_called()

    def test_dispatch_wildcard_matches_all_events(self, dispatcher: WebhookDispatcher) -> None:
        req = _create_request(event_types=["*"])
        dispatcher.register(req)

        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = self._make_mock_response(200)
            results = dispatcher.dispatch_event("audit.exported", {"count": 1})

        assert len(results) == 1
        assert results[0].status == WebhookDeliveryStatus.SUCCESS

    def test_dispatch_org_scoped_delivery(self, dispatcher: WebhookDispatcher) -> None:
        req_a = _create_request(name="org-a", org_id="org-a", event_types=["guard.allow"])
        req_b = _create_request(name="org-b", org_id="org-b", event_types=["guard.allow"])
        dispatcher.register(req_a)
        dispatcher.register(req_b)

        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = self._make_mock_response(200)
            results = dispatcher.dispatch_event("guard.allow", {}, org_id="org-a")

        assert len(results) == 1

    def test_failed_delivery_populates_dead_letter(self, dispatcher: WebhookDispatcher) -> None:
        import urllib.error

        req = _create_request(max_retries=0)
        dispatcher.register(req)

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
            results = dispatcher.dispatch_event("guard.allow", {})

        assert results[0].status == WebhookDeliveryStatus.FAILED
        dlq = dispatcher.list_dead_letter()
        assert len(dlq) == 1
        assert dlq[0]["event_type"] == "guard.allow"

    def test_failure_increments_failure_count(self, dispatcher: WebhookDispatcher) -> None:
        import urllib.error

        req = _create_request(max_retries=0)
        created = dispatcher.register(req)

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
            dispatcher.dispatch_event("guard.allow", {})

        record = dispatcher.get(created.webhook_id)
        assert record is not None
        assert record.failure_count == 1

    def test_high_failure_threshold_marks_failing(self, dispatcher: WebhookDispatcher) -> None:
        import urllib.error

        req = _create_request(max_retries=0)
        created = dispatcher.register(req)

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
            for _ in range(5):
                dispatcher.dispatch_event("guard.allow", {})

        record = dispatcher.get(created.webhook_id)
        assert record is not None
        assert record.status == WebhookStatus.FAILING

    def test_success_resets_failure_count(self, dispatcher: WebhookDispatcher) -> None:
        import urllib.error

        req = _create_request(max_retries=0)
        created = dispatcher.register(req)

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
            dispatcher.dispatch_event("guard.allow", {})

        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = self._make_mock_response(200)
            dispatcher.dispatch_event("guard.allow", {})

        record = dispatcher.get(created.webhook_id)
        assert record is not None
        assert record.failure_count == 0

    def test_delivery_log_recorded_on_success(self, dispatcher: WebhookDispatcher) -> None:
        req = _create_request(max_retries=0)
        created = dispatcher.register(req)

        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = self._make_mock_response(200)
            dispatcher.dispatch_event("guard.allow", {})

        log = dispatcher.get_delivery_log(created.webhook_id)
        assert len(log) == 1
        assert log[0].status == WebhookDeliveryStatus.SUCCESS

    def test_delivery_log_recorded_on_failure(self, dispatcher: WebhookDispatcher) -> None:
        import urllib.error

        req = _create_request(max_retries=0)
        created = dispatcher.register(req)

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
            dispatcher.dispatch_event("guard.allow", {})

        log = dispatcher.get_delivery_log(created.webhook_id)
        assert len(log) == 1
        assert log[0].status == WebhookDeliveryStatus.FAILED

    def test_delivery_log_limit_respected(self, dispatcher: WebhookDispatcher) -> None:
        req = _create_request(max_retries=0)
        created = dispatcher.register(req)

        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = self._make_mock_response(200)
            for _ in range(10):
                dispatcher.dispatch_event("guard.allow", {})

        log = dispatcher.get_delivery_log(created.webhook_id, limit=3)
        assert len(log) == 3

    def test_non_2xx_response_is_failure(self, dispatcher: WebhookDispatcher) -> None:
        req = _create_request(max_retries=0)
        dispatcher.register(req)

        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = self._make_mock_response(500)
            results = dispatcher.dispatch_event("guard.allow", {})

        assert results[0].status == WebhookDeliveryStatus.FAILED

    def test_timeout_error_is_failure(self, dispatcher: WebhookDispatcher) -> None:
        req = _create_request(max_retries=0)
        dispatcher.register(req)

        with patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
            results = dispatcher.dispatch_event("guard.allow", {})

        assert results[0].status == WebhookDeliveryStatus.FAILED
        assert "timed out" in (results[0].error_message or "")

    def test_send_test_returns_test_response(self, dispatcher: WebhookDispatcher) -> None:
        req = _create_request()
        created = dispatcher.register(req)

        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = self._make_mock_response(200)
            result = dispatcher.send_test(created.webhook_id, "guard.allow")

        assert result.webhook_id == created.webhook_id
        assert result.event_type == "guard.allow"
        assert result.delivery_status == WebhookDeliveryStatus.SUCCESS

    def test_send_test_missing_webhook(self, dispatcher: WebhookDispatcher) -> None:
        result = dispatcher.send_test("nonexistent-wh", "guard.allow")
        assert result.delivery_status == WebhookDeliveryStatus.FAILED
        assert result.error_message == "Webhook not found"


# ===========================================================================
# Section 5 — Dead-letter queue
# ===========================================================================


class TestDeadLetterQueue:
    def _make_mock_response(self, status_code: int = 200) -> Any:
        class _Resp:
            status = status_code

            def read(self, n: int) -> bytes:
                return b"ok"

            def __enter__(self) -> _Resp:
                return self

            def __exit__(self, *args: Any) -> None:
                pass

        return _Resp()

    def test_purge_clears_all_entries(self, dispatcher: WebhookDispatcher) -> None:
        import urllib.error

        req = _create_request(max_retries=0)
        dispatcher.register(req)

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
            dispatcher.dispatch_event("guard.allow", {})
            dispatcher.dispatch_event("guard.allow", {})

        count = dispatcher.purge_dead_letter()
        assert count == 2
        assert dispatcher.list_dead_letter() == []

    def test_replay_dead_letter_success(self, dispatcher: WebhookDispatcher) -> None:
        import urllib.error

        req = _create_request(max_retries=0)
        dispatcher.register(req)

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
            dispatcher.dispatch_event("guard.allow", {})

        dlq = dispatcher.list_dead_letter()
        assert len(dlq) == 1
        delivery_id = dlq[0]["delivery_id"]

        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = self._make_mock_response(200)
            result = dispatcher.replay_dead_letter(delivery_id)

        assert result is not None
        assert result.status == WebhookDeliveryStatus.SUCCESS
        assert dispatcher.list_dead_letter() == []

    def test_replay_dead_letter_not_found(self, dispatcher: WebhookDispatcher) -> None:
        result = dispatcher.replay_dead_letter("nonexistent-dlq-id")
        assert result is None

    def test_list_dead_letter_limit(self, dispatcher: WebhookDispatcher) -> None:
        import urllib.error

        req = _create_request(max_retries=0)
        dispatcher.register(req)

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
            for _ in range(5):
                dispatcher.dispatch_event("guard.allow", {})

        entries = dispatcher.list_dead_letter(limit=2)
        assert len(entries) == 2

    def test_dead_letter_entry_fields(self, dispatcher: WebhookDispatcher) -> None:
        import urllib.error

        req = _create_request(max_retries=0)
        created = dispatcher.register(req)

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
            dispatcher.dispatch_event("guard.allow", {})

        entry = dispatcher.list_dead_letter()[0]
        assert "delivery_id" in entry
        assert "webhook_id" in entry
        assert entry["webhook_id"] == created.webhook_id
        assert "event_type" in entry
        assert "payload_hash" in entry
        assert "error_message" in entry
        assert "attempt_count" in entry
        assert "queued_at" in entry


# ===========================================================================
# Section 6 — API route tests
# ===========================================================================


class TestWebhookAPI:
    _PAYLOAD = {
        "name": "api-hook",
        "target_url": _TEST_URL,
        "secret": _TEST_SECRET,
        "event_types": ["guard.allow"],
        "active": True,
        "max_retries": 0,
        "timeout_seconds": 5,
    }

    def _register(self, client: TestClient, overrides: dict | None = None) -> dict:
        payload = {**self._PAYLOAD, **(overrides or {})}
        resp = client.post("/webhooks", json=payload, headers=_AUTH_HEADERS)
        assert resp.status_code == 201, resp.text
        return resp.json()

    def test_register_webhook_201(self, client: TestClient) -> None:
        data = self._register(client)
        assert "webhook_id" in data
        assert data["name"] == "api-hook"
        assert data["active"] is True
        assert data["status"] == "active"

    def test_register_secret_not_in_response(self, client: TestClient) -> None:
        data = self._register(client)
        assert "secret" not in data

    def test_register_http_url_rejected(self, client: TestClient) -> None:
        payload = {**self._PAYLOAD, "target_url": "http://example.com/hook"}
        resp = client.post("/webhooks", json=payload, headers=_AUTH_HEADERS)
        assert resp.status_code == 422

    def test_register_short_secret_rejected(self, client: TestClient) -> None:
        payload = {**self._PAYLOAD, "secret": "short"}
        resp = client.post("/webhooks", json=payload, headers=_AUTH_HEADERS)
        assert resp.status_code == 422

    def test_list_webhooks_empty(self, client: TestClient) -> None:
        resp = client.get("/webhooks", headers=_AUTH_HEADERS)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_webhooks_returns_registered(self, client: TestClient) -> None:
        self._register(client)
        resp = client.get("/webhooks", headers=_AUTH_HEADERS)
        assert resp.status_code == 200
        items = resp.json()
        assert len(items) >= 1

    def test_list_webhooks_filter_active(self, client: TestClient) -> None:
        self._register(client)
        resp = client.get("/webhooks?active=true", headers=_AUTH_HEADERS)
        assert resp.status_code == 200
        assert all(item["active"] for item in resp.json())

    def test_get_webhook_by_id(self, client: TestClient) -> None:
        created = self._register(client)
        resp = client.get(f"/webhooks/{created['webhook_id']}", headers=_AUTH_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["webhook_id"] == created["webhook_id"]

    def test_get_webhook_not_found(self, client: TestClient) -> None:
        resp = client.get("/webhooks/nonexistent-id", headers=_AUTH_HEADERS)
        assert resp.status_code == 404

    def test_update_webhook_name(self, client: TestClient) -> None:
        created = self._register(client)
        resp = client.patch(
            f"/webhooks/{created['webhook_id']}",
            json={"name": "updated-name"},
            headers=_AUTH_HEADERS,
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "updated-name"

    def test_update_webhook_not_found(self, client: TestClient) -> None:
        resp = client.patch(
            "/webhooks/nonexistent-id",
            json={"name": "x"},
            headers=_AUTH_HEADERS,
        )
        assert resp.status_code == 404

    def test_delete_webhook(self, client: TestClient) -> None:
        created = self._register(client)
        resp = client.delete(f"/webhooks/{created['webhook_id']}", headers=_AUTH_HEADERS)
        assert resp.status_code == 204
        resp2 = client.get(f"/webhooks/{created['webhook_id']}", headers=_AUTH_HEADERS)
        assert resp2.status_code == 404

    def test_delete_webhook_not_found(self, client: TestClient) -> None:
        resp = client.delete("/webhooks/nonexistent-id", headers=_AUTH_HEADERS)
        assert resp.status_code == 404

    def test_enable_webhook(self, client: TestClient) -> None:
        created = self._register(client, {"active": False})
        resp = client.post(f"/webhooks/{created['webhook_id']}/enable", headers=_AUTH_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["active"] is True
        assert resp.json()["status"] == "active"

    def test_disable_webhook(self, client: TestClient) -> None:
        created = self._register(client)
        resp = client.post(f"/webhooks/{created['webhook_id']}/disable", headers=_AUTH_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["active"] is False
        assert resp.json()["status"] == "disabled"

    def test_enable_not_found(self, client: TestClient) -> None:
        resp = client.post("/webhooks/ghost-id/enable", headers=_AUTH_HEADERS)
        assert resp.status_code == 404

    def test_disable_not_found(self, client: TestClient) -> None:
        resp = client.post("/webhooks/ghost-id/disable", headers=_AUTH_HEADERS)
        assert resp.status_code == 404

    def test_rotate_secret(self, client: TestClient) -> None:
        created = self._register(client)
        resp = client.post(
            f"/webhooks/{created['webhook_id']}/rotate-secret",
            headers=_AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["webhook_id"] == created["webhook_id"]
        assert "rotated_at" in data
        assert "secret" not in data

    def test_rotate_secret_not_found(self, client: TestClient) -> None:
        resp = client.post("/webhooks/ghost-id/rotate-secret", headers=_AUTH_HEADERS)
        assert resp.status_code == 404

    def test_get_delivery_log_empty(self, client: TestClient) -> None:
        created = self._register(client)
        resp = client.get(f"/webhooks/{created['webhook_id']}/deliveries", headers=_AUTH_HEADERS)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_get_delivery_log_not_found(self, client: TestClient) -> None:
        resp = client.get("/webhooks/ghost-id/deliveries", headers=_AUTH_HEADERS)
        assert resp.status_code == 404

    def test_dead_letter_list_empty(self, client: TestClient) -> None:
        resp = client.get("/webhooks/dead-letter", headers=_AUTH_HEADERS)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_dead_letter_purge(self, client: TestClient) -> None:
        resp = client.delete("/webhooks/dead-letter", headers=_AUTH_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["purged"] == 0

    def test_dead_letter_replay_not_found(self, client: TestClient) -> None:
        resp = client.post("/webhooks/dead-letter/ghost-dlv/replay", headers=_AUTH_HEADERS)
        assert resp.status_code == 404

    def test_test_webhook_endpoint_not_found(self, client: TestClient) -> None:
        resp = client.post("/webhooks/ghost-id/test", headers=_AUTH_HEADERS)
        assert resp.status_code == 404

    def test_test_webhook_endpoint_mocked(self, client: TestClient) -> None:
        created = self._register(client)

        class _MockResp:
            status = 200

            def read(self, n: int) -> bytes:
                return b"ok"

            def __enter__(self) -> _MockResp:
                return self

            def __exit__(self, *args: Any) -> None:
                pass

        with patch("urllib.request.urlopen", return_value=_MockResp()):
            resp = client.post(
                f"/webhooks/{created['webhook_id']}/test",
                headers=_AUTH_HEADERS,
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["webhook_id"] == created["webhook_id"]
        assert data["delivery_status"] == "success"

    def test_dispatch_event_no_subscribers(self, client: TestClient) -> None:
        resp = client.post(
            "/webhooks/dispatch?event_type=guard.allow",
            headers=_AUTH_HEADERS,
        )
        assert resp.status_code == 200
        assert resp.json() == []

    def test_unauthenticated_request_rejected(self, client: TestClient) -> None:
        resp = client.post("/webhooks", json=self._PAYLOAD)
        assert resp.status_code in (401, 403, 422)


# ===========================================================================
# Section 7 — Org scope isolation
# ===========================================================================


class TestOrgScopeIsolation:
    _PAYLOAD = {
        "name": "scoped-hook",
        "target_url": _TEST_URL,
        "secret": _TEST_SECRET,
        "event_types": ["guard.allow"],
        "active": True,
        "max_retries": 0,
    }

    def _headers(self, org: str) -> dict:
        return {"X-API-Key": "test-api-key", "X-Organization-Id": org}

    def test_cross_org_get_forbidden(self, client: TestClient) -> None:
        resp = client.post("/webhooks", json=self._PAYLOAD, headers=self._headers("org-alpha"))
        assert resp.status_code == 201
        webhook_id = resp.json()["webhook_id"]

        resp2 = client.get(f"/webhooks/{webhook_id}", headers=self._headers("org-beta"))
        assert resp2.status_code == 403

    def test_cross_org_update_forbidden(self, client: TestClient) -> None:
        resp = client.post("/webhooks", json=self._PAYLOAD, headers=self._headers("org-alpha"))
        assert resp.status_code == 201
        webhook_id = resp.json()["webhook_id"]

        resp2 = client.patch(
            f"/webhooks/{webhook_id}",
            json={"name": "hijack"},
            headers=self._headers("org-beta"),
        )
        assert resp2.status_code == 403

    def test_cross_org_delete_forbidden(self, client: TestClient) -> None:
        resp = client.post("/webhooks", json=self._PAYLOAD, headers=self._headers("org-alpha"))
        assert resp.status_code == 201
        webhook_id = resp.json()["webhook_id"]

        resp2 = client.delete(f"/webhooks/{webhook_id}", headers=self._headers("org-beta"))
        assert resp2.status_code == 403

    def test_list_returns_only_own_org(self, client: TestClient) -> None:
        client.post("/webhooks", json=self._PAYLOAD, headers=self._headers("org-alpha"))
        client.post(
            "/webhooks",
            json={**self._PAYLOAD, "name": "beta-hook"},
            headers=self._headers("org-beta"),
        )

        resp = client.get("/webhooks", headers=self._headers("org-alpha"))
        assert resp.status_code == 200
        items = resp.json()
        assert all(item["org_id"] == "org-alpha" for item in items)


# ===========================================================================
# Section 8 — Live delivery (real local server)
# ===========================================================================


class TestLiveDelivery:
    def _inject_record(
        self,
        dispatcher: WebhookDispatcher,
        port: int,
        name: str = "live-hook",
    ) -> str:
        from uuid import uuid4

        from app.services.webhook_dispatcher import _utcnow_iso, _WebhookRecord

        now = _utcnow_iso()
        wh_id = f"wh-{uuid4().hex[:16]}"
        internal = _WebhookRecord(
            webhook_id=wh_id,
            name=name,
            target_url=f"http://127.0.0.1:{port}/hook",
            secret=_TEST_SECRET,
            event_types=["guard.allow"],
            org_id=None,
            signing_algorithm="hmac-sha256",
            status="active",
            active=True,
            max_retries=0,
            timeout_seconds=5,
            failure_count=0,
            last_triggered_at=None,
            metadata={},
            created_at=now,
            updated_at=now,
        )
        with dispatcher._lock:
            dispatcher._webhooks[wh_id] = internal
            dispatcher._delivery_log[wh_id] = []
        return wh_id

    def test_live_delivery_receives_post(self, dispatcher: WebhookDispatcher, local_server: Any) -> None:
        _, port = local_server
        wh_id = self._inject_record(dispatcher, port)

        results = dispatcher.dispatch_event("guard.allow", {"probe": True})
        assert len(results) == 1
        assert results[0].status == WebhookDeliveryStatus.SUCCESS

        assert len(_RecordingHandler.received) >= 1
        received = _RecordingHandler.received[-1]
        body = json.loads(received["body"])
        assert body["event_type"] == "guard.allow"
        assert body["webhook_id"] == wh_id
        assert "ironclaw_delivery_id" in body
        assert body["data"]["probe"] is True

    def test_live_delivery_sends_signature_header(self, dispatcher: WebhookDispatcher, local_server: Any) -> None:
        _, port = local_server
        self._inject_record(dispatcher, port, name="sig-hook")

        dispatcher.dispatch_event("guard.allow", {})

        received = _RecordingHandler.received[-1]
        headers = {k.lower(): v for k, v in received["headers"].items()}
        assert "x-ironclaw-signature-256" in headers
        sig = headers["x-ironclaw-signature-256"]
        assert sig.startswith("sha256=")

        expected_sig = _sign_payload(received["body"], _TEST_SECRET, WebhookSigningAlgorithm.HMAC_SHA256)
        assert sig == expected_sig

    def test_live_delivery_sends_required_headers(self, dispatcher: WebhookDispatcher, local_server: Any) -> None:
        _, port = local_server
        self._inject_record(dispatcher, port, name="header-hook")

        dispatcher.dispatch_event("guard.allow", {})

        received = _RecordingHandler.received[-1]
        headers = {k.lower(): v for k, v in received["headers"].items()}
        assert "x-ironclaw-delivery" in headers
        assert "x-ironclaw-event" in headers
        assert headers["x-ironclaw-event"] == "guard.allow"
        assert "user-agent" in headers
        assert "IronClaw-Webhook" in headers["user-agent"]


# ===========================================================================
# Section 9 — Payload envelope integrity
# ===========================================================================


class TestPayloadEnvelope:
    def test_dispatch_sets_delivery_id_in_payload(self, dispatcher: WebhookDispatcher) -> None:
        dispatcher.register(_create_request())

        captured: list[bytes] = []

        class _MockResp:
            status = 200

            def read(self, n: int) -> bytes:
                return b"ok"

            def __enter__(self) -> _MockResp:
                return self

            def __exit__(self, *args: Any) -> None:
                pass

        def _capture(req_obj: Any, timeout: int) -> _MockResp:
            captured.append(req_obj.data)
            return _MockResp()

        with patch("urllib.request.urlopen", side_effect=_capture):
            dispatcher.dispatch_event("guard.allow", {"key": "value"})

        assert len(captured) == 1
        body = json.loads(captured[0])
        assert "ironclaw_delivery_id" in body
        assert body["event_type"] == "guard.allow"
        assert body["data"]["key"] == "value"
        assert "sent_at" in body
        assert "schema_version" in body

    def test_payload_hash_matches_delivered_body(self, dispatcher: WebhookDispatcher) -> None:
        dispatcher.register(_create_request(max_retries=0))

        captured: list[bytes] = []

        class _MockResp:
            status = 200

            def read(self, n: int) -> bytes:
                return b"ok"

            def __enter__(self) -> _MockResp:
                return self

            def __exit__(self, *args: Any) -> None:
                pass

        def _capture(req_obj: Any, timeout: int) -> _MockResp:
            captured.append(req_obj.data)
            return _MockResp()

        with patch("urllib.request.urlopen", side_effect=_capture):
            results = dispatcher.dispatch_event("guard.allow", {})

        assert len(captured) == 1
        expected_hash = _hash_payload(captured[0])
        assert results[0].payload_hash == expected_hash
