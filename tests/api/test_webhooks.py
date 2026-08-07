from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.api.webhooks import _dispatcher, router
from app.core.auth import get_auth_context
from app.models.webhook import (
    WebhookCreateRequest,
    WebhookEventType,
    WebhookFilterRequest,
    WebhookSigningAlgorithm,
)
from app.services.webhook_dispatcher import reset_webhook_dispatcher

ORG_A = "org-alpha"
ORG_B = "org-bravo"
WEBHOOK_ID = "wh_123"
DELIVERY_ID = "dlv_123"


def _auth_context(*, org_id: str | None) -> SimpleNamespace:
    return SimpleNamespace(org_id=org_id)


def _make_delivery_attempt(
    *,
    webhook_id: str = WEBHOOK_ID,
    delivery_id: str = "att_123",
    event_type: str = str(WebhookEventType.GUARD_ALLOW),
) -> SimpleNamespace:
    return SimpleNamespace(
        attempt_id=delivery_id,
        webhook_id=webhook_id,
        event_type=event_type,
        payload_hash="a" * 64,
        attempt_number=1,
        status="success",
        created_at="2026-07-30T00:00:00Z",
    )


def _make_webhook_response(
    *,
    webhook_id: str = WEBHOOK_ID,
    org_id: str | None = ORG_A,
    active: bool = True,
) -> SimpleNamespace:
    return SimpleNamespace(
        webhook_id=webhook_id,
        name="Primary webhook",
        target_url="https://example.test/webhook",
        event_types=[WebhookEventType.GUARD_ALLOW],
        org_id=org_id,
        signing_algorithm=WebhookSigningAlgorithm.HMAC_SHA256,
        status="active",
        active=active,
        max_retries=3,
        timeout_seconds=30,
        metadata={},
        created_at="2026-07-30T00:00:00Z",
        updated_at="2026-07-30T00:00:00Z",
    )


def _make_webhook_summary(
    *,
    webhook_id: str = WEBHOOK_ID,
    org_id: str | None = ORG_A,
) -> SimpleNamespace:
    return SimpleNamespace(
        webhook_id=webhook_id,
        name="Primary webhook",
        target_url="https://example.test/webhook",
        org_id=org_id,
        status="active",
        active=True,
        failure_count=0,
        event_type_count=1,
        created_at="2026-07-30T00:00:00Z",
    )


def _make_test_response(
    *,
    webhook_id: str = WEBHOOK_ID,
    event_type: str = str(WebhookEventType.GUARD_ALLOW),
) -> SimpleNamespace:
    return SimpleNamespace(
        webhook_id=webhook_id,
        event_type=event_type,
        delivery_status="success",
        delivery=_make_delivery_attempt(webhook_id=webhook_id, event_type=event_type),
    )


def _make_rotate_secret_response(*, webhook_id: str = WEBHOOK_ID) -> SimpleNamespace:
    return SimpleNamespace(
        webhook_id=webhook_id,
        signing_algorithm=WebhookSigningAlgorithm.HMAC_SHA256,
    )


class _StubDispatcher:
    def __init__(self) -> None:
        self.list_dead_letter_calls: list[dict[str, object]] = []
        self.replay_dead_letter_calls: list[dict[str, object]] = []
        self.purge_dead_letter_calls: list[dict[str, object]] = []
        self.list_webhooks_calls: list[WebhookFilterRequest] = []
        self.dispatch_event_calls: list[dict[str, object]] = []
        self.send_test_calls: list[dict[str, object]] = []
        self.rotate_secret_calls: list[tuple[str, str]] = []
        self.get_calls: list[str] = []
        self.register_calls: list[WebhookCreateRequest] = []

        self.list_dead_letter_result: list[dict[str, object]] = []
        self.replay_dead_letter_result: SimpleNamespace | None = None
        self.purge_dead_letter_result: int = 0
        self.list_webhooks_result: list[SimpleNamespace] = []
        self.dispatch_event_result: list[SimpleNamespace] = []
        self.send_test_result: SimpleNamespace | None = None
        self.rotate_secret_result: SimpleNamespace | None = None
        self.get_result: SimpleNamespace | None = None

    def register(self, payload: WebhookCreateRequest) -> SimpleNamespace:
        self.register_calls.append(payload)
        return _make_webhook_response(org_id=payload.org_id)

    def list_webhooks(self, filter_req: WebhookFilterRequest) -> list[SimpleNamespace]:
        self.list_webhooks_calls.append(filter_req)
        return self.list_webhooks_result

    def list_dead_letter(
        self,
        *,
        org_id: str | None = None,
        limit: int = 100,
        allow_global: bool = True,
    ) -> list[dict[str, object]]:
        self.list_dead_letter_calls.append(
            {
                "org_id": org_id,
                "limit": limit,
                "allow_global": allow_global,
            },
        )
        return self.list_dead_letter_result

    def replay_dead_letter(
        self,
        delivery_id: str,
        *,
        org_id: str | None = None,
        allow_global: bool = True,
    ) -> SimpleNamespace | None:
        self.replay_dead_letter_calls.append(
            {
                "delivery_id": delivery_id,
                "org_id": org_id,
                "allow_global": allow_global,
            },
        )
        return self.replay_dead_letter_result

    def purge_dead_letter(
        self,
        *,
        org_id: str | None = None,
        allow_global: bool = True,
    ) -> int:
        self.purge_dead_letter_calls.append(
            {
                "org_id": org_id,
                "allow_global": allow_global,
            },
        )
        return self.purge_dead_letter_result

    def dispatch_event(
        self,
        event_type: str,
        data: dict[str, object],
        *,
        org_id: str | None = None,
    ) -> list[SimpleNamespace]:
        self.dispatch_event_calls.append(
            {
                "event_type": event_type,
                "data": data,
                "org_id": org_id,
            },
        )
        return self.dispatch_event_result

    def get(self, webhook_id: str) -> SimpleNamespace | None:
        self.get_calls.append(webhook_id)
        return self.get_result

    def update(self, webhook_id: str, payload: object) -> SimpleNamespace | None:
        raise NotImplementedError

    def delete(self, webhook_id: str) -> None:
        raise NotImplementedError

    def set_active(self, webhook_id: str, *, active: bool) -> SimpleNamespace | None:
        raise NotImplementedError

    def rotate_secret(self, webhook_id: str, new_secret: str) -> SimpleNamespace | None:
        self.rotate_secret_calls.append((webhook_id, new_secret))
        return self.rotate_secret_result

    def send_test(self, webhook_id: str, event_type: str) -> SimpleNamespace:
        self.send_test_calls.append(
            {
                "webhook_id": webhook_id,
                "event_type": event_type,
            },
        )
        if self.send_test_result is None:
            raise AssertionError("send_test_result must be set in this test")
        return self.send_test_result

    def get_delivery_log(
        self,
        webhook_id: str,
        *,
        limit: int = 50,
    ) -> list[SimpleNamespace]:
        return []


@pytest.fixture(autouse=True)
def _reset_dispatcher_singleton() -> Iterator[None]:
    reset_webhook_dispatcher()
    yield
    reset_webhook_dispatcher()


@pytest.fixture()
def dispatcher() -> _StubDispatcher:
    return _StubDispatcher()


@pytest.fixture()
def app(dispatcher: _StubDispatcher) -> FastAPI:
    test_app = FastAPI()
    test_app.include_router(router)
    test_app.dependency_overrides[_dispatcher] = lambda: dispatcher
    return test_app


def _client_with_org(app: FastAPI, *, org_id: str | None) -> TestClient:
    app.dependency_overrides[get_auth_context] = lambda: _auth_context(org_id=org_id)
    return TestClient(app)


class TestDeadLetterOrgScoping:
    def test_list_dead_letter_is_org_scoped(self, app: FastAPI, dispatcher: _StubDispatcher) -> None:
        dispatcher.list_dead_letter_result = [{"delivery_id": DELIVERY_ID, "org_id": ORG_A}]
        client = _client_with_org(app, org_id=ORG_A)

        response = client.get("/webhooks/dead-letter?limit=25")

        assert response.status_code == 200
        assert response.json() == [{"delivery_id": DELIVERY_ID, "org_id": ORG_A}]
        assert dispatcher.list_dead_letter_calls == [
            {"org_id": ORG_A, "limit": 25, "allow_global": False},
        ]

    def test_list_dead_letter_requires_org_context(self, app: FastAPI, dispatcher: _StubDispatcher) -> None:
        client = _client_with_org(app, org_id=None)

        response = client.get("/webhooks/dead-letter")

        assert response.status_code == 400
        assert response.json()["detail"] == "Organization context is required to list dead-letter entries"
        assert dispatcher.list_dead_letter_calls == []

    def test_replay_dead_letter_is_org_scoped(self, app: FastAPI, dispatcher: _StubDispatcher) -> None:
        dispatcher.replay_dead_letter_result = _make_delivery_attempt(delivery_id=DELIVERY_ID)
        client = _client_with_org(app, org_id=ORG_A)

        response = client.post(f"/webhooks/dead-letter/{DELIVERY_ID}/replay")

        assert response.status_code == 200
        assert response.json()["attempt_id"] == DELIVERY_ID
        assert dispatcher.replay_dead_letter_calls == [
            {
                "delivery_id": DELIVERY_ID,
                "org_id": ORG_A,
                "allow_global": False,
            },
        ]

    def test_replay_dead_letter_does_not_replay_other_org_entry(
        self,
        app: FastAPI,
        dispatcher: _StubDispatcher,
    ) -> None:
        dispatcher.replay_dead_letter_result = None
        client = _client_with_org(app, org_id=ORG_A)

        response = client.post(f"/webhooks/dead-letter/{DELIVERY_ID}/replay")

        assert response.status_code == 404
        assert response.json()["detail"] == f"Dead-letter entry '{DELIVERY_ID}' not found"
        assert dispatcher.replay_dead_letter_calls == [
            {
                "delivery_id": DELIVERY_ID,
                "org_id": ORG_A,
                "allow_global": False,
            },
        ]

    def test_replay_dead_letter_requires_org_context(self, app: FastAPI, dispatcher: _StubDispatcher) -> None:
        client = _client_with_org(app, org_id=None)

        response = client.post(f"/webhooks/dead-letter/{DELIVERY_ID}/replay")

        assert response.status_code == 400
        assert response.json()["detail"] == "Organization context is required to replay dead-letter entries"
        assert dispatcher.replay_dead_letter_calls == []

    def test_purge_dead_letter_is_org_scoped(self, app: FastAPI, dispatcher: _StubDispatcher) -> None:
        dispatcher.purge_dead_letter_result = 3
        client = _client_with_org(app, org_id=ORG_A)

        response = client.delete("/webhooks/dead-letter")

        assert response.status_code == 200
        assert response.json() == {"purged": 3}
        assert dispatcher.purge_dead_letter_calls == [
            {"org_id": ORG_A, "allow_global": False},
        ]

    def test_purge_dead_letter_does_not_purge_other_org_entries(
        self,
        app: FastAPI,
        dispatcher: _StubDispatcher,
    ) -> None:
        dispatcher.purge_dead_letter_result = 0
        client = _client_with_org(app, org_id=ORG_A)

        response = client.delete("/webhooks/dead-letter")

        assert response.status_code == 200
        assert response.json() == {"purged": 0}
        assert dispatcher.purge_dead_letter_calls == [
            {"org_id": ORG_A, "allow_global": False},
        ]

    def test_purge_dead_letter_requires_org_context(self, app: FastAPI, dispatcher: _StubDispatcher) -> None:
        client = _client_with_org(app, org_id=None)

        response = client.delete("/webhooks/dead-letter")

        assert response.status_code == 400
        assert response.json()["detail"] == "Organization context is required to purge dead-letter entries"
        assert dispatcher.purge_dead_letter_calls == []


class TestEventTypeValidation:
    @pytest.mark.parametrize(
        ("path", "method"),
        [
            ("/webhooks?event_type=definitely-not-valid", "get"),
            ("/webhooks/dispatch?event_type=definitely-not-valid", "post"),
            (f"/webhooks/{WEBHOOK_ID}/test?event_type=definitely-not-valid", "post"),
        ],
    )
    def test_invalid_event_type_fails_consistently(
        self,
        app: FastAPI,
        dispatcher: _StubDispatcher,
        path: str,
        method: str,
    ) -> None:
        dispatcher.get_result = _make_webhook_response(webhook_id=WEBHOOK_ID, org_id=ORG_A)
        client = _client_with_org(app, org_id=ORG_A)

        response = getattr(client, method)(path)

        assert response.status_code == 422
        payload = response.json()
        assert payload["detail"]
        assert dispatcher.list_webhooks_calls == []
        assert dispatcher.dispatch_event_calls == []
        assert dispatcher.send_test_calls == []

    def test_list_webhooks_valid_event_type_reaches_dispatcher(
        self,
        app: FastAPI,
        dispatcher: _StubDispatcher,
    ) -> None:
        dispatcher.list_webhooks_result = [_make_webhook_summary()]
        client = _client_with_org(app, org_id=ORG_A)

        response = client.get(f"/webhooks?event_type={WebhookEventType.GUARD_ALLOW}")

        assert response.status_code == 200
        assert len(dispatcher.list_webhooks_calls) == 1
        filter_req = dispatcher.list_webhooks_calls[0]
        assert filter_req.org_id == ORG_A
        assert filter_req.event_type == WebhookEventType.GUARD_ALLOW

    def test_dispatch_valid_event_type_reaches_dispatcher(
        self,
        app: FastAPI,
        dispatcher: _StubDispatcher,
    ) -> None:
        dispatcher.dispatch_event_result = [_make_delivery_attempt()]
        client = _client_with_org(app, org_id=ORG_A)

        response = client.post(
            f"/webhooks/dispatch?event_type={WebhookEventType.GUARD_BLOCK}",
            json={"reason": "policy"},
        )

        assert response.status_code == 200
        assert dispatcher.dispatch_event_calls == [
            {
                "event_type": str(WebhookEventType.GUARD_BLOCK),
                "data": {"reason": "policy"},
                "org_id": ORG_A,
            },
        ]

    def test_test_webhook_valid_event_type_reaches_dispatcher(
        self,
        app: FastAPI,
        dispatcher: _StubDispatcher,
    ) -> None:
        dispatcher.get_result = _make_webhook_response(webhook_id=WEBHOOK_ID, org_id=ORG_A)
        dispatcher.send_test_result = _make_test_response(
            webhook_id=WEBHOOK_ID,
            event_type=str(WebhookEventType.GUARD_ALLOW),
        )
        client = _client_with_org(app, org_id=ORG_A)

        response = client.post(f"/webhooks/{WEBHOOK_ID}/test?event_type={WebhookEventType.GUARD_ALLOW}")

        assert response.status_code == 200
        assert dispatcher.send_test_calls == [
            {
                "webhook_id": WEBHOOK_ID,
                "event_type": str(WebhookEventType.GUARD_ALLOW),
            },
        ]


class TestRotateSecret:
    def test_rotate_secret_returns_metadata_only_and_not_raw_secret(
        self,
        app: FastAPI,
        dispatcher: _StubDispatcher,
    ) -> None:
        dispatcher.get_result = _make_webhook_response(webhook_id=WEBHOOK_ID, org_id=ORG_A)
        dispatcher.rotate_secret_result = _make_rotate_secret_response(webhook_id=WEBHOOK_ID)
        client = _client_with_org(app, org_id=ORG_A)

        response = client.post(f"/webhooks/{WEBHOOK_ID}/rotate-secret")

        assert response.status_code == 200
        payload = response.json()
        assert payload["webhook_id"] == WEBHOOK_ID
        assert payload["signing_algorithm"] == str(WebhookSigningAlgorithm.HMAC_SHA256)
        assert "secret" not in payload
        assert "new_secret" not in payload
        assert len(dispatcher.rotate_secret_calls) == 1
        rotate_webhook_id, generated_secret = dispatcher.rotate_secret_calls[0]
        assert rotate_webhook_id == WEBHOOK_ID
        assert isinstance(generated_secret, str)
        assert len(generated_secret) == 64

    def test_rotate_secret_enforces_org_scope(self, app: FastAPI, dispatcher: _StubDispatcher) -> None:
        dispatcher.get_result = _make_webhook_response(webhook_id=WEBHOOK_ID, org_id=ORG_B)
        client = _client_with_org(app, org_id=ORG_A)

        response = client.post(f"/webhooks/{WEBHOOK_ID}/rotate-secret")

        assert response.status_code == 403
        assert response.json()["detail"] == (f"Webhook '{WEBHOOK_ID}' does not belong to your organization")
        assert dispatcher.rotate_secret_calls == []


class TestRouterOrgScope:
    def test_get_webhook_blocks_cross_org_access(self, app: FastAPI, dispatcher: _StubDispatcher) -> None:
        dispatcher.get_result = _make_webhook_response(webhook_id=WEBHOOK_ID, org_id=ORG_B)
        client = _client_with_org(app, org_id=ORG_A)

        response = client.get(f"/webhooks/{WEBHOOK_ID}")

        assert response.status_code == 403
        assert response.json()["detail"] == (f"Webhook '{WEBHOOK_ID}' does not belong to your organization")

    def test_test_webhook_blocks_cross_org_access(self, app: FastAPI, dispatcher: _StubDispatcher) -> None:
        dispatcher.get_result = _make_webhook_response(webhook_id=WEBHOOK_ID, org_id=ORG_B)
        client = _client_with_org(app, org_id=ORG_A)

        response = client.post(f"/webhooks/{WEBHOOK_ID}/test")

        assert response.status_code == 403
        assert response.json()["detail"] == (f"Webhook '{WEBHOOK_ID}' does not belong to your organization")
        assert dispatcher.send_test_calls == []

    def test_register_webhook_applies_caller_org_when_payload_org_is_missing(
        self,
        app: FastAPI,
        dispatcher: _StubDispatcher,
    ) -> None:
        client = _client_with_org(app, org_id=ORG_A)

        response = client.post(
            "/webhooks",
            json={
                "name": "Primary webhook",
                "target_url": "https://example.test/webhook",
                "secret": "super-secret-value",
                "event_types": [str(WebhookEventType.GUARD_ALLOW)],
            },
        )

        assert response.status_code == 201
        assert response.json()["org_id"] == ORG_A
        assert len(dispatcher.register_calls) == 1
        assert dispatcher.register_calls[0].org_id == ORG_A

    def test_register_webhook_rejects_payload_org_mismatch(
        self,
        app: FastAPI,
        dispatcher: _StubDispatcher,
    ) -> None:
        client = _client_with_org(app, org_id=ORG_A)

        response = client.post(
            "/webhooks",
            json={
                "name": "Primary webhook",
                "target_url": "https://example.test/webhook",
                "secret": "super-secret-value",
                "event_types": [str(WebhookEventType.GUARD_ALLOW)],
                "org_id": ORG_B,
            },
        )

        assert response.status_code == 403
        assert response.json()["detail"] == "Payload org_id does not match your organization context"
        assert dispatcher.register_calls == []
