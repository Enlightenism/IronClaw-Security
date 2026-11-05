from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest
import stripe as stripe_lib

from app.core.auth import AuthContext, get_auth_context
from app.core.supabase_persistence import PersistenceError
import app.routers.webhooks as _wh
from app.routers.webhooks import router

_app = FastAPI()
_app.include_router(router)


_TENANT_ID = "tenant-abc-123"
_SUB_ID = "sub-00000001-0000-0000-0000-000000000001"
_DELIVERY_ID = "del-00000001-0000-0000-0000-000000000001"
_NOW = datetime.now(UTC).isoformat()
_PERSISTENCE_MODULE = "app.routers.webhooks"
_STRIPE_URL = "/webhooks/stripe"
_STRIPE_RAW_BODY = b'{"id":"evt_test","type":"payment_intent.created","data":{"object":{}}}'


_AUTH = AuthContext(
    api_key="test-key",
    principal_type="platform",
    principal_id="p-001",
    session_id=None,
    org_id=_TENANT_ID,
    authenticated=True,
    auth_source="configured",
    auth_method="api_key",
    key_type="personal",
    metadata={"header": "X-API-Key", "org_source": "api_key_record"},
)


def _override_auth(ctx: AuthContext = _AUTH) -> None:
    _app.dependency_overrides[get_auth_context] = lambda: ctx


def _clear_overrides() -> None:
    _app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def _inject_auth() -> Generator[None, None, None]:
    _override_auth(_AUTH)
    yield
    _clear_overrides()


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    with TestClient(_app, raise_server_exceptions=False) as c:
        yield c


_SUB_ROW: dict[str, Any] = {
    "id": _SUB_ID,
    "tenant_id": _TENANT_ID,
    "target_url": "https://example.com/hook",
    "events": ["guard.allow"],
    "secret_hash": "deadbeef" * 8,
    "active": True,
    "max_attempts": 5,
    "metadata": {},
    "created_at": _NOW,
}

_DELIVERY_ROW: dict[str, Any] = {
    "id": _DELIVERY_ID,
    "subscription_id": _SUB_ID,
    "tenant_id": _TENANT_ID,
    "event_type": "guard.block",
    "status": "failed",
    "attempts": 2,
    "http_status": 503,
    "error_detail": "upstream timeout",
    "delivered_at": None,
    "next_attempt_at": _NOW,
    "created_at": _NOW,
    "payload_json": "{}",
}

_RETRYABLE_ROW: dict[str, Any] = {
    "id": _DELIVERY_ID,
    "subscription_id": _SUB_ID,
    "tenant_id": _TENANT_ID,
    "event_type": "guard.block",
    "status": "failed",
    "attempts": 2,
    "next_attempt_at": _NOW,
}

_DISPATCH_RESULT = MagicMock()
_DISPATCH_RESULT.to_dict.return_value = {
    "delivery_id": _DELIVERY_ID,
    "subscription_id": _SUB_ID,
    "tenant_id": _TENANT_ID,
    "event_type": "webhook.test",
    "status": "success",
    "http_status": 200,
    "attempts": 1,
    "error_detail": None,
    "delivered_at": _NOW,
}

_RETRY_RESULT = MagicMock()
_RETRY_RESULT.status = MagicMock()
_RETRY_RESULT.status.value = "success"
_RETRY_RESULT.to_dict.return_value = {
    "delivery_id": _DELIVERY_ID,
    "subscription_id": _SUB_ID,
    "tenant_id": _TENANT_ID,
    "event_type": "guard.block",
    "status": "success",
    "http_status": 200,
    "attempts": 3,
    "error_detail": None,
    "delivered_at": _NOW,
}


def _auth_without_tenant() -> AuthContext:
    return AuthContext(
        api_key="test-key",
        principal_type="platform",
        principal_id="p-001",
        session_id=None,
        org_id=None,
        authenticated=True,
        auth_source="configured",
        auth_method="api_key",
        key_type="personal",
        metadata={"header": "X-API-Key", "org_source": "none"},
    )


def _validated_delivery_row() -> dict[str, Any]:
    return {
        "id": _DELIVERY_ID,
        "subscription_id": _SUB_ID,
        "tenant_id": _TENANT_ID,
        "event_type": "guard.block",
        "status": "failed",
        "attempts": 2,
        "http_status": 503,
        "error_detail": "upstream timeout",
        "delivered_at": None,
        "next_attempt_at": _NOW,
        "created_at": _NOW,
    }


class TestCreateWebhookSubscription:
    _URL = "/webhooks/subscriptions"
    _PAYLOAD = {
        "target_url": "https://example.com/hook",
        "events": ["guard.allow"],
        "max_attempts": 5,
        "metadata": {},
    }

    def test_returns_201(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_create_subscription", return_value=None):
            resp = client.post(self._URL, json=self._PAYLOAD)
        assert resp.status_code == 201

    def test_response_contains_signing_secret(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_create_subscription", return_value=None):
            resp = client.post(self._URL, json=self._PAYLOAD)
        body = resp.json()
        assert "signing_secret" in body
        assert len(body["signing_secret"]) == 64

    def test_response_contains_secret_hint(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_create_subscription", return_value=None):
            resp = client.post(self._URL, json=self._PAYLOAD)
        body = resp.json()
        assert "secret_hint" in body
        assert body["secret_hint"].endswith("...")

    def test_secret_hash_not_in_response(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_create_subscription", return_value=None):
            resp = client.post(self._URL, json=self._PAYLOAD)
        assert "secret_hash" not in resp.json()

    def test_response_contains_expected_fields(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_create_subscription", return_value=None):
            resp = client.post(self._URL, json=self._PAYLOAD)
        body = resp.json()
        for field in (
            "id",
            "tenant_id",
            "target_url",
            "events",
            "active",
            "max_attempts",
            "metadata",
            "created_at",
            "secret_hint",
            "signing_secret",
        ):
            assert field in body

    def test_active_defaults_to_true(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_create_subscription", return_value=None):
            resp = client.post(self._URL, json=self._PAYLOAD)
        assert resp.json()["active"] is True

    def test_tenant_id_from_auth_context(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_create_subscription", return_value=None):
            resp = client.post(self._URL, json=self._PAYLOAD)
        assert resp.json()["tenant_id"] == _TENANT_ID

    def test_persistence_error_returns_500(self, client: TestClient):
        with patch(
            f"{_PERSISTENCE_MODULE}._persist_create_subscription",
            side_effect=PersistenceError("db down"),
        ):
            resp = client.post(self._URL, json=self._PAYLOAD)
        assert resp.status_code == 500
        assert resp.json()["detail"] == "subscription_create_failed"

    def test_no_tenant_id_returns_400(self, client: TestClient):
        _override_auth(_auth_without_tenant())
        with patch(f"{_PERSISTENCE_MODULE}._persist_create_subscription", return_value=None):
            resp = client.post(self._URL, json=self._PAYLOAD)
        assert resp.status_code == 400
        assert resp.json()["detail"] == "tenant_id could not be resolved from auth context"

    def test_wildcard_event_rejected(self, client: TestClient):
        payload = {**self._PAYLOAD, "events": ["*"]}
        with patch(f"{_PERSISTENCE_MODULE}._persist_create_subscription", return_value=None):
            resp = client.post(self._URL, json=payload)
        assert resp.status_code == 422

    def test_unknown_event_rejected(self, client: TestClient):
        payload = {**self._PAYLOAD, "events": ["not.a.real.event"]}
        with patch(f"{_PERSISTENCE_MODULE}._persist_create_subscription", return_value=None):
            resp = client.post(self._URL, json=payload)
        assert resp.status_code == 422

    def test_http_url_rejected(self, client: TestClient):
        payload = {**self._PAYLOAD, "target_url": "http://example.com/hook"}
        with patch(f"{_PERSISTENCE_MODULE}._persist_create_subscription", return_value=None):
            resp = client.post(self._URL, json=payload)
        assert resp.status_code == 422


class TestListWebhookSubscriptions:
    _URL = "/webhooks/subscriptions"

    def test_returns_200(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_list_subscriptions", return_value=[_SUB_ROW]):
            resp = client.get(self._URL)
        assert resp.status_code == 200

    def test_response_shape(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_list_subscriptions", return_value=[_SUB_ROW]):
            resp = client.get(self._URL)
        body = resp.json()
        assert "count" in body
        assert "subscriptions" in body
        assert body["count"] == 1

    def test_secret_hash_not_in_any_item(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_list_subscriptions", return_value=[_SUB_ROW]):
            resp = client.get(self._URL)
        for item in resp.json()["subscriptions"]:
            assert "secret_hash" not in item

    def test_empty_returns_count_zero(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_list_subscriptions", return_value=[]):
            resp = client.get(self._URL)
        assert resp.json()["count"] == 0

    def test_active_only_query_param_forwarded(self, client: TestClient):
        mock = MagicMock(return_value=[])
        with patch(f"{_PERSISTENCE_MODULE}._persist_list_subscriptions", mock):
            client.get(self._URL + "?active_only=true")
        _, kwargs = mock.call_args
        assert kwargs.get("active_only") is True

    def test_limit_and_offset_forwarded(self, client: TestClient):
        mock = MagicMock(return_value=[])
        with patch(f"{_PERSISTENCE_MODULE}._persist_list_subscriptions", mock):
            client.get(self._URL + "?limit=25&offset=5")
        _, kwargs = mock.call_args
        assert kwargs.get("limit") == 25
        assert kwargs.get("offset") == 5

    def test_persistence_error_returns_500(self, client: TestClient):
        with patch(
            f"{_PERSISTENCE_MODULE}._persist_list_subscriptions",
            side_effect=PersistenceError("db error"),
        ):
            resp = client.get(self._URL)
        assert resp.status_code == 500
        assert resp.json()["detail"] == "list_failed"

    def test_signing_secret_not_in_list_response(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_list_subscriptions", return_value=[_SUB_ROW]):
            resp = client.get(self._URL)
        for item in resp.json()["subscriptions"]:
            assert "signing_secret" not in item

    def test_secret_hint_present_in_list_response(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_list_subscriptions", return_value=[_SUB_ROW]):
            resp = client.get(self._URL)
        item = resp.json()["subscriptions"][0]
        assert item["secret_hint"] == _SUB_ROW["secret_hash"][:8] + "..."


class TestGetWebhookSubscription:
    def _url(self, sub_id: str = _SUB_ID) -> str:
        return f"/webhooks/subscriptions/{sub_id}"

    def test_returns_200(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=_SUB_ROW):
            resp = client.get(self._url())
        assert resp.status_code == 200

    def test_secret_hash_not_in_response(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=_SUB_ROW):
            resp = client.get(self._url())
        assert "secret_hash" not in resp.json()

    def test_signing_secret_not_in_get_response(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=_SUB_ROW):
            resp = client.get(self._url())
        assert "signing_secret" not in resp.json()

    def test_secret_hint_present(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=_SUB_ROW):
            resp = client.get(self._url())
        assert resp.json()["secret_hint"] == _SUB_ROW["secret_hash"][:8] + "..."

    def test_404_when_not_found(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=None):
            resp = client.get(self._url("nonexistent-id"))
        assert resp.status_code == 404

    def test_404_detail(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=None):
            resp = client.get(self._url("nonexistent-id"))
        assert resp.json()["detail"] == "subscription_not_found"

    def test_persistence_error_returns_500(self, client: TestClient):
        with patch(
            f"{_PERSISTENCE_MODULE}._persist_get_subscription",
            side_effect=PersistenceError("db error"),
        ):
            resp = client.get(self._url())
        assert resp.status_code == 500
        assert resp.json()["detail"] == "fetch_failed"


class TestUpdateWebhookSubscription:
    def _url(self, sub_id: str = _SUB_ID) -> str:
        return f"/webhooks/subscriptions/{sub_id}"

    def test_returns_200(self, client: TestClient):
        with patch(
            f"{_PERSISTENCE_MODULE}._persist_get_subscription",
            side_effect=[_SUB_ROW, {**_SUB_ROW, "active": False}],
        ):
            with patch(f"{_PERSISTENCE_MODULE}._persist_update_subscription", return_value=None):
                resp = client.patch(self._url(), json={"active": False})
        assert resp.status_code == 200

    def test_404_when_subscription_missing(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=None):
            resp = client.patch(self._url("ghost-id"), json={"active": False})
        assert resp.status_code == 404

    def test_empty_payload_returns_existing_unchanged(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=_SUB_ROW):
            with patch(f"{_PERSISTENCE_MODULE}._persist_update_subscription") as mock_update:
                resp = client.patch(self._url(), json={})
        mock_update.assert_not_called()
        assert resp.status_code == 200
        assert resp.json()["id"] == _SUB_ID

    def test_secret_hash_not_in_response(self, client: TestClient):
        updated_row = {**_SUB_ROW, "active": False}
        with patch(
            f"{_PERSISTENCE_MODULE}._persist_get_subscription",
            side_effect=[_SUB_ROW, updated_row],
        ):
            with patch(f"{_PERSISTENCE_MODULE}._persist_update_subscription", return_value=None):
                resp = client.patch(self._url(), json={"active": False})
        assert "secret_hash" not in resp.json()

    def test_update_events(self, client: TestClient):
        updated_row = {**_SUB_ROW, "events": ["guard.block"]}
        with patch(
            f"{_PERSISTENCE_MODULE}._persist_get_subscription",
            side_effect=[_SUB_ROW, updated_row],
        ):
            with patch(f"{_PERSISTENCE_MODULE}._persist_update_subscription", return_value=None):
                resp = client.patch(self._url(), json={"events": ["guard.block"]})
        assert resp.status_code == 200
        assert resp.json()["events"] == ["guard.block"]

    def test_update_forwards_expected_fields(self, client: TestClient):
        updated_row = {
            **_SUB_ROW,
            "active": False,
            "events": ["guard.block"],
            "max_attempts": 7,
            "metadata": {"env": "test"},
        }
        mock_update = MagicMock(return_value=None)
        with patch(
            f"{_PERSISTENCE_MODULE}._persist_get_subscription",
            side_effect=[_SUB_ROW, updated_row],
        ):
            with patch(f"{_PERSISTENCE_MODULE}._persist_update_subscription", mock_update):
                resp = client.patch(
                    self._url(),
                    json={
                        "active": False,
                        "events": ["guard.block"],
                        "max_attempts": 7,
                        "metadata": {"env": "test"},
                    },
                )
        assert resp.status_code == 200
        _, kwargs = mock_update.call_args
        assert kwargs["updates"] == {
            "active": False,
            "events": ["guard.block"],
            "max_attempts": 7,
            "metadata": {"env": "test"},
        }

    def test_wildcard_event_rejected_in_update(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=_SUB_ROW):
            resp = client.patch(self._url(), json={"events": ["*"]})
        assert resp.status_code == 422

    def test_persistence_error_on_fetch_returns_500(self, client: TestClient):
        with patch(
            f"{_PERSISTENCE_MODULE}._persist_get_subscription",
            side_effect=PersistenceError("db error"),
        ):
            resp = client.patch(self._url(), json={"active": False})
        assert resp.status_code == 500
        assert resp.json()["detail"] == "fetch_failed"

    def test_persistence_error_on_update_returns_500(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=_SUB_ROW):
            with patch(
                f"{_PERSISTENCE_MODULE}._persist_update_subscription",
                side_effect=PersistenceError("db error"),
            ):
                resp = client.patch(self._url(), json={"active": False})
        assert resp.status_code == 500
        assert resp.json()["detail"] == "update_failed"

    def test_post_update_fetch_missing_returns_500(self, client: TestClient):
        with patch(
            f"{_PERSISTENCE_MODULE}._persist_get_subscription",
            side_effect=[_SUB_ROW, None],
        ):
            with patch(f"{_PERSISTENCE_MODULE}._persist_update_subscription", return_value=None):
                resp = client.patch(self._url(), json={"active": False})
        assert resp.status_code == 500
        assert resp.json()["detail"] == "post_update_fetch_failed"

    def test_post_update_fetch_error_returns_500(self, client: TestClient):
        with patch(
            f"{_PERSISTENCE_MODULE}._persist_get_subscription",
            side_effect=[_SUB_ROW, PersistenceError("db error")],
        ):
            with patch(f"{_PERSISTENCE_MODULE}._persist_update_subscription", return_value=None):
                resp = client.patch(self._url(), json={"active": False})
        assert resp.status_code == 500
        assert resp.json()["detail"] == "post_update_fetch_failed"


class TestDeleteWebhookSubscription:
    def _url(self, sub_id: str = _SUB_ID) -> str:
        return f"/webhooks/subscriptions/{sub_id}"

    def test_returns_200_with_deleted_true(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=_SUB_ROW):
            with patch(f"{_PERSISTENCE_MODULE}._persist_delete_subscription", return_value=None):
                resp = client.delete(self._url())
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True

    def test_response_contains_id(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=_SUB_ROW):
            with patch(f"{_PERSISTENCE_MODULE}._persist_delete_subscription", return_value=None):
                resp = client.delete(self._url())
        assert resp.json()["id"] == _SUB_ID

    def test_404_when_not_found(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=None):
            resp = client.delete(self._url("ghost-id"))
        assert resp.status_code == 404

    def test_404_detail(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=None):
            resp = client.delete(self._url("ghost-id"))
        assert resp.json()["detail"] == "subscription_not_found"

    def test_persistence_error_on_fetch_returns_500(self, client: TestClient):
        with patch(
            f"{_PERSISTENCE_MODULE}._persist_get_subscription",
            side_effect=PersistenceError("db error"),
        ):
            resp = client.delete(self._url())
        assert resp.status_code == 500
        assert resp.json()["detail"] == "fetch_failed"

    def test_persistence_error_on_delete_returns_500(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=_SUB_ROW):
            with patch(
                f"{_PERSISTENCE_MODULE}._persist_delete_subscription",
                side_effect=PersistenceError("db error"),
            ):
                resp = client.delete(self._url())
        assert resp.status_code == 500
        assert resp.json()["detail"] == "delete_failed"


class TestRotateWebhookSecret:
    def _url(self, sub_id: str = _SUB_ID) -> str:
        return f"/webhooks/subscriptions/{sub_id}/rotate-secret"

    def test_returns_200(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=_SUB_ROW):
            with patch(f"{_PERSISTENCE_MODULE}._persist_update_subscription", return_value=None):
                resp = client.post(self._url())
        assert resp.status_code == 200

    def test_response_contains_signing_secret(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=_SUB_ROW):
            with patch(f"{_PERSISTENCE_MODULE}._persist_update_subscription", return_value=None):
                resp = client.post(self._url())
        body = resp.json()
        assert "signing_secret" in body
        assert len(body["signing_secret"]) == 64

    def test_response_contains_secret_hint(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=_SUB_ROW):
            with patch(f"{_PERSISTENCE_MODULE}._persist_update_subscription", return_value=None):
                resp = client.post(self._url())
        assert resp.json()["secret_hint"].endswith("...")

    def test_response_contains_rotated_at(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=_SUB_ROW):
            with patch(f"{_PERSISTENCE_MODULE}._persist_update_subscription", return_value=None):
                resp = client.post(self._url())
        assert "rotated_at" in resp.json()

    def test_secret_hash_not_in_response(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=_SUB_ROW):
            with patch(f"{_PERSISTENCE_MODULE}._persist_update_subscription", return_value=None):
                resp = client.post(self._url())
        assert "secret_hash" not in resp.json()

    def test_404_when_not_found(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=None):
            resp = client.post(self._url("ghost-id"))
        assert resp.status_code == 404

    def test_rotate_secret_is_different_each_call(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=_SUB_ROW):
            with patch(f"{_PERSISTENCE_MODULE}._persist_update_subscription", return_value=None):
                r1 = client.post(self._url()).json()["signing_secret"]
                r2 = client.post(self._url()).json()["signing_secret"]
        assert r1 != r2

    def test_persistence_error_on_fetch_returns_500(self, client: TestClient):
        with patch(
            f"{_PERSISTENCE_MODULE}._persist_get_subscription",
            side_effect=PersistenceError("db error"),
        ):
            resp = client.post(self._url())
        assert resp.status_code == 500
        assert resp.json()["detail"] == "fetch_failed"

    def test_persistence_error_returns_500(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=_SUB_ROW):
            with patch(
                f"{_PERSISTENCE_MODULE}._persist_update_subscription",
                side_effect=PersistenceError("db error"),
            ):
                resp = client.post(self._url())
        assert resp.status_code == 500
        assert resp.json()["detail"] == "rotate_failed"


class TestWebhookTestDispatch:
    _URL = "/webhooks/test"

    def test_returns_200(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}.dispatch_event", return_value=[_DISPATCH_RESULT]):
            resp = client.post(self._URL)
        assert resp.status_code == 200

    def test_response_shape(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}.dispatch_event", return_value=[_DISPATCH_RESULT]):
            resp = client.post(self._URL)
        body = resp.json()
        assert "dispatched" in body
        assert "results" in body
        assert body["dispatched"] == 1

    def test_dispatch_event_called_with_fire_edge_function_true(self, client: TestClient):
        mock_dispatch = MagicMock(return_value=[_DISPATCH_RESULT])
        with patch(f"{_PERSISTENCE_MODULE}.dispatch_event", mock_dispatch):
            client.post(self._URL)
        args, kwargs = mock_dispatch.call_args
        assert args[0] == _TENANT_ID
        assert args[1] == "webhook.test"
        assert isinstance(args[2], dict)
        assert kwargs["fire_edge_function"] is True

    def test_no_subscriptions_returns_zero_dispatched(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}.dispatch_event", return_value=[]):
            resp = client.post(self._URL)
        assert resp.json()["dispatched"] == 0

    def test_dispatch_exception_returns_500(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}.dispatch_event", side_effect=RuntimeError("edge down")):
            resp = client.post(self._URL)
        assert resp.status_code == 500
        assert resp.json()["detail"] == "dispatch_failed"

    def test_no_tenant_id_returns_400(self, client: TestClient):
        _override_auth(_auth_without_tenant())
        with patch(f"{_PERSISTENCE_MODULE}.dispatch_event", return_value=[]):
            resp = client.post(self._URL)
        assert resp.status_code == 400
        assert resp.json()["detail"] == "tenant_id could not be resolved from auth context"


class TestListWebhookDeliveries:
    _URL = "/webhooks/deliveries"

    def test_returns_200(self, client: TestClient):
        with patch(
            f"{_PERSISTENCE_MODULE}.WebhookDeliveryLogEntry.model_validate",
            side_effect=lambda row: MagicMock(model_dump=lambda: row),
        ):
            with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_log", return_value=[_validated_delivery_row()]):
                resp = client.get(self._URL)
        assert resp.status_code == 200

    def test_response_shape(self, client: TestClient):
        with patch(
            f"{_PERSISTENCE_MODULE}.WebhookDeliveryLogEntry.model_validate",
            side_effect=lambda row: MagicMock(model_dump=lambda: row),
        ):
            with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_log", return_value=[_validated_delivery_row()]):
                resp = client.get(self._URL)
        body = resp.json()
        assert "count" in body
        assert "deliveries" in body
        assert body["count"] == 1

    def test_empty_returns_count_zero(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_log", return_value=[]):
            resp = client.get(self._URL)
        assert resp.json()["count"] == 0

    def test_filter_by_subscription_id_forwarded(self, client: TestClient):
        mock = MagicMock(return_value=[])
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_log", mock):
            client.get(self._URL + f"?subscription_id={_SUB_ID}")
        _, kwargs = mock.call_args
        assert kwargs.get("subscription_id") == _SUB_ID

    def test_filter_by_event_type_forwarded(self, client: TestClient):
        mock = MagicMock(return_value=[])
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_log", mock):
            client.get(self._URL + "?event_type=guard.block")
        _, kwargs = mock.call_args
        assert kwargs.get("event_type") == "guard.block"

    def test_filter_by_status_forwarded(self, client: TestClient):
        mock = MagicMock(return_value=[])
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_log", mock):
            client.get(self._URL + "?delivery_status=failed")
        _, kwargs = mock.call_args
        assert kwargs.get("delivery_status") == "failed"

    def test_limit_and_offset_forwarded(self, client: TestClient):
        mock = MagicMock(return_value=[])
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_log", mock):
            client.get(self._URL + "?limit=25&offset=5")
        _, kwargs = mock.call_args
        assert kwargs.get("limit") == 25
        assert kwargs.get("offset") == 5

    def test_persistence_error_returns_500(self, client: TestClient):
        with patch(
            f"{_PERSISTENCE_MODULE}._persist_get_delivery_log",
            side_effect=PersistenceError("db error"),
        ):
            resp = client.get(self._URL)
        assert resp.status_code == 500
        assert resp.json()["detail"] == "list_failed"

    def test_no_tenant_id_returns_400(self, client: TestClient):
        _override_auth(_auth_without_tenant())
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_log", return_value=[]):
            resp = client.get(self._URL)
        assert resp.status_code == 400
        assert resp.json()["detail"] == "tenant_id could not be resolved from auth context"


class TestListRetryableDeliveries:
    _URL = "/webhooks/deliveries/retryable"

    def test_returns_200(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}.list_retryable_deliveries", return_value=[_RETRYABLE_ROW]):
            resp = client.get(self._URL)
        assert resp.status_code == 200

    def test_response_shape(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}.list_retryable_deliveries", return_value=[_RETRYABLE_ROW]):
            resp = client.get(self._URL)
        body = resp.json()
        assert "count" in body
        assert "deliveries" in body
        assert body["count"] == 1

    def test_empty_list_returns_zero(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}.list_retryable_deliveries", return_value=[]):
            resp = client.get(self._URL)
        assert resp.json()["count"] == 0

    def test_limit_forwarded(self, client: TestClient):
        mock = MagicMock(return_value=[])
        with patch(f"{_PERSISTENCE_MODULE}.list_retryable_deliveries", mock):
            client.get(self._URL + "?limit=12")
        _, kwargs = mock.call_args
        assert kwargs.get("limit") == 12

    def test_runtime_error_returns_500(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}.list_retryable_deliveries", side_effect=RuntimeError("db down")):
            resp = client.get(self._URL)
        assert resp.status_code == 500
        assert resp.json()["detail"] == "list_failed"


class TestRetryWebhookDelivery:
    def _url(self, delivery_id: str = _DELIVERY_ID) -> str:
        return f"/webhooks/deliveries/{delivery_id}/retry"

    def test_returns_200_on_success(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_record", return_value=_DELIVERY_ROW):
            with patch(f"{_PERSISTENCE_MODULE}.retry_failed_delivery", return_value=_RETRY_RESULT):
                resp = client.post(self._url())
        assert resp.status_code == 200

    def test_404_when_delivery_not_found(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_record", return_value=None):
            resp = client.post(self._url("ghost-delivery"))
        assert resp.status_code == 404

    def test_404_detail(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_record", return_value=None):
            resp = client.post(self._url("ghost-delivery"))
        assert resp.json()["detail"] == "delivery_not_found"

    def test_403_on_tenant_mismatch(self, client: TestClient):
        mismatched_row = {**_DELIVERY_ROW, "tenant_id": "other-tenant-999"}
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_record", return_value=mismatched_row):
            resp = client.post(self._url())
        assert resp.status_code == 403

    def test_403_detail(self, client: TestClient):
        mismatched_row = {**_DELIVERY_ROW, "tenant_id": "other-tenant-999"}
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_record", return_value=mismatched_row):
            resp = client.post(self._url())
        assert resp.json()["detail"] == "delivery_not_accessible"

    def test_422_when_status_is_success(self, client: TestClient):
        success_row = {**_DELIVERY_ROW, "status": "success"}
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_record", return_value=success_row):
            resp = client.post(self._url())
        assert resp.status_code == 422

    def test_422_when_status_is_pending(self, client: TestClient):
        pending_row = {**_DELIVERY_ROW, "status": "pending"}
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_record", return_value=pending_row):
            resp = client.post(self._url())
        assert resp.status_code == 422

    def test_retryable_when_status_is_exhausted(self, client: TestClient):
        exhausted_row = {**_DELIVERY_ROW, "status": "exhausted"}
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_record", return_value=exhausted_row):
            with patch(f"{_PERSISTENCE_MODULE}.retry_failed_delivery", return_value=_RETRY_RESULT):
                resp = client.post(self._url())
        assert resp.status_code == 200

    def test_retry_service_receives_expected_values(self, client: TestClient):
        mock_retry = MagicMock(return_value=_RETRY_RESULT)
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_record", return_value=_DELIVERY_ROW):
            with patch(f"{_PERSISTENCE_MODULE}.retry_failed_delivery", mock_retry):
                client.post(self._url())
        _, kwargs = mock_retry.call_args
        assert kwargs == {
            "delivery_id": _DELIVERY_ID,
            "subscription_id": _SUB_ID,
            "tenant_id": _TENANT_ID,
            "event_type": "guard.block",
            "payload_json": "{}",
            "current_attempts": 2,
        }

    def test_persistence_error_on_fetch_returns_500(self, client: TestClient):
        with patch(
            f"{_PERSISTENCE_MODULE}._persist_get_delivery_record",
            side_effect=PersistenceError("db error"),
        ):
            resp = client.post(self._url())
        assert resp.status_code == 500
        assert resp.json()["detail"] == "fetch_failed"

    def test_retry_service_exception_returns_500(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_record", return_value=_DELIVERY_ROW):
            with patch(f"{_PERSISTENCE_MODULE}.retry_failed_delivery", side_effect=RuntimeError("network error")):
                resp = client.post(self._url())
        assert resp.status_code == 500
        assert resp.json()["detail"] == "retry_failed"

    def test_response_contains_dispatch_result_fields(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_record", return_value=_DELIVERY_ROW):
            with patch(f"{_PERSISTENCE_MODULE}.retry_failed_delivery", return_value=_RETRY_RESULT):
                resp = client.post(self._url())
        body = resp.json()
        for field in ("delivery_id", "subscription_id", "tenant_id", "event_type", "status"):
            assert field in body


class TestListSupportedEvents:
    _URL = "/webhooks/events"

    def test_returns_200(self, client: TestClient):
        resp = client.get(self._URL)
        assert resp.status_code == 200

    def test_response_contains_events_list(self, client: TestClient):
        resp = client.get(self._URL)
        body = resp.json()
        assert "events" in body
        assert isinstance(body["events"], list)
        assert len(body["events"]) > 0

    def test_wildcard_not_in_events(self, client: TestClient):
        resp = client.get(self._URL)
        assert "*" not in resp.json()["events"]

    def test_known_event_type_present(self, client: TestClient):
        resp = client.get(self._URL)
        assert "guard.allow" in resp.json()["events"]

    def test_events_are_sorted(self, client: TestClient):
        resp = client.get(self._URL)
        events = resp.json()["events"]
        assert events == sorted(events)


class TestListStripeEventTypes:
    _URL = "/webhooks/stripe/events"

    def test_returns_200(self, client: TestClient):
        resp = client.get(self._URL)
        assert resp.status_code == 200

    def test_response_contains_stripe_events_list(self, client: TestClient):
        resp = client.get(self._URL)
        body = resp.json()
        assert "stripe_events" in body
        assert isinstance(body["stripe_events"], list)

    def test_events_are_sorted(self, client: TestClient):
        resp = client.get(self._URL)
        events = resp.json()["stripe_events"]
        assert events == sorted(events)


class TestNoDirectSupabaseClientOnModule:
    def test_get_supabase_client_does_not_exist_on_module(self):
        assert not hasattr(
            _wh,
            "_get_supabase_client",
        ), "_get_supabase_client must not exist on app.routers.webhooks — all Supabase access must go through app.core.supabase_persistence"

    def test_get_supabase_service_client_not_imported_directly(self):
        module_globals = vars(_wh)
        assert "get_supabase_service_client" not in module_globals, "get_supabase_service_client must not be imported directly in app.routers.webhooks — use persistence layer only"


class TestStripeWebhookReceiver:
    def test_valid_secret_returns_200(self, client: TestClient):
        fake_event = {
            "id": "evt_test_001",
            "type": "payment_intent.created",
            "data": {"object": {}},
        }
        stripe_service = MagicMock()
        _app.dependency_overrides[_wh.get_stripe_service] = lambda: stripe_service
        try:
            with patch(f"{_PERSISTENCE_MODULE}.vault.stripe_webhook_secret", return_value="whsec_testsecret"):
                with patch(f"{_PERSISTENCE_MODULE}.stripe_lib.Webhook.construct_event", return_value=fake_event):
                    resp = client.post(
                        _STRIPE_URL,
                        content=_STRIPE_RAW_BODY,
                        headers={
                            "stripe-signature": "t=1,v1=abc123",
                            "content-type": "application/json",
                        },
                    )
        finally:
            _app.dependency_overrides.pop(_wh.get_stripe_service, None)
        assert resp.status_code == 200
        body = resp.json()
        assert body["received"] is True
        assert body["event_id"] == "evt_test_001"
        assert body["event_type"] == "payment_intent.created"

    def test_missing_vault_secret_returns_400_not_configured(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}.vault.stripe_webhook_secret", return_value=""):
            resp = client.post(
                _STRIPE_URL,
                content=_STRIPE_RAW_BODY,
                headers={
                    "stripe-signature": "t=1,v1=abc123",
                    "content-type": "application/json",
                },
            )
        assert resp.status_code == 400
        assert resp.json()["detail"] == "stripe_webhook_not_configured"

    def test_missing_signature_header_returns_400(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}.vault.stripe_webhook_secret", return_value="whsec_testsecret"):
            resp = client.post(
                _STRIPE_URL,
                content=_STRIPE_RAW_BODY,
                headers={"content-type": "application/json"},
            )
        assert resp.status_code == 400
        assert resp.json()["detail"] == "stripe_webhook_missing_signature"

    def test_empty_body_returns_400(self, client: TestClient):
        resp = client.post(
            _STRIPE_URL,
            content=b"",
            headers={
                "stripe-signature": "t=1,v1=abc123",
                "content-type": "application/json",
            },
        )
        assert resp.status_code == 400
        assert resp.json()["detail"] == "stripe_webhook_empty_body"

    def test_signature_verification_error_returns_400(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}.vault.stripe_webhook_secret", return_value="whsec_testsecret"):
            with patch(
                f"{_PERSISTENCE_MODULE}.stripe_lib.Webhook.construct_event",
                side_effect=stripe_lib.error.SignatureVerificationError(
                    "No signatures found",
                    "t=1,v1=bad",
                ),
            ):
                resp = client.post(
                    _STRIPE_URL,
                    content=_STRIPE_RAW_BODY,
                    headers={
                        "stripe-signature": "t=1,v1=bad",
                        "content-type": "application/json",
                    },
                )
        assert resp.status_code == 400
        assert resp.json()["detail"] == "stripe_webhook_signature_invalid"

    def test_generic_construct_event_error_returns_400(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}.vault.stripe_webhook_secret", return_value="whsec_testsecret"):
            with patch(
                f"{_PERSISTENCE_MODULE}.stripe_lib.Webhook.construct_event",
                side_effect=RuntimeError("boom"),
            ):
                resp = client.post(
                    _STRIPE_URL,
                    content=_STRIPE_RAW_BODY,
                    headers={
                        "stripe-signature": "t=1,v1=bad",
                        "content-type": "application/json",
                    },
                )
        assert resp.status_code == 400
        assert resp.json()["detail"] == "stripe_webhook_signature_invalid"

    def test_checkout_session_completed_calls_fulfill(self, client: TestClient):
        fake_event = {
            "id": "evt_checkout_001",
            "type": "checkout.session.completed",
            "data": {"object": {"id": "cs_test_001", "metadata": {"units": "100"}}},
        }
        stripe_service = MagicMock()
        _app.dependency_overrides[_wh.get_stripe_service] = lambda: stripe_service
        try:
            with patch(f"{_PERSISTENCE_MODULE}.vault.stripe_webhook_secret", return_value="whsec_testsecret"):
                with patch(f"{_PERSISTENCE_MODULE}.stripe_lib.Webhook.construct_event", return_value=fake_event):
                    with patch(f"{_PERSISTENCE_MODULE}._fulfill_checkout_session", return_value=True) as mock_fulfill:
                        resp = client.post(
                            _STRIPE_URL,
                            content=_STRIPE_RAW_BODY,
                            headers={
                                "stripe-signature": "t=1,v1=abc123",
                                "content-type": "application/json",
                            },
                        )
        finally:
            _app.dependency_overrides.pop(_wh.get_stripe_service, None)
        assert resp.status_code == 200
        mock_fulfill.assert_called_once_with(fake_event["data"]["object"])

    def test_dispatchable_event_calls_stripe_service_for_known_runtime_event(self, client: TestClient):
        if not _wh._STRIPE_DISPATCHABLE_EVENTS:
            pytest.skip("No dispatchable Stripe events are defined on the router module.")

        dispatchable_event_type = sorted(_wh._STRIPE_DISPATCHABLE_EVENTS)[0]
        fake_event = {
            "id": "evt_dispatch_001",
            "type": dispatchable_event_type,
            "data": {"object": {}},
        }
        stripe_service = MagicMock()
        _app.dependency_overrides[_wh.get_stripe_service] = lambda: stripe_service
        try:
            with patch(f"{_PERSISTENCE_MODULE}.vault.stripe_webhook_secret", return_value="whsec_testsecret"):
                with patch(f"{_PERSISTENCE_MODULE}.stripe_lib.Webhook.construct_event", return_value=fake_event):
                    resp = client.post(
                        _STRIPE_URL,
                        content=_STRIPE_RAW_BODY,
                        headers={
                            "stripe-signature": "t=1,v1=abc123",
                            "content-type": "application/json",
                        },
                    )
        finally:
            _app.dependency_overrides.pop(_wh.get_stripe_service, None)
        assert resp.status_code == 200
        stripe_service.dispatch_webhook_event.assert_called_once_with(fake_event)

    def test_charge_refunded_event_dispatches_to_stripe_service_and_returns_200(self, client: TestClient):
        fake_event = {
            "id": "evt_refund_router_001",
            "type": "charge.refunded",
            "data": {"object": {"id": "ch_123", "payment_intent": "pi_123", "refunded": True}},
        }
        stripe_service = MagicMock()
        _app.dependency_overrides[_wh.get_stripe_service] = lambda: stripe_service
        try:
            with patch(f"{_PERSISTENCE_MODULE}.vault.stripe_webhook_secret", return_value="whsec_testsecret"):
                with patch(f"{_PERSISTENCE_MODULE}.stripe_lib.Webhook.construct_event", return_value=fake_event):
                    resp = client.post(
                        _STRIPE_URL,
                        content=_STRIPE_RAW_BODY,
                        headers={
                            "stripe-signature": "t=1,v1=abc123",
                            "content-type": "application/json",
                        },
                    )
        finally:
            _app.dependency_overrides.pop(_wh.get_stripe_service, None)
        assert resp.status_code == 200
        stripe_service.dispatch_webhook_event.assert_called_once_with(fake_event)

    def test_dispatch_failure_returns_500_for_known_runtime_event(self, client: TestClient):
        if not _wh._STRIPE_DISPATCHABLE_EVENTS:
            pytest.skip("No dispatchable Stripe events are defined on the router module.")

        dispatchable_event_type = sorted(_wh._STRIPE_DISPATCHABLE_EVENTS)[0]
        fake_event = {
            "id": "evt_dispatch_fail_001",
            "type": dispatchable_event_type,
            "data": {"object": {}},
        }
        stripe_service = MagicMock()
        stripe_service.dispatch_webhook_event.side_effect = RuntimeError("dispatch failed")
        _app.dependency_overrides[_wh.get_stripe_service] = lambda: stripe_service
        try:
            with patch(f"{_PERSISTENCE_MODULE}.vault.stripe_webhook_secret", return_value="whsec_testsecret"):
                with patch(f"{_PERSISTENCE_MODULE}.stripe_lib.Webhook.construct_event", return_value=fake_event):
                    resp = client.post(
                        _STRIPE_URL,
                        content=_STRIPE_RAW_BODY,
                        headers={
                            "stripe-signature": "t=1,v1=abc123",
                            "content-type": "application/json",
                        },
                    )
        finally:
            _app.dependency_overrides.pop(_wh.get_stripe_service, None)
        assert resp.status_code == 500
        assert resp.json()["detail"] == "stripe_webhook_dispatch_failed"

    def test_unrecognised_event_is_acknowledged_without_dispatch(self, client: TestClient):
        fake_event = {
            "id": "evt_unknown_001",
            "type": "totally.unknown",
            "data": {"object": {}},
        }
        stripe_service = MagicMock()
        _app.dependency_overrides[_wh.get_stripe_service] = lambda: stripe_service
        try:
            with patch(f"{_PERSISTENCE_MODULE}.vault.stripe_webhook_secret", return_value="whsec_testsecret"):
                with patch(f"{_PERSISTENCE_MODULE}.stripe_lib.Webhook.construct_event", return_value=fake_event):
                    resp = client.post(
                        _STRIPE_URL,
                        content=_STRIPE_RAW_BODY,
                        headers={
                            "stripe-signature": "t=1,v1=abc123",
                            "content-type": "application/json",
                        },
                    )
        finally:
            _app.dependency_overrides.pop(_wh.get_stripe_service, None)
        assert resp.status_code == 200
        stripe_service.dispatch_webhook_event.assert_not_called()
