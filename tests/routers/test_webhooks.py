from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.core.auth import AuthContext
import app.routers.webhooks as _wh
from app.routers.webhooks import router

# ---------------------------------------------------------------------------
# App fixture
# ---------------------------------------------------------------------------

_app = FastAPI()
_app.include_router(router)

_TENANT_ID = "tenant-abc-123"
_SUB_ID = "sub-00000001-0000-0000-0000-000000000001"
_DELIVERY_ID = "del-00000001-0000-0000-0000-000000000001"

_ANON_AUTH = AuthContext(
    api_key=None,
    principal_type="anonymous",
    principal_id=None,
    session_id=None,
    org_id=_TENANT_ID,
    authenticated=False,
    auth_source="disabled",
    auth_method=None,
)

_AUTH = AuthContext(
    api_key="test-key",
    principal_type="platform",
    principal_id="p-001",
    session_id=None,
    org_id=_TENANT_ID,
    authenticated=True,
    auth_source="configured",
    auth_method="api_key",
)


def _override_auth(ctx: AuthContext = _AUTH):
    from app.core.auth import get_auth_context

    _app.dependency_overrides[get_auth_context] = lambda: ctx


def _clear_overrides():
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


# ---------------------------------------------------------------------------
# Shared mock data
# ---------------------------------------------------------------------------

_NOW = datetime.now(UTC).isoformat()

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

_PERSISTENCE_MODULE = "app.routers.webhooks"


# ---------------------------------------------------------------------------
# POST /webhooks/subscriptions
# ---------------------------------------------------------------------------


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
        for field in ("id", "tenant_id", "target_url", "events", "active", "max_attempts", "created_at"):
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
        from app.core.supabase_persistence import PersistenceError

        with patch(f"{_PERSISTENCE_MODULE}._persist_create_subscription", side_effect=PersistenceError("db down")):
            resp = client.post(self._URL, json=self._PAYLOAD)
        assert resp.status_code == 500

    def test_no_tenant_id_returns_400(self, client: TestClient):
        from app.core.auth import get_auth_context

        no_tenant_auth = AuthContext(
            api_key="test-key",
            principal_type="platform",
            principal_id="p-001",
            session_id=None,
            org_id=None,
            authenticated=True,
            auth_source="configured",
            auth_method="api_key",
        )
        _app.dependency_overrides[get_auth_context] = lambda: no_tenant_auth
        with patch(f"{_PERSISTENCE_MODULE}._persist_create_subscription", return_value=None):
            resp = client.post(self._URL, json=self._PAYLOAD)
        assert resp.status_code == 400

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


# ---------------------------------------------------------------------------
# GET /webhooks/subscriptions
# ---------------------------------------------------------------------------


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

    def test_persistence_error_returns_500(self, client: TestClient):
        from app.core.supabase_persistence import PersistenceError

        with patch(f"{_PERSISTENCE_MODULE}._persist_list_subscriptions", side_effect=PersistenceError("db error")):
            resp = client.get(self._URL)
        assert resp.status_code == 500

    def test_signing_secret_not_in_list_response(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_list_subscriptions", return_value=[_SUB_ROW]):
            resp = client.get(self._URL)
        for item in resp.json()["subscriptions"]:
            assert "signing_secret" not in item


# ---------------------------------------------------------------------------
# GET /webhooks/subscriptions/{subscription_id}
# ---------------------------------------------------------------------------


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

    def test_404_when_not_found(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=None):
            resp = client.get(self._url("nonexistent-id"))
        assert resp.status_code == 404

    def test_404_detail(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=None):
            resp = client.get(self._url("nonexistent-id"))
        assert resp.json()["detail"] == "subscription_not_found"

    def test_persistence_error_returns_500(self, client: TestClient):
        from app.core.supabase_persistence import PersistenceError

        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", side_effect=PersistenceError("db error")):
            resp = client.get(self._url())
        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# PATCH /webhooks/subscriptions/{subscription_id}
# ---------------------------------------------------------------------------


class TestUpdateWebhookSubscription:
    def _url(self, sub_id: str = _SUB_ID) -> str:
        return f"/webhooks/subscriptions/{sub_id}"

    def test_returns_200(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=_SUB_ROW):
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

    def test_secret_hash_not_in_response(self, client: TestClient):
        updated_row = {**_SUB_ROW, "active": False}
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=updated_row):
            with patch(f"{_PERSISTENCE_MODULE}._persist_update_subscription", return_value=None):
                resp = client.patch(self._url(), json={"active": False})
        assert "secret_hash" not in resp.json()

    def test_update_events(self, client: TestClient):
        updated_row = {**_SUB_ROW, "events": ["guard.block"]}
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=updated_row):
            with patch(f"{_PERSISTENCE_MODULE}._persist_update_subscription", return_value=None):
                resp = client.patch(self._url(), json={"events": ["guard.block"]})
        assert resp.status_code == 200

    def test_wildcard_event_rejected_in_update(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=_SUB_ROW):
            resp = client.patch(self._url(), json={"events": ["*"]})
        assert resp.status_code == 422

    def test_persistence_error_on_fetch_returns_500(self, client: TestClient):
        from app.core.supabase_persistence import PersistenceError

        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", side_effect=PersistenceError("db error")):
            resp = client.patch(self._url(), json={"active": False})
        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# DELETE /webhooks/subscriptions/{subscription_id}
# ---------------------------------------------------------------------------


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

    def test_persistence_error_on_delete_returns_500(self, client: TestClient):
        from app.core.supabase_persistence import PersistenceError

        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=_SUB_ROW):
            with patch(f"{_PERSISTENCE_MODULE}._persist_delete_subscription", side_effect=PersistenceError("db error")):
                resp = client.delete(self._url())
        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# POST /webhooks/subscriptions/{subscription_id}/rotate-secret
# ---------------------------------------------------------------------------


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

    def test_persistence_error_returns_500(self, client: TestClient):
        from app.core.supabase_persistence import PersistenceError

        with patch(f"{_PERSISTENCE_MODULE}._persist_get_subscription", return_value=_SUB_ROW):
            with patch(f"{_PERSISTENCE_MODULE}._persist_update_subscription", side_effect=PersistenceError("db error")):
                resp = client.post(self._url())
        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# POST /webhooks/test
# ---------------------------------------------------------------------------


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

    def test_no_subscriptions_returns_zero_dispatched(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}.dispatch_event", return_value=[]):
            resp = client.post(self._URL)
        assert resp.json()["dispatched"] == 0

    def test_dispatch_exception_returns_500(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}.dispatch_event", side_effect=RuntimeError("edge down")):
            resp = client.post(self._URL)
        assert resp.status_code == 500

    def test_no_tenant_id_returns_400(self, client: TestClient):
        from app.core.auth import get_auth_context

        no_tenant_auth = AuthContext(
            api_key="test-key",
            principal_type="platform",
            principal_id="p-001",
            session_id=None,
            org_id=None,
            authenticated=True,
            auth_source="configured",
            auth_method="api_key",
        )
        _app.dependency_overrides[get_auth_context] = lambda: no_tenant_auth
        with patch(f"{_PERSISTENCE_MODULE}.dispatch_event", return_value=[]):
            resp = client.post(self._URL)
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# GET /webhooks/deliveries
# ---------------------------------------------------------------------------


class TestListWebhookDeliveries:
    _URL = "/webhooks/deliveries"

    def test_returns_200(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_log", return_value=[_DELIVERY_ROW]):
            resp = client.get(self._URL)
        assert resp.status_code == 200

    def test_response_shape(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_log", return_value=[_DELIVERY_ROW]):
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

    def test_filter_by_status_forwarded(self, client: TestClient):
        mock = MagicMock(return_value=[])
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_log", mock):
            client.get(self._URL + "?delivery_status=failed")
        _, kwargs = mock.call_args
        assert kwargs.get("delivery_status") == "failed"

    def test_persistence_error_returns_500(self, client: TestClient):
        from app.core.supabase_persistence import PersistenceError

        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_log", side_effect=PersistenceError("db error")):
            resp = client.get(self._URL)
        assert resp.status_code == 500

    def test_no_tenant_id_returns_400(self, client: TestClient):
        from app.core.auth import get_auth_context

        no_tenant_auth = AuthContext(
            api_key="test-key",
            principal_type="platform",
            principal_id="p-001",
            session_id=None,
            org_id=None,
            authenticated=True,
            auth_source="configured",
            auth_method="api_key",
        )
        _app.dependency_overrides[get_auth_context] = lambda: no_tenant_auth
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_log", return_value=[]):
            resp = client.get(self._URL)
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# GET /webhooks/deliveries/retryable
# ---------------------------------------------------------------------------


class TestListRetryableDeliveries:
    _URL = "/webhooks/deliveries/retryable"

    def test_returns_200(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}.list_retryable_deliveries", return_value=[_DELIVERY_ROW]):
            resp = client.get(self._URL)
        assert resp.status_code == 200

    def test_response_shape(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}.list_retryable_deliveries", return_value=[_DELIVERY_ROW]):
            resp = client.get(self._URL)
        body = resp.json()
        assert "count" in body
        assert "deliveries" in body
        assert body["count"] == 1

    def test_empty_list_returns_zero(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}.list_retryable_deliveries", return_value=[]):
            resp = client.get(self._URL)
        assert resp.json()["count"] == 0

    def test_runtime_error_returns_500(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}.list_retryable_deliveries", side_effect=RuntimeError("db down")):
            resp = client.get(self._URL)
        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# POST /webhooks/deliveries/{delivery_id}/retry
# ---------------------------------------------------------------------------


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

    def test_persistence_error_on_fetch_returns_500(self, client: TestClient):
        from app.core.supabase_persistence import PersistenceError

        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_record", side_effect=PersistenceError("db error")):
            resp = client.post(self._url())
        assert resp.status_code == 500

    def test_retry_service_exception_returns_500(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_record", return_value=_DELIVERY_ROW):
            with patch(f"{_PERSISTENCE_MODULE}.retry_failed_delivery", side_effect=RuntimeError("network error")):
                resp = client.post(self._url())
        assert resp.status_code == 500

    def test_response_contains_dispatch_result_fields(self, client: TestClient):
        with patch(f"{_PERSISTENCE_MODULE}._persist_get_delivery_record", return_value=_DELIVERY_ROW):
            with patch(f"{_PERSISTENCE_MODULE}.retry_failed_delivery", return_value=_RETRY_RESULT):
                resp = client.post(self._url())
        body = resp.json()
        for field in ("delivery_id", "subscription_id", "tenant_id", "event_type", "status"):
            assert field in body


# ---------------------------------------------------------------------------
# GET /webhooks/events
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Negative: _get_supabase_client removed — module-level verification
# ---------------------------------------------------------------------------


class TestNoDirectSupabaseClientOnModule:
    def test_get_supabase_client_does_not_exist_on_module(self):
        assert not hasattr(_wh, "_get_supabase_client"), "_get_supabase_client must not exist on app.routers.webhooks — all Supabase access must go through app.core.supabase_persistence"

    def test_get_supabase_service_client_not_imported_directly(self):
        module_globals = vars(_wh)
        assert "get_supabase_service_client" not in module_globals, "get_supabase_service_client must not be imported directly in app.routers.webhooks — use persistence layer only"
