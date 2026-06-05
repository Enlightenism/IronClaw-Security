"""tests/test_ui_customer_keys.py

Tests for:
  GET  /customer-keys
  POST /customer-keys
  POST /customer-keys/{key_id}/revoke
"""

from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from app.core.apikeys import APIKeyRegistry, generate_api_key
from app.core.auth import require_api_key

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def registry() -> APIKeyRegistry:
    """Fresh isolated registry for every test."""
    return APIKeyRegistry()


@pytest.fixture()
def client(registry: APIKeyRegistry) -> TestClient:
    import app.api.customer_keys as ck_module
    from app.main import app

    def _override_require_api_key() -> str:
        return "test-token"

    def _override_registry() -> APIKeyRegistry:
        return registry

    app.dependency_overrides[require_api_key] = _override_require_api_key

    original = ck_module.get_api_key_registry
    ck_module.get_api_key_registry = _override_registry  # type: ignore[assignment]

    with TestClient(app, raise_server_exceptions=True) as c:
        yield c

    app.dependency_overrides.pop(require_api_key, None)
    ck_module.get_api_key_registry = original  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_AUTH = {"X-API-Key": "test-token"}
_BASE = "/customer-keys"


def _create(client: TestClient, display_name: str = "Test Key", metadata: dict | None = None) -> dict:
    body: dict = {"display_name": display_name}
    if metadata is not None:
        body["metadata"] = metadata
    resp = client.post(_BASE, json=body, headers=_AUTH)
    assert resp.status_code == 201
    return resp.json()


# ---------------------------------------------------------------------------
# No-auth helpers
# ---------------------------------------------------------------------------


def _patch_singleton(registry: APIKeyRegistry):
    """
    Replaces app.core.apikeys._registry with the provided registry and forces
    auth_required=True on app.state.settings so _is_auth_required() returns
    True regardless of the .env default.
    """
    import app.core.apikeys as apikeys_module
    from app.main import app

    class _Ctx:
        def __enter__(self):
            self._orig_registry = apikeys_module._registry
            apikeys_module._registry = registry

            self._orig_settings = getattr(app.state, "settings", None)
            try:
                from app.core.settings import get_settings

                settings = get_settings().model_copy(update={"auth_required": True})
            except Exception:
                from app.core.settings import Settings

                settings = Settings(auth_required=True)
            app.state.settings = settings
            return self

        def __exit__(self, *_):
            apikeys_module._registry = self._orig_registry
            if self._orig_settings is None:
                try:
                    del app.state.settings
                except AttributeError:
                    pass
            else:
                app.state.settings = self._orig_settings

    return _Ctx()


# ---------------------------------------------------------------------------
# GET /customer-keys
# ---------------------------------------------------------------------------


def test_list_customer_keys_empty_returns_200(client: TestClient) -> None:
    resp = client.get(_BASE, headers=_AUTH)
    assert resp.status_code == 200


def test_list_customer_keys_key_view_shape(client: TestClient) -> None:
    _create(client)
    resp = client.get(_BASE, headers=_AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "service" in data
    assert "timestamp" in data
    assert "total_keys" in data
    assert "keys" in data
    assert isinstance(data["keys"], list)
    assert len(data["keys"]) >= 1
    key = data["keys"][0]
    for field in ("key_id", "display_name", "masked_key", "created_at", "active", "metadata"):
        assert field in key, f"missing field: {field}"


def test_list_customer_keys_content_type_json(client: TestClient) -> None:
    resp = client.get(_BASE, headers=_AUTH)
    assert "application/json" in resp.headers.get("content-type", "")


def test_list_customer_keys_without_auth_returns_401_or_403(registry: APIKeyRegistry) -> None:
    from app.main import app

    registry.create_key("guard-key", api_key=generate_api_key())

    with _patch_singleton(registry):
        app.dependency_overrides.clear()
        with TestClient(app, raise_server_exceptions=False) as c:
            resp = c.get(_BASE)
        assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# POST /customer-keys
# ---------------------------------------------------------------------------


def test_create_customer_key_returns_201(client: TestClient) -> None:
    resp = client.post(_BASE, json={"display_name": "My Key"}, headers=_AUTH)
    assert resp.status_code == 201


def test_create_customer_key_content_type_json(client: TestClient) -> None:
    resp = client.post(_BASE, json={"display_name": "My Key"}, headers=_AUTH)
    assert "application/json" in resp.headers.get("content-type", "")


def test_create_customer_key_top_level_fields(client: TestClient) -> None:
    resp = client.post(_BASE, json={"display_name": "My Key"}, headers=_AUTH)
    data = resp.json()
    for field in ("status", "service", "timestamp", "api_key", "key"):
        assert field in data, f"missing top-level field: {field}"


def test_create_customer_key_key_view_shape(client: TestClient) -> None:
    data = _create(client)
    key = data["key"]
    for field in ("key_id", "display_name", "masked_key", "created_at", "active", "metadata"):
        assert field in key, f"missing key view field: {field}"


def test_create_customer_key_api_key_not_masked(client: TestClient) -> None:
    data = _create(client)
    raw = data["api_key"]
    assert isinstance(raw, str)
    assert "..." not in raw
    assert len(raw) > 10


def test_create_customer_key_display_name_stripped(client: TestClient) -> None:
    data = _create(client, display_name="  Padded Name  ")
    assert data["key"]["display_name"] == "Padded Name"


def test_create_customer_key_with_metadata(client: TestClient) -> None:
    meta = {"env": "staging", "team": "platform"}
    data = _create(client, display_name="Meta Key", metadata=meta)
    assert data["key"]["metadata"]["env"] == "staging"
    assert data["key"]["metadata"]["team"] == "platform"


def test_create_customer_key_appears_in_list(client: TestClient) -> None:
    created = _create(client, display_name="ListCheck")
    key_id = created["key"]["key_id"]
    resp = client.get(_BASE, headers=_AUTH)
    ids = [k["key_id"] for k in resp.json()["keys"]]
    assert key_id in ids


def test_create_multiple_keys_increments_total(client: TestClient) -> None:
    _create(client, display_name="Key One")
    _create(client, display_name="Key Two")
    resp = client.get(_BASE, headers=_AUTH)
    assert resp.json()["total_keys"] >= 2


def test_create_customer_key_active_true(client: TestClient) -> None:
    data = _create(client)
    assert data["key"]["active"] is True


def test_create_customer_key_masked_key_present(client: TestClient) -> None:
    data = _create(client)
    masked = data["key"]["masked_key"]
    assert isinstance(masked, str)
    assert len(masked) > 0


# ---------------------------------------------------------------------------
# POST /customer-keys/{key_id}/revoke
# ---------------------------------------------------------------------------


def test_revoke_customer_key_returns_200(client: TestClient) -> None:
    created = _create(client)
    key_id = created["key"]["key_id"]
    resp = client.post(f"{_BASE}/{key_id}/revoke", headers=_AUTH)
    assert resp.status_code == 200


def test_revoke_customer_key_response_shape(client: TestClient) -> None:
    created = _create(client)
    key_id = created["key"]["key_id"]
    resp = client.post(f"{_BASE}/{key_id}/revoke", headers=_AUTH)
    data = resp.json()
    for field in ("status", "service", "timestamp", "revoked_key_id"):
        assert field in data, f"missing revoke response field: {field}"


def test_revoke_customer_key_marks_key_inactive(client: TestClient, registry: APIKeyRegistry) -> None:
    created = _create(client)
    key_id = created["key"]["key_id"]
    client.post(f"{_BASE}/{key_id}/revoke", headers=_AUTH)
    record = registry.get_by_id(key_id)
    assert record is not None
    assert record.active is False


def test_revoke_customer_key_content_type_json(client: TestClient) -> None:
    created = _create(client)
    key_id = created["key"]["key_id"]
    resp = client.post(f"{_BASE}/{key_id}/revoke", headers=_AUTH)
    assert "application/json" in resp.headers.get("content-type", "")


def test_revoke_customer_key_revoked_key_id_matches(client: TestClient) -> None:
    created = _create(client)
    key_id = created["key"]["key_id"]
    resp = client.post(f"{_BASE}/{key_id}/revoke", headers=_AUTH)
    assert resp.json()["revoked_key_id"] == key_id


def test_revoke_customer_key_without_auth_returns_401_or_403(registry: APIKeyRegistry) -> None:
    from app.main import app

    record = registry.create_key("auth-guard", api_key=generate_api_key())

    with _patch_singleton(registry):
        app.dependency_overrides.clear()
        with TestClient(app, raise_server_exceptions=False) as c:
            resp = c.post(f"{_BASE}/{record.key_id}/revoke")
        assert resp.status_code in (401, 403)
