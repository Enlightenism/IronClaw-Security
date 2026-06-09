from __future__ import annotations

from collections.abc import Iterator
import os

from fastapi.testclient import TestClient
import pytest

os.environ["IRONCLAW_PERSISTENCE_MODE"] = "memory"
os.environ["ENVIRONMENT"] = "test"
os.environ["IRONCLAW_API_KEY"] = "test-api-key"
os.environ["AUTH_REQUIRED"] = "true"
os.environ["SUPABASE_URL"] = ""
os.environ["SUPABASE_SERVICE_ROLE_KEY"] = ""
os.environ["SUPABASE_KEY"] = ""
os.environ["SUPABASE_ANON_KEY"] = ""

from app.core.auth import AuthContext, require_auth_context
from app.core.settings import get_settings
from app.main import app
from app.services.audit_log_service import reset_audit_log

_VALID_API_KEY = os.environ["IRONCLAW_API_KEY"]
_AUTH_HEADERS = {"X-API-Key": _VALID_API_KEY}

_REQUIRED_RESPONSE_KEYS = {
    "status",
    "service",
    "timestamp",
    "requested_by",
    "total",
    "active_count",
    "suspended_count",
    "items",
}

_REQUIRED_ITEM_KEYS = {"operator_id", "role", "status", "permissions"}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _refresh_settings() -> Iterator[None]:
    get_settings.cache_clear()
    app.state.settings = get_settings()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _reset_audit() -> Iterator[None]:
    reset_audit_log()
    yield
    reset_audit_log()


@pytest.fixture()
def client() -> TestClient:
    c = TestClient(app, raise_server_exceptions=True)
    c.headers.update(_AUTH_HEADERS)
    return c


@pytest.fixture()
def client_with_principal() -> Iterator[TestClient]:
    """Client whose auth context carries a known principal_id."""

    def _override_context() -> AuthContext:
        return AuthContext(
            api_key=_VALID_API_KEY,
            principal_type="api_key",
            principal_id="test-principal-001",
            session_id=None,
            org_id=None,
            authenticated=True,
            auth_source="test",
            auth_method="test_override",
        )

    app.dependency_overrides[require_auth_context] = _override_context
    c = TestClient(app, raise_server_exceptions=True)
    c.headers.update(_AUTH_HEADERS)
    yield c
    app.dependency_overrides.pop(require_auth_context, None)


# ===========================================================================
# /ui/admin/operators — auth
# ===========================================================================


def test_operators_unauthenticated_rejected() -> None:
    bare = TestClient(app, raise_server_exceptions=True)
    response = bare.get("/ui/admin/operators")
    assert response.status_code in (401, 403)


def test_operators_valid_key_accepted(client: TestClient) -> None:
    response = client.get("/ui/admin/operators")
    assert response.status_code == 200


# ===========================================================================
# Response shape
# ===========================================================================


def test_operators_response_shape(client: TestClient) -> None:
    response = client.get("/ui/admin/operators")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, dict)
    missing = _REQUIRED_RESPONSE_KEYS - set(data.keys())
    assert not missing, f"Missing response keys: {sorted(missing)}"


def test_operators_response_field_types(client: TestClient) -> None:
    response = client.get("/ui/admin/operators")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "IronClaw-Security"
    assert isinstance(data["timestamp"], str)
    assert isinstance(data["requested_by"], str)
    assert isinstance(data["total"], int)
    assert isinstance(data["active_count"], int)
    assert isinstance(data["suspended_count"], int)
    assert isinstance(data["items"], list)


def test_operators_counts_consistent(client: TestClient) -> None:
    response = client.get("/ui/admin/operators")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == len(data["items"])
    active = sum(1 for i in data["items"] if i["status"] == "active")
    suspended = sum(1 for i in data["items"] if i["status"] == "suspended")
    assert data["active_count"] == active
    assert data["suspended_count"] == suspended


# ===========================================================================
# Items list
# ===========================================================================


def test_operators_items_list_non_empty(client: TestClient) -> None:
    response = client.get("/ui/admin/operators")
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) > 0, "Expected at least one operator item"


def test_operators_each_item_has_required_fields(client: TestClient) -> None:
    response = client.get("/ui/admin/operators")
    assert response.status_code == 200
    data = response.json()
    for item in data["items"]:
        missing = _REQUIRED_ITEM_KEYS - set(item.keys())
        assert not missing, f"Operator item missing keys: {sorted(missing)} in {item}"


def test_operators_each_item_permissions_is_list(client: TestClient) -> None:
    response = client.get("/ui/admin/operators")
    assert response.status_code == 200
    data = response.json()
    for item in data["items"]:
        assert isinstance(item["permissions"], list), f"permissions must be a list, got {type(item['permissions'])} " f"for {item['operator_id']}"


def test_operators_each_permission_has_required_fields(client: TestClient) -> None:
    response = client.get("/ui/admin/operators")
    assert response.status_code == 200
    data = response.json()
    for item in data["items"]:
        for perm in item["permissions"]:
            assert "key" in perm
            assert "label" in perm
            assert "enabled" in perm
            assert isinstance(perm["enabled"], bool)


# ===========================================================================
# requested_by reflects context.principal_id
# ===========================================================================


def test_requested_by_reflects_principal_id(
    client_with_principal: TestClient,
) -> None:
    response = client_with_principal.get("/ui/admin/operators")
    assert response.status_code == 200
    data = response.json()
    assert data["requested_by"] == "test-principal-001"


def test_requested_by_falls_back_to_query_param(client: TestClient) -> None:
    response = client.get("/ui/admin/operators?requested_by=custom-caller")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data["requested_by"], str)
    assert len(data["requested_by"]) > 0
