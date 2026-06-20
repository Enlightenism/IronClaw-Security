from __future__ import annotations

from collections.abc import Generator
import os

from fastapi.testclient import TestClient
import pytest

from app.core.auth import AuthContext, require_auth_context
from app.main import app as _app

_TEST_AUTH_CONTEXT = AuthContext(
    api_key="test-api-key",
    principal_type="api_key",
    principal_id="test-principal",
    session_id=None,
    org_id="test-org",
    permissions=(),
    roles=(),
    authenticated=True,
    auth_source="test",
    auth_method="api_key",
)


def _override_auth() -> AuthContext:
    return _TEST_AUTH_CONTEXT


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    _app.dependency_overrides[require_auth_context] = _override_auth
    with TestClient(_app, raise_server_exceptions=True) as c:
        c.headers.update({"X-API-Key": os.environ.get("IRONCLAW_API_KEY", "test-api-key")})
        yield c
    _app.dependency_overrides.pop(require_auth_context, None)


def test_ui_customer_keys_route_is_registered(client: TestClient) -> None:
    response = client.get("/ui/customer-keys")
    assert response.status_code == 200


def test_ui_customer_keys_returns_json_object(client: TestClient) -> None:
    response = client.get("/ui/customer-keys")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)


def test_ui_customer_keys_contains_core_fields(client: TestClient) -> None:
    response = client.get("/ui/customer-keys")
    assert response.status_code == 200

    data = response.json()
    assert data

    assert any(k in data for k in ("title", "headline", "summary", "page_title"))
    assert any(k in data for k in ("keys", "items", "rows", "records", "customers", "entries"))
    assert any(k in data for k in ("actions", "filters", "status", "sections", "policies", "columns"))
