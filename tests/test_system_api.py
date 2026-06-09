from __future__ import annotations

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

from app.core.settings import get_settings
from app.main import app
from app.services.audit_log_service import reset_audit_log

_VALID_API_KEY = os.environ["IRONCLAW_API_KEY"]
_AUTH_HEADERS = {"X-API-Key": _VALID_API_KEY}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _refresh_settings():
    get_settings.cache_clear()
    app.state.settings = get_settings()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _reset_audit():
    reset_audit_log()
    yield
    reset_audit_log()


@pytest.fixture()
def client() -> TestClient:
    c = TestClient(app, raise_server_exceptions=True)
    c.headers.update(_AUTH_HEADERS)
    return c


# ===========================================================================
# Public routes — no auth required
# ===========================================================================


def test_root_returns_ok(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_returns_ok(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_liveness_returns_ok(client: TestClient) -> None:
    response = client.get("/health/liveness")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_readiness_returns_ok(client: TestClient) -> None:
    response = client.get("/health/readiness")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_system_status_returns_ok(client: TestClient) -> None:
    response = client.get("/system/status")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    assert body, "System status response should not be empty"


def test_runtime_status_returns_ok(client: TestClient) -> None:
    response = client.get("/runtime/status")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)


# ===========================================================================
# Docs / OpenAPI — optional protected mounts
# install_protected_docs is optional; routes may be 404 in minimal test mode.
# ===========================================================================


def test_redoc_route_is_disabled(client: TestClient) -> None:
    # redoc_url=None in create_app() — always 404
    response = client.get("/redoc")
    assert response.status_code == 404


def test_docs_route_available_or_not_mounted(client: TestClient) -> None:
    # docs_url=None; install_protected_docs mounts /docs if present
    response = client.get("/docs")
    assert response.status_code in (200, 404)
    if response.status_code == 200:
        assert "text/html" in response.headers.get("content-type", "")


def test_openapi_json_available_or_not_mounted(client: TestClient) -> None:
    # openapi_url=None; install_protected_docs mounts /openapi.json if present
    response = client.get("/openapi.json")
    assert response.status_code in (200, 404)
    if response.status_code == 200:
        assert response.headers.get("content-type", "").startswith("application/json")
        body = response.json()
        assert "openapi" in body
        assert "paths" in body


# ===========================================================================
# Auth — unauthenticated requests on protected system routes
# ===========================================================================


def test_policy_status_unauthenticated_rejected() -> None:
    bare = TestClient(app, raise_server_exceptions=True)
    response = bare.get("/policy/status")
    assert response.status_code in (401, 403)


def test_history_events_unauthenticated_rejected() -> None:
    bare = TestClient(app, raise_server_exceptions=True)
    response = bare.get("/history/events")
    assert response.status_code in (401, 403)
