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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _assert_has_keys(payload: dict, required_keys: set[str]) -> None:
    missing = required_keys - set(payload.keys())
    assert not missing, f"Missing keys: {sorted(missing)} in payload: {payload}"


# ===========================================================================
# Public routes — no auth required
# ===========================================================================


def test_root_contract(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    assert body, "Root response should not be empty"
    _assert_has_keys(body, {"status"})
    assert body["status"] == "ok"


def test_health_contract(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    _assert_has_keys(body, {"status"})
    assert body["status"] == "ok"


def test_health_liveness_contract(client: TestClient) -> None:
    response = client.get("/health/liveness")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    _assert_has_keys(body, {"status"})


def test_health_readiness_contract(client: TestClient) -> None:
    response = client.get("/health/readiness")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    _assert_has_keys(body, {"status"})


def test_system_status_contract(client: TestClient) -> None:
    response = client.get("/system/status")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    assert body, "System status response should not be empty"


# ===========================================================================
# /policy — protected routes
# ===========================================================================


def test_policy_status_contract(client: TestClient) -> None:
    response = client.get("/policy/status")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    assert body, "Policy status response should not be empty"


def test_policy_status_unauthenticated_rejected() -> None:
    bare = TestClient(app, raise_server_exceptions=True)
    response = bare.get("/policy/status")
    assert response.status_code in (401, 403)


def test_policy_system_status_contract(client: TestClient) -> None:
    response = client.get("/policy/system-status")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    _assert_has_keys(body, {"policy", "review_summary"})
    assert isinstance(body["review_summary"], dict)


def test_policy_system_status_unauthenticated_rejected() -> None:
    bare = TestClient(app, raise_server_exceptions=True)
    response = bare.get("/policy/system-status")
    assert response.status_code in (401, 403)


# ===========================================================================
# /guard — protected routes
# ===========================================================================


def test_guard_reviews_summary_contract(client: TestClient) -> None:
    response = client.get("/guard/reviews/summary")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    assert body, "Summary response should not be empty"


def test_guard_reviews_summary_unauthenticated_rejected() -> None:
    bare = TestClient(app, raise_server_exceptions=True)
    response = bare.get("/guard/reviews/summary")
    assert response.status_code in (401, 403)


def test_pending_reviews_contract(client: TestClient) -> None:
    response = client.get("/guard/reviews/pending")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)


def test_guard_audit_events_contract(client: TestClient) -> None:
    response = client.get("/guard/audit/events")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)


def test_guard_audit_events_unauthenticated_rejected() -> None:
    bare = TestClient(app, raise_server_exceptions=True)
    response = bare.get("/guard/audit/events")
    assert response.status_code in (401, 403)


# ===========================================================================
# /history — protected routes
# ===========================================================================


def test_history_events_contract(client: TestClient) -> None:
    response = client.get("/history/events")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)


def test_history_events_unauthenticated_rejected() -> None:
    bare = TestClient(app, raise_server_exceptions=True)
    response = bare.get("/history/events")
    assert response.status_code in (401, 403)


# ===========================================================================
# /guard/reviews/summary — shape assertions
# ===========================================================================


def test_guard_bundle_contract(client: TestClient) -> None:
    response = client.post(
        "/policy/guard-bundle",
        json={"user_prompt": "safe content for contract test"},
    )
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    _assert_has_keys(body, {"highest_verdict", "should_halt", "should_warn"})
    assert isinstance(body["should_halt"], bool)
    assert isinstance(body["should_warn"], bool)
    assert isinstance(body["highest_verdict"], str)
