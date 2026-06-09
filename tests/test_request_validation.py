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

from app.core.settings import get_settings  # noqa: E402
from app.main import app  # noqa: E402
from app.services.audit_log_service import reset_audit_log  # noqa: E402

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


@pytest.fixture()
def bare_client() -> TestClient:
    """Unauthenticated client — no X-API-Key header.

    Settings cache is cleared inside the fixture so auth enforcement is
    evaluated against the current env (AUTH_REQUIRED=true) rather than a
    stale cached value from a prior test.
    """
    get_settings.cache_clear()
    app.state.settings = get_settings()
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _assert_validation_failure(response) -> None:
    assert response.status_code == 422, f"Expected 422 validation error, got {response.status_code}: {response.text}"


def _assert_client_input_failure(response) -> None:
    assert response.status_code in {400, 422}, f"Expected 400 or 422 client input error, got {response.status_code}: {response.text}"


def _assert_auth_rejected(response) -> None:
    assert response.status_code in {401, 403}, f"Expected 401 or 403 auth rejection, got {response.status_code}: {response.text}"


# ===========================================================================
# /api/scan/ — 422 validation paths (authenticated)
# ===========================================================================


def test_scan_rejects_empty_body(client: TestClient) -> None:
    response = client.post("/api/scan/", json={})
    _assert_validation_failure(response)


def test_scan_rejects_wrong_types(client: TestClient) -> None:
    response = client.post(
        "/api/scan/",
        json={
            "target_type": 12345,
            "target_value": ["not", "a", "string"],
        },
    )
    _assert_validation_failure(response)


def test_scan_rejects_invalid_target_type_enum(client: TestClient) -> None:
    response = client.post(
        "/api/scan/",
        json={
            "target_type": "not_a_real_type",
            "target_value": "some value",
        },
    )
    _assert_validation_failure(response)


def test_scan_rejects_empty_target_value(client: TestClient) -> None:
    response = client.post(
        "/api/scan/",
        json={
            "target_type": "prompt",
            "target_value": "",
        },
    )
    _assert_validation_failure(response)


def test_scan_rejects_missing_target_value(client: TestClient) -> None:
    response = client.post(
        "/api/scan/",
        json={"target_type": "prompt"},
    )
    _assert_validation_failure(response)


def test_scan_rejects_missing_target_type(client: TestClient) -> None:
    response = client.post(
        "/api/scan/",
        json={"target_value": "some value"},
    )
    _assert_validation_failure(response)


# ===========================================================================
# /api/scan/batch — 422 validation paths (authenticated)
# ===========================================================================


def test_scan_batch_rejects_empty_body(client: TestClient) -> None:
    response = client.post("/api/scan/batch", json={})
    _assert_validation_failure(response)


def test_scan_batch_rejects_wrong_types(client: TestClient) -> None:
    response = client.post(
        "/api/scan/batch",
        json={"items": "not-a-list"},
    )
    _assert_validation_failure(response)


def test_scan_batch_rejects_empty_items_list(client: TestClient) -> None:
    response = client.post(
        "/api/scan/batch",
        json={"items": []},
    )
    _assert_validation_failure(response)


def test_scan_batch_rejects_invalid_item_in_list(client: TestClient) -> None:
    response = client.post(
        "/api/scan/batch",
        json={"items": [{}]},
    )
    _assert_validation_failure(response)


# ===========================================================================
# /history/{id}/review — 422 validation paths (authenticated)
# ===========================================================================


def test_history_review_rejects_empty_body(client: TestClient) -> None:
    response = client.post("/history/test-scan-id/review", json={})
    _assert_validation_failure(response)


def test_history_review_rejects_wrong_types(client: TestClient) -> None:
    response = client.post(
        "/history/test-scan-id/review",
        json={
            "approved": "yes",
            "reviewer": ["not-a-string"],
            "notes": {"unexpected": "object"},
        },
    )
    _assert_validation_failure(response)


# ===========================================================================
# /policy/guard-bundle — 400/422 validation paths (authenticated)
# ===========================================================================


def test_policy_guard_bundle_rejects_empty_body(client: TestClient) -> None:
    response = client.post("/policy/guard-bundle", json={})
    _assert_client_input_failure(response)


def test_policy_guard_bundle_rejects_all_none_fields(client: TestClient) -> None:
    response = client.post(
        "/policy/guard-bundle",
        json={
            "user_prompt": None,
            "retrieved_doc": None,
            "tool_output": None,
            "model_output": None,
        },
    )
    _assert_client_input_failure(response)


def test_policy_guard_bundle_rejects_whitespace_only_fields(client: TestClient) -> None:
    response = client.post(
        "/policy/guard-bundle",
        json={
            "user_prompt": "   ",
            "retrieved_doc": "  ",
        },
    )
    _assert_client_input_failure(response)


# ===========================================================================
# Auth — unauthenticated requests must be rejected before body validation
# ===========================================================================


def test_scan_unauthenticated_rejected(bare_client: TestClient) -> None:
    response = bare_client.post("/api/scan/", json={})
    _assert_auth_rejected(response)


def test_scan_batch_unauthenticated_rejected(bare_client: TestClient) -> None:
    response = bare_client.post("/api/scan/batch", json={})
    _assert_auth_rejected(response)


def test_policy_guard_bundle_unauthenticated_rejected(bare_client: TestClient) -> None:
    response = bare_client.post("/policy/guard-bundle", json={"user_prompt": "hello"})
    _assert_auth_rejected(response)


def test_history_review_unauthenticated_rejected(bare_client: TestClient) -> None:
    response = bare_client.post("/history/some-id/review", json={"action": "approve"})
    _assert_auth_rejected(response)


def test_scan_invalid_api_key_rejected(bare_client: TestClient) -> None:
    response = bare_client.post(
        "/api/scan/",
        headers={"X-API-Key": "wrong-key"},
        json={},
    )
    _assert_auth_rejected(response)
