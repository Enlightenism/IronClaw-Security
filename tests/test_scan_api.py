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

from app.api.scan import _rate_limit_buckets  # noqa: E402
from app.core.settings import get_settings  # noqa: E402
from app.dependencies.action_execute import reset_action_execute_pipeline  # noqa: E402
from app.main import app  # noqa: E402
from app.services.audit_log_service import reset_audit_log  # noqa: E402
from app.services.history import reset_scan_history  # noqa: E402
from app.services.review_queue_service import reset_review_queue  # noqa: E402

_VALID_API_KEY = os.environ["IRONCLAW_API_KEY"]
_AUTH_HEADERS = {"X-API-Key": _VALID_API_KEY}

_VALID_VERDICTS = {"allow", "warn", "quarantine", "block"}


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
def _reset_state():
    reset_review_queue()
    reset_action_execute_pipeline()
    reset_audit_log()
    reset_scan_history()
    _rate_limit_buckets.clear()
    yield
    reset_review_queue()
    reset_action_execute_pipeline()
    reset_audit_log()
    reset_scan_history()
    _rate_limit_buckets.clear()


@pytest.fixture()
def client() -> TestClient:
    c = TestClient(app, raise_server_exceptions=True)
    c.headers.update(_AUTH_HEADERS)
    return c


@pytest.fixture()
def bare_client() -> TestClient:
    """Unauthenticated client — no X-API-Key header.

    Cache is cleared so auth enforcement is evaluated against the current
    env (AUTH_REQUIRED=true) rather than a stale cached value.
    """
    get_settings.cache_clear()
    app.state.settings = get_settings()
    return TestClient(app, raise_server_exceptions=False)


# ===========================================================================
# /api/scan/ — 200 success paths
# ===========================================================================


def test_scan_endpoint_basic_ok(client: TestClient) -> None:
    payload = {
        "target_type": "url",
        "target_value": "https://example.com/safe",
        "client_id": "scan-actor-001",
    }
    response = client.post("/api/scan/", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["target_type"] == "url"
    assert data["target_value"] == "https://example.com/safe"
    assert data["client_id"] == "scan-actor-001"
    assert "verdict" in data
    assert data["verdict"] in _VALID_VERDICTS
    assert "scan_id" in data
    assert "risk_score" in data
    assert isinstance(data["risk_score"], int)
    assert 0 <= data["risk_score"] <= 100
    assert "matched_patterns" in data
    assert isinstance(data["matched_patterns"], list)


def test_scan_endpoint_accepts_prompt_target(client: TestClient) -> None:
    payload = {
        "target_type": "prompt",
        "target_value": "Summarize this safe document for me.",
        "client_id": "scan-actor-005",
    }
    response = client.post("/api/scan/", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["target_type"] == "prompt"
    assert data["verdict"] in _VALID_VERDICTS


def test_scan_endpoint_accepts_text_target(client: TestClient) -> None:
    payload = {
        "target_type": "text",
        "target_value": "Some plain text content to scan.",
        "client_id": "scan-actor-006",
    }
    response = client.post("/api/scan/", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["target_type"] == "text"
    assert data["verdict"] in _VALID_VERDICTS


def test_scan_endpoint_accepts_local_path_target(client: TestClient) -> None:
    payload = {
        "target_type": "local_path",
        "target_value": "C:/temp/example.txt",
        "client_id": "scan-actor-002",
    }
    response = client.post("/api/scan/", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["target_type"] == "local_path"
    assert data["target_value"] == "C:/temp/example.txt"
    assert data["client_id"] == "scan-actor-002"


def test_scan_result_persisted_to_history(client: TestClient) -> None:
    payload = {
        "target_type": "url",
        "target_value": "https://example.com/safe",
        "client_id": "scan-actor-001",
    }
    scan_resp = client.post("/api/scan/", json=payload)
    assert scan_resp.status_code == 200
    scan_id = scan_resp.json()["scan_id"]

    history_resp = client.get("/history/")
    assert history_resp.status_code == 200
    history = history_resp.json()
    assert history["count"] >= 1
    assert any(item["scan_id"] == scan_id for item in history["items"])


def test_scan_without_client_id(client: TestClient) -> None:
    payload = {
        "target_type": "prompt",
        "target_value": "Hello, is this safe?",
    }
    response = client.post("/api/scan/", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] in _VALID_VERDICTS


# ===========================================================================
# /api/scan/ — 422 rejection paths
# ===========================================================================


def test_scan_rejects_invalid_target_type_enum(client: TestClient) -> None:
    payload = {
        "target_type": "http_url",
        "target_value": "https://example.com/nope",
        "client_id": "scan-actor-003",
    }
    response = client.post("/api/scan/", json=payload)
    assert response.status_code == 422


def test_scan_rejects_missing_required_fields(client: TestClient) -> None:
    payload = {"client_id": "scan-actor-004"}
    response = client.post("/api/scan/", json=payload)
    assert response.status_code == 422


def test_scan_rejects_empty_target_value(client: TestClient) -> None:
    payload = {
        "target_type": "prompt",
        "target_value": "",
    }
    response = client.post("/api/scan/", json=payload)
    assert response.status_code == 422


# ===========================================================================
# /api/scan/batch — 200 success path
# ===========================================================================


def test_scan_batch_basic_ok(client: TestClient) -> None:
    payload = {
        "items": [
            {
                "target_type": "prompt",
                "target_value": "Safe prompt one.",
                "client_id": "batch-actor-001",
            },
            {
                "target_type": "url",
                "target_value": "https://example.com/batch",
                "client_id": "batch-actor-001",
            },
        ]
    }
    response = client.post("/api/scan/batch", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 2
    assert len(data["items"]) == 2
    for item in data["items"]:
        assert item["verdict"] in _VALID_VERDICTS


# ===========================================================================
# /api/scan/ — auth enforcement
# ===========================================================================


def test_scan_unauthenticated_rejected(bare_client: TestClient) -> None:
    response = bare_client.post(
        "/api/scan/",
        json={"target_type": "prompt", "target_value": "hello"},
    )
    assert response.status_code in (401, 403)


def test_scan_batch_unauthenticated_rejected(bare_client: TestClient) -> None:
    response = bare_client.post(
        "/api/scan/batch",
        json={"items": [{"target_type": "prompt", "target_value": "hello"}]},
    )
    assert response.status_code in (401, 403)


def test_scan_invalid_api_key_rejected(bare_client: TestClient) -> None:
    response = bare_client.post(
        "/api/scan/",
        headers={"X-API-Key": "invalid-key"},
        json={"target_type": "prompt", "target_value": "hello"},
    )
    assert response.status_code in (401, 403)


def test_scan_batch_invalid_api_key_rejected(bare_client: TestClient) -> None:
    response = bare_client.post(
        "/api/scan/batch",
        headers={"X-API-Key": "invalid-key"},
        json={"items": [{"target_type": "prompt", "target_value": "hello"}]},
    )
    assert response.status_code in (401, 403)
