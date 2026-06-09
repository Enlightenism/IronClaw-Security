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
# 200 — single-field paths
# ===========================================================================


def test_guard_bundle_accepts_user_prompt_only(client: TestClient) -> None:
    response = client.post(
        "/policy/guard-bundle",
        json={"user_prompt": "Summarize this safe content for the user."},
    )
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, dict)
    assert "highest_verdict" in data
    assert "should_halt" in data
    assert "should_warn" in data


def test_guard_bundle_accepts_retrieved_doc_only(client: TestClient) -> None:
    response = client.post(
        "/policy/guard-bundle",
        json={"retrieved_doc": "Reference material content."},
    )
    assert response.status_code == 200
    data = response.json()
    assert "highest_verdict" in data


def test_guard_bundle_accepts_tool_output_only(client: TestClient) -> None:
    response = client.post(
        "/policy/guard-bundle",
        json={"tool_output": "Tool returned a harmless response."},
    )
    assert response.status_code == 200
    data = response.json()
    assert "highest_verdict" in data


def test_guard_bundle_accepts_model_output_only(client: TestClient) -> None:
    response = client.post(
        "/policy/guard-bundle",
        json={"model_output": "Draft assistant response."},
    )
    assert response.status_code == 200
    data = response.json()
    assert "highest_verdict" in data


# ===========================================================================
# 200 — multi-source payload
# ===========================================================================


def test_guard_bundle_accepts_multi_source_payload(client: TestClient) -> None:
    response = client.post(
        "/policy/guard-bundle",
        json={
            "user_prompt": "Please review this result.",
            "retrieved_doc": "Reference material content.",
            "tool_output": "Tool returned a harmless response.",
            "model_output": "Draft assistant response.",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, dict)
    assert "highest_verdict" in data
    assert "user_prompt" in data


def test_guard_bundle_accepts_user_prompt_and_retrieved_doc(client: TestClient) -> None:
    response = client.post(
        "/policy/guard-bundle",
        json={
            "user_prompt": "Hello world",
            "retrieved_doc": "Supporting context here.",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "highest_verdict" in data


# ===========================================================================
# 200 — response shape
# ===========================================================================


def test_guard_bundle_response_shape(client: TestClient) -> None:
    response = client.post(
        "/policy/guard-bundle",
        json={"user_prompt": "Hello world"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "highest_verdict" in data
    assert "should_halt" in data
    assert "should_warn" in data
    assert isinstance(data["should_halt"], bool)
    assert isinstance(data["should_warn"], bool)
    assert isinstance(data["highest_verdict"], str)


# ===========================================================================
# 400 — rejection paths
# ===========================================================================


def test_guard_bundle_rejects_empty_payload(client: TestClient) -> None:
    response = client.post("/policy/guard-bundle", json={})
    assert response.status_code == 400


def test_guard_bundle_rejects_all_none_fields(client: TestClient) -> None:
    response = client.post(
        "/policy/guard-bundle",
        json={
            "user_prompt": None,
            "retrieved_doc": None,
            "tool_output": None,
            "model_output": None,
        },
    )
    assert response.status_code == 400


def test_guard_bundle_rejects_whitespace_only_fields(client: TestClient) -> None:
    response = client.post(
        "/policy/guard-bundle",
        json={
            "user_prompt": "   ",
            "retrieved_doc": "  ",
            "tool_output": "\t",
            "model_output": "\n",
        },
    )
    assert response.status_code == 400


# ===========================================================================
# Auth
# ===========================================================================


def test_guard_bundle_unauthenticated_rejected() -> None:
    bare = TestClient(app, raise_server_exceptions=True)
    response = bare.post(
        "/policy/guard-bundle",
        json={"user_prompt": "Hello world"},
    )
    assert response.status_code in (401, 403)


def test_guard_bundle_allows_access_with_api_key(client: TestClient) -> None:
    response = client.post(
        "/policy/guard-bundle",
        json={"user_prompt": "Hello world"},
    )
    assert response.status_code == 200
