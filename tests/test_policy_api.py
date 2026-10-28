from __future__ import annotations

import os
from types import SimpleNamespace

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

import app.api.policy as policy_api
from app.config import RISK_THRESHOLD_BLOCK_MIN
from app.core.settings import get_settings
from app.main import app
from app.schemas.policy import PolicyEnforcementMode
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
# /policy/status
# ===========================================================================


def test_policy_status_returns_current_policy_state(client: TestClient) -> None:
    response = client.get("/policy/status")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, dict)
    assert len(data) >= 1


def test_policy_status_unauthenticated_rejected_policy_api() -> None:
    bare = TestClient(app, raise_server_exceptions=True)
    response = bare.get("/policy/status")
    assert response.status_code in (401, 403)


def test_policy_evaluation_maps_non_allow_to_block_and_floors_risk() -> None:
    evaluation = SimpleNamespace(
        final_effect=PolicyEnforcementMode.warn,
        matched_rules=[],
        context=SimpleNamespace(risk_score=0),
        decision="warn",
        mode="enforce",
    )

    result = policy_api._engine_eval_to_schema_result(evaluation)

    assert result.verdict == "block"
    assert result.risk_score >= RISK_THRESHOLD_BLOCK_MIN


# ===========================================================================
# /policy/system-status
# ===========================================================================


def test_system_status_returns_policy_and_review_summary(client: TestClient) -> None:
    response = client.get("/policy/system-status")
    assert response.status_code == 200
    data = response.json()
    assert "policy" in data
    assert "review_summary" in data


def test_system_status_unauthenticated_rejected() -> None:
    bare = TestClient(app, raise_server_exceptions=True)
    response = bare.get("/policy/system-status")
    assert response.status_code in (401, 403)


# ===========================================================================
# /policy/guard-bundle — 200 paths
# ===========================================================================


def test_guard_bundle_accepts_user_prompt(client: TestClient) -> None:
    response = client.post(
        "/policy/guard-bundle",
        json={"user_prompt": "Summarize this safe text"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["highest_verdict"] in {"allow", "block"}
    assert "should_halt" in data
    assert data["should_halt"] is (data["highest_verdict"] == "block")
    assert data["should_warn"] is False


@pytest.mark.parametrize(
    "verdict",
    [PolicyEnforcementMode.warn, PolicyEnforcementMode.quarantine],
)
def test_guard_bundle_maps_legacy_non_allow_verdicts_to_block(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    verdict: PolicyEnforcementMode,
) -> None:
    monkeypatch.setattr(policy_api, "evaluate_policy", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        policy_api,
        "_engine_eval_to_schema_result",
        lambda *args, **kwargs: SimpleNamespace(verdict=verdict, risk_score=17, reasoning="legacy verdict"),
    )

    response = client.post("/policy/guard-bundle", json={"user_prompt": "Safe text"})

    assert response.status_code == 200
    data = response.json()
    assert data["highest_verdict"] == "block"
    assert data["should_halt"] is True
    assert data["should_warn"] is False


def test_guard_bundle_blocks_when_any_field_evaluation_fails(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def evaluate_field(context, *args, **kwargs):
        if context.file_path == "user_prompt":
            raise RuntimeError("evaluation unavailable")
        return None

    monkeypatch.setattr(policy_api, "evaluate_policy", evaluate_field)
    monkeypatch.setattr(
        policy_api,
        "_engine_eval_to_schema_result",
        lambda *args, **kwargs: SimpleNamespace(
            verdict=PolicyEnforcementMode.allow,
            risk_score=0,
            reasoning="allow",
        ),
    )

    response = client.post(
        "/policy/guard-bundle",
        json={"user_prompt": "First field", "retrieved_doc": "Second field"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["highest_verdict"] == "block"
    assert data["should_halt"] is True
    assert data["should_warn"] is False
    assert "policy evaluation failed" in data["reasoning"]


def test_guard_bundle_accepts_retrieved_doc(client: TestClient) -> None:
    response = client.post(
        "/policy/guard-bundle",
        json={"retrieved_doc": "Reference document content"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "highest_verdict" in data


def test_guard_bundle_accepts_tool_output(client: TestClient) -> None:
    response = client.post(
        "/policy/guard-bundle",
        json={"tool_output": "Tool returned safe result"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "highest_verdict" in data


def test_guard_bundle_accepts_model_output(client: TestClient) -> None:
    response = client.post(
        "/policy/guard-bundle",
        json={"model_output": "Model produced safe response"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "highest_verdict" in data


def test_guard_bundle_accepts_all_fields(client: TestClient) -> None:
    response = client.post(
        "/policy/guard-bundle",
        json={
            "user_prompt": "Summarize this safe text",
            "retrieved_doc": "Reference document content",
            "tool_output": "Tool output content",
            "model_output": "Model output content",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["highest_verdict"] in {"allow", "block"}
    assert "should_halt" in data
    assert data["should_halt"] is (data["highest_verdict"] == "block")
    assert data["should_warn"] is False


def test_guard_bundle_accepts_user_prompt_and_retrieved_doc_policy_api(client: TestClient) -> None:
    response = client.post(
        "/policy/guard-bundle",
        json={
            "user_prompt": "Summarize this safe text",
            "retrieved_doc": "Reference document content",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "highest_verdict" in data


# ===========================================================================
# /policy/guard-bundle — 400 paths
# ===========================================================================


def test_guard_bundle_rejects_empty_payload_policy_api(client: TestClient) -> None:
    response = client.post("/policy/guard-bundle", json={})
    assert response.status_code == 400


def test_guard_bundle_rejects_all_none_fields_policy_api(client: TestClient) -> None:
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


def test_guard_bundle_rejects_whitespace_only_fields_policy_api(client: TestClient) -> None:
    response = client.post(
        "/policy/guard-bundle",
        json={
            "user_prompt": "   ",
            "retrieved_doc": "  ",
        },
    )
    assert response.status_code == 400


def test_guard_bundle_unauthenticated_rejected_policy_api() -> None:
    bare = TestClient(app, raise_server_exceptions=True)
    response = bare.post(
        "/policy/guard-bundle",
        json={"user_prompt": "hello"},
    )
    assert response.status_code in (401, 403)


# ===========================================================================
# /policy/status — auth key header casing
# ===========================================================================


def test_policy_endpoint_allows_access_with_api_key(client: TestClient) -> None:
    response = client.get("/policy/status")
    assert response.status_code == 200
