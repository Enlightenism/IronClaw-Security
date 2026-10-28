from __future__ import annotations

from collections.abc import Generator
import os
from typing import Any
from unittest.mock import MagicMock, patch

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
import pytest

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("IRONCLAW_API_KEY", "test-api-key")
os.environ.setdefault("AUTH_REQUIRED", "true")
os.environ.setdefault("IRONCLAW_RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "")
os.environ.setdefault("SUPABASE_KEY", "")
os.environ.setdefault("SUPABASE_ANON_KEY", "")

import app.api.routes.guard as _guard_module
from app.api.routes.guard import router as guard_router
from app.config import RISK_THRESHOLD_BLOCK_MIN
from app.core.auth import require_api_key
from app.core.errors import AppError

# ---------------------------------------------------------------------------
# Isolated app — AppError handler mirrors app.main behavior
# ---------------------------------------------------------------------------

_isolated_app = FastAPI()
_isolated_app.include_router(guard_router)


@_isolated_app.exception_handler(AppError)
async def _app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message},
    )


def _allow_api_key() -> str:
    return "test-api-key"


def _deny_api_key() -> None:
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing API key — provide X-API-Key or Bearer token",
    )


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    _isolated_app.dependency_overrides[require_api_key] = _allow_api_key
    with TestClient(_isolated_app, raise_server_exceptions=False) as c:
        c.headers.update({"X-API-Key": "test-api-key"})
        yield c
    _isolated_app.dependency_overrides.pop(require_api_key, None)


@pytest.fixture()
def unauthed_client() -> Generator[TestClient, None, None]:
    _isolated_app.dependency_overrides.pop(require_api_key, None)
    with TestClient(_isolated_app, raise_server_exceptions=False) as c:
        yield c
    _isolated_app.dependency_overrides.pop(require_api_key, None)


# ---------------------------------------------------------------------------
# Shared payloads
# ---------------------------------------------------------------------------

_ACTION_DECISION_PAYLOAD: dict[str, Any] = {
    "action_type": "file_read",
    "target": "/etc/passwd",
    "content": "read file contents",
    "client_id": "test-client",
    "session_id": "test-session",
    "file_path": None,
    "metadata": {},
}

_EXECUTE_PAYLOAD: dict[str, Any] = {
    "action_type": "file_write",
    "target": "/tmp/output.txt",
    "content": "write data",
    "risk_score": 30,
    "client_id": "test-client",
    "session_id": "test-session",
    "file_path": "/tmp/output.txt",
    "metadata": {},
}

_MOCK_TOOL_DECISION: dict[str, Any] = {
    "verdict": "allow",
    "risk_score": 10,
    "should_halt": False,
    "summary": "No threats detected.",
    "decision_source": "action_decision_service",
    "matched_patterns": [],
}

_MOCK_TOOL_DECISION_BLOCK: dict[str, Any] = {
    "verdict": "block",
    "risk_score": 95,
    "should_halt": True,
    "summary": "High-risk path detected.",
    "decision_source": "action_decision_service",
    "matched_patterns": ["path_traversal"],
}


def _make_policy_decision(
    verdict: str = "allow",
    risk_score: int = 10,
    risk_level: str = "low",
    allow_execution: bool = True,
    requires_review: bool = False,
    matched_rules: list | None = None,
    reasons: list[str] | None = None,
) -> MagicMock:
    decision = MagicMock()
    decision.decision_id = "dec-test-001"
    decision.verdict = verdict
    decision.risk_score = risk_score
    decision.risk_level = risk_level
    decision.allow_execution = allow_execution
    decision.requires_review = requires_review
    decision.matched_rules = matched_rules or []
    decision.reasons = reasons or []
    return decision


# ---------------------------------------------------------------------------
# POST /guard/action-decision — response shape
# ---------------------------------------------------------------------------


class TestActionDecisionShape:
    def test_returns_200_on_allow(self, client: TestClient) -> None:
        with patch.object(_guard_module, "evaluate_action_execution", return_value=_MOCK_TOOL_DECISION):
            resp = client.post("/guard/action-decision", json=_ACTION_DECISION_PAYLOAD)
        assert resp.status_code == 200

    def test_response_contains_trace_id(self, client: TestClient) -> None:
        with patch.object(_guard_module, "evaluate_action_execution", return_value=_MOCK_TOOL_DECISION):
            resp = client.post("/guard/action-decision", json=_ACTION_DECISION_PAYLOAD)
        data = resp.json()
        assert "trace_id" in data
        assert data["trace_id"].startswith("trace-")

    def test_response_contains_verdict(self, client: TestClient) -> None:
        with patch.object(_guard_module, "evaluate_action_execution", return_value=_MOCK_TOOL_DECISION):
            resp = client.post("/guard/action-decision", json=_ACTION_DECISION_PAYLOAD)
        assert resp.json()["verdict"] == "allow"

    def test_response_contains_risk_score(self, client: TestClient) -> None:
        with patch.object(_guard_module, "evaluate_action_execution", return_value=_MOCK_TOOL_DECISION):
            resp = client.post("/guard/action-decision", json=_ACTION_DECISION_PAYLOAD)
        assert resp.json()["risk_score"] == 10

    def test_response_risk_score_is_int(self, client: TestClient) -> None:
        with patch.object(_guard_module, "evaluate_action_execution", return_value=_MOCK_TOOL_DECISION):
            resp = client.post("/guard/action-decision", json=_ACTION_DECISION_PAYLOAD)
        assert isinstance(resp.json()["risk_score"], int)

    def test_response_contains_should_halt(self, client: TestClient) -> None:
        with patch.object(_guard_module, "evaluate_action_execution", return_value=_MOCK_TOOL_DECISION):
            resp = client.post("/guard/action-decision", json=_ACTION_DECISION_PAYLOAD)
        assert resp.json()["should_halt"] is False

    def test_response_should_halt_is_bool(self, client: TestClient) -> None:
        with patch.object(_guard_module, "evaluate_action_execution", return_value=_MOCK_TOOL_DECISION):
            resp = client.post("/guard/action-decision", json=_ACTION_DECISION_PAYLOAD)
        assert isinstance(resp.json()["should_halt"], bool)

    def test_response_contains_summary(self, client: TestClient) -> None:
        with patch.object(_guard_module, "evaluate_action_execution", return_value=_MOCK_TOOL_DECISION):
            resp = client.post("/guard/action-decision", json=_ACTION_DECISION_PAYLOAD)
        assert "summary" in resp.json()

    def test_response_contains_decision_source(self, client: TestClient) -> None:
        with patch.object(_guard_module, "evaluate_action_execution", return_value=_MOCK_TOOL_DECISION):
            resp = client.post("/guard/action-decision", json=_ACTION_DECISION_PAYLOAD)
        assert resp.json()["decision_source"] == "action_decision_service"

    def test_response_contains_matched_patterns_list(self, client: TestClient) -> None:
        with patch.object(_guard_module, "evaluate_action_execution", return_value=_MOCK_TOOL_DECISION):
            resp = client.post("/guard/action-decision", json=_ACTION_DECISION_PAYLOAD)
        assert isinstance(resp.json()["matched_patterns"], list)

    def test_block_verdict_sets_should_halt_true(self, client: TestClient) -> None:
        with patch.object(_guard_module, "evaluate_action_execution", return_value=_MOCK_TOOL_DECISION_BLOCK):
            resp = client.post("/guard/action-decision", json=_ACTION_DECISION_PAYLOAD)
        data = resp.json()
        assert data["verdict"] == "block"
        assert data["should_halt"] is True

    def test_block_verdict_populates_matched_patterns(self, client: TestClient) -> None:
        with patch.object(_guard_module, "evaluate_action_execution", return_value=_MOCK_TOOL_DECISION_BLOCK):
            resp = client.post("/guard/action-decision", json=_ACTION_DECISION_PAYLOAD)
        assert "path_traversal" in resp.json()["matched_patterns"]

    def test_missing_required_action_type_returns_422(self, client: TestClient) -> None:
        payload = {**_ACTION_DECISION_PAYLOAD}
        del payload["action_type"]
        with patch.object(_guard_module, "evaluate_action_execution", return_value=_MOCK_TOOL_DECISION):
            resp = client.post("/guard/action-decision", json=payload)
        assert resp.status_code == 422

    def test_missing_required_target_returns_422(self, client: TestClient) -> None:
        payload = {**_ACTION_DECISION_PAYLOAD}
        del payload["target"]
        with patch.object(_guard_module, "evaluate_action_execution", return_value=_MOCK_TOOL_DECISION):
            resp = client.post("/guard/action-decision", json=payload)
        assert resp.status_code == 422

    def test_empty_action_type_returns_422(self, client: TestClient) -> None:
        payload = {**_ACTION_DECISION_PAYLOAD, "action_type": ""}
        with patch.object(_guard_module, "evaluate_action_execution", return_value=_MOCK_TOOL_DECISION):
            resp = client.post("/guard/action-decision", json=payload)
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /guard/execute — response shape
# ---------------------------------------------------------------------------


class TestGuardExecuteShape:
    def test_returns_200_on_allow(self, client: TestClient) -> None:
        decision = _make_policy_decision()
        with patch.object(_guard_module, "enforce_policy", return_value=decision):
            resp = client.post("/guard/execute", json=_EXECUTE_PAYLOAD)
        assert resp.status_code == 200

    def test_response_contains_execution_id(self, client: TestClient) -> None:
        decision = _make_policy_decision()
        with patch.object(_guard_module, "enforce_policy", return_value=decision):
            resp = client.post("/guard/execute", json=_EXECUTE_PAYLOAD)
        assert resp.json()["execution_id"] == "dec-test-001"

    def test_response_contains_trace_id(self, client: TestClient) -> None:
        decision = _make_policy_decision()
        with patch.object(_guard_module, "enforce_policy", return_value=decision):
            resp = client.post("/guard/execute", json=_EXECUTE_PAYLOAD)
        data = resp.json()
        assert "trace_id" in data
        assert data["trace_id"].startswith("trace-")

    def test_response_contains_policy_verdict(self, client: TestClient) -> None:
        decision = _make_policy_decision(verdict="allow")
        with patch.object(_guard_module, "enforce_policy", return_value=decision):
            resp = client.post("/guard/execute", json=_EXECUTE_PAYLOAD)
        assert resp.json()["policy_verdict"] == "allow"

    def test_response_contains_response_status(self, client: TestClient) -> None:
        decision = _make_policy_decision(allow_execution=True)
        with patch.object(_guard_module, "enforce_policy", return_value=decision):
            resp = client.post("/guard/execute", json=_EXECUTE_PAYLOAD)
        assert resp.json()["response_status"] == "completed"

    def test_response_contains_execution_state(self, client: TestClient) -> None:
        decision = _make_policy_decision(allow_execution=True)
        with patch.object(_guard_module, "enforce_policy", return_value=decision):
            resp = client.post("/guard/execute", json=_EXECUTE_PAYLOAD)
        assert resp.json()["execution_state"] == "executed"

    def test_response_contains_risk_score(self, client: TestClient) -> None:
        decision = _make_policy_decision(risk_score=30)
        with patch.object(_guard_module, "enforce_policy", return_value=decision):
            resp = client.post("/guard/execute", json=_EXECUTE_PAYLOAD)
        assert resp.json()["risk_score"] == 30

    def test_response_contains_risk_level(self, client: TestClient) -> None:
        decision = _make_policy_decision(risk_level="low")
        with patch.object(_guard_module, "enforce_policy", return_value=decision):
            resp = client.post("/guard/execute", json=_EXECUTE_PAYLOAD)
        assert resp.json()["risk_level"] == "low"

    def test_response_contains_allow_execution(self, client: TestClient) -> None:
        decision = _make_policy_decision(allow_execution=True)
        with patch.object(_guard_module, "enforce_policy", return_value=decision):
            resp = client.post("/guard/execute", json=_EXECUTE_PAYLOAD)
        assert resp.json()["allow_execution"] is True

    def test_response_contains_requires_review(self, client: TestClient) -> None:
        decision = _make_policy_decision(requires_review=False)
        with patch.object(_guard_module, "enforce_policy", return_value=decision):
            resp = client.post("/guard/execute", json=_EXECUTE_PAYLOAD)
        assert resp.json()["requires_review"] is False

    def test_response_contains_matched_rules_list(self, client: TestClient) -> None:
        decision = _make_policy_decision()
        with patch.object(_guard_module, "enforce_policy", return_value=decision):
            resp = client.post("/guard/execute", json=_EXECUTE_PAYLOAD)
        assert isinstance(resp.json()["matched_rules"], list)

    def test_response_contains_reasons_list(self, client: TestClient) -> None:
        decision = _make_policy_decision(reasons=["policy matched"])
        with patch.object(_guard_module, "enforce_policy", return_value=decision):
            resp = client.post("/guard/execute", json=_EXECUTE_PAYLOAD)
        assert isinstance(resp.json()["reasons"], list)

    def test_response_contains_target(self, client: TestClient) -> None:
        decision = _make_policy_decision()
        with patch.object(_guard_module, "enforce_policy", return_value=decision):
            resp = client.post("/guard/execute", json=_EXECUTE_PAYLOAD)
        assert resp.json()["target"] == "/tmp/output.txt"

    def test_response_contains_action_type(self, client: TestClient) -> None:
        decision = _make_policy_decision()
        with patch.object(_guard_module, "enforce_policy", return_value=decision):
            resp = client.post("/guard/execute", json=_EXECUTE_PAYLOAD)
        assert resp.json()["action_type"] == "file_write"

    def test_response_contains_file_path(self, client: TestClient) -> None:
        decision = _make_policy_decision()
        with patch.object(_guard_module, "enforce_policy", return_value=decision):
            resp = client.post("/guard/execute", json=_EXECUTE_PAYLOAD)
        assert resp.json()["file_path"] == "/tmp/output.txt"

    def test_block_verdict_sets_response_status_denied(self, client: TestClient) -> None:
        decision = _make_policy_decision(
            verdict="block",
            allow_execution=False,
            requires_review=False,
        )
        with patch.object(_guard_module, "enforce_policy", return_value=decision):
            resp = client.post("/guard/execute", json=_EXECUTE_PAYLOAD)
        data = resp.json()
        assert data["response_status"] == "denied"
        assert data["execution_state"] == "denied"

    def test_requires_review_sets_queued_status(self, client: TestClient) -> None:
        decision = _make_policy_decision(
            verdict="warn",
            allow_execution=False,
            requires_review=True,
        )
        with patch.object(_guard_module, "enforce_policy", return_value=decision):
            resp = client.post("/guard/execute", json=_EXECUTE_PAYLOAD)
        data = resp.json()
        assert data["response_status"] == "queued_for_review"
        assert data["execution_state"] == "held"
        assert data["policy_verdict"] == "block"
        assert data["risk_score"] >= RISK_THRESHOLD_BLOCK_MIN

    def test_legacy_nonbinary_verdict_without_review_fails_closed(self, client: TestClient) -> None:
        decision = _make_policy_decision(
            verdict="warn",
            allow_execution=False,
            requires_review=False,
        )
        with patch.object(_guard_module, "enforce_policy", return_value=decision):
            resp = client.post("/guard/execute", json=_EXECUTE_PAYLOAD)
        data = resp.json()
        assert data["response_status"] == "denied"
        assert data["execution_state"] == "failed"
        assert data["policy_verdict"] == "block"
        assert data["risk_score"] >= RISK_THRESHOLD_BLOCK_MIN

    def test_risk_score_clamped_to_100_max_in_payload(self, client: TestClient) -> None:
        payload = {**_EXECUTE_PAYLOAD, "risk_score": 101}
        decision = _make_policy_decision()
        with patch.object(_guard_module, "enforce_policy", return_value=decision):
            resp = client.post("/guard/execute", json=payload)
        assert resp.status_code == 422

    def test_risk_score_below_zero_rejected(self, client: TestClient) -> None:
        payload = {**_EXECUTE_PAYLOAD, "risk_score": -1}
        decision = _make_policy_decision()
        with patch.object(_guard_module, "enforce_policy", return_value=decision):
            resp = client.post("/guard/execute", json=payload)
        assert resp.status_code == 422

    def test_missing_required_action_type_returns_422(self, client: TestClient) -> None:
        payload = {**_EXECUTE_PAYLOAD}
        del payload["action_type"]
        decision = _make_policy_decision()
        with patch.object(_guard_module, "enforce_policy", return_value=decision):
            resp = client.post("/guard/execute", json=payload)
        assert resp.status_code == 422

    def test_missing_required_target_returns_422(self, client: TestClient) -> None:
        payload = {**_EXECUTE_PAYLOAD}
        del payload["target"]
        decision = _make_policy_decision()
        with patch.object(_guard_module, "enforce_policy", return_value=decision):
            resp = client.post("/guard/execute", json=payload)
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Auth rejection — both endpoints reject missing or invalid API key
# ---------------------------------------------------------------------------


class TestAuthRejection:
    def test_action_decision_rejects_missing_api_key(self, unauthed_client: TestClient) -> None:
        resp = unauthed_client.post("/guard/action-decision", json=_ACTION_DECISION_PAYLOAD)
        assert resp.status_code in (401, 403)

    def test_execute_rejects_missing_api_key(self, unauthed_client: TestClient) -> None:
        resp = unauthed_client.post("/guard/execute", json=_EXECUTE_PAYLOAD)
        assert resp.status_code in (401, 403)

    def test_action_decision_rejects_wrong_api_key(self, unauthed_client: TestClient) -> None:
        resp = unauthed_client.post(
            "/guard/action-decision",
            json=_ACTION_DECISION_PAYLOAD,
            headers={"X-API-Key": "invalid-key-xyz"},
        )
        assert resp.status_code in (401, 403)

    def test_execute_rejects_wrong_api_key(self, unauthed_client: TestClient) -> None:
        resp = unauthed_client.post(
            "/guard/execute",
            json=_EXECUTE_PAYLOAD,
            headers={"X-API-Key": "invalid-key-xyz"},
        )
        assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# GET /guard/audit/events — must NOT exist on this router (owned by audit_log.py)
# ---------------------------------------------------------------------------


class TestAuditEventsRouteRemoved:
    def test_get_guard_audit_events_returns_404(self, client: TestClient) -> None:
        resp = client.get("/guard/audit/events")
        assert resp.status_code == 404

    def test_get_guard_audit_events_not_in_router_routes(self) -> None:
        routes = [getattr(r, "path", "") for r in guard_router.routes]
        assert "/guard/audit/events" not in routes
        assert "/audit/events" not in routes

    def test_guard_module_has_no_audit_events_list(self) -> None:
        assert not hasattr(_guard_module, "_AUDIT_EVENTS")

    def test_guard_module_has_no_append_audit_fn(self) -> None:
        assert not hasattr(_guard_module, "_append_audit_event")
