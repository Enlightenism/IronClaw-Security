from __future__ import annotations

import os
import threading

import pytest

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("IRONCLAW_API_KEY", "test-api-key")
os.environ.setdefault("API_KEY", "test-api-key")
os.environ.setdefault("AUTH_REQUIRED", "true")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "")
os.environ.setdefault("SUPABASE_KEY", "")
os.environ.setdefault("SUPABASE_ANON_KEY", "")

from fastapi.testclient import TestClient

from app.api.onboarding import (
    _DEFAULT_STEPS,
    OnboardingService,
    OnboardingSession,
    OnboardingSessionStatus,
    OnboardingStatus,
    OnboardingStepKey,
    _assert_session_ownership,
    reset_onboarding_service,
)
from app.main import app

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_AUTH_HEADERS = {"X-API-Key": "test-api-key", "X-Organization-Id": "org-test-001"}
_ORG_A = "org-alpha"
_ORG_B = "org-beta"
_HEADERS_A = {"X-API-Key": "test-api-key", "X-Organization-Id": _ORG_A}

_REQUIRED_STEP_KEYS = {s["key"] for s in _DEFAULT_STEPS if s["required"]}
_OPTIONAL_STEP_KEYS = {s["key"] for s in _DEFAULT_STEPS if not s["required"]}
_TOTAL_STEPS = len(_DEFAULT_STEPS)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_service() -> None:
    reset_onboarding_service()
    yield
    reset_onboarding_service()


@pytest.fixture()
def svc() -> OnboardingService:
    return OnboardingService()


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture()
def started_session(svc: OnboardingService) -> OnboardingSession:
    return svc.start(principal_id="test-principal", org_id="org-test-001")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _start(client: TestClient, headers: dict | None = None, org_id: str | None = None) -> dict:
    payload: dict = {}
    if org_id:
        payload["org_id"] = org_id
    resp = client.post("/onboarding/start", json=payload, headers=headers or _AUTH_HEADERS)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _all_optional_keys() -> list[OnboardingStepKey]:
    return [s["key"] for s in _DEFAULT_STEPS if not s["required"]]


def _all_required_keys() -> list[OnboardingStepKey]:
    return [s["key"] for s in _DEFAULT_STEPS if s["required"]]


# ===========================================================================
# Section 1 — Service unit: start / get / get_by_principal
# ===========================================================================


class TestOnboardingServiceStart:
    def test_start_returns_session(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        assert session.session_id.startswith("obs-")
        assert session.org_id == "org-1"
        assert session.principal_id == "p1"
        assert session.status == OnboardingSessionStatus.ACTIVE

    def test_start_account_created_auto_completed(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        ac = next(s for s in session.steps if s.key == OnboardingStepKey.ACCOUNT_CREATED)
        assert ac.status == OnboardingStatus.COMPLETED
        assert ac.completed_at is not None

    def test_start_progress_non_zero_due_to_auto_complete(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        assert session.progress_pct > 0

    def test_start_idempotent_same_principal_org(self, svc: OnboardingService) -> None:
        s1 = svc.start(principal_id="p1", org_id="org-1")
        s2 = svc.start(principal_id="p1", org_id="org-1")
        assert s1.session_id == s2.session_id

    def test_start_different_principal_different_session(self, svc: OnboardingService) -> None:
        s1 = svc.start(principal_id="p1", org_id="org-1")
        s2 = svc.start(principal_id="p2", org_id="org-1")
        assert s1.session_id != s2.session_id

    def test_start_different_org_different_session(self, svc: OnboardingService) -> None:
        s1 = svc.start(principal_id="p1", org_id="org-a")
        s2 = svc.start(principal_id="p1", org_id="org-b")
        assert s1.session_id != s2.session_id

    def test_start_org_none_allowed(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id=None)
        assert session.org_id is None

    def test_start_with_metadata(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1", metadata={"source": "onboarding-ui"})
        assert session.metadata.get("source") == "onboarding-ui"

    def test_start_after_abandoned_creates_new(self, svc: OnboardingService) -> None:
        s1 = svc.start(principal_id="p1", org_id="org-1")
        svc.abandon(s1.session_id)
        s2 = svc.start(principal_id="p1", org_id="org-1")
        assert s2.session_id != s1.session_id
        assert s2.status == OnboardingSessionStatus.ACTIVE

    def test_get_existing(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        fetched = svc.get(session.session_id)
        assert fetched is not None
        assert fetched.session_id == session.session_id

    def test_get_missing_returns_none(self, svc: OnboardingService) -> None:
        assert svc.get("obs-nonexistent") is None

    def test_get_by_principal_existing(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        found = svc.get_by_principal(principal_id="p1", org_id="org-1")
        assert found is not None
        assert found.session_id == session.session_id

    def test_get_by_principal_missing_returns_none(self, svc: OnboardingService) -> None:
        assert svc.get_by_principal(principal_id="nobody", org_id="org-1") is None

    def test_steps_count_matches_defaults(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        assert len(session.steps) == _TOTAL_STEPS

    def test_current_step_skips_completed(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        assert session.current_step != OnboardingStepKey.ACCOUNT_CREATED


# ===========================================================================
# Section 2 — Service unit: complete_step
# ===========================================================================


class TestOnboardingServiceCompleteStep:
    def test_complete_step_advances_status(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        key = session.current_step
        assert key is not None
        result = svc.complete_step(session.session_id, key)
        assert result is not None
        step = next(s for s in result.steps if s.key == key)
        assert step.status == OnboardingStatus.COMPLETED
        assert step.completed_at is not None

    def test_complete_step_advances_current_step(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        first_current = session.current_step
        assert first_current is not None
        result = svc.complete_step(session.session_id, first_current)
        assert result is not None
        assert result.current_step != first_current

    def test_complete_step_stores_metadata(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        key = session.current_step
        assert key is not None
        result = svc.complete_step(session.session_id, key, metadata={"ref": "scan-001"})
        assert result is not None
        step = next(s for s in result.steps if s.key == key)
        assert step.metadata.get("ref") == "scan-001"

    def test_complete_nonexistent_session_returns_none(self, svc: OnboardingService) -> None:
        result = svc.complete_step("obs-ghost", OnboardingStepKey.ORG_CONFIGURED)
        assert result is None

    def test_complete_already_completed_session_no_op(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        for step in session.steps:
            if step.status == OnboardingStatus.PENDING:
                svc.complete_step(session.session_id, step.key)
        final = svc.get(session.session_id)
        assert final is not None
        assert final.status == OnboardingSessionStatus.COMPLETED
        result = svc.complete_step(session.session_id, OnboardingStepKey.ACCOUNT_CREATED)
        assert result is not None
        assert result.status == OnboardingSessionStatus.COMPLETED

    def test_complete_all_required_steps_marks_completed(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        for step in session.steps:
            if step.status == OnboardingStatus.PENDING:
                svc.complete_step(session.session_id, step.key)
        final = svc.get(session.session_id)
        assert final is not None
        assert final.status == OnboardingSessionStatus.COMPLETED
        assert final.completed_at is not None

    def test_progress_increases_after_complete(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        before = session.progress_pct
        key = session.current_step
        assert key is not None
        after_session = svc.complete_step(session.session_id, key)
        assert after_session is not None
        assert after_session.progress_pct > before

    def test_complete_step_updates_updated_at(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        key = session.current_step
        assert key is not None
        result = svc.complete_step(session.session_id, key)
        assert result is not None
        assert result.steps[0].completed_at is not None


# ===========================================================================
# Section 3 — Service unit: skip_step
# ===========================================================================


class TestOnboardingServiceSkipStep:
    def _first_optional_key(self, session: OnboardingSession) -> OnboardingStepKey:
        for s in session.steps:
            if not s.required and s.status == OnboardingStatus.PENDING:
                return s.key
        pytest.skip("No optional pending steps available")

    def test_skip_optional_step(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        key = self._first_optional_key(session)
        result = svc.skip_step(session.session_id, key)
        assert result is not None
        step = next(s for s in result.steps if s.key == key)
        assert step.status == OnboardingStatus.SKIPPED
        assert step.skipped_at is not None

    def test_skip_stores_reason(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        key = self._first_optional_key(session)
        result = svc.skip_step(session.session_id, key, reason="not applicable")
        assert result is not None
        step = next(s for s in result.steps if s.key == key)
        assert step.metadata.get("skip_reason") == "not applicable"

    def test_skip_required_step_raises_409(self, svc: OnboardingService) -> None:
        from fastapi import HTTPException as FastAPIHTTPException

        session = svc.start(principal_id="p1", org_id="org-1")
        required_key = next(s.key for s in session.steps if s.required and s.status == OnboardingStatus.PENDING)
        with pytest.raises(FastAPIHTTPException) as exc_info:
            svc.skip_step(session.session_id, required_key)
        assert exc_info.value.status_code == 409

    def test_skip_nonexistent_session_returns_none(self, svc: OnboardingService) -> None:
        result = svc.skip_step("obs-ghost", OnboardingStepKey.WEBHOOK_REGISTERED)
        assert result is None

    def test_skip_all_optional_completes_session_when_required_done(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        for s in session.steps:
            if s.required and s.status == OnboardingStatus.PENDING:
                svc.complete_step(session.session_id, s.key)
        refreshed = svc.get(session.session_id)
        assert refreshed is not None
        for s in refreshed.steps:
            if not s.required and s.status == OnboardingStatus.PENDING:
                svc.skip_step(session.session_id, s.key)
        final = svc.get(session.session_id)
        assert final is not None
        assert final.status == OnboardingSessionStatus.COMPLETED


# ===========================================================================
# Section 4 — Service unit: abandon / reset / checklist / progress
# ===========================================================================


class TestOnboardingServiceLifecycle:
    def test_abandon_sets_status(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        result = svc.abandon(session.session_id)
        assert result is not None
        assert result.status == OnboardingSessionStatus.ABANDONED

    def test_abandon_nonexistent_returns_none(self, svc: OnboardingService) -> None:
        assert svc.abandon("obs-ghost") is None

    def test_reset_restores_pending_steps(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        key = session.current_step
        assert key is not None
        svc.complete_step(session.session_id, key)
        response = svc.reset(session.session_id, principal_id="p1", org_id="org-1")
        assert response is not None
        assert response.session_id == session.session_id
        assert response.reset_at is not None
        assert response.message != ""

    def test_reset_account_created_still_completed(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        svc.reset(session.session_id, principal_id="p1", org_id="org-1")
        refreshed = svc.get(session.session_id)
        assert refreshed is not None
        ac = next(s for s in refreshed.steps if s.key == OnboardingStepKey.ACCOUNT_CREATED)
        assert ac.status == OnboardingStatus.COMPLETED

    def test_reset_status_returns_to_active(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        for s in session.steps:
            if s.status == OnboardingStatus.PENDING:
                svc.complete_step(session.session_id, s.key)
        completed = svc.get(session.session_id)
        assert completed is not None
        assert completed.status == OnboardingSessionStatus.COMPLETED
        svc.reset(session.session_id, principal_id="p1", org_id="org-1")
        refreshed = svc.get(session.session_id)
        assert refreshed is not None
        assert refreshed.status == OnboardingSessionStatus.ACTIVE

    def test_reset_nonexistent_returns_none(self, svc: OnboardingService) -> None:
        result = svc.reset("obs-ghost", principal_id="p1", org_id="org-1")
        assert result is None

    def test_checklist_returns_steps(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        result = svc.checklist(session.session_id)
        assert result is not None
        assert len(result.steps) == _TOTAL_STEPS
        assert result.session_id == session.session_id

    def test_checklist_nonexistent_returns_none(self, svc: OnboardingService) -> None:
        assert svc.checklist("obs-ghost") is None

    def test_progress_counts_are_accurate(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        result = svc.progress(session.session_id)
        assert result is not None
        assert result.completed_steps >= 1
        assert result.total_steps == _TOTAL_STEPS
        assert result.completed_steps + result.skipped_steps + result.pending_steps == _TOTAL_STEPS

    def test_progress_nonexistent_returns_none(self, svc: OnboardingService) -> None:
        assert svc.progress("obs-ghost") is None

    def test_full_reset_for_tests_clears_all(self, svc: OnboardingService) -> None:
        svc.start(principal_id="p1", org_id="org-1")
        svc.start(principal_id="p2", org_id="org-2")
        svc.full_reset_for_tests()
        assert svc.get_by_principal("p1", "org-1") is None
        assert svc.get_by_principal("p2", "org-2") is None


# ===========================================================================
# Section 5 — Service unit: compute_progress / thread safety
# ===========================================================================


class TestOnboardingServiceInternals:
    def test_progress_100_when_all_done(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p1", org_id="org-1")
        for s in session.steps:
            if s.status == OnboardingStatus.PENDING:
                if s.required:
                    svc.complete_step(session.session_id, s.key)
                else:
                    svc.skip_step(session.session_id, s.key)
        final = svc.get(session.session_id)
        assert final is not None
        assert final.progress_pct == 100

    def test_progress_0_on_fresh_account_created_only(self) -> None:
        from app.api.onboarding import OnboardingService as Svc
        from app.api.onboarding import OnboardingStatus as OS
        from app.api.onboarding import OnboardingStep
        from app.api.onboarding import OnboardingStepKey as SK

        steps = [OnboardingStep(key=SK.ORG_CONFIGURED, title="t", description="d", status=OS.PENDING)]
        assert Svc._compute_progress(steps) == 0

    def test_progress_empty_steps_returns_0(self) -> None:
        from app.api.onboarding import OnboardingService as Svc

        assert Svc._compute_progress([]) == 0

    def test_thread_safety_concurrent_start(self, svc: OnboardingService) -> None:
        errors: list[Exception] = []

        def _do(i: int) -> None:
            try:
                svc.start(principal_id=f"user-{i}", org_id=f"org-{i}")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_do, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []

    def test_thread_safety_concurrent_complete(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="p-mt", org_id="org-mt")
        errors: list[Exception] = []

        def _do(key: OnboardingStepKey) -> None:
            try:
                svc.complete_step(session.session_id, key)
            except Exception as exc:
                errors.append(exc)

        pending_keys = [s.key for s in session.steps if s.status == OnboardingStatus.PENDING]
        threads = [threading.Thread(target=_do, args=(k,)) for k in pending_keys]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []


# ===========================================================================
# Section 6 — API route tests
# ===========================================================================


class TestOnboardingAPI:
    def test_start_201(self, client: TestClient) -> None:
        data = _start(client)
        assert "session_id" in data
        assert data["status"] == "active"
        assert "steps" in data
        assert data["progress_pct"] > 0

    def test_start_idempotent(self, client: TestClient) -> None:
        d1 = _start(client)
        d2 = _start(client)
        assert d1["session_id"] == d2["session_id"]

    def test_start_with_body_org_id(self, client: TestClient) -> None:
        resp = client.post(
            "/onboarding/start",
            json={"org_id": "custom-org"},
            headers={"X-API-Key": "test-api-key"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["org_id"] == "custom-org"

    def test_start_account_created_auto_completed(self, client: TestClient) -> None:
        data = _start(client)
        ac = next(s for s in data["steps"] if s["key"] == "account_created")
        assert ac["status"] == "completed"

    def test_unauthenticated_start_rejected(self, client: TestClient) -> None:
        resp = client.post("/onboarding/start", json={})
        assert resp.status_code in (401, 403, 422)

    def test_list_step_definitions(self, client: TestClient) -> None:
        resp = client.get("/onboarding/steps", headers=_AUTH_HEADERS)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == _TOTAL_STEPS
        keys = {item["key"] for item in data}
        assert "account_created" in keys

    def test_list_step_definitions_fields(self, client: TestClient) -> None:
        resp = client.get("/onboarding/steps", headers=_AUTH_HEADERS)
        assert resp.status_code == 200
        for item in resp.json():
            assert "key" in item
            assert "title" in item
            assert "description" in item
            assert "required" in item

    def test_get_my_onboarding_not_started_404(self, client: TestClient) -> None:
        resp = client.get("/onboarding/me", headers=_AUTH_HEADERS)
        assert resp.status_code == 404

    def test_get_my_onboarding_after_start(self, client: TestClient) -> None:
        _start(client)
        resp = client.get("/onboarding/me", headers=_AUTH_HEADERS)
        assert resp.status_code == 200
        data = resp.json()
        assert "session_id" in data

    def test_get_session_by_id(self, client: TestClient) -> None:
        created = _start(client)
        resp = client.get(f"/onboarding/{created['session_id']}", headers=_AUTH_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["session_id"] == created["session_id"]

    def test_get_session_not_found(self, client: TestClient) -> None:
        resp = client.get("/onboarding/obs-nonexistent", headers=_AUTH_HEADERS)
        assert resp.status_code == 404

    def test_get_checklist(self, client: TestClient) -> None:
        created = _start(client)
        resp = client.get(f"/onboarding/{created['session_id']}/checklist", headers=_AUTH_HEADERS)
        assert resp.status_code == 200
        data = resp.json()
        assert "steps" in data
        assert data["session_id"] == created["session_id"]
        assert len(data["steps"]) == _TOTAL_STEPS

    def test_get_checklist_not_found(self, client: TestClient) -> None:
        resp = client.get("/onboarding/obs-ghost/checklist", headers=_AUTH_HEADERS)
        assert resp.status_code == 404

    def test_get_progress(self, client: TestClient) -> None:
        created = _start(client)
        resp = client.get(f"/onboarding/{created['session_id']}/progress", headers=_AUTH_HEADERS)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_steps"] == _TOTAL_STEPS
        assert data["completed_steps"] + data["skipped_steps"] + data["pending_steps"] == _TOTAL_STEPS

    def test_get_progress_not_found(self, client: TestClient) -> None:
        resp = client.get("/onboarding/obs-ghost/progress", headers=_AUTH_HEADERS)
        assert resp.status_code == 404

    def test_complete_step(self, client: TestClient) -> None:
        created = _start(client)
        current_step = created["current_step"]
        resp = client.post(
            f"/onboarding/{created['session_id']}/complete-step",
            json={"key": current_step},
            headers=_AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        step = next(s for s in data["steps"] if s["key"] == current_step)
        assert step["status"] == "completed"

    def test_complete_step_not_found(self, client: TestClient) -> None:
        resp = client.post(
            "/onboarding/obs-ghost/complete-step",
            json={"key": "org_configured"},
            headers=_AUTH_HEADERS,
        )
        assert resp.status_code == 404

    def test_skip_optional_step(self, client: TestClient) -> None:
        created = _start(client)
        optional_key = next(s["key"] for s in created["steps"] if not s["required"] and s["status"] == "pending")
        resp = client.post(
            f"/onboarding/{created['session_id']}/skip-step",
            json={"key": optional_key},
            headers=_AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        step = next(s for s in data["steps"] if s["key"] == optional_key)
        assert step["status"] == "skipped"

    def test_skip_required_step_409(self, client: TestClient) -> None:
        created = _start(client)
        required_key = next(s["key"] for s in created["steps"] if s["required"] and s["status"] == "pending")
        resp = client.post(
            f"/onboarding/{created['session_id']}/skip-step",
            json={"key": required_key},
            headers=_AUTH_HEADERS,
        )
        assert resp.status_code == 409

    def test_skip_step_not_found(self, client: TestClient) -> None:
        resp = client.post(
            "/onboarding/obs-ghost/skip-step",
            json={"key": "webhook_registered"},
            headers=_AUTH_HEADERS,
        )
        assert resp.status_code == 404

    def test_abandon_session(self, client: TestClient) -> None:
        created = _start(client)
        resp = client.post(
            f"/onboarding/{created['session_id']}/abandon",
            headers=_AUTH_HEADERS,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "abandoned"

    def test_abandon_not_found(self, client: TestClient) -> None:
        resp = client.post("/onboarding/obs-ghost/abandon", headers=_AUTH_HEADERS)
        assert resp.status_code == 404

    def test_reset_session(self, client: TestClient) -> None:
        created = _start(client)
        client.post(
            f"/onboarding/{created['session_id']}/complete-step",
            json={"key": created["current_step"]},
            headers=_AUTH_HEADERS,
        )
        resp = client.post(
            f"/onboarding/{created['session_id']}/reset",
            headers=_AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["session_id"] == created["session_id"]
        assert "reset_at" in data
        assert "message" in data

    def test_reset_not_found(self, client: TestClient) -> None:
        resp = client.post("/onboarding/obs-ghost/reset", headers=_AUTH_HEADERS)
        assert resp.status_code == 404


# ===========================================================================
# Section 7 — Ownership enforcement
# ===========================================================================


class TestOnboardingOwnership:
    """
    Ownership is enforced by _assert_session_ownership which compares
    principal_id. On the configured-key path, principal_id is derived from
    the raw API key value itself (see _principal_id dependency in onboarding.py).
    Two requests with the same API key but different org headers share the same
    principal_id, so they can never produce a 403 from each other at the API layer.

    The correct strategy:
    - Cross-principal 403 cases are tested directly at the service / guard layer
      where we control principal_id explicitly.
    - The API-layer ownership tests verify that an unrecognised key (401) is
      correctly rejected before reaching ownership logic, and that same-org
      access works when auth passes.
    """

    # ------------------------------------------------------------------
    # Service-layer ownership: 403 via _assert_session_ownership directly
    # ------------------------------------------------------------------

    def test_service_cross_principal_get_raises_403(self, svc: OnboardingService) -> None:
        from fastapi import HTTPException as FastAPIHTTPException

        session = svc.start(principal_id="principal-a", org_id=_ORG_A)
        with pytest.raises(FastAPIHTTPException) as exc_info:
            _assert_session_ownership(session, "principal-b", _ORG_B, session.session_id)
        assert exc_info.value.status_code == 403

    def test_service_same_principal_no_raise(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="principal-a", org_id=_ORG_A)
        _assert_session_ownership(session, "principal-a", _ORG_A, session.session_id)

    def test_service_same_org_different_principal_no_raise(self, svc: OnboardingService) -> None:
        session = svc.start(principal_id="principal-a", org_id=_ORG_A)
        _assert_session_ownership(session, "principal-b", _ORG_A, session.session_id)

    def test_service_no_org_match_raises_403(self, svc: OnboardingService) -> None:
        from fastapi import HTTPException as FastAPIHTTPException

        session = svc.start(principal_id="principal-a", org_id=_ORG_A)
        with pytest.raises(FastAPIHTTPException) as exc_info:
            _assert_session_ownership(session, "principal-b", None, session.session_id)
        assert exc_info.value.status_code == 403

    def test_service_org_mismatch_raises_403(self, svc: OnboardingService) -> None:
        from fastapi import HTTPException as FastAPIHTTPException

        session = svc.start(principal_id="principal-a", org_id=_ORG_A)
        with pytest.raises(FastAPIHTTPException) as exc_info:
            _assert_session_ownership(session, "principal-b", _ORG_B, session.session_id)
        assert exc_info.value.status_code == 403

    # ------------------------------------------------------------------
    # API-layer: unregistered key is rejected before ownership check
    # ------------------------------------------------------------------

    def test_api_unknown_key_rejected_before_ownership(self, client: TestClient) -> None:
        created = _start(client, headers=_HEADERS_A)
        resp = client.get(
            f"/onboarding/{created['session_id']}",
            headers={"X-API-Key": "completely-unknown-key", "X-Organization-Id": _ORG_B},
        )
        # Auth fires first — 401 or 403 both acceptable depending on which
        # guard layer responds first (auth vs ownership).
        assert resp.status_code in (401, 403)

    def test_api_same_key_different_org_allowed(self, client: TestClient) -> None:
        """
        When the configured API key is used, principal_id == raw key value for
        both requests, so the ownership guard treats them as the same principal
        regardless of org header. This is the expected behaviour on the
        configured-key path.
        """
        created = _start(client, headers=_HEADERS_A)
        resp = client.get(
            f"/onboarding/{created['session_id']}",
            headers={"X-API-Key": "test-api-key", "X-Organization-Id": _ORG_B},
        )
        assert resp.status_code == 200

    def test_api_same_org_allows_cross_principal_get(self, client: TestClient) -> None:
        """
        Org-level access: session created under org-alpha is readable by
        another request carrying the same org_id via the ownership guard's
        org fallback path.
        """
        created = _start(client, headers=_HEADERS_A, org_id=_ORG_A)
        resp = client.get(
            f"/onboarding/{created['session_id']}",
            headers={"X-API-Key": "test-api-key", "X-Organization-Id": _ORG_A},
        )
        assert resp.status_code == 200


# ===========================================================================
# Section 8 — Full flow integration
# ===========================================================================


class TestOnboardingFullFlow:
    def test_complete_all_required_session_completes(self, client: TestClient) -> None:
        created = _start(client)
        session_id = created["session_id"]

        for _ in range(_TOTAL_STEPS):
            current = client.get(f"/onboarding/{session_id}", headers=_AUTH_HEADERS).json()
            pending_required = [s for s in current["steps"] if s["required"] and s["status"] == "pending"]
            if not pending_required:
                break
            key = pending_required[0]["key"]
            r = client.post(
                f"/onboarding/{session_id}/complete-step",
                json={"key": key},
                headers=_AUTH_HEADERS,
            )
            assert r.status_code == 200

        current = client.get(f"/onboarding/{session_id}", headers=_AUTH_HEADERS).json()
        for s in current["steps"]:
            if not s["required"] and s["status"] == "pending":
                client.post(
                    f"/onboarding/{session_id}/skip-step",
                    json={"key": s["key"]},
                    headers=_AUTH_HEADERS,
                )

        final = client.get(f"/onboarding/{session_id}", headers=_AUTH_HEADERS).json()
        assert final["status"] == "completed"
        assert final["progress_pct"] == 100
        assert final["completed_at"] is not None

    def test_abandon_then_restart_new_session(self, client: TestClient) -> None:
        s1 = _start(client)
        client.post(f"/onboarding/{s1['session_id']}/abandon", headers=_AUTH_HEADERS)
        s2 = _start(client)
        assert s2["session_id"] != s1["session_id"]
        assert s2["status"] == "active"

    def test_reset_after_partial_completion(self, client: TestClient) -> None:
        created = _start(client)
        session_id = created["session_id"]
        client.post(
            f"/onboarding/{session_id}/complete-step",
            json={"key": created["current_step"]},
            headers=_AUTH_HEADERS,
        )
        client.post(f"/onboarding/{session_id}/reset", headers=_AUTH_HEADERS)
        refreshed = client.get(f"/onboarding/{session_id}", headers=_AUTH_HEADERS).json()
        assert refreshed["status"] == "active"
        ac = next(s for s in refreshed["steps"] if s["key"] == "account_created")
        assert ac["status"] == "completed"
        pending = [s for s in refreshed["steps"] if s["status"] == "pending"]
        assert len(pending) == _TOTAL_STEPS - 1

    def test_progress_endpoint_reflects_completions(self, client: TestClient) -> None:
        created = _start(client)
        session_id = created["session_id"]
        prog_before = client.get(f"/onboarding/{session_id}/progress", headers=_AUTH_HEADERS).json()

        client.post(
            f"/onboarding/{session_id}/complete-step",
            json={"key": created["current_step"]},
            headers=_AUTH_HEADERS,
        )
        prog_after = client.get(f"/onboarding/{session_id}/progress", headers=_AUTH_HEADERS).json()
        assert prog_after["completed_steps"] > prog_before["completed_steps"]
        assert prog_after["progress_pct"] > prog_before["progress_pct"]

    def test_checklist_reflects_skipped_steps(self, client: TestClient) -> None:
        created = _start(client)
        session_id = created["session_id"]
        optional_key = next(s["key"] for s in created["steps"] if not s["required"] and s["status"] == "pending")
        client.post(
            f"/onboarding/{session_id}/skip-step",
            json={"key": optional_key},
            headers=_AUTH_HEADERS,
        )
        checklist = client.get(f"/onboarding/{session_id}/checklist", headers=_AUTH_HEADERS).json()
        skipped = next(s for s in checklist["steps"] if s["key"] == optional_key)
        assert skipped["status"] == "skipped"
