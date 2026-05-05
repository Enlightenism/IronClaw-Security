from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient

from dependencies.release_policy import (
    get_release_policy_decision_store,
    get_release_policy_service,
)
from models.release_policy_decision import ReleasePolicyDecision
from services.release_policy_service import ReleasePolicyService


class _StubReleasePolicyService(ReleasePolicyService):
    pass


class _StubDecisionStore:
    def list_recent(self, limit: int = 50) -> list[ReleasePolicyDecision]:
        _ = limit
        return [
            ReleasePolicyDecision(
                decision_id="release-policy-production-20260427T220000Z",
                channel="production",
                allowed=True,
                requested_version="1.0.0",
                minimum_upgrade_from="1.0.0",
                decision_reason="all release policy checks passed",
                actor="test-suite",
                decided_at=datetime(2026, 4, 27, 22, 0, 0, tzinfo=UTC),
                metadata={"source": "pytest"},
            )
        ]


def _build_test_app() -> FastAPI:
    app = FastAPI()
    router = APIRouter(prefix="/api/release-policy", tags=["release-policy"])

    @router.get("/latest-decision")
    def latest_release_policy_decision(
        service: Annotated[ReleasePolicyService, Depends(get_release_policy_service)],
        store: Annotated[object, Depends(get_release_policy_decision_store)],
    ) -> dict[str, object]:
        _ = service
        latest = store.list_recent(limit=1)
        if not latest:
            return {
                "status": "empty",
                "decision": None,
            }

        decision = latest[0]
        return {
            "status": "ok",
            "decision": decision.model_dump(mode="json"),
        }

    app.include_router(router)
    return app


def test_release_policy_latest_decision_returns_latest_record() -> None:
    app = _build_test_app()
    app.dependency_overrides[get_release_policy_service] = lambda: _StubReleasePolicyService()
    app.dependency_overrides[get_release_policy_decision_store] = lambda: _StubDecisionStore()

    try:
        with TestClient(app) as client:
            response = client.get("/api/release-policy/latest-decision")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()

    assert payload["status"] == "ok"
    assert payload["decision"]["decision_id"] == "release-policy-production-20260427T220000Z"
    assert payload["decision"]["channel"] == "production"
    assert payload["decision"]["allowed"] is True
    assert payload["decision"]["requested_version"] == "1.0.0"
    assert payload["decision"]["actor"] == "test-suite"
    assert payload["decision"]["metadata"]["source"] == "pytest"


def test_release_policy_latest_decision_returns_empty_when_no_records_exist() -> None:
    class _EmptyDecisionStore:
        def list_recent(self, limit: int = 50) -> list[ReleasePolicyDecision]:
            _ = limit
            return []

    app = _build_test_app()
    app.dependency_overrides[get_release_policy_service] = lambda: _StubReleasePolicyService()
    app.dependency_overrides[get_release_policy_decision_store] = lambda: _EmptyDecisionStore()

    try:
        with TestClient(app) as client:
            response = client.get("/api/release-policy/latest-decision")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() == {
        "status": "empty",
        "decision": None,
    }