from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.release_policy_routes import router as release_policy_router


def create_app() -> FastAPI:
    app = FastAPI()
    app.include_router(release_policy_router)
    return app


def test_evaluate_release_policy_happy_path():
    app = create_app()
    client = TestClient(app)

    payload = {
        "integration_id": "integration-123",
        "compatibility_state": "supported",
        "telemetry_state": "supported",
        "lifecycle_state": "active",
        "risk_score": 95.0,
        "has_open_blockers": False,
        "has_audit_gaps": False,
        "has_rollback_plan": True,
        "has_test_evidence": True,
        "requires_manual_review": False,
        "manual_review_completed": False,
        "metadata": {"env": "staging"},
    }

    response = client.post("/release-policy/evaluate", json=payload)

    assert response.status_code == 200
    data = response.json()

    assert data["integration_id"] == "integration-123"
    assert "rollout_decision" in data
    assert "readiness_result" in data
    assert "release_summary" in data

    recommendation = data["rollout_decision"]["recommendation"]
    assert recommendation in ("ship", "limited_rollout")

    assert isinstance(data["release_summary"]["ready"], bool)
    assert data["release_summary"]["risk_score"] <= payload["risk_score"]
    assert data["release_summary"]["integration_id"] == "integration-123"


def test_evaluate_release_policy_blocked_by_compatibility():
    app = create_app()
    client = TestClient(app)

    payload = {
        "integration_id": "integration-unsupported",
        "compatibility_state": "unsupported",
        "telemetry_state": "supported",
        "lifecycle_state": "active",
        "risk_score": 80.0,
        "has_open_blockers": False,
        "has_audit_gaps": False,
        "has_rollback_plan": True,
        "has_test_evidence": True,
        "requires_manual_review": False,
        "manual_review_completed": False,
        "metadata": {"env": "staging"},
    }

    response = client.post("/release-policy/evaluate", json=payload)

    assert response.status_code == 200
    data = response.json()

    assert data["integration_id"] == "integration-unsupported"
    rollout = data["rollout_decision"]
    readiness = data["readiness_result"]
    summary = data["release_summary"]

    assert rollout["recommendation"] in ("hold", "rollback_ready")
    assert readiness["level"] in ("fail", "warn")
    assert summary["ready"] is False
    assert summary["integration_id"] == "integration-unsupported"
