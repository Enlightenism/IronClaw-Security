from __future__ import annotations

from fastapi.testclient import TestClient

from app.dependencies.action_execute import reset_action_execute_pipeline
from app.main import app
from app.services.audit_log_service import reset_audit_log
from app.services.review_queue_service import reset_review_queue

client = TestClient(app)


def setup_function() -> None:
    reset_action_execute_pipeline()
    reset_audit_log()
    reset_review_queue()


def test_action_execute_rejects_invalid_payload():
    response = client.post(
        "/guard/execute",
        headers={"x-api-key": "test-api-key"},
        json={},
    )

    assert response.status_code == 422


def test_action_execute_route_is_available_with_api_key():
    response = client.post(
        "/guard/execute",
        headers={"x-api-key": "test-api-key"},
        json={},
    )

    assert response.status_code in (200, 400, 422)


def test_action_execute_without_api_key_is_not_success():
    response = client.post(
        "/guard/execute",
        json={},
    )

    assert response.status_code in (400, 401, 403, 422)
