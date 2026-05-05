from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _assert_validation_failure(response) -> None:
    assert response.status_code == 422, (
        f"Expected 422 validation error, got {response.status_code}: {response.text}"
    )


def _assert_client_input_failure(response) -> None:
    assert response.status_code in {400, 422}, (
        f"Expected 400 or 422 client input error, got {response.status_code}: {response.text}"
    )


def test_scan_rejects_empty_body():
    response = client.post("/scan/", json={})
    _assert_validation_failure(response)


def test_scan_batch_rejects_empty_body():
    response = client.post("/scan/batch", json={})
    _assert_validation_failure(response)


def test_history_review_rejects_empty_body():
    response = client.post("/history/test-scan-id/review", json={})
    _assert_validation_failure(response)


def test_policy_guard_bundle_rejects_empty_body():
    response = client.post("/policy/guard-bundle", json={})
    _assert_client_input_failure(response)


def test_scan_rejects_wrong_types():
    response = client.post(
        "/scan/",
        json={
            "target": ["not", "a", "string"],
            "content": {"unexpected": "object"},
            "risk_score": "high",
        },
    )
    _assert_validation_failure(response)


def test_scan_batch_rejects_wrong_types():
    response = client.post(
        "/scan/batch",
        json={
            "items": "not-a-list",
        },
    )
    _assert_validation_failure(response)


def test_history_review_rejects_wrong_types():
    response = client.post(
        "/history/test-scan-id/review",
        json={
            "approved": "yes",
            "reviewer": ["not-a-string"],
            "notes": {"unexpected": "object"},
        },
    )
    _assert_validation_failure(response)


def test_policy_guard_bundle_rejects_wrong_types():
    response = client.post(
        "/policy/guard-bundle",
        json={
            "version": 123,
            "rules": "not-a-list",
        },
    )
    _assert_client_input_failure(response)