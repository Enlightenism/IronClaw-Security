from __future__ import annotations

from fastapi.testclient import TestClient

from app.api.scan import _rate_limit_buckets
from app.dependencies.action_execute import reset_action_execute_pipeline
from app.main import app
from app.services.audit_log_service import reset_audit_log
from app.services.history import reset_scan_history
from app.services.review_queue_service import reset_review_queue

client = TestClient(app)


def setup_function() -> None:
    reset_review_queue()
    reset_action_execute_pipeline()
    reset_audit_log()
    reset_scan_history()
    _rate_limit_buckets.clear()


def test_scan_batch_accepts_valid_items():
    payload = {
        "items": [
            {
                "target_type": "url",
                "target_value": "https://example.com/one",
                "client_id": "batch-client-001",
            },
            {
                "target_type": "text",
                "target_value": "safe text content",
                "client_id": "batch-client-002",
            },
        ],
    }

    response = client.post(
        "/api/scan/batch",
        headers={"x-api-key": "test-api-key"},
        json=payload,
    )
    assert response.status_code == 200
    data = response.json()

    assert data["count"] == 2
    assert len(data["items"]) == 2
    assert data["items"][0]["client_id"] == "batch-client-001"
    assert data["items"][1]["client_id"] == "batch-client-002"


def test_scan_batch_rejects_empty_items():
    payload = {
        "items": [],
    }

    response = client.post(
        "/api/scan/batch",
        headers={"x-api-key": "test-api-key"},
        json=payload,
    )

    assert response.status_code == 422


def test_scan_batch_rejects_invalid_item_shape():
    payload = {
        "items": [
            {
                "target_type": "http_url",
                "target_value": "https://example.com/not-valid-for-schema",
                "client_id": "batch-client-003",
            },
        ],
    }

    response = client.post(
        "/api/scan/batch",
        headers={"x-api-key": "test-api-key"},
        json=payload,
    )

    assert response.status_code == 422


def test_scan_batch_route_allows_access_with_api_key():
    payload = {
        "items": [
            {
                "target_type": "url",
                "target_value": "https://example.com/ok",
                "client_id": "batch-client-004",
            },
        ],
    }

    response = client.post(
        "/api/scan/batch",
        headers={"x-api-key": "test-api-key"},
        json=payload,
    )

    assert response.status_code == 200
