from __future__ import annotations

from fastapi.testclient import TestClient

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


def test_scan_endpoint_basic_ok():
    payload = {
        "target_type": "url",
        "target_value": "https://example.com/safe",
        "client_id": "scan-actor-001",
    }

    response = client.post(
        "/scan/",
        headers={"x-api-key": "test-api-key"},
        json=payload,
    )
    assert response.status_code == 200
    data = response.json()

    assert data["target_type"] == "url"
    assert data["target_value"] == "https://example.com/safe"
    assert data["client_id"] == "scan-actor-001"
    assert "verdict" in data
    assert "scan_id" in data

    history_resp = client.get(
        "/history/",
        headers={"x-api-key": "test-api-key"},
    )
    assert history_resp.status_code == 200
    history = history_resp.json()
    assert history["count"] >= 1
    assert any(item["scan_id"] == data["scan_id"] for item in history["items"])


def test_scan_endpoint_accepts_local_path_target():
    payload = {
        "target_type": "local_path",
        "target_value": "C:/temp/example.txt",
        "client_id": "scan-actor-002",
    }

    response = client.post(
        "/scan/",
        headers={"x-api-key": "test-api-key"},
        json=payload,
    )
    assert response.status_code == 200
    data = response.json()

    assert data["target_type"] == "local_path"
    assert data["target_value"] == "C:/temp/example.txt"
    assert data["client_id"] == "scan-actor-002"


def test_scan_requires_valid_payload_shape():
    payload = {
        "target_type": "http_url",
        "target_value": "https://example.com/nope",
        "client_id": "scan-actor-003",
    }

    response = client.post(
        "/scan/",
        headers={"x-api-key": "test-api-key"},
        json=payload,
    )

    assert response.status_code == 422


def test_scan_rejects_invalid_payload():
    payload = {
        "client_id": "scan-actor-004",
    }

    response = client.post(
        "/scan/",
        headers={"x-api-key": "test-api-key"},
        json=payload,
    )
    assert response.status_code == 422