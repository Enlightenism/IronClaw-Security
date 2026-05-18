from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
authed_client = TestClient(app, headers={"X-API-Key": "test-api-key"})


def test_missing_route_returns_json_error_shape():
    response = client.get("/definitely-not-a-real-route")
    assert response.status_code == 404

    body = response.json()
    assert isinstance(body, dict)
    assert "detail" in body


def test_guard_execute_validation_error_shape():
    response = authed_client.post("/guard/execute", json={})
    assert response.status_code == 422

    body = response.json()
    assert isinstance(body, dict)
    assert body.get("error") == "validation_error"
    assert body.get("message") == "Request validation failed"
    assert "details" in body
    assert isinstance(body["details"], dict)
    assert "errors" in body["details"]
    assert isinstance(body["details"]["errors"], list)
    assert len(body["details"]["errors"]) > 0


def test_history_lookup_missing_resource_error_shape():
    response = authed_client.get("/history/does-not-exist")
    assert response.status_code in {404, 422}

    body = response.json()
    assert isinstance(body, dict)
    assert body, "Error body should not be empty"


def test_policy_bundle_wrong_method_error_shape_stays_json():
    response = client.get("/policy/guard-bundle")
    assert response.status_code == 405

    content_type = response.headers.get("content-type", "").lower()
    assert "application/json" in content_type

    body = response.json()
    assert isinstance(body, dict)
    assert "detail" in body
