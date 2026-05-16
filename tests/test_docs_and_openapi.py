from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def setup_function() -> None:
    app.openapi_schema = None


def test_docs_endpoint_is_available():
    response = client.get("/docs")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "").lower()


def test_openapi_json_is_available():
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert "application/json" in response.headers.get("content-type", "").lower()

    body = response.json()
    assert isinstance(body, dict)
    assert "openapi" in body
    assert "paths" in body
    assert isinstance(body["paths"], dict)
    assert body["paths"], "OpenAPI paths should not be empty"


def test_openapi_includes_core_paths():
    response = client.get("/openapi.json")
    assert response.status_code == 200

    paths = response.json()["paths"]

    expected_paths = {
        "/",
        "/health",
        "/scan/",
        "/scan/batch",
        "/history/",
        "/history/{scan_id}",
        "/history/{scan_id}/review",
        "/history/events",
        "/guard/reviews/summary",
        "/guard/reviews/pending",
        "/guard/reviews/{review_id}",
        "/guard/reviews/{review_id}/approve",
        "/guard/reviews/{review_id}/reject",
        "/guard/audit/events",
        "/guard/execute",
        "/policy/status",
        "/policy/guard-bundle",
    }

    missing = expected_paths - set(paths.keys())
    assert not missing, f"Missing OpenAPI paths: {sorted(missing)}"


def test_openapi_describes_guard_execute_post():
    response = client.get("/openapi.json")
    assert response.status_code == 200

    paths = response.json()["paths"]
    guard_execute = paths["/guard/execute"]
    assert "post" in guard_execute

    post_op = guard_execute["post"]
    assert "responses" in post_op
    assert "requestBody" in post_op
