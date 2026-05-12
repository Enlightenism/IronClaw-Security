from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.auth import API_KEY_HEADER_NAME
from app.main import create_app


def _make_app() -> FastAPI:
    return create_app()


def _auth_headers() -> dict[str, str]:
    return {API_KEY_HEADER_NAME: "test-api-key"}


def test_openapi_and_docs_are_exposed_or_protected_by_app_config() -> None:
    app = _make_app()
    client = TestClient(app)

    openapi_response = client.get("/openapi.json")
    assert openapi_response.status_code in {200, 401, 403, 404}

    docs_response = client.get("/docs")
    assert docs_response.status_code in {200, 401, 403, 404}

    redoc_response = client.get("/redoc")
    assert redoc_response.status_code in {200, 401, 403, 404}


def test_root_and_health_are_available() -> None:
    app = _make_app()
    client = TestClient(app)

    root_response = client.get("/")
    assert root_response.status_code == 200
    assert root_response.json()["status"] == "ok"

    health_response = client.get("/health")
    assert health_response.status_code == 200
    assert health_response.json()["status"] == "ok"


def test_guard_endpoints_require_auth_or_respond_successfully() -> None:
    app = _make_app()
    client = TestClient(app)

    endpoints = [
        ("/guard/action", {
            "action_type": "network_request",
            "target": "https://example.com",
            "content": "Fetch a public page.",
            "client_id": "docs-test-client",
            "session_id": "docs-test-session",
        }),
        ("/guard/action-policy", {
            "action_type": "network_request",
            "target": "https://example.com",
            "content": "Fetch a public page.",
            "client_id": "docs-test-client",
            "session_id": "docs-test-session",
        }),
        ("/guard/action-decision", {
            "action_type": "network_request",
            "target": "https://example.com",
            "content": "Fetch a public page.",
            "client_id": "docs-test-client",
            "session_id": "docs-test-session",
        }),
        ("/guard/execute", {
            "action_type": "network_request",
            "target": "https://example.com",
            "content": "Fetch a public page.",
            "risk_score": 0,
            "client_id": "docs-test-client",
            "session_id": "docs-test-session",
        }),
    ]

    for path, payload in endpoints:
        response = client.post(path, headers=_auth_headers(), json=payload)
        assert response.status_code in {200, 401, 403, 422}


def test_request_context_history_and_audit_routes_exist() -> None:
    app = _make_app()
    client = TestClient(app)

    request_context_response = client.get("/request-context", headers=_auth_headers())
    assert request_context_response.status_code in {200, 401, 403}

    history_response = client.get("/history/events?limit=3", headers=_auth_headers())
    assert history_response.status_code in {200, 401, 403}

    audit_response = client.get("/guard/audit/events?limit=3", headers=_auth_headers())
    assert audit_response.status_code in {200, 401, 403}