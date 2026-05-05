from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.auth import API_KEY_HEADER_NAME
from app.main import create_app


def _make_app() -> FastAPI:
    return create_app()


def _auth_headers(api_key: str = "test-api-key", **extra_headers: str) -> dict[str, str]:
    headers = {API_KEY_HEADER_NAME: api_key}
    headers.update(extra_headers)
    return headers


def test_missing_api_key_returns_unauthorized_or_forbidden() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get("/organizations")

    assert response.status_code in {401, 403}


def test_blank_api_key_keeps_error_contract() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get("/organizations", headers=_auth_headers(api_key=""))

    assert response.status_code in {401, 403, 422}


def test_protected_auth_routes_reject_missing_api_key() -> None:
    app = _make_app()
    client = TestClient(app)

    paths = [
        "/api/auth/context",
        "/api/operator-auth/context",
        "/api/customer-auth/context",
        "/api/session-security/context",
        "/api/access-control/context",
        "/api/org-context/context",
    ]

    for path in paths:
        response = client.get(path)
        assert response.status_code in {401, 403}


def test_permission_routes_reject_missing_api_key() -> None:
    app = _make_app()
    client = TestClient(app)

    paths = [
        "/api/operator-auth/permissions/read",
        "/api/operator-auth/permissions/write",
        "/api/customer-auth/permissions/read",
        "/api/customer-auth/permissions/write",
    ]

    for path in paths:
        response = client.get(path)
        assert response.status_code in {401, 403}


def test_explicit_org_context_endpoint_rejects_missing_auth() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get(
        "/api/org-context/explicit",
        headers={"x-org-id": "org-test"},
    )

    assert response.status_code in {401, 403}


def test_invalid_auth_requests_keep_json_error_shape_when_present() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get("/api/auth/context")

    assert response.status_code in {401, 403}
    if response.headers.get("content-type", "").startswith("application/json"):
        body = response.json()
        assert isinstance(body, dict)


def test_forbidden_style_responses_do_not_return_success_status() -> None:
    app = _make_app()
    client = TestClient(app)

    paths = [
        "/organizations",
        "/dashboard/overview",
        "/api/auth/context",
        "/api/operator-auth/context",
        "/api/customer-auth/context",
    ]

    for path in paths:
        response = client.get(path)
        assert response.status_code not in {200, 201, 202, 204}