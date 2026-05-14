from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.auth import API_KEY_HEADER_NAME
from app.main import create_app


def _make_app() -> FastAPI:
    return create_app()


def _auth_headers(api_key: str = "test-api-key") -> dict[str, str]:
    return {API_KEY_HEADER_NAME: api_key}


def test_protected_routes_require_authentication() -> None:
    app = _make_app()
    client = TestClient(app)

    protected_paths = [
        "/organizations",
        "/dashboard/overview",
        "/api/auth/context",
        "/api/operator-auth/context",
        "/api/customer-auth/context",
        "/api/session-security/context",
        "/api/access-control/context",
        "/api/org-context/context",
    ]

    for path in protected_paths:
        response = client.get(path)
        assert response.status_code in {401, 403}


def test_protected_routes_allow_authenticated_requests() -> None:
    app = _make_app()
    client = TestClient(app)

    protected_paths = [
        "/organizations",
        "/dashboard/overview",
        "/api/auth/context",
        "/api/operator-auth/context",
        "/api/customer-auth/context",
        "/api/session-security/context",
        "/api/access-control/context",
        "/api/org-context/context",
    ]

    for path in protected_paths:
        response = client.get(path, headers=_auth_headers())
        assert response.status_code == 200


def test_permission_routes_require_authentication() -> None:
    app = _make_app()
    client = TestClient(app)

    permission_paths = [
        "/api/operator-auth/permissions/read",
        "/api/operator-auth/permissions/write",
        "/api/operator-auth/permissions/manage",
        "/api/customer-auth/permissions/read",
        "/api/customer-auth/permissions/write",
        "/api/customer-auth/permissions/session",
    ]

    for path in permission_paths:
        response = client.get(path)
        assert response.status_code in {401, 403}


def test_permission_routes_allow_authenticated_requests() -> None:
    app = _make_app()
    client = TestClient(app)

    permission_paths = [
        "/api/operator-auth/permissions/read",
        "/api/operator-auth/permissions/write",
        "/api/operator-auth/permissions/manage",
        "/api/customer-auth/permissions/read",
        "/api/customer-auth/permissions/write",
        "/api/customer-auth/permissions/session",
    ]

    for path in permission_paths:
        response = client.get(path, headers=_auth_headers())
        assert response.status_code == 200


def test_blank_api_key_does_not_bypass_protected_routes() -> None:
    app = _make_app()
    client = TestClient(app)

    protected_paths = [
        "/organizations",
        "/dashboard/overview",
        "/api/auth/context",
    ]

    for path in protected_paths:
        response = client.get(path, headers=_auth_headers(api_key=""))
        assert response.status_code in {401, 403, 422}


def test_protected_routes_return_json_on_success() -> None:
    app = _make_app()
    client = TestClient(app)

    protected_paths = [
        "/organizations",
        "/dashboard/overview",
        "/api/auth/context",
        "/api/operator-auth/context",
        "/api/customer-auth/context",
    ]

    for path in protected_paths:
        response = client.get(path, headers=_auth_headers())
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
