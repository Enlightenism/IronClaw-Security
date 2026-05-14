from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.auth import API_KEY_HEADER_NAME
from app.main import create_app


def _make_app() -> FastAPI:
    return create_app()


def _auth_headers(api_key: str = "test-api-key") -> dict[str, str]:
    return {API_KEY_HEADER_NAME: api_key}


def test_auth_integration_api_key_header_name_is_accepted_by_application() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get("/api/auth/context", headers=_auth_headers())

    assert response.status_code == 200


def test_auth_integration_invalid_api_key_shape_does_not_break_error_contract() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get("/api/auth/me", headers=_auth_headers(api_key=""))

    assert response.status_code in {401, 403, 422}


def test_auth_integration_protection_applies_to_verified_routes() -> None:
    app = _make_app()
    client = TestClient(app)

    protected_paths = [
        "/api/auth/me",
        "/api/auth/context",
        "/api/operator-auth/context",
        "/api/customer-auth/context",
        "/api/session-security/context",
        "/api/access-control/context",
        "/api/org-context/authenticated",
    ]

    for path in protected_paths:
        unauthorized = client.get(path)
        authorized = client.get(path, headers=_auth_headers())

        assert unauthorized.status_code in {401, 403}
        assert authorized.status_code == 200


def test_auth_integration_endpoints_keep_auth_contract_with_api_key() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get("/api/auth/context", headers=_auth_headers())

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    assert "authenticated" in body
    assert "principal_type" in body


def test_auth_integration_operator_auth_endpoint_is_protected() -> None:
    app = _make_app()
    client = TestClient(app)

    unauthorized = client.get("/api/operator-auth/context")
    authorized = client.get("/api/operator-auth/context", headers=_auth_headers())

    assert unauthorized.status_code in {401, 403}
    assert authorized.status_code == 200


def test_auth_integration_customer_auth_endpoint_is_protected() -> None:
    app = _make_app()
    client = TestClient(app)

    unauthorized = client.get("/api/customer-auth/context")
    authorized = client.get("/api/customer-auth/context", headers=_auth_headers())

    assert unauthorized.status_code in {401, 403}
    assert authorized.status_code == 200


def test_auth_integration_session_security_endpoint_is_protected() -> None:
    app = _make_app()
    client = TestClient(app)

    unauthorized = client.get("/api/session-security/context")
    authorized = client.get("/api/session-security/context", headers=_auth_headers())

    assert unauthorized.status_code in {401, 403}
    assert authorized.status_code == 200


def test_auth_integration_access_control_endpoint_is_protected() -> None:
    app = _make_app()
    client = TestClient(app)

    unauthorized = client.get("/api/access-control/context")
    authorized = client.get("/api/access-control/context", headers=_auth_headers())

    assert unauthorized.status_code in {401, 403}
    assert authorized.status_code == 200


def test_auth_integration_org_context_authenticated_endpoint_is_protected() -> None:
    app = _make_app()
    client = TestClient(app)

    unauthorized = client.get("/api/org-context/authenticated")
    authorized = client.get("/api/org-context/authenticated", headers=_auth_headers())

    assert unauthorized.status_code in {401, 403}
    assert authorized.status_code == 200
