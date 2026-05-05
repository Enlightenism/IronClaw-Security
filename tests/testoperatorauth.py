from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.auth import API_KEY_HEADER_NAME
from app.main import create_app


def _make_app() -> FastAPI:
    return create_app()


def _auth_headers(api_key: str = "test-api-key") -> dict[str, str]:
    return {API_KEY_HEADER_NAME: api_key}


def test_operator_auth_context_requires_authentication() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get("/api/operator-auth/context")

    assert response.status_code in {401, 403}


def test_operator_auth_context_allows_authenticated_request() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get("/api/operator-auth/context", headers=_auth_headers())

    assert response.status_code == 200


def test_operator_auth_context_returns_json_contract() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get("/api/operator-auth/context", headers=_auth_headers())

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    body = response.json()
    assert body["authenticated"] is True
    assert "principal_id" in body
    assert "principal_type" in body
    assert "org_id" in body
    assert "roles" in body
    assert "permissions" in body


def test_operator_read_endpoint_requires_authentication() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get("/api/operator-auth/read")

    assert response.status_code in {401, 403}


def test_operator_read_endpoint_allows_authenticated_request() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get("/api/operator-auth/read", headers=_auth_headers())

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")


def test_operator_write_endpoint_allows_authenticated_request() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get("/api/operator-auth/write", headers=_auth_headers())

    assert response.status_code == 200


def test_operator_manage_endpoint_allows_authenticated_request() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get("/api/operator-auth/manage", headers=_auth_headers())

    assert response.status_code == 200


def test_operator_org_endpoint_allows_authenticated_request() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get(
        "/api/operator-auth/org",
        headers={**_auth_headers(), "x-org-id": "org-test"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["authorized"] is True
    assert body["scope"] == "operator_org"


def test_operator_permissions_read_endpoint_allows_authenticated_request() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get(
        "/api/operator-auth/permissions/read",
        headers=_auth_headers(),
    )

    assert response.status_code == 200


def test_operator_permissions_write_endpoint_allows_authenticated_request() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get(
        "/api/operator-auth/permissions/write",
        headers=_auth_headers(),
    )

    assert response.status_code == 200