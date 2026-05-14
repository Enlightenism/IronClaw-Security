from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.auth import API_KEY_HEADER_NAME
from app.main import create_app


def _make_app() -> FastAPI:
    return create_app()


def _auth_headers(api_key: str = "test-api-key") -> dict[str, str]:
    return {API_KEY_HEADER_NAME: api_key}


def test_operator_permissions_read_requires_authentication() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get("/api/operator-auth/permissions/read")

    assert response.status_code in {401, 403}


def test_operator_permissions_read_allows_authenticated_request() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get(
        "/api/operator-auth/permissions/read",
        headers=_auth_headers(),
    )

    assert response.status_code == 200


def test_operator_permissions_write_requires_authentication() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get("/api/operator-auth/permissions/write")

    assert response.status_code in {401, 403}


def test_operator_permissions_write_allows_authenticated_request() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get(
        "/api/operator-auth/permissions/write",
        headers=_auth_headers(),
    )

    assert response.status_code == 200


def test_operator_permissions_manage_allows_authenticated_request() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get(
        "/api/operator-auth/permissions/manage",
        headers=_auth_headers(),
    )

    assert response.status_code == 200


def test_operator_permissions_endpoints_return_json() -> None:
    app = _make_app()
    client = TestClient(app)

    paths = [
        "/api/operator-auth/permissions/read",
        "/api/operator-auth/permissions/write",
        "/api/operator-auth/permissions/manage",
    ]

    for path in paths:
        response = client.get(path, headers=_auth_headers())
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")


def test_operator_permissions_read_response_contract() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get(
        "/api/operator-auth/permissions/read",
        headers=_auth_headers(),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["authorized"] is True
    assert body["scope"] == "operator_permission"
    assert "principal_id" in body
    assert "org_id" in body


def test_operator_permissions_write_response_contract() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get(
        "/api/operator-auth/permissions/write",
        headers=_auth_headers(),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["authorized"] is True
    assert body["scope"] == "operator_permission"
    assert "principal_id" in body
    assert "org_id" in body
