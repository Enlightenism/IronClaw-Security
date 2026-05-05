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


def test_org_context_endpoint_requires_authentication() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get("/api/org-context/context")

    assert response.status_code in {401, 403}


def test_org_context_endpoint_allows_authenticated_request() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get("/api/org-context/context", headers=_auth_headers())

    assert response.status_code == 200


def test_org_context_endpoint_returns_json_contract() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get("/api/org-context/context", headers=_auth_headers())

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    body = response.json()
    assert "org" in body
    assert isinstance(body["org"], dict)


def test_explicit_org_context_endpoint_allows_authenticated_request() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get(
        "/api/org-context/explicit",
        headers=_auth_headers(**{"x-org-id": "org-test"}),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["explicit"] is True


def test_authenticated_org_context_endpoint_allows_authenticated_request() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get(
        "/api/org-context/authenticated",
        headers=_auth_headers(),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["authenticated"] is True
    assert "principal_id" in body
    assert "target_org_id" in body


def test_operator_org_context_endpoint_allows_authenticated_request() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get(
        "/api/org-context/operator",
        headers=_auth_headers(**{"x-org-id": "org-test"}),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["authorized"] is True
    assert body["scope"] == "operator_org_context"


def test_customer_org_context_endpoint_allows_authenticated_request() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get(
        "/api/org-context/customer",
        headers=_auth_headers(**{"x-org-id": "org-test"}),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["authorized"] is True
    assert body["scope"] == "customer_org_context"


def test_org_context_endpoint_accepts_query_org_id() -> None:
    app = _make_app()
    client = TestClient(app)

    response = client.get(
        "/api/org-context/context",
        params={"org_id": "org-query-test"},
        headers=_auth_headers(),
    )

    assert response.status_code == 200
    body = response.json()
    assert "org" in body


def test_org_context_related_endpoints_return_json() -> None:
    app = _make_app()
    client = TestClient(app)

    paths = [
        "/api/org-context/context",
        "/api/org-context/authenticated",
    ]

    for path in paths:
        response = client.get(path, headers=_auth_headers())
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")