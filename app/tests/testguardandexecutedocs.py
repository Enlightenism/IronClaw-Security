from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app


def test_guard_execute_route_declares_api_key_security_in_openapi() -> None:
    client = TestClient(app)

    response = client.get("/openapi.json")

    assert response.status_code == 200
    document = response.json()

    guard_execute_post = document["paths"]["/guard/execute"]["post"]
    assert guard_execute_post["security"] == [{"APIKeyHeader": []}]


def test_guard_action_routes_declare_api_key_security_in_openapi() -> None:
    client = TestClient(app)

    response = client.get("/openapi.json")

    assert response.status_code == 200
    document = response.json()

    assert document["paths"]["/guard/action-policy"]["post"]["security"] == [{"APIKeyHeader": []}]
    assert document["paths"]["/guard/action-decision"]["post"]["security"] == [{"APIKeyHeader": []}]


def test_unprotected_guard_route_remains_unsecured_in_openapi() -> None:
    client = TestClient(app)

    response = client.get("/openapi.json")

    assert response.status_code == 200
    document = response.json()

    guard_action_post = document["paths"]["/guard/action"]["post"]
    assert "security" not in guard_action_post


def test_docs_html_mentions_api_key_header_name() -> None:
    client = TestClient(app)

    response = client.get("/docs")

    assert response.status_code == 200
    assert "X-API-Key" in response.text or "APIKeyHeader" in response.text