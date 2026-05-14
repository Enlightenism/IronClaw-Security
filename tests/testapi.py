from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_root_endpoint_returns_success_payload() -> None:
    response = client.get("/")

    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "ok"


def test_openapi_document_is_available() -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200

    data = response.json()
    assert "openapi" in data
    assert "paths" in data
    assert "/api/actionhistorytest" in data["paths"]


def test_docs_endpoint_is_available() -> None:
    response = client.get("/docs")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_redoc_endpoint_is_available() -> None:
    response = client.get("/redoc")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_actionhistorytest_api_endpoint_is_available() -> None:
    response = client.get("/api/actionhistorytest")

    assert response.status_code == 200

    data = response.json()
    assert data["title"] == "Action History Test"
    assert data["total"] == 3


def test_ui_manifest_endpoint_is_available() -> None:
    response = client.get("/api/ui-manifest")

    assert response.status_code == 200


def test_groq_registry_endpoint_is_available() -> None:
    response = client.get("/api/groq-registry")

    assert response.status_code == 200
