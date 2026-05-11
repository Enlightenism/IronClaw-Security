from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_main_root_returns_ok() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_main_health_returns_ok() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_openapi_endpoint_is_available_or_protected() -> None:
    response = client.get("/openapi.json")
    assert response.status_code in {200, 401, 403, 404, 405}


def test_docs_endpoint_is_available_or_protected() -> None:
    response = client.get("/docs")
    assert response.status_code in {200, 401, 403, 404}