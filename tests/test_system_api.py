from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app


def test_root_returns_ok() -> None:
    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_returns_ok() -> None:
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_docs_route_is_available() -> None:
    with TestClient(app) as client:
        response = client.get("/docs")

    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")


def test_redoc_route_is_disabled() -> None:
    with TestClient(app) as client:
        response = client.get("/redoc")

    assert response.status_code == 404


def test_openapi_route_is_available() -> None:
    with TestClient(app) as client:
        response = client.get("/openapi.json")

    assert response.status_code == 200
    assert response.headers.get("content-type", "").startswith("application/json")