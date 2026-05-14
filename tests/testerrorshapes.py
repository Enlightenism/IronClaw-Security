from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app, raise_server_exceptions=False)


def test_unknown_route_returns_json_error_shape() -> None:
    response = client.get("/this-route-does-not-exist")

    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)
    assert any(key in data for key in ("detail", "message", "error", "status"))


def test_unknown_organization_route_returns_error_shape() -> None:
    response = client.get("/organizations/org-does-not-exist")

    assert response.status_code in {200, 404}
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)


def test_invalid_method_returns_json_or_empty_error_response() -> None:
    response = client.post("/ui/routes")

    assert response.status_code in {404, 405}
    content_type = response.headers.get("content-type", "")
    assert content_type == "" or content_type.startswith("application/json")


def test_openapi_document_paths_shape_is_stable() -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)
    assert "paths" in data
    assert isinstance(data["paths"], dict)


def test_validation_error_shape_is_json_when_query_param_is_invalid() -> None:
    response = client.get("/organizations?status=not-a-valid-status")

    assert response.status_code in {400, 404, 422}
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)
    assert any(key in data for key in ("detail", "message", "error", "status"))
