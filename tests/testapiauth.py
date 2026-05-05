from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.auth import API_KEY_HEADER_NAME
from app.routes.dashboard import router as dashboard_router
from app.routes.organizations import router as organizations_router


def _build_test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(dashboard_router)
    app.include_router(organizations_router)
    return app


def _headers(api_key: str = "test-api-key") -> dict[str, str]:
    return {API_KEY_HEADER_NAME: api_key}


def test_organizations_route_accepts_api_key_header() -> None:
    client = TestClient(_build_test_app(), raise_server_exceptions=False)

    response = client.get("/organizations", headers=_headers())

    assert response.status_code == 200


def test_dashboard_route_accepts_api_key_header() -> None:
    client = TestClient(_build_test_app(), raise_server_exceptions=False)

    response = client.get("/dashboard/overview", headers=_headers())

    assert response.status_code == 200


def test_organizations_route_returns_json_with_api_key() -> None:
    client = TestClient(_build_test_app(), raise_server_exceptions=False)

    response = client.get("/organizations", headers=_headers())

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")


def test_dashboard_route_returns_json_with_api_key() -> None:
    client = TestClient(_build_test_app(), raise_server_exceptions=False)

    response = client.get("/dashboard/overview", headers=_headers())

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")


def test_api_key_header_constant_is_present() -> None:
    assert isinstance(API_KEY_HEADER_NAME, str)
    assert API_KEY_HEADER_NAME != ""


def test_routes_reject_missing_api_key_header() -> None:
    client = TestClient(_build_test_app(), raise_server_exceptions=False)

    organizations_response = client.get("/organizations")
    dashboard_response = client.get("/dashboard/overview")

    assert organizations_response.status_code in {401, 403}
    assert dashboard_response.status_code in {401, 403}


def test_routes_reject_blank_api_key_header() -> None:
    client = TestClient(_build_test_app(), raise_server_exceptions=False)

    organizations_response = client.get("/organizations", headers=_headers(api_key=""))
    dashboard_response = client.get("/dashboard/overview", headers=_headers(api_key=""))

    assert organizations_response.status_code in {401, 403, 422}
    assert dashboard_response.status_code in {401, 403, 422}


def test_api_key_header_name_works_consistently_across_routes() -> None:
    client = TestClient(_build_test_app(), raise_server_exceptions=False)

    for path in ("/organizations", "/dashboard/overview"):
        response = client.get(path, headers=_headers())
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")