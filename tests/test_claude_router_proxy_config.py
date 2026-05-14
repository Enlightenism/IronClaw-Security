from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.claude_router_proxy import router as claude_router_proxy_router
from app.core.errors import register_exception_handlers


def _build_test_app() -> FastAPI:
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(claude_router_proxy_router)
    app.state.settings = type(
        "TestSettings",
        (),
        {
            "auth_required": True,
            "api_key": "test-key",
            "admin_api_key": "",
        },
    )()
    return app


def _headers() -> dict[str, str]:
    return {"X-API-Key": "test-key"}


def test_router_proxy_requires_api_key() -> None:
    app = _build_test_app()
    client = TestClient(app, raise_server_exceptions=False)

    response = client.post(
        "/claude/router-proxy/proxy",
        json={
            "upstream_url": "https://upstream.example/router",
            "upstream_payload": {"prompt": "hello"},
        },
    )

    assert response.status_code == 401
    assert response.json()["error"] == "missing_api_key"
    assert response.json()["message"] == "Missing API key"


def test_router_proxy_requires_upstream_url_even_with_api_key() -> None:
    app = _build_test_app()
    client = TestClient(app, raise_server_exceptions=False)

    response = client.post(
        "/claude/router-proxy/proxy",
        headers=_headers(),
        json={"upstream_payload": {"prompt": "hello"}},
    )

    assert response.status_code == 400
    assert response.json()["error"] == "http_error"
    assert response.json()["message"] == "Missing 'upstream_url' in request body."


def test_router_proxy_accepts_empty_upstream_payload() -> None:
    app = _build_test_app()
    client = TestClient(app, raise_server_exceptions=False)

    response = client.post(
        "/claude/router-proxy/proxy",
        headers=_headers(),
        json={
            "upstream_url": "https://upstream.example/router",
        },
    )

    assert response.status_code in {200, 502}
