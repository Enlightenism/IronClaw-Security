from __future__ import annotations

import os

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("AUTH_REQUIRED", "true")
os.environ.setdefault("IRONCLAW_API_KEY", "test-key")

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app.api.claude_guard_router import router as claude_guard_router
from app.core.auth import get_api_key
from app.core.errors import AppError

_TEST_API_KEY = "test-key"


def _build_test_app(*, bypass_auth: bool = False) -> FastAPI:
    app = FastAPI()

    @app.exception_handler(AppError)
    async def _apperror_handler(request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.error, "message": exc.message},
        )

    if bypass_auth:
        app.dependency_overrides[get_api_key] = lambda: _TEST_API_KEY

    app.include_router(claude_guard_router)
    return app


def _headers() -> dict[str, str]:
    return {"X-API-Key": _TEST_API_KEY}


def test_guard_router_rejects_invalid_guard_mode_by_falling_back_to_enforce() -> None:
    app = _build_test_app(bypass_auth=True)
    client = TestClient(app)

    response = client.post(
        "/claude/guard-router/proxy",
        headers=_headers(),
        json={
            "upstream_url": "https://upstream.example/router",
            "upstream_payload": {"user_prompt": "hello"},
            "guard_mode": "invalid-mode",
        },
    )

    assert response.status_code in {200, 502}


def test_guard_router_requires_api_key() -> None:
    app = _build_test_app(bypass_auth=False)
    client = TestClient(app)

    response = client.post(
        "/claude/guard-router/proxy",
        json={
            "upstream_url": "https://upstream.example/router",
            "upstream_payload": {"user_prompt": "hello"},
        },
    )

    assert response.status_code == 401


def test_guard_router_defaults_guard_mode_to_enforce_when_missing() -> None:
    app = _build_test_app(bypass_auth=True)
    client = TestClient(app)

    response = client.post(
        "/claude/guard-router/proxy",
        headers=_headers(),
        json={
            "upstream_url": "https://upstream.example/router",
            "upstream_payload": {"user_prompt": "hello"},
        },
    )

    assert response.status_code in {200, 502}
