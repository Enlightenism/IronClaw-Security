from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.claude_guard_router import router as claude_guard_router


def _build_test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(claude_guard_router)
    return app


def _headers() -> dict[str, str]:
    return {"X-API-Key": "test-key"}


def test_guard_router_rejects_invalid_guard_mode_by_falling_back_to_enforce() -> None:
    app = _build_test_app()
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
    app = _build_test_app()
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
    app = _build_test_app()
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