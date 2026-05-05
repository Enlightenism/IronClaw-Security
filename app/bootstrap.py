from __future__ import annotations

from time import perf_counter
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Request

from app.core.settings import get_settings


class InMemoryHistoryService:
    def __init__(self) -> None:
        self._items: list[dict[str, Any]] = []

    def append_scan_result(self, result: dict[str, Any]) -> None:
        self._items.append(dict(result))

    def list_results(self) -> list[dict[str, Any]]:
        return list(self._items)

    def get_result(self, scan_id: str) -> dict[str, Any] | None:
        for item in self._items:
            if item.get("scan_id") == scan_id:
                return dict(item)
        return None


class DefaultScannerService:
    def perform_scan(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return {}


class DefaultGuardService:
    def evaluate(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return {}


class DefaultActionPolicyService:
    def evaluate(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return {}


class DefaultActionDecisionService:
    def evaluate(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return {}


def configure_app_state(app: FastAPI) -> FastAPI:
    settings = get_settings()

    if not hasattr(app.state, "settings"):
        app.state.settings = settings

    if not hasattr(app.state, "scanner_service"):
        app.state.scanner_service = DefaultScannerService()

    if not hasattr(app.state, "history_service"):
        app.state.history_service = InMemoryHistoryService()

    if not hasattr(app.state, "guard_service"):
        app.state.guard_service = DefaultGuardService()

    if not hasattr(app.state, "action_policy_service"):
        app.state.action_policy_service = DefaultActionPolicyService()

    if not hasattr(app.state, "action_decision_service"):
        app.state.action_decision_service = DefaultActionDecisionService()

    return app


def add_request_tracing_middleware(app: FastAPI) -> FastAPI:
    if getattr(app.state, "_request_tracing_middleware_installed", False):
        return app

    @app.middleware("http")
    async def add_request_tracing(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid4())
        trace_id = request.headers.get("X-Trace-ID") or request_id
        started_at = perf_counter()

        request.state.request_id = request_id
        request.state.trace_id = trace_id
        request.state.request_started_at = started_at

        response = await call_next(request)

        duration_ms = max(0, int((perf_counter() - started_at) * 1000))

        response.headers.setdefault("X-Request-ID", request_id)
        response.headers.setdefault("X-Trace-ID", trace_id)
        response.headers.setdefault("X-Response-Time-Ms", str(duration_ms))

        return response

    app.state._request_tracing_middleware_installed = True
    return app


def add_security_middleware(app: FastAPI) -> FastAPI:
    if getattr(app.state, "_security_middleware_installed", False):
        return app

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("X-XSS-Protection", "1; mode=block")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        if request.url.scheme == "https":
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response

    app.state._security_middleware_installed = True
    return app


def bootstrap_app(app: FastAPI) -> FastAPI:
    """
    Entry point to configure global app state and middleware.
    Call this once, right after creating the FastAPI() instance.
    """
    app = configure_app_state(app)
    app = add_request_tracing_middleware(app)
    app = add_security_middleware(app)
    return app