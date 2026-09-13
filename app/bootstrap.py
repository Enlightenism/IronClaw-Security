from __future__ import annotations

from collections.abc import Awaitable, Callable
import logging
from time import perf_counter
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Request, Response

from app.core.settings import get_settings
from app.persistencebootstrap import (
    StoreType,
    get_persistence_store,
    get_registered_tables,
)

_log = logging.getLogger(__name__)

_EXPECTED_TABLE_COUNT = len(get_registered_tables())


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


def assert_schema_completeness() -> frozenset[str]:
    """Assert all expected DDL-registered tables are present before accepting traffic."""
    registered = get_registered_tables()
    count = len(registered)
    if count != _EXPECTED_TABLE_COUNT:
        raise RuntimeError(f"IronClaw schema completeness check failed: expected {_EXPECTED_TABLE_COUNT} tables, registry has {count}. Tables present: {sorted(registered)}")
    _log.info(
        "bootstrap: schema completeness check passed — %d tables registered: %s",
        count,
        sorted(registered),
    )
    return registered


def configure_app_state(app: FastAPI) -> FastAPI:
    settings = get_settings()

    if not hasattr(app.state, "settings"):
        app.state.settings = settings

    if not hasattr(app.state, "persistence_store"):
        try:
            store: StoreType = get_persistence_store()
            app.state.persistence_store = store
            _log.info(
                "bootstrap: persistence store ready — backend=%s ready=%s",
                store.backend_name,
                store.ready,
            )
        except Exception as exc:  # noqa: BLE001
            _log.error("bootstrap: persistence store init failed: %s", exc)
            app.state.persistence_store = None

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

    if not hasattr(app.state, "action_execute_pipeline"):
        app.state.action_execute_pipeline = None

    return app


def add_request_tracing_middleware(app: FastAPI) -> FastAPI:
    if getattr(app.state, "_request_tracing_middleware_installed", False):
        return app

    @app.middleware("http")
    async def add_request_tracing(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
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
    async def add_security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-XSS-Protection", "1; mode=block")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        )
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; frame-ancestors 'none'; form-action 'self'",
        )
        if request.url.scheme == "https":
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response

    app.state._security_middleware_installed = True
    return app


def _run_deferred_startup(app: FastAPI) -> bool:
    """Execute startup-time checks that must not run at module import."""
    try:
        assert_schema_completeness()
        return True
    except RuntimeError as exc:
        _log.critical(
            "bootstrap.startup: schema completeness check FAILED — server will continue but schema integrity is not guaranteed: %s",
            exc,
        )
        return False


def bootstrap_app(app: FastAPI) -> FastAPI:
    """Configure global app state and lightweight header-only middleware.

    This bootstrap must not install auth, host-validation, or request-blocking
    middleware. CORS handling must be installed separately and earlier in the
    effective request pipeline so browser OPTIONS preflight requests can return
    HTTP OK before any protected API route logic is evaluated.
    """
    if getattr(app.state, "_bootstrap_installed", False):
        return app

    if not getattr(app.state, "_bootstrap_startup_registered", False):

        @app.on_event("startup")
        async def _bootstrap_startup_event() -> None:
            passed = _run_deferred_startup(app)
            if passed:
                _log.info("bootstrap.startup: schema completeness check passed — all tables verified")

        app.state._bootstrap_startup_registered = True

    app = configure_app_state(app)
    app = add_request_tracing_middleware(app)
    app = add_security_middleware(app)

    app.state._bootstrap_installed = True
    return app
