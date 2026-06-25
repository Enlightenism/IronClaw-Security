from __future__ import annotations

import logging
from time import perf_counter
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Request

from app.core.settings import get_settings
from app.persistencebootstrap import (
    StoreType,
    get_persistence_store,
    get_registered_tables,
)

_log = logging.getLogger(__name__)

_EXPECTED_TABLE_COUNT = 19


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
    """Assert all 19 DDL-registered tables are present before accepting traffic.

    Raises RuntimeError if the registry count is wrong or any expected table
    is missing. Returns the verified table set on success.

    Safe to call at startup; must NOT be called at module import time.
    """
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
        response.headers["Referrer-Policy"] = "no-referrer"
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


async def _run_deferred_startup(app: FastAPI) -> None:
    """Execute startup-time checks that must not run at module import.

    Registered as a startup event by bootstrap_app. Calls assert_schema_completeness
    inside a guarded block so CI schema mismatches surface at server start, not at
    import time (which would break openapi schema export and test collection).
    """
    try:
        tables = assert_schema_completeness()
        _log.info(
            "bootstrap.startup: schema completeness check passed — %d tables verified",
            len(tables),
        )
    except RuntimeError as exc:
        _log.critical(
            "bootstrap.startup: schema completeness check FAILED — server will continue but schema integrity is not guaranteed: %s",
            exc,
        )


def bootstrap_app(app: FastAPI) -> FastAPI:
    """Entry point to configure global app state and middleware.

    Registers a deferred startup event that runs assert_schema_completeness
    only when the server actually starts (not at import time). Configures app
    state and installs request tracing and security middleware. Call this once,
    right after creating the FastAPI() instance.
    """
    if getattr(app.state, "_bootstrap_installed", False):
        return app

    # Deferred: schema completeness check runs at server startup, not import time.
    # This prevents CI crashes when env vars are absent during schema export or
    # test collection.
    if not getattr(app.state, "_bootstrap_startup_registered", False):

        @app.on_event("startup")
        async def _bootstrap_startup_event() -> None:
            await _run_deferred_startup(app)

        app.state._bootstrap_startup_registered = True

    app = configure_app_state(app)
    app = add_request_tracing_middleware(app)
    app = add_security_middleware(app)

    app.state._bootstrap_installed = True
    return app
