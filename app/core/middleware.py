from __future__ import annotations

from time import perf_counter
from typing import Any

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.apikeys import get_api_key_registry
from app.core.auth import API_KEY_HEADER_NAME
from app.core.usage_metering import get_usage_metering_registry


def _resolve_api_key_record(raw_api_key: str) -> Any:
    registry = get_api_key_registry()

    resolver = getattr(registry, "resolve_api_key", None)
    if callable(resolver):
        try:
            record = resolver(raw_api_key)
            if record is not None:
                return record
        except Exception:
            pass

    authenticate = getattr(registry, "authenticate", None)
    if callable(authenticate):
        try:
            record = authenticate(raw_api_key, touch=False)
            if record is not None:
                return record
        except TypeError:
            try:
                record = authenticate(raw_api_key)
                if record is not None:
                    return record
            except Exception:
                pass
        except Exception:
            pass

    return None


def _resolve_route_path(scope: Scope) -> str:
    route = scope.get("route")
    route_path = getattr(route, "path", None)
    if isinstance(route_path, str) and route_path.strip():
        return route_path

    path = scope.get("path")
    if isinstance(path, str) and path.strip():
        return path

    return "/"


def _resolve_units_from_path(path: str) -> int:
    if path.startswith("/guard"):
        return 5
    if path.startswith("/scan"):
        return 2
    return 1


class UsageMeteringMiddleware:
    """Record lightweight per-request usage events for authenticated API-key callers.

    Design goals:
    - No hard dependency on auth success.
    - Only meter requests that present a known active API key.
    - Never block or alter request handling.
    - Never interfere with CORS preflight OPTIONS handling.
    - Keep event payload compact and stable for future billing pipelines.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = str(scope.get("method", "")).upper()
        if method == "OPTIONS":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        raw_api_key = headers.get(API_KEY_HEADER_NAME)
        if not isinstance(raw_api_key, str):
            await self.app(scope, receive, send)
            return

        raw_api_key = raw_api_key.strip()
        if not raw_api_key:
            await self.app(scope, receive, send)
            return

        started_at = perf_counter()
        response_started_message: Message | None = None

        async def send_wrapper(message: Message) -> None:
            nonlocal response_started_message
            if message["type"] == "http.response.start":
                response_started_message = message
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration_ms = round((perf_counter() - started_at) * 1000, 3)

            if response_started_message is not None:
                record = _resolve_api_key_record(raw_api_key)
                if record is not None and getattr(record, "active", True):
                    key_id = getattr(record, "key_id", None)
                    if key_id:
                        state = scope.get("state") or {}
                        request_id = state.get("request_id")
                        path = str(scope.get("path", "") or "")
                        route_path = _resolve_route_path(scope)

                        try:
                            get_usage_metering_registry().record_event(
                                api_key_id=key_id,
                                route=route_path,
                                method=method,
                                status_code=int(response_started_message["status"]),
                                units=_resolve_units_from_path(path),
                                metadata={
                                    "path": path,
                                    "duration_ms": duration_ms,
                                    "request_id": request_id,
                                },
                            )
                        except Exception:
                            pass
