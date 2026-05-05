from __future__ import annotations


from time import perf_counter

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.core.api_keys import get_api_key_registry
from app.core.auth import API_KEY_HEADER_NAME
from app.core.usage_metering import get_usage_metering_registry


def _resolve_api_key_record(raw_api_key: str):
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


def _resolve_route_path(request: Request) -> str:
    route = request.scope.get("route")
    route_path = getattr(route, "path", None)
    if isinstance(route_path, str) and route_path.strip():
        return route_path
    return request.url.path


def _resolve_units(request: Request) -> int:
    path = request.url.path
    if path.startswith("/guard"):
        return 5
    if path.startswith("/scan"):
        return 2
    return 1


class UsageMeteringMiddleware(BaseHTTPMiddleware):
    """
    Middleware that records lightweight per-request usage events.

    Design goals:
    - No hard dependency on auth success.
    - Only meter requests that present a known API key.
    - Keep event payload compact and stable for future billing pipelines.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        started_at = perf_counter()
        response = await call_next(request)
        duration_ms = round((perf_counter() - started_at) * 1000, 3)

        raw_api_key = request.headers.get(API_KEY_HEADER_NAME)
        if not isinstance(raw_api_key, str):
            return response

        raw_api_key = raw_api_key.strip()
        if not raw_api_key:
            return response

        record = _resolve_api_key_record(raw_api_key)
        if record is None or not getattr(record, "active", True):
            return response

        key_id = getattr(record, "key_id", None)
        if not key_id:
            return response

        request_id = getattr(request.state, "request_id", None)

        get_usage_metering_registry().record_event(
            api_key_id=key_id,
            route=_resolve_route_path(request),
            method=request.method,
            status_code=response.status_code,
            units=_resolve_units(request),
            metadata={
                "path": request.url.path,
                "duration_ms": duration_ms,
                "request_id": request_id,
            },
        )

        return response