from __future__ import annotations

from dataclasses import dataclass
import logging
import math
import time
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from app.core.logging import get_logger

_logger: logging.Logger = get_logger("ironclaw.rate_limiter")

_T_RATE_LIMIT_STATE = "rate_limit_state"

DEFAULT_LIMIT: int = 60
DEFAULT_WINDOW_SECONDS: int = 60


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    key: str
    allowed: bool
    limit: int
    remaining: int
    window_seconds: int
    window_start: float
    current_count: int
    retry_after: int


def _build_429_headers(result: RateLimitResult) -> dict[str, str]:
    return {
        "Retry-After": str(result.retry_after),
        "X-RateLimit-Limit": str(result.limit),
        "X-RateLimit-Remaining": "0",
        "X-RateLimit-Reset": str(int(result.window_start) + result.window_seconds),
        "X-RateLimit-Window": str(result.window_seconds),
    }


def raise_429(result: RateLimitResult) -> None:
    """Raise HTTPException 429 with Retry-After and X-RateLimit-* headers."""
    headers = _build_429_headers(result)
    raise HTTPException(
        status_code=429,
        detail={
            "error": "rate_limit_exceeded",
            "message": f"Rate limit of {result.limit} requests per {result.window_seconds}s exceeded.",
            "retry_after_seconds": result.retry_after,
            "limit": result.limit,
            "window_seconds": result.window_seconds,
        },
        headers=headers,
    )


def build_429_response(result: RateLimitResult) -> JSONResponse:
    """Return a JSONResponse 429 with Retry-After and X-RateLimit-* headers.

    Use this variant when you need to return a response without raising
    (e.g. in middleware where raising is not appropriate).
    """
    headers = _build_429_headers(result)
    return JSONResponse(
        status_code=429,
        content={
            "error": "rate_limit_exceeded",
            "message": f"Rate limit of {result.limit} requests per {result.window_seconds}s exceeded.",
            "retry_after_seconds": result.retry_after,
            "limit": result.limit,
            "window_seconds": result.window_seconds,
        },
        headers=headers,
    )


def _get_client():
    from app.core.supabase import get_supabase_service_client  # noqa: PLC0415

    return get_supabase_service_client()


def _supabase_errors() -> tuple[type[Exception], type[Exception]]:
    from app.supabaseclient import SupabaseAPIError, SupabaseClientError  # noqa: PLC0415

    return SupabaseAPIError, SupabaseClientError


def _now_ts() -> float:
    return time.time()


def check_and_increment(
    key: str,
    limit: int = DEFAULT_LIMIT,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> RateLimitResult:
    """Sliding-window rate check and increment for ``key``.

    Returns a ``RateLimitResult`` describing the current window state.
    The caller is responsible for calling ``raise_429(result)`` or
    ``build_429_response(result)`` when ``result.allowed`` is False.

    This function never raises on Supabase errors — it fails open
    (allowed=True) and logs the error, so a DB outage does not block
    legitimate traffic.
    """
    if not key or not key.strip():
        raise ValueError("rate limiter key must be a non-empty string")

    key = key.strip()
    now = _now_ts()
    window_start = now
    count = 1

    try:
        client = _get_client()

        fetch_resp = client.table(_T_RATE_LIMIT_STATE).select("count, window_start, window_seconds, rate_limit").eq("key", key).maybe_single().execute()
        row: dict[str, Any] | None = None
        raw = fetch_resp.data
        if isinstance(raw, dict) and raw:
            row = raw
        elif isinstance(raw, list) and raw:
            row = raw[0]

        if row is not None:
            stored_window_start = float(row.get("window_start") or now)
            stored_window_seconds = int(row.get("window_seconds") or window_seconds)
            stored_count = int(row.get("count") or 0)
            window_elapsed = now - stored_window_start

            if window_elapsed >= stored_window_seconds:
                window_start = now
                count = 1
            else:
                window_start = stored_window_start
                count = stored_count + 1
        else:
            window_start = now
            count = 1

        upsert_record: dict[str, Any] = {
            "key": key,
            "count": count,
            "window_start": window_start,
            "window_seconds": window_seconds,
            "rate_limit": limit,
            "updated_at": _iso_now(),
        }

        client.table(_T_RATE_LIMIT_STATE).upsert(
            upsert_record,
            on_conflict="key",
            returning="minimal",
        ).execute()

    except Exception as exc:  # noqa: BLE001
        SupabaseAPIError, SupabaseClientError = _supabase_errors()
        _logger.error(
            "rate_limiter: DB error for key=%r: %s",
            key,
            exc,
            exc_info=isinstance(exc, (SupabaseAPIError, SupabaseClientError)),
        )
        return RateLimitResult(
            key=key,
            allowed=True,
            limit=limit,
            remaining=limit,
            window_seconds=window_seconds,
            window_start=now,
            current_count=0,
            retry_after=0,
        )

    allowed = count <= limit
    remaining = max(0, limit - count)

    if allowed:
        retry_after = 0
    else:
        elapsed = now - window_start
        retry_after = max(1, math.ceil(window_seconds - elapsed))

    result = RateLimitResult(
        key=key,
        allowed=allowed,
        limit=limit,
        remaining=remaining,
        window_seconds=window_seconds,
        window_start=window_start,
        current_count=count,
        retry_after=retry_after,
    )

    if not allowed:
        _logger.warning(
            "rate_limiter.exceeded",
            extra={
                "key": key,
                "count": count,
                "limit": limit,
                "window_seconds": window_seconds,
                "retry_after": retry_after,
            },
        )
    else:
        _logger.debug(
            "rate_limiter.allowed",
            extra={
                "key": key,
                "count": count,
                "limit": limit,
                "remaining": remaining,
            },
        )

    return result


def key_for_ip(request: Request) -> str:
    """Build a rate limit key from the client IP address."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        ip = forwarded_for.split(",")[0].strip()
    else:
        ip = request.client.host if request.client else "unknown"
    return f"ip:{ip}"


def key_for_agent(agent_id: str) -> str:
    """Build a rate limit key scoped to an agent_id."""
    if not agent_id or not agent_id.strip():
        return "agent:unknown"
    return f"agent:{agent_id.strip()}"


def key_for_api_key(api_key: str) -> str:
    """Build a rate limit key scoped to an API key (last 8 chars only — never log full key)."""
    if not api_key or len(api_key) < 4:
        return "apikey:unknown"
    return f"apikey:{api_key[-8:]}"


def key_composite(prefix: str, *parts: str) -> str:
    """Build a composite rate limit key from arbitrary string parts.

    Example: key_composite("scan", agent_id, endpoint)
    """
    clean = ":".join(p.strip() for p in parts if p and p.strip())
    return f"{prefix.strip()}:{clean}" if clean else prefix.strip()


def rate_limit_dependency(
    limit: int = DEFAULT_LIMIT,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
):
    """Return a FastAPI dependency that enforces a per-IP sliding window limit.

    Usage:
        @router.post("/scan", dependencies=[Depends(rate_limit_dependency(60, 60))])

    The dependency raises HTTP 429 with Retry-After when the limit is exceeded.
    """

    async def _dep(request: Request) -> RateLimitResult:
        key = key_for_ip(request)
        result = check_and_increment(key, limit=limit, window_seconds=window_seconds)
        if not result.allowed:
            raise_429(result)
        return result

    return _dep


def agent_rate_limit_dependency(
    agent_id_param: str,
    limit: int = DEFAULT_LIMIT,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
):
    """Return a FastAPI dependency that enforces a per-agent sliding window limit.

    Usage:
        @router.post("/scan", dependencies=[Depends(agent_rate_limit_dependency("agent_id", 100, 60))])

    ``agent_id_param`` is the name of the path or query parameter carrying the agent_id.
    """

    async def _dep(request: Request) -> RateLimitResult:
        agent_id = request.path_params.get(agent_id_param) or request.query_params.get(agent_id_param) or "unknown"
        key = key_for_agent(str(agent_id))
        result = check_and_increment(key, limit=limit, window_seconds=window_seconds)
        if not result.allowed:
            raise_429(result)
        return result

    return _dep


def reset_key(key: str) -> bool:
    """Delete the rate_limit_state row for ``key``.

    Returns True on success, False on error.

    .. deprecated::
        Admin-facing callers and routers should call
        ``supabase_persistence.delete_rate_limit_state(key)`` directly.
        That function raises ``PersistenceError`` on failure and stays within
        the canonical persistence boundary.  This wrapper is retained for
        internal use by ``check_and_increment`` and any existing test fixtures
        that depend on the bool return contract.
    """
    key = key.strip() if key else ""
    if not key:
        return False
    try:
        from app.core.supabase_persistence import delete_rate_limit_state  # noqa: PLC0415

        delete_rate_limit_state(key)
        return True
    except Exception as exc:  # noqa: BLE001
        _logger.error("rate_limiter.reset_key error for key=%r: %s", key, exc)
        return False


def get_key_state(key: str) -> dict[str, Any] | None:
    """Return the raw rate_limit_state row for ``key``, or None if not found.

    .. deprecated::
        Admin-facing callers and routers should call
        ``supabase_persistence.get_rate_limit_state(key)`` directly.
        That function raises ``PersistenceError`` on failure and stays within
        the canonical persistence boundary.  This wrapper is retained for
        internal health-check callers and existing test fixtures that depend
        on the None-on-error contract.
    """
    key = key.strip() if key else ""
    if not key:
        return None
    try:
        from app.core.supabase_persistence import get_rate_limit_state  # noqa: PLC0415

        return get_rate_limit_state(key)
    except Exception as exc:  # noqa: BLE001
        _logger.error("rate_limiter.get_key_state error for key=%r: %s", key, exc)
        return None


def _iso_now() -> str:
    from datetime import UTC, datetime  # noqa: PLC0415

    return datetime.now(UTC).isoformat()


__all__ = [
    "RateLimitResult",
    "DEFAULT_LIMIT",
    "DEFAULT_WINDOW_SECONDS",
    "check_and_increment",
    "raise_429",
    "build_429_response",
    "key_for_ip",
    "key_for_agent",
    "key_for_api_key",
    "key_composite",
    "rate_limit_dependency",
    "agent_rate_limit_dependency",
    "reset_key",
    "get_key_state",
]
