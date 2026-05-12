from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Depends, Request

from app.core.auth import get_api_key
from app.core.ratelimit import rate_limit_dependency


def require_api_key(api_key: str = Depends(get_api_key)) -> str:
    return api_key


def build_rate_limit_dependency(
    scope: str,
    *,
    limit: int,
    window_seconds: int,
    key_func: Callable[[Request], str | Awaitable[str]] | None = None,
):
    async def dependency(
        request: Request,
        api_key: str = Depends(require_api_key),
    ) -> str:
        limiter = rate_limit_dependency(
            scope=scope,
            limit=limit,
            window_seconds=window_seconds,
            key_func=key_func,
        )
        await limiter(request)
        return api_key

    return dependency


__all__ = [
    "build_rate_limit_dependency",
    "require_api_key",
]