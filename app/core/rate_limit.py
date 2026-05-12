from __future__ import annotations

from collections import deque
from threading import Lock
from time import time

from fastapi import Request, status

from app.core.errors import AppError


class SlidingWindowRateLimiter:
    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = {}
        self._lock = Lock()

    def allow(self, key: str, *, limit: int, window_seconds: int) -> bool:
        now = time()

        with self._lock:
            bucket = self._events.setdefault(key, deque())

            while bucket and bucket[0] <= now - window_seconds:
                bucket.popleft()

            if len(bucket) >= limit:
                return False

            bucket.append(now)
            return True


rate_limiter = SlidingWindowRateLimiter()


def _get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    if request.client and request.client.host:
        return request.client.host

    return "unknown"


def enforce_rate_limit(
    request: Request,
    *,
    bucket: str,
    limit: int = 60,
    window_seconds: int = 60,
) -> None:
    client_ip = _get_client_ip(request)
    key = f"{bucket}:{client_ip}"

    allowed = rate_limiter.allow(
        key,
        limit=limit,
        window_seconds=window_seconds,
    )

    if allowed:
        return

    raise AppError(
        error="rate_limit_exceeded",
        message="Rate limit exceeded. Please try again soon.",
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        details={
            "bucket": bucket,
            "limit": limit,
            "window_seconds": window_seconds,
            "client_ip": client_ip,
        },
    )
