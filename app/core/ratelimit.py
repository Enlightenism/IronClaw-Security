from __future__ import annotations

from dataclasses import dataclass
import math
import threading
import time

from fastapi import FastAPI, status
from fastapi.responses import JSONResponse
from starlette.datastructures import Headers, MutableHeaders
from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.logging import get_logger


@dataclass(frozen=True)
class RateLimit:
    capacity: int
    refill_rate: float
    scope: str


class TokenBucket:
    def __init__(self, capacity: int, refill_rate: float) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be greater than 0")
        if refill_rate <= 0:
            raise ValueError("refill_rate must be greater than 0")

        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = float(capacity)
        self.updated_at = time.monotonic()
        self.lock = threading.Lock()

    def consume(self, amount: float = 1.0) -> bool:
        with self.lock:
            self._refill()
            if self.tokens >= amount:
                self.tokens -= amount
                return True
            return False

    def remaining(self) -> int:
        with self.lock:
            self._refill()
            return max(0, int(self.tokens))

    def retry_after_seconds(self, amount: float = 1.0) -> int:
        with self.lock:
            self._refill()
            if self.tokens >= amount:
                return 0
            missing = amount - self.tokens
            return max(1, math.ceil(missing / self.refill_rate))

    def reset_seconds(self) -> int:
        with self.lock:
            self._refill()
            if self.tokens >= self.capacity:
                return 0
            missing = self.capacity - self.tokens
            return max(1, math.ceil(missing / self.refill_rate))

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.updated_at
        if elapsed <= 0:
            return
        self.tokens = min(self.capacity, self.tokens + (elapsed * self.refill_rate))
        self.updated_at = now


class TokenBucketRateLimiter:
    def __init__(self) -> None:
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def get_bucket(self, key: str, limit: RateLimit) -> TokenBucket:
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = TokenBucket(capacity=limit.capacity, refill_rate=limit.refill_rate)
                self._buckets[key] = bucket
            return bucket


DEFAULT_RATE_LIMITS: dict[str, RateLimit] = {
    "/scan": RateLimit(capacity=30, refill_rate=0.5, scope="scan"),
    "/guard-action": RateLimit(capacity=60, refill_rate=1.0, scope="guard_action"),
    "/guard-action-policy": RateLimit(capacity=60, refill_rate=1.0, scope="guard_action_policy"),
    "/guard-action-decision": RateLimit(capacity=60, refill_rate=1.0, scope="guard_action_decision"),
}


class RateLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        limiter: TokenBucketRateLimiter | None = None,
        route_limits: dict[str, RateLimit] | None = None,
    ) -> None:
        self.app = app
        self.limiter = limiter or TokenBucketRateLimiter()
        self.route_limits = route_limits or DEFAULT_RATE_LIMITS
        self.logger = get_logger("ironclaw.ratelimit")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path")
        if not isinstance(path, str):
            await self.app(scope, receive, send)
            return

        limit = self._match_limit(path)
        if limit is None:
            await self.app(scope, receive, send)
            return

        connection = HTTPConnection(scope)
        client_key = self._build_client_key(connection, limit.scope)
        bucket = self.limiter.get_bucket(client_key, limit)

        if not bucket.consume():
            retry_after = bucket.retry_after_seconds()
            remaining = bucket.remaining()
            headers = self._build_headers(limit, remaining, retry_after, rejected=True)

            self.logger.warning(
                "rate_limit_exceeded",
                extra={
                    "event": "rate_limit_exceeded",
                    "path": path,
                    "http_method": scope.get("method", "UNKNOWN"),
                    "client_key": client_key,
                    "scope": limit.scope,
                    "limit": limit.capacity,
                    "remaining": remaining,
                    "retry_after_seconds": retry_after,
                },
            )

            response = JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "rate_limit_exceeded",
                    "message": "Too many requests. Please try again later.",
                    "details": {
                        "scope": limit.scope,
                        "retry_after_seconds": retry_after,
                    },
                },
                headers=headers,
            )
            await response(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                remaining = bucket.remaining()
                reset_after = bucket.reset_seconds()
                response_headers = MutableHeaders(raw=message["headers"])
                for header, value in self._build_headers(limit, remaining, reset_after).items():
                    response_headers[header] = value
            await send(message)

        await self.app(scope, receive, send_wrapper)

    def _match_limit(self, path: str) -> RateLimit | None:
        return self.route_limits.get(path)

    def _build_client_key(self, connection: HTTPConnection, scope_name: str) -> str:
        headers = Headers(scope=connection.scope)
        request_id = headers.get("X-Client-ID")
        session_id = headers.get("X-Session-ID")
        forwarded_for = headers.get("X-Forwarded-For")
        real_ip = headers.get("X-Real-IP")
        client_ip = connection.client.host if connection.client else "unknown"

        identity = request_id or session_id or forwarded_for or real_ip or client_ip
        identity = identity.split(",")[0].strip() or "unknown"
        return f"{scope_name}:{identity}"

    def _build_headers(
        self,
        limit: RateLimit,
        remaining: int,
        reset_after: int,
        *,
        rejected: bool = False,
    ) -> dict[str, str]:
        headers = {
            "X-RateLimit-Limit": str(limit.capacity),
            "X-RateLimit-Remaining": str(max(0, remaining)),
            "X-RateLimit-Reset": str(max(0, reset_after)),
            "X-RateLimit-Scope": limit.scope,
        }
        if rejected:
            headers["Retry-After"] = str(max(1, reset_after))
        return headers


def install_rate_limit_middleware(
    app: FastAPI,
    *,
    limiter: TokenBucketRateLimiter | None = None,
    route_limits: dict[str, RateLimit] | None = None,
) -> None:
    app.add_middleware(
        RateLimitMiddleware,
        limiter=limiter,
        route_limits=route_limits or DEFAULT_RATE_LIMITS,
    )
