from __future__ import annotations

from types import SimpleNamespace

import anyio
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
import pytest

from app.core.ratelimit import (
    DEFAULT_RATE_LIMITS,
    RateLimit,
    RateLimitMiddleware,
    TokenBucket,
    TokenBucketRateLimiter,
    install_rate_limit_middleware,
)


def _build_app(
    *,
    limiter: TokenBucketRateLimiter | None = None,
    route_limits: dict[str, RateLimit] | None = None,
) -> FastAPI:
    app = FastAPI()
    install_rate_limit_middleware(
        app,
        limiter=limiter,
        route_limits=route_limits,
    )

    @app.get("/scan")
    async def scan() -> JSONResponse:
        return JSONResponse({"ok": True})

    @app.get("/guard-action")
    async def guard_action() -> JSONResponse:
        return JSONResponse({"ok": True})

    @app.get("/guard-action-policy")
    async def guard_action_policy() -> JSONResponse:
        return JSONResponse({"ok": True})

    @app.get("/unlimited")
    async def unlimited() -> JSONResponse:
        return JSONResponse({"ok": True})

    return app


class TestTokenBucket:
    def test_init_raises_for_non_positive_capacity(self) -> None:
        with pytest.raises(ValueError, match="capacity must be greater than 0"):
            TokenBucket(capacity=0, refill_rate=1.0)

    def test_init_raises_for_non_positive_refill_rate(self) -> None:
        with pytest.raises(ValueError, match="refill_rate must be greater than 0"):
            TokenBucket(capacity=1, refill_rate=0)

    def test_consume_returns_true_when_tokens_available(self) -> None:
        bucket = TokenBucket(capacity=2, refill_rate=1.0)

        assert bucket.consume() is True
        assert bucket.remaining() in {0, 1}

    def test_consume_returns_false_when_tokens_exhausted(self) -> None:
        bucket = TokenBucket(capacity=1, refill_rate=1.0)

        assert bucket.consume() is True
        assert bucket.consume() is False

    def test_retry_after_seconds_zero_when_enough_tokens(self) -> None:
        bucket = TokenBucket(capacity=2, refill_rate=1.0)

        assert bucket.retry_after_seconds() == 0

    def test_retry_after_seconds_at_least_one_when_blocked(self) -> None:
        bucket = TokenBucket(capacity=1, refill_rate=1.0)
        assert bucket.consume() is True

        assert bucket.retry_after_seconds() >= 1

    def test_reset_seconds_zero_when_bucket_full(self) -> None:
        bucket = TokenBucket(capacity=3, refill_rate=1.0)

        assert bucket.reset_seconds() == 0

    def test_reset_seconds_at_least_one_when_not_full(self) -> None:
        bucket = TokenBucket(capacity=2, refill_rate=1.0)
        assert bucket.consume() is True

        assert bucket.reset_seconds() >= 1

    def test_refill_restores_tokens_over_time(self, monkeypatch) -> None:
        times = iter([100.0, 100.0, 100.0, 103.0])
        monkeypatch.setattr("app.core.ratelimit.time.monotonic", lambda: next(times))

        bucket = TokenBucket(capacity=3, refill_rate=1.0)
        assert bucket.consume(amount=3.0) is True
        assert bucket.consume() is False
        assert bucket.remaining() == 3


class TestTokenBucketRateLimiter:
    def test_get_bucket_returns_same_instance_for_same_key(self) -> None:
        limiter = TokenBucketRateLimiter()
        limit = RateLimit(capacity=5, refill_rate=1.0, scope="scan")

        first = limiter.get_bucket("scan:client-1", limit)
        second = limiter.get_bucket("scan:client-1", limit)

        assert first is second

    def test_get_bucket_returns_different_instance_for_different_key(self) -> None:
        limiter = TokenBucketRateLimiter()
        limit = RateLimit(capacity=5, refill_rate=1.0, scope="scan")

        first = limiter.get_bucket("scan:client-1", limit)
        second = limiter.get_bucket("scan:client-2", limit)

        assert first is not second


class TestRateLimitMiddlewareHelpers:
    def test_match_limit_returns_exact_path_limit(self) -> None:
        middleware = RateLimitMiddleware(
            app=lambda scope, receive, send: None,
            route_limits={"/scan": RateLimit(capacity=5, refill_rate=1.0, scope="scan")},
        )

        limit = middleware._match_limit("/scan")

        assert limit is not None
        assert limit.scope == "scan"

    def test_match_limit_returns_none_for_unconfigured_path(self) -> None:
        middleware = RateLimitMiddleware(
            app=lambda scope, receive, send: None,
            route_limits={"/scan": RateLimit(capacity=5, refill_rate=1.0, scope="scan")},
        )

        assert middleware._match_limit("/unknown") is None

    def test_build_headers_for_allowed_response(self) -> None:
        middleware = RateLimitMiddleware(app=lambda scope, receive, send: None)
        limit = RateLimit(capacity=10, refill_rate=1.0, scope="scan")

        headers = middleware._build_headers(limit, remaining=7, reset_after=12)

        assert headers == {
            "X-RateLimit-Limit": "10",
            "X-RateLimit-Remaining": "7",
            "X-RateLimit-Reset": "12",
            "X-RateLimit-Scope": "scan",
        }

    def test_build_headers_for_rejected_response_includes_retry_after(self) -> None:
        middleware = RateLimitMiddleware(app=lambda scope, receive, send: None)
        limit = RateLimit(capacity=10, refill_rate=1.0, scope="scan")

        headers = middleware._build_headers(limit, remaining=0, reset_after=9, rejected=True)

        assert headers["Retry-After"] == "9"
        assert headers["X-RateLimit-Remaining"] == "0"

    def test_build_client_key_prefers_x_client_id(self) -> None:
        middleware = RateLimitMiddleware(app=lambda scope, receive, send: None)
        connection = SimpleNamespace(
            scope={
                "headers": [(b"x-client-id", b"client-123")],
            },
            client=SimpleNamespace(host="10.0.0.1"),
        )

        key = middleware._build_client_key(connection, "scan")

        assert key == "scan:client-123"

    def test_build_client_key_falls_back_to_session_id(self) -> None:
        middleware = RateLimitMiddleware(app=lambda scope, receive, send: None)
        connection = SimpleNamespace(
            scope={
                "headers": [(b"x-session-id", b"session-123")],
            },
            client=SimpleNamespace(host="10.0.0.1"),
        )

        key = middleware._build_client_key(connection, "scan")

        assert key == "scan:session-123"

    def test_build_client_key_uses_first_forwarded_for_ip(self) -> None:
        middleware = RateLimitMiddleware(app=lambda scope, receive, send: None)
        connection = SimpleNamespace(
            scope={
                "headers": [(b"x-forwarded-for", b"203.0.113.5, 10.0.0.1")],
            },
            client=SimpleNamespace(host="10.0.0.1"),
        )

        key = middleware._build_client_key(connection, "scan")

        assert key == "scan:203.0.113.5"

    def test_build_client_key_falls_back_to_real_ip(self) -> None:
        middleware = RateLimitMiddleware(app=lambda scope, receive, send: None)
        connection = SimpleNamespace(
            scope={
                "headers": [(b"x-real-ip", b"198.51.100.10")],
            },
            client=SimpleNamespace(host="10.0.0.1"),
        )

        key = middleware._build_client_key(connection, "scan")

        assert key == "scan:198.51.100.10"

    def test_build_client_key_falls_back_to_client_host(self) -> None:
        middleware = RateLimitMiddleware(app=lambda scope, receive, send: None)
        connection = SimpleNamespace(
            scope={"headers": []},
            client=SimpleNamespace(host="10.0.0.1"),
        )

        key = middleware._build_client_key(connection, "scan")

        assert key == "scan:10.0.0.1"

    def test_build_client_key_uses_unknown_when_identity_blank(self) -> None:
        middleware = RateLimitMiddleware(app=lambda scope, receive, send: None)
        connection = SimpleNamespace(
            scope={
                "headers": [(b"x-client-id", b"   ")],
            },
            client=None,
        )

        key = middleware._build_client_key(connection, "scan")

        assert key == "scan:unknown"


class TestRateLimitMiddlewareASGI:
    def test_passes_through_non_http_scope(self) -> None:
        events: list[dict[str, object]] = []

        async def app(scope, receive, send) -> None:
            events.append({"scope_type": scope["type"]})
            await send({"type": "lifespan.startup.complete"})

        middleware = RateLimitMiddleware(app)

        async def receive() -> dict[str, object]:
            return {"type": "lifespan.startup"}

        async def send(message: dict[str, object]) -> None:
            events.append({"message_type": message["type"]})

        anyio.run(
            middleware,
            {"type": "lifespan", "state": {}},
            receive,
            send,
        )

        assert events == [
            {"scope_type": "lifespan"},
            {"message_type": "lifespan.startup.complete"},
        ]

    def test_passes_through_when_scope_path_missing_or_invalid(self) -> None:
        messages: list[dict[str, object]] = []

        async def app(scope, receive, send) -> None:
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b"", "more_body": False})

        middleware = RateLimitMiddleware(app)

        async def receive() -> dict[str, object]:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message: dict[str, object]) -> None:
            messages.append(message)

        anyio.run(
            middleware,
            {
                "type": "http",
                "method": "GET",
                "path": None,
                "headers": [],
                "state": {},
            },
            receive,
            send,
        )

        assert messages[0]["type"] == "http.response.start"
        assert messages[0]["status"] == 204


class TestRateLimitMiddlewareIntegration:
    def test_install_rate_limit_middleware_adds_headers_for_allowed_request(self) -> None:
        app = _build_app(
            route_limits={
                "/scan": RateLimit(capacity=2, refill_rate=1.0, scope="scan"),
            }
        )
        client = TestClient(app)

        response = client.get("/scan")

        assert response.status_code == 200
        assert response.headers["X-RateLimit-Limit"] == "2"
        assert response.headers["X-RateLimit-Remaining"] == "1"
        assert response.headers["X-RateLimit-Scope"] == "scan"
        assert "X-RateLimit-Reset" in response.headers

    def test_unconfigured_route_passes_through_without_rate_limit_headers(self) -> None:
        app = _build_app(
            route_limits={
                "/scan": RateLimit(capacity=2, refill_rate=1.0, scope="scan"),
            }
        )
        client = TestClient(app)

        response = client.get("/unlimited")

        assert response.status_code == 200
        assert "X-RateLimit-Limit" not in response.headers
        assert "X-RateLimit-Remaining" not in response.headers
        assert "X-RateLimit-Scope" not in response.headers

    def test_rejected_request_returns_429_and_retry_headers(self) -> None:
        app = _build_app(
            route_limits={
                "/scan": RateLimit(capacity=1, refill_rate=0.01, scope="scan"),
            }
        )
        client = TestClient(app)

        first = client.get("/scan", headers={"X-Client-ID": "client-1"})
        second = client.get("/scan", headers={"X-Client-ID": "client-1"})

        assert first.status_code == 200
        assert second.status_code == 429
        assert second.json()["error"] == "rate_limit_exceeded"
        assert second.json()["details"]["scope"] == "scan"
        assert int(second.headers["Retry-After"]) >= 1
        assert second.headers["X-RateLimit-Limit"] == "1"
        assert second.headers["X-RateLimit-Remaining"] == "0"
        assert second.headers["X-RateLimit-Scope"] == "scan"

    def test_different_client_keys_get_independent_buckets(self) -> None:
        app = _build_app(
            route_limits={
                "/scan": RateLimit(capacity=1, refill_rate=0.01, scope="scan"),
            }
        )
        client = TestClient(app)

        first = client.get("/scan", headers={"X-Client-ID": "client-1"})
        second = client.get("/scan", headers={"X-Client-ID": "client-2"})

        assert first.status_code == 200
        assert second.status_code == 200

    def test_default_rate_limits_are_installed_when_not_overridden(self) -> None:
        app = _build_app()
        client = TestClient(app)

        response = client.get("/scan", headers={"X-Client-ID": "client-1"})

        assert response.status_code == 200
        assert response.headers["X-RateLimit-Limit"] == str(DEFAULT_RATE_LIMITS["/scan"].capacity)
        assert response.headers["X-RateLimit-Scope"] == DEFAULT_RATE_LIMITS["/scan"].scope

    def test_logger_warning_called_when_rate_limit_exceeded(self, monkeypatch) -> None:
        warnings: list[tuple[str, dict[str, object]]] = []

        class Logger:
            def warning(self, message: str, *, extra: dict[str, object]) -> None:
                warnings.append((message, extra))

        monkeypatch.setattr("app.core.ratelimit.get_logger", lambda name: Logger())

        app = _build_app(
            route_limits={
                "/scan": RateLimit(capacity=1, refill_rate=0.01, scope="scan"),
            }
        )
        client = TestClient(app)

        client.get("/scan", headers={"X-Client-ID": "client-1"})
        blocked = client.get("/scan", headers={"X-Client-ID": "client-1"})

        assert blocked.status_code == 429
        assert len(warnings) == 1
        message, extra = warnings[0]
        assert message == "rate_limit_exceeded"
        assert extra["event"] == "rate_limit_exceeded"
        assert extra["path"] == "/scan"
        assert extra["http_method"] == "GET"
        assert extra["client_key"] == "scan:client-1"
        assert extra["scope"] == "scan"
        assert extra["limit"] == 1
        assert extra["remaining"] == 0
        assert int(extra["retry_after_seconds"]) >= 1
