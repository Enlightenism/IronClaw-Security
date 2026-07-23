from __future__ import annotations

from types import SimpleNamespace

import anyio
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app.core.auth import API_KEY_HEADER_NAME
from app.core.middleware import (
    UsageMeteringMiddleware,
    _resolve_api_key_record,
    _resolve_route_path,
    _resolve_units_from_path,
)


def _build_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(UsageMeteringMiddleware)

    @app.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @app.get("/guard/check")
    async def guard_check() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @app.get("/scan/run")
    async def scan_run() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @app.options("/health")
    async def health_options() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @app.get("/custom-status")
    async def custom_status() -> JSONResponse:
        return JSONResponse({"status": "accepted"}, status_code=202)

    return app


def test_resolve_route_path_prefers_route_path() -> None:
    route = SimpleNamespace(path="/templated/{item_id}")
    scope = {"route": route, "path": "/templated/123"}

    assert _resolve_route_path(scope) == "/templated/{item_id}"


def test_resolve_route_path_falls_back_to_scope_path() -> None:
    scope = {"path": "/fallback/path"}

    assert _resolve_route_path(scope) == "/fallback/path"


def test_resolve_route_path_defaults_to_root() -> None:
    assert _resolve_route_path({}) == "/"


def test_resolve_units_from_path_returns_guard_weight() -> None:
    assert _resolve_units_from_path("/guard/check") == 5


def test_resolve_units_from_path_returns_scan_weight() -> None:
    assert _resolve_units_from_path("/scan/run") == 2


def test_resolve_units_from_path_returns_default_weight() -> None:
    assert _resolve_units_from_path("/health") == 1


def test_resolve_api_key_record_uses_resolve_api_key_when_available(monkeypatch) -> None:
    expected = SimpleNamespace(key_id="key_123", active=True)

    class Registry:
        def resolve_api_key(self, raw_api_key: str):
            assert raw_api_key == "secret-key"
            return expected

    monkeypatch.setattr("app.core.middleware.get_api_key_registry", lambda: Registry())

    assert _resolve_api_key_record("secret-key") is expected


def test_resolve_api_key_record_falls_back_to_authenticate_touch_false(monkeypatch) -> None:
    expected = SimpleNamespace(key_id="key_456", active=True)

    class Registry:
        def resolve_api_key(self, raw_api_key: str):
            return None

        def authenticate(self, raw_api_key: str, touch: bool = True):
            assert raw_api_key == "secret-key"
            assert touch is False
            return expected

    monkeypatch.setattr("app.core.middleware.get_api_key_registry", lambda: Registry())

    assert _resolve_api_key_record("secret-key") is expected


def test_resolve_api_key_record_falls_back_after_type_error(monkeypatch) -> None:
    expected = SimpleNamespace(key_id="key_789", active=True)

    class Registry:
        def resolve_api_key(self, raw_api_key: str):
            return None

        def authenticate(self, raw_api_key: str, touch: bool = True):
            if touch is False:
                raise TypeError("touch not supported")
            assert raw_api_key == "secret-key"
            return expected

    monkeypatch.setattr("app.core.middleware.get_api_key_registry", lambda: Registry())

    assert _resolve_api_key_record("secret-key") is expected


def test_resolve_api_key_record_returns_none_when_all_resolution_paths_fail(monkeypatch) -> None:
    class Registry:
        def resolve_api_key(self, raw_api_key: str):
            raise RuntimeError("resolver failed")

        def authenticate(self, raw_api_key: str, touch: bool = True):
            raise RuntimeError("authenticate failed")

    monkeypatch.setattr("app.core.middleware.get_api_key_registry", lambda: Registry())

    assert _resolve_api_key_record("secret-key") is None


def test_usage_metering_middleware_passes_through_non_http_scope() -> None:
    events: list[dict[str, object]] = []

    async def app(scope, receive, send) -> None:
        events.append({"scope_type": scope["type"]})
        await send({"type": "lifespan.startup.complete"})

    middleware = UsageMeteringMiddleware(app)

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


def test_usage_metering_middleware_skips_options_requests(monkeypatch) -> None:
    events: list[dict[str, object]] = []

    class MeteringRegistry:
        def record_event(self, **kwargs) -> None:
            events.append(kwargs)

    class ApiKeyRegistry:
        def resolve_api_key(self, raw_api_key: str):
            return SimpleNamespace(key_id="key_123", active=True)

    monkeypatch.setattr("app.core.middleware.get_usage_metering_registry", lambda: MeteringRegistry())
    monkeypatch.setattr("app.core.middleware.get_api_key_registry", lambda: ApiKeyRegistry())

    client = TestClient(_build_app())
    response = client.options(
        "/health",
        headers={
            "Origin": "https://moving-forward.ca",
            "Access-Control-Request-Method": "GET",
            API_KEY_HEADER_NAME: "secret-key",
        },
    )

    assert response.status_code == 200
    assert events == []


def test_usage_metering_middleware_skips_when_api_key_header_missing(monkeypatch) -> None:
    events: list[dict[str, object]] = []

    class MeteringRegistry:
        def record_event(self, **kwargs) -> None:
            events.append(kwargs)

    monkeypatch.setattr("app.core.middleware.get_usage_metering_registry", lambda: MeteringRegistry())

    client = TestClient(_build_app())
    response = client.get("/health")

    assert response.status_code == 200
    assert events == []


def test_usage_metering_middleware_skips_when_api_key_header_blank(monkeypatch) -> None:
    events: list[dict[str, object]] = []

    class MeteringRegistry:
        def record_event(self, **kwargs) -> None:
            events.append(kwargs)

    monkeypatch.setattr("app.core.middleware.get_usage_metering_registry", lambda: MeteringRegistry())

    client = TestClient(_build_app())
    response = client.get("/health", headers={API_KEY_HEADER_NAME: "   "})

    assert response.status_code == 200
    assert events == []


def test_usage_metering_middleware_records_event_for_known_active_api_key(monkeypatch) -> None:
    events: list[dict[str, object]] = []

    class MeteringRegistry:
        def record_event(self, **kwargs) -> None:
            events.append(kwargs)

    class ApiKeyRegistry:
        def resolve_api_key(self, raw_api_key: str):
            assert raw_api_key == "secret-key"
            return SimpleNamespace(key_id="key_123", active=True)

    monkeypatch.setattr("app.core.middleware.get_usage_metering_registry", lambda: MeteringRegistry())
    monkeypatch.setattr("app.core.middleware.get_api_key_registry", lambda: ApiKeyRegistry())

    client = TestClient(_build_app())
    response = client.get("/health", headers={API_KEY_HEADER_NAME: "secret-key"})

    assert response.status_code == 200
    assert len(events) == 1

    event = events[0]
    assert event["api_key_id"] == "key_123"
    assert event["route"] == "/health"
    assert event["method"] == "GET"
    assert event["status_code"] == 200
    assert event["units"] == 1
    assert event["metadata"]["path"] == "/health"
    assert isinstance(event["metadata"]["duration_ms"], float)
    assert event["metadata"]["duration_ms"] >= 0
    assert event["metadata"]["request_id"] is None


def test_usage_metering_middleware_uses_guard_units(monkeypatch) -> None:
    events: list[dict[str, object]] = []

    class MeteringRegistry:
        def record_event(self, **kwargs) -> None:
            events.append(kwargs)

    class ApiKeyRegistry:
        def resolve_api_key(self, raw_api_key: str):
            return SimpleNamespace(key_id="guard-key", active=True)

    monkeypatch.setattr("app.core.middleware.get_usage_metering_registry", lambda: MeteringRegistry())
    monkeypatch.setattr("app.core.middleware.get_api_key_registry", lambda: ApiKeyRegistry())

    client = TestClient(_build_app())
    response = client.get("/guard/check", headers={API_KEY_HEADER_NAME: "secret-key"})

    assert response.status_code == 200
    assert len(events) == 1
    assert events[0]["units"] == 5
    assert events[0]["route"] == "/guard/check"


def test_usage_metering_middleware_uses_scan_units(monkeypatch) -> None:
    events: list[dict[str, object]] = []

    class MeteringRegistry:
        def record_event(self, **kwargs) -> None:
            events.append(kwargs)

    class ApiKeyRegistry:
        def resolve_api_key(self, raw_api_key: str):
            return SimpleNamespace(key_id="scan-key", active=True)

    monkeypatch.setattr("app.core.middleware.get_usage_metering_registry", lambda: MeteringRegistry())
    monkeypatch.setattr("app.core.middleware.get_api_key_registry", lambda: ApiKeyRegistry())

    client = TestClient(_build_app())
    response = client.get("/scan/run", headers={API_KEY_HEADER_NAME: "secret-key"})

    assert response.status_code == 200
    assert len(events) == 1
    assert events[0]["units"] == 2
    assert events[0]["route"] == "/scan/run"


def test_usage_metering_middleware_uses_request_id_from_scope_state(monkeypatch) -> None:
    events: list[dict[str, object]] = []

    class MeteringRegistry:
        def record_event(self, **kwargs) -> None:
            events.append(kwargs)

    class ApiKeyRegistry:
        def resolve_api_key(self, raw_api_key: str):
            return SimpleNamespace(key_id="key_123", active=True)

    async def app(scope, receive, send) -> None:
        scope.setdefault("state", {})
        scope["state"]["request_id"] = "req-123"
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": b"{}",
                "more_body": False,
            }
        )

    monkeypatch.setattr("app.core.middleware.get_usage_metering_registry", lambda: MeteringRegistry())
    monkeypatch.setattr("app.core.middleware.get_api_key_registry", lambda: ApiKeyRegistry())

    middleware = UsageMeteringMiddleware(app)

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    sent_messages: list[dict[str, object]] = []

    async def send(message: dict[str, object]) -> None:
        sent_messages.append(message)

    anyio.run(
        middleware,
        {
            "type": "http",
            "method": "GET",
            "path": "/health",
            "headers": [(API_KEY_HEADER_NAME.lower().encode(), b"secret-key")],
            "state": {},
        },
        receive,
        send,
    )

    assert len(events) == 1
    assert events[0]["metadata"]["request_id"] == "req-123"
    assert sent_messages[0]["type"] == "http.response.start"


def test_usage_metering_middleware_skips_unknown_api_key(monkeypatch) -> None:
    events: list[dict[str, object]] = []

    class MeteringRegistry:
        def record_event(self, **kwargs) -> None:
            events.append(kwargs)

    class ApiKeyRegistry:
        def resolve_api_key(self, raw_api_key: str):
            return None

    monkeypatch.setattr("app.core.middleware.get_usage_metering_registry", lambda: MeteringRegistry())
    monkeypatch.setattr("app.core.middleware.get_api_key_registry", lambda: ApiKeyRegistry())

    client = TestClient(_build_app())
    response = client.get("/health", headers={API_KEY_HEADER_NAME: "unknown-key"})

    assert response.status_code == 200
    assert events == []


def test_usage_metering_middleware_skips_inactive_api_key(monkeypatch) -> None:
    events: list[dict[str, object]] = []

    class MeteringRegistry:
        def record_event(self, **kwargs) -> None:
            events.append(kwargs)

    class ApiKeyRegistry:
        def resolve_api_key(self, raw_api_key: str):
            return SimpleNamespace(key_id="key_123", active=False)

    monkeypatch.setattr("app.core.middleware.get_usage_metering_registry", lambda: MeteringRegistry())
    monkeypatch.setattr("app.core.middleware.get_api_key_registry", lambda: ApiKeyRegistry())

    client = TestClient(_build_app())
    response = client.get("/health", headers={API_KEY_HEADER_NAME: "secret-key"})

    assert response.status_code == 200
    assert events == []


def test_usage_metering_middleware_skips_record_without_key_id(monkeypatch) -> None:
    events: list[dict[str, object]] = []

    class MeteringRegistry:
        def record_event(self, **kwargs) -> None:
            events.append(kwargs)

    class ApiKeyRegistry:
        def resolve_api_key(self, raw_api_key: str):
            return SimpleNamespace(key_id=None, active=True)

    monkeypatch.setattr("app.core.middleware.get_usage_metering_registry", lambda: MeteringRegistry())
    monkeypatch.setattr("app.core.middleware.get_api_key_registry", lambda: ApiKeyRegistry())

    client = TestClient(_build_app())
    response = client.get("/health", headers={API_KEY_HEADER_NAME: "secret-key"})

    assert response.status_code == 200
    assert events == []


def test_usage_metering_middleware_uses_response_start_status(monkeypatch) -> None:
    events: list[dict[str, object]] = []

    class MeteringRegistry:
        def record_event(self, **kwargs) -> None:
            events.append(kwargs)

    class ApiKeyRegistry:
        def resolve_api_key(self, raw_api_key: str):
            return SimpleNamespace(key_id="key_202", active=True)

    monkeypatch.setattr("app.core.middleware.get_usage_metering_registry", lambda: MeteringRegistry())
    monkeypatch.setattr("app.core.middleware.get_api_key_registry", lambda: ApiKeyRegistry())

    client = TestClient(_build_app())
    response = client.get("/custom-status", headers={API_KEY_HEADER_NAME: "secret-key"})

    assert response.status_code == 202
    assert len(events) == 1
    assert events[0]["status_code"] == 202


def test_usage_metering_middleware_does_not_break_request_when_metering_fails(monkeypatch) -> None:
    class MeteringRegistry:
        def record_event(self, **kwargs) -> None:
            raise RuntimeError("metering failed")

    class ApiKeyRegistry:
        def resolve_api_key(self, raw_api_key: str):
            return SimpleNamespace(key_id="key_123", active=True)

    monkeypatch.setattr("app.core.middleware.get_usage_metering_registry", lambda: MeteringRegistry())
    monkeypatch.setattr("app.core.middleware.get_api_key_registry", lambda: ApiKeyRegistry())

    client = TestClient(_build_app())
    response = client.get("/health", headers={API_KEY_HEADER_NAME: "secret-key"})

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_usage_metering_middleware_does_not_record_when_response_start_not_sent(monkeypatch) -> None:
    events: list[dict[str, object]] = []

    class MeteringRegistry:
        def record_event(self, **kwargs) -> None:
            events.append(kwargs)

    class ApiKeyRegistry:
        def resolve_api_key(self, raw_api_key: str):
            return SimpleNamespace(key_id="key_123", active=True)

    async def app(scope, receive, send) -> None:
        return

    monkeypatch.setattr("app.core.middleware.get_usage_metering_registry", lambda: MeteringRegistry())
    monkeypatch.setattr("app.core.middleware.get_api_key_registry", lambda: ApiKeyRegistry())

    middleware = UsageMeteringMiddleware(app)

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, object]) -> None:
        return

    anyio.run(
        middleware,
        {
            "type": "http",
            "method": "GET",
            "path": "/health",
            "headers": [(API_KEY_HEADER_NAME.lower().encode(), b"secret-key")],
            "state": {},
        },
        receive,
        send,
    )

    assert events == []
