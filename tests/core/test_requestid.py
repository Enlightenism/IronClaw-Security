from __future__ import annotations

import anyio
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app.core.requestid import (
    REQUEST_ID_HEADER_NAME,
    RequestIDMiddleware,
    _normalize_request_id,
    clear_request_id,
    generate_request_id,
    get_or_create_request_id,
    get_request_id,
    set_request_id,
)


def _build_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(RequestIDMiddleware)

    @app.get("/health")
    async def health(request: Request) -> dict[str, str | None]:
        return {
            "request_id": get_request_id(),
            "state_request_id": getattr(request.state, "request_id", None),
        }

    @app.options("/health")
    async def health_options(request: Request) -> dict[str, str | None]:
        return {
            "request_id": get_request_id(),
            "state_request_id": getattr(request.state, "request_id", None),
        }

    @app.get("/custom-header")
    async def custom_header() -> JSONResponse:
        return JSONResponse(
            content={"status": "ok"},
            headers={REQUEST_ID_HEADER_NAME: "route-set-request-id"},
        )

    return app


def test_normalize_request_id_returns_none_for_non_string() -> None:
    assert _normalize_request_id(None) is None
    assert _normalize_request_id(123) is None  # type: ignore[arg-type]


def test_normalize_request_id_returns_none_for_blank_string() -> None:
    assert _normalize_request_id("") is None
    assert _normalize_request_id("   ") is None


def test_normalize_request_id_strips_and_truncates() -> None:
    long_value = "  abc123" + ("x" * 200) + "  "
    normalized = _normalize_request_id(long_value)

    assert normalized is not None
    assert normalized.startswith("abc123")
    assert len(normalized) == 128


def test_generate_request_id_returns_hex_uuid() -> None:
    request_id = generate_request_id()

    assert isinstance(request_id, str)
    assert len(request_id) == 32
    assert all(ch in "0123456789abcdef" for ch in request_id)


def test_get_and_set_request_id_round_trip() -> None:
    clear_request_id()

    set_request_id("abc-123")
    assert get_request_id() == "abc-123"

    clear_request_id()
    assert get_request_id() is None


def test_set_request_id_normalizes_value() -> None:
    clear_request_id()

    set_request_id("  abc-123  ")
    assert get_request_id() == "abc-123"

    set_request_id("   ")
    assert get_request_id() is None


def test_get_or_create_request_id_uses_request_state_when_present() -> None:
    app = FastAPI()

    @app.get("/state")
    async def state_route(request: Request) -> dict[str, str]:
        request.state.request_id = "state-request-id"
        return {"request_id": get_or_create_request_id(request)}

    client = TestClient(app)
    response = client.get("/state")

    assert response.status_code == 200
    assert response.json()["request_id"] == "state-request-id"


def test_get_or_create_request_id_uses_incoming_header_when_state_missing() -> None:
    app = FastAPI()

    @app.get("/header")
    async def header_route(request: Request) -> dict[str, str]:
        return {"request_id": get_or_create_request_id(request)}

    client = TestClient(app)
    response = client.get(
        "/header",
        headers={REQUEST_ID_HEADER_NAME: "incoming-request-id"},
    )

    assert response.status_code == 200
    assert response.json()["request_id"] == "incoming-request-id"


def test_get_or_create_request_id_generates_when_missing_everywhere() -> None:
    app = FastAPI()

    @app.get("/generated")
    async def generated_route(request: Request) -> dict[str, str]:
        return {"request_id": get_or_create_request_id(request)}

    client = TestClient(app)
    response = client.get("/generated")

    request_id = response.json()["request_id"]
    assert response.status_code == 200
    assert isinstance(request_id, str)
    assert len(request_id) == 32


def test_request_id_middleware_sets_generated_request_id_on_response_and_state() -> None:
    clear_request_id()
    client = TestClient(_build_app())

    response = client.get("/health")

    assert response.status_code == 200
    response_request_id = response.headers[REQUEST_ID_HEADER_NAME]
    body = response.json()

    assert response_request_id
    assert len(response_request_id) == 32
    assert body["request_id"] == response_request_id
    assert body["state_request_id"] == response_request_id
    assert get_request_id() is None


def test_request_id_middleware_preserves_incoming_request_id() -> None:
    clear_request_id()
    client = TestClient(_build_app())

    response = client.get(
        "/health",
        headers={REQUEST_ID_HEADER_NAME: "client-request-id"},
    )

    assert response.status_code == 200
    assert response.headers[REQUEST_ID_HEADER_NAME] == "client-request-id"
    assert response.json()["request_id"] == "client-request-id"
    assert response.json()["state_request_id"] == "client-request-id"
    assert get_request_id() is None


def test_incoming_x_request_id_preserved_on_options() -> None:
    clear_request_id()
    client = TestClient(_build_app())

    response = client.options(
        "/health",
        headers={
            "Origin": "https://moving-forward.ca",
            "Access-Control-Request-Method": "GET",
            REQUEST_ID_HEADER_NAME: "options-request-id",
        },
    )

    assert response.status_code == 200
    assert response.headers[REQUEST_ID_HEADER_NAME] == "options-request-id"
    assert response.json()["request_id"] == "options-request-id"
    assert response.json()["state_request_id"] == "options-request-id"
    assert get_request_id() is None


def test_generated_request_id_returned_on_options_when_missing() -> None:
    clear_request_id()
    client = TestClient(_build_app())

    response = client.options(
        "/health",
        headers={
            "Origin": "https://moving-forward.ca",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    response_request_id = response.headers[REQUEST_ID_HEADER_NAME]
    body = response.json()

    assert response_request_id
    assert len(response_request_id) == 32
    assert body["request_id"] == response_request_id
    assert body["state_request_id"] == response_request_id
    assert get_request_id() is None


def test_request_id_context_cleared_after_request() -> None:
    clear_request_id()
    client = TestClient(_build_app())

    response = client.get(
        "/health",
        headers={REQUEST_ID_HEADER_NAME: "cleanup-request-id"},
    )

    assert response.status_code == 200
    assert get_request_id() is None


def test_request_id_context_does_not_leak_between_requests() -> None:
    clear_request_id()
    client = TestClient(_build_app())

    first = client.get(
        "/health",
        headers={REQUEST_ID_HEADER_NAME: "first-request-id"},
    )
    second = client.get("/health")

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.headers[REQUEST_ID_HEADER_NAME] == "first-request-id"
    assert second.headers[REQUEST_ID_HEADER_NAME] != "first-request-id"
    assert len(second.headers[REQUEST_ID_HEADER_NAME]) == 32
    assert get_request_id() is None


def test_existing_response_header_is_not_overwritten() -> None:
    clear_request_id()
    client = TestClient(_build_app())

    response = client.get(
        "/custom-header",
        headers={REQUEST_ID_HEADER_NAME: "incoming-request-id"},
    )

    assert response.status_code == 200
    assert response.headers[REQUEST_ID_HEADER_NAME] == "route-set-request-id"
    assert get_request_id() is None


def test_non_http_scopes_pass_through_unchanged() -> None:
    events: list[dict[str, object]] = []

    async def app(scope, receive, send) -> None:
        events.append(
            {
                "scope_type": scope["type"],
                "state_present": "state" in scope,
                "request_id_context": get_request_id(),
            }
        )
        await send({"type": "lifespan.startup.complete"})

    middleware = RequestIDMiddleware(app)

    async def receive() -> dict[str, object]:
        return {"type": "lifespan.startup"}

    async def send(message: dict[str, object]) -> None:
        events.append(
            {
                "message_type": message["type"],
                "request_id_context": get_request_id(),
            }
        )

    clear_request_id()
    anyio.run(
        middleware,
        {"type": "lifespan", "state": {}},
        receive,
        send,
    )

    assert events[0]["scope_type"] == "lifespan"
    assert events[0]["state_present"] is True
    assert events[0]["request_id_context"] is None
    assert events[1]["message_type"] == "lifespan.startup.complete"
    assert events[1]["request_id_context"] is None
    assert get_request_id() is None
