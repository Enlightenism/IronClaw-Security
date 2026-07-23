from __future__ import annotations

from uuid import uuid4

from fastapi import Request
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

REQUEST_ID_HEADER_NAME = "X-Request-ID"
_MAX_REQUEST_ID_LENGTH = 128


def _normalize_request_id(value: str | None) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized:
        return None
    return normalized[:_MAX_REQUEST_ID_LENGTH]


def generate_request_id() -> str:
    return str(uuid4())


class SimpleRequestIDMiddleware:
    """Attach a stable request ID to each HTTP request/response cycle.

    Behavior:
    - Reuse an incoming X-Request-ID if the caller provides one.
    - Otherwise generate a new UUID4-based request ID.
    - Expose the request ID through scope["state"] / request.state for route handlers and logs.
    - Return the same request ID in the response headers.
    - Pass through non-HTTP ASGI scopes unchanged.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = MutableHeaders(scope=scope)
        incoming_request_id = _normalize_request_id(headers.get(REQUEST_ID_HEADER_NAME))
        request_id = incoming_request_id or generate_request_id()

        state = scope.setdefault("state", {})
        state["request_id"] = request_id

        async def send_with_request_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                response_headers = MutableHeaders(raw=message["headers"])
                response_headers.setdefault(REQUEST_ID_HEADER_NAME, request_id)
            await send(message)

        await self.app(scope, receive, send_with_request_id)


def get_request_id_from_request(request: Request) -> str | None:
    value = getattr(request.state, "request_id", None)
    normalized = _normalize_request_id(str(value) if value is not None else None)
    return normalized
