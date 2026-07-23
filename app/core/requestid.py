from __future__ import annotations

from contextvars import ContextVar
import uuid

from fastapi import Request
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

REQUEST_ID_HEADER_NAME = "X-Request-ID"
_REQUEST_ID_HEADER_NAME_LOWER = REQUEST_ID_HEADER_NAME.lower()
_MAX_REQUEST_ID_LENGTH = 128

_request_id_var: ContextVar[str | None] = ContextVar(
    "ironclaw_request_id",
    default=None,
)


def get_request_id() -> str | None:
    return _request_id_var.get()


def set_request_id(request_id: str | None) -> None:
    _request_id_var.set(_normalize_request_id(request_id))


def clear_request_id() -> None:
    _request_id_var.set(None)


def _normalize_request_id(value: str | None) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized:
        return None
    return normalized[:_MAX_REQUEST_ID_LENGTH]


def generate_request_id() -> str:
    return uuid.uuid4().hex


def get_or_create_request_id(request: Request) -> str:
    request_id = _normalize_request_id(getattr(request.state, "request_id", None))
    if request_id:
        return request_id

    incoming = _normalize_request_id(request.headers.get(REQUEST_ID_HEADER_NAME))
    return incoming or generate_request_id()


class RequestIDMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = MutableHeaders(scope=scope)
        incoming_request_id = _normalize_request_id(headers.get(REQUEST_ID_HEADER_NAME))
        request_id = incoming_request_id or generate_request_id()

        scope.setdefault("state", {})
        scope["state"]["request_id"] = request_id

        token = _request_id_var.set(request_id)

        async def send_with_request_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                response_headers = MutableHeaders(raw=message["headers"])
                response_headers.setdefault(REQUEST_ID_HEADER_NAME, request_id)
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        finally:
            _request_id_var.reset(token)
