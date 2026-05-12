from __future__ import annotations

import uuid
from collections.abc import Callable
from contextvars import ContextVar

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

REQUEST_ID_HEADER_NAME = "X-Request-ID"

_request_id_var: ContextVar[str | None] = ContextVar("ironclaw_request_id", default=None)


def get_request_id() -> str | None:
    return _request_id_var.get()


def set_request_id(request_id: str | None) -> None:
    _request_id_var.set(request_id)


def clear_request_id() -> None:
    _request_id_var.set(None)


def _normalize_request_id(value: str | None) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value:
        return None
    return value[:128]


def generate_request_id() -> str:
    return uuid.uuid4().hex


def get_or_create_request_id(request: Request) -> str:
    request_id = getattr(request.state, "request_id", None)
    if request_id:
        return str(request_id)
    incoming = _normalize_request_id(request.headers.get(REQUEST_ID_HEADER_NAME))
    return incoming or generate_request_id()


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable[..., Response]) -> Response:
        incoming_request_id = _normalize_request_id(request.headers.get(REQUEST_ID_HEADER_NAME))
        request_id = incoming_request_id or generate_request_id()

        token = _request_id_var.set(request_id)
        request.state.request_id = request_id

        try:
            response = await call_next(request)
        finally:
            _request_id_var.reset(token)

        response.headers.setdefault(REQUEST_ID_HEADER_NAME, request_id)
        return response