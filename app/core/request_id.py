from __future__ import annotations

from uuid import uuid4

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


REQUEST_ID_HEADER_NAME = "X-Request-ID"


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Attach a stable request ID to each request/response cycle.

    Behavior:
    - Reuse an incoming X-Request-ID if the caller provides one.
    - Otherwise generate a new UUID4-based request ID.
    - Expose the request ID through request.state for route handlers and logs.
    - Return the same request ID in the response headers.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get(REQUEST_ID_HEADER_NAME)
        if not request_id:
            request_id = str(uuid4())

        request.state.request_id = request_id
        response = await call_next(request)
        response.headers[REQUEST_ID_HEADER_NAME] = request_id
        return response


def get_request_id(request: Request) -> str | None:
    value = getattr(request.state, "request_id", None)
    if value is None:
        return None
    return str(value)