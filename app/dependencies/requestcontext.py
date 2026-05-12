from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Header, Request

from app.core.requestid import get_or_create_request_id
from app.schemas.requestcontext import RequestContextResponse


def _clean_optional_header(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _derive_client_ip(request: Request) -> str | None:
    forwarded_for = _clean_optional_header(request.headers.get("x-forwarded-for"))
    if forwarded_for:
        first_hop = forwarded_for.split(",")[0].strip()
        if first_hop:
            return first_hop

    real_ip = _clean_optional_header(request.headers.get("x-real-ip"))
    if real_ip:
        return real_ip

    if request.client and request.client.host:
        return request.client.host

    return None


def get_request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def get_trace_id(request: Request) -> str | None:
    return getattr(request.state, "trace_id", None)


def get_request_started_at(request: Request) -> float | None:
    return getattr(request.state, "request_started_at", None)


def get_client_host(request: Request) -> str | None:
    client = getattr(request, "client", None)
    return getattr(client, "host", None) if client else None


def get_request_path(request: Request) -> str:
    return request.url.path


def get_request_method(request: Request) -> str:
    return request.method


async def get_request_context(
    request: Request,
    x_client_id: str | None = Header(default=None, alias="X-Client-Id"),
    x_session_id: str | None = Header(default=None, alias="X-Session-Id"),
    x_trace_id: str | None = Header(default=None, alias="X-Trace-Id"),
    x_integration_id: str | None = Header(default=None, alias="X-Integration-Id"),
) -> RequestContextResponse:
    request_id = get_or_create_request_id(request)
    return RequestContextResponse(
        request_id=request_id,
        trace_id=_clean_optional_header(x_trace_id) or request_id,
        client_id=_clean_optional_header(x_client_id),
        session_id=_clean_optional_header(x_session_id),
        integration_id=_clean_optional_header(x_integration_id),
        method=request.method,
        path=request.url.path,
        client_ip=_derive_client_ip(request),
        user_agent=_clean_optional_header(request.headers.get("user-agent")),
        timestamp=datetime.now(UTC).isoformat(),
    )


RequestContextDep = Annotated[RequestContextResponse, Depends(get_request_context)]