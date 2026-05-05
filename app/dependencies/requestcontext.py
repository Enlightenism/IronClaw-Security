from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import Header, Request

from app.core.requestid import get_or_create_request_id


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


def build_request_context(
    request: Request,
    *,
    client_id: str | None = None,
    session_id: str | None = None,
    trace_id: str | None = None,
    integration_id: str | None = None,
) -> dict[str, Any]:
    request_id = get_or_create_request_id(request)
    context: dict[str, Any] = {
        "request_id": request_id,
        "trace_id": _clean_optional_header(trace_id) or request_id,
        "client_id": _clean_optional_header(client_id),
        "session_id": _clean_optional_header(session_id),
        "integration_id": _clean_optional_header(integration_id),
        "method": request.method,
        "path": request.url.path,
        "client_ip": _derive_client_ip(request),
        "user_agent": _clean_optional_header(request.headers.get("user-agent")),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return context


async def get_request_context(
    request: Request,
    x_client_id: str | None = Header(default=None, alias="X-Client-Id"),
    x_session_id: str | None = Header(default=None, alias="X-Session-Id"),
    x_trace_id: str | None = Header(default=None, alias="X-Trace-Id"),
    x_integration_id: str | None = Header(default=None, alias="X-Integration-Id"),
) -> dict[str, Any]:
    return build_request_context(
        request,
        client_id=x_client_id,
        session_id=x_session_id,
        trace_id=x_trace_id,
        integration_id=x_integration_id,
    )


async def read_request_context(
    request: Request,
    x_client_id: str | None = Header(default=None, alias="X-Client-Id"),
    x_session_id: str | None = Header(default=None, alias="X-Session-Id"),
    x_trace_id: str | None = Header(default=None, alias="X-Trace-Id"),
    x_integration_id: str | None = Header(default=None, alias="X-Integration-Id"),
) -> dict[str, Any]:
    return await get_request_context(
        request=request,
        x_client_id=x_client_id,
        x_session_id=x_session_id,
        x_trace_id=x_trace_id,
        x_integration_id=x_integration_id,
    )