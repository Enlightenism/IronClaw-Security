from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from app.dependencies.request_context import get_request_context
from app.services.telemetry import append_telemetry_event

router = APIRouter(prefix="/request-context", tags=["request-context"])


class RequestContextResponse(BaseModel):
    request_id: str | None = None
    trace_id: str | None = None
    request_started_at: float | None = None
    client_host: str | None = None
    path: str
    method: str
    headers: dict[str, Any] = Field(default_factory=dict)


@router.get("", response_model=RequestContextResponse)
def read_request_context(request: Request) -> RequestContextResponse:
    context = get_request_context(request)

    safe_headers = {
        "x-request-id": request.headers.get("X-Request-ID"),
        "x-trace-id": request.headers.get("X-Trace-ID"),
        "user-agent": request.headers.get("User-Agent"),
    }

    try:
        append_telemetry_event(
            "request_context_requested",
            {
                "request_id": context.get("request_id"),
                "trace_id": context.get("trace_id"),
                "path": context.get("path"),
                "method": context.get("method"),
            },
        )
    except Exception:
        pass

    return RequestContextResponse(
        request_id=context.get("request_id"),
        trace_id=context.get("trace_id"),
        request_started_at=context.get("request_started_at"),
        client_host=context.get("client_host"),
        path=context.get("path") or request.url.path,
        method=context.get("method") or request.method,
        headers=safe_headers,
    )