from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.services.telemetry import append_telemetry_event

router = APIRouter()

SERVICE_NAME = "IronClaw-Security"
OK_STATUS = "ok"


class RequestMeta(BaseModel):
    request_id: str | None = None
    trace_id: str | None = None
    path: str
    method: str


class HeadersPresent(BaseModel):
    x_request_id: bool
    x_trace_id: bool
    user_agent: bool


class ClientInfo(BaseModel):
    host: str | None = None
    port: int | None = None


class DiagnosticsDetails(BaseModel):
    request: RequestMeta
    headers_present: HeadersPresent
    client: ClientInfo


class DiagnosticsResponse(BaseModel):
    status: str
    service: str
    diagnostics: DiagnosticsDetails


def _request_meta(request: Request) -> RequestMeta:
    return RequestMeta(
        request_id=getattr(request.state, "request_id", None),
        trace_id=getattr(request.state, "trace_id", None),
        path=request.url.path,
        method=request.method,
    )


def _client_info(request: Request) -> ClientInfo:
    client = request.client
    return ClientInfo(
        host=client.host if client else None,
        port=client.port if client else None,
    )


def _headers_present(request: Request) -> HeadersPresent:
    return HeadersPresent(
        x_request_id=request.headers.get("x-request-id") is not None,
        x_trace_id=request.headers.get("x-trace-id") is not None,
        user_agent=request.headers.get("user-agent") is not None,
    )


def _safe_append_telemetry_event(event_name: str, payload: dict[str, Any]) -> None:
    try:
        append_telemetry_event(event_name, payload)
    except Exception:
        pass


@router.get("/diagnostics", response_model=DiagnosticsResponse, tags=["system"], summary="Diagnostics")
def diagnostics(request: Request) -> DiagnosticsResponse:
    request_meta = _request_meta(request)
    client_info = _client_info(request)
    headers_present = _headers_present(request)

    payload = DiagnosticsResponse(
        status=OK_STATUS,
        service=SERVICE_NAME,
        diagnostics=DiagnosticsDetails(
            request=request_meta,
            headers_present=headers_present,
            client=client_info,
        ),
    )

    _safe_append_telemetry_event(
        "diagnostics_requested",
        {
            **request_meta.model_dump(),
            "client_host": client_info.host,
            "client_port": client_info.port,
            "headers_present": headers_present.model_dump(),
        },
    )

    return payload
