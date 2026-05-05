from __future__ import annotations

from typing import Any

from fastapi import Request


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


def get_request_context(request: Request) -> dict[str, Any]:
    return {
        "request_id": get_request_id(request),
        "trace_id": get_trace_id(request),
        "request_started_at": get_request_started_at(request),
        "client_host": get_client_host(request),
        "path": get_request_path(request),
        "method": get_request_method(request),
    }