from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class RequestContextResponse(BaseModel):
    """
    Normalized request context snapshot for UI and API consumers.

    This schema is wired to the `request-context` endpoint in the OpenAPI
    specification and must remain stable for tests and downstream clients.
    """

    request_id: str | None = Field(
        default=None,
        title="Request Id",
        description="Stable identifier for the current request, if available.",
    )
    trace_id: str | None = Field(
        default=None,
        title="Trace Id",
        description="Trace identifier for correlating logs, spans, and security events.",
    )
    client_id: str | None = Field(
        default=None,
        title="Client Id",
        description="Caller-supplied client identifier from X-Client-Id header.",
    )
    session_id: str | None = Field(
        default=None,
        title="Session Id",
        description="Caller-supplied session identifier from X-Session-Id header.",
    )
    integration_id: str | None = Field(
        default=None,
        title="Integration Id",
        description="Caller-supplied integration identifier from X-Integration-Id header.",
    )
    request_started_at: float | None = Field(
        default=None,
        title="Request Started At",
        description=(
            "Wall-clock timestamp (seconds since epoch) when the request "
            "was first received by IronClaw-Security."
        ),
    )
    client_host: str | None = Field(
        default=None,
        title="Client Host",
        description="Best-effort resolved client host or IP address.",
    )
    client_ip: str | None = Field(
        default=None,
        title="Client Ip",
        description="Resolved client IP, preferring X-Forwarded-For then X-Real-IP then direct.",
    )
    path: str = Field(
        ...,
        title="Path",
        description="Canonical request path as seen by the FastAPI router.",
    )
    method: str = Field(
        ...,
        title="Method",
        description="HTTP method for the request (GET, POST, etc.).",
    )
    user_agent: str | None = Field(
        default=None,
        title="User Agent",
        description="Sanitized User-Agent header value.",
    )
    timestamp: str | None = Field(
        default=None,
        title="Timestamp",
        description="ISO 8601 UTC timestamp when the context snapshot was built.",
    )
    headers: dict[str, Any] = Field(
        default_factory=dict,
        title="Headers",
        description=(
            "Normalized request headers captured at the security boundary. "
            "Values may be redacted according to policy."
        ),
    )

    model_config = {
        "title": "RequestContextResponse",
        "json_schema_extra": {
            "description": (
                "Snapshot of the current HTTP request, used for security telemetry, "
                "audit trails, and UI inspection flows."
            )
        },
    }