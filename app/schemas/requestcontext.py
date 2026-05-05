from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class RequestContextResponse(BaseModel):
    """
    Normalized request context snapshot for UI and API consumers.

    This schema is wired to the `request-context` endpoint in the OpenAPI
    specification and must remain stable for tests and downstream clients.
    """

    request_id: Optional[str] = Field(
        default=None,
        title="Request Id",
        description="Stable identifier for the current request, if available.",
    )
    trace_id: Optional[str] = Field(
        default=None,
        title="Trace Id",
        description="Trace identifier for correlating logs, spans, and security events.",
    )
    request_started_at: Optional[float] = Field(
        default=None,
        title="Request Started At",
        description=(
            "Wall-clock timestamp (seconds since epoch) when the request "
            "was first received by IronClaw-Security."
        ),
    )
    client_host: Optional[str] = Field(
        default=None,
        title="Client Host",
        description="Best-effort resolved client host or IP address.",
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
    headers: Dict[str, Any] = Field(
        default_factory=dict,
        title="Headers",
        description=(
            "Normalized request headers captured at the security boundary. "
            "Values may be redacted according to policy."
        ),
    )

    class Config:
        title = "RequestContextResponse"
        json_schema_extra = {
            "description": (
                "Snapshot of the current HTTP request, used for security telemetry, "
                "audit trails, and UI inspection flows."
            )
        }