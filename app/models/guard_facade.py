from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class GuardActionRequest(BaseModel):
    """Stable, transport-agnostic request model for the guard façade.

    This is what internal callers (agents, orchestrators, tools) should use
    instead of binding directly to the HTTP-layer ExecuteRequest.
    """

    action_type: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    content: str = Field(default="")
    risk_score: int = Field(ge=0, le=100)
    client_id: str | None = None
    session_id: str | None = None
    file_path: str | None = None
    extra_metadata: dict[str, Any] | None = None
