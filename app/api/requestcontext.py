from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Security

from app.dependencies.requestcontext import get_request_context
from app.schemas.requestcontext import RequestContextResponse
from app.security.apikey import api_key_header_auth

router = APIRouter(
    prefix="/request-context",
    tags=["request-context"],
)


@router.get(
    "",
    response_model=RequestContextResponse,
    summary="Read Request Context",
    include_in_schema=True,
)
async def read_request_context(
    request: Request,
    context: Annotated[RequestContextResponse, Depends(get_request_context)],
    api_key: Annotated[str, Security(api_key_header_auth)],
) -> RequestContextResponse:
    """
    Return a normalized snapshot of the current HTTP request context.

    This is primarily used by UI and diagnostics tooling to quickly inspect
    how IronClaw-Security sees the inbound request at the security boundary.
    All normalization, redaction, and correlation logic is centralized in
    `get_request_context`; this handler simply returns the validated model.
    """
    # We intentionally depend on `get_request_context` so that all normalization,
    # redaction, and correlation logic lives in a single shared dependency.
    # The handler simply returns the already-validated Pydantic model.
    _ = request  # accessed to keep the signature stable and avoid linter warnings
    return context