from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app.dependencies.requestcontext import get_request_context
from app.schemas.requestcontext import RequestContextResponse

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
) -> RequestContextResponse:
    _ = request
    return context