from __future__ import annotations

from fastapi import APIRouter, Depends

from app.dependencies.requestcontext import get_request_context
from app.schemas.requestcontext import RequestContextResponse

router = APIRouter(tags=["request-context"])


@router.get(
    "/request-context",
    operation_id="read_request_context",
    response_model=RequestContextResponse,
)
async def read_request_context(
    context: RequestContextResponse = Depends(get_request_context),
) -> RequestContextResponse:
    return context