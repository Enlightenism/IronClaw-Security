from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.schemas.requestcontext import RequestContextResponse
from app.ui.router import register_page

try:
    from app.ui.telemetryaccesssummary import get_telemetry_context
except ImportError:  # pragma: no cover

    def get_telemetry_context() -> dict[str, Any]:
        return {}


router = APIRouter()


@register_page(
    router=router,
    slug="request-context",
    label="Request context",
    category="Diagnostics",
    tags=["diagnostics", "runtime", "http"],
)
@router.get(
    "/ui/request-context",
    response_model=RequestContextResponse,
    summary="Request context inspector",
)
async def ui_request_context_page(
    request_context: RequestContextResponse = Depends(),
    _ui_context: dict[str, Any] = Depends(get_telemetry_context),
) -> RequestContextResponse:
    """UI-facing request context inspector.

    This route mirrors the `/request-context` API contract so the UI can
    render the normalized current-request view without introducing schema
    drift. UI-only decoration belongs in manifest/view-model layers, not
    in this response contract.
    """
    return request_context
