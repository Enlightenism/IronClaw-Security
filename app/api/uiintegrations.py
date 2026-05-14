from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.core.auth import require_api_key
from app.ui.uiintegrations import get_ui_integrations_page

router = APIRouter(tags=["ui"])


@router.get("/ui/integrations")
def get_ui_integrations_root(
    request: Request,
    _: str | None = Depends(require_api_key),
) -> dict[str, object]:
    page = dict(get_ui_integrations_page())
    page.setdefault("status", "ok")
    page["request_id"] = getattr(request.state, "request_id", None)
    return page
