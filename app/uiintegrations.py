from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.ui.integrationsettings import build_integrations_settings_page

router = APIRouter(tags=["ui-integrations"])


@router.get("/ui/integrations/settings")
def get_integrations_settings_page() -> JSONResponse:
    return JSONResponse(content=build_integrations_settings_page())
