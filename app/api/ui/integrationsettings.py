from __future__ import annotations

from fastapi import APIRouter

from app.ui.integrationsettings import get_ui_integration_settings_page

router = APIRouter(prefix="/ui/integrations", tags=["ui-integrations"])


@router.get("/settings")
def read_ui_integration_settings() -> dict[str, object]:
    return get_ui_integration_settings_page()