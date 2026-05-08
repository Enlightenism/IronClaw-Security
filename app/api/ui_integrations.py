from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.core.auth import require_api_key
from app.services.integration_registry import initialize_integration_registry
from app.ui.integrations.controls import build_integration_controls_view
from app.ui.integrations.governance import build_integration_governance_view
from app.ui.integrations.matrix import build_integration_matrix_view
from app.ui.integrations.profile import build_integration_profile_view
from app.ui.integrations.status import build_integration_status_view
from app.ui.integrations.summary import build_integration_summary_view

router = APIRouter(prefix="/ui/integrations", tags=["ui-integrations"])


@router.get("/summary")
def get_integration_summary(
    requested_by: str = Query("ui-router", min_length=1),
    _: str = Depends(require_api_key),
) -> dict:
    registry = initialize_integration_registry()
    view = build_integration_summary_view(
        registry=registry,
        requested_by=requested_by,
    )
    return view.to_dict()


@router.get("/status")
def get_integration_status(
    requested_by: str = Query("ui-router", min_length=1),
    _: str = Depends(require_api_key),
) -> dict:
    registry = initialize_integration_registry()
    view = build_integration_status_view(
        registry=registry,
        requested_by=requested_by,
    )
    return view.to_dict()


@router.get("/controls")
def get_integration_controls(
    requested_by: str = Query("ui-router", min_length=1),
    _: str = Depends(require_api_key),
) -> dict:
    registry = initialize_integration_registry()
    view = build_integration_controls_view(
        registry=registry,
        requested_by=requested_by,
    )
    return view.to_dict()


@router.get("/matrix")
def get_integration_matrix(
    requested_by: str = Query("ui-router", min_length=1),
    _: str = Depends(require_api_key),
) -> dict:
    registry = initialize_integration_registry()
    view = build_integration_matrix_view(
        registry=registry,
        requested_by=requested_by,
    )
    return view.to_dict()


@router.get("/governance")
def get_integration_governance(
    requested_by: str = Query("ui-router", min_length=1),
    _: str = Depends(require_api_key),
) -> dict:
    registry = initialize_integration_registry()
    view = build_integration_governance_view(
        registry=registry,
        requested_by=requested_by,
    )
    return view.to_dict()


@router.get("/profile/{integration_id}")
def get_integration_profile(
    integration_id: str,
    requested_by: str = Query("ui-router", min_length=1),
    _: str = Depends(require_api_key),
) -> dict:
    registry = initialize_integration_registry()
    view = build_integration_profile_view(
        registry=registry,
        integration_id=integration_id,
        requested_by=requested_by,
    )
    return view.to_dict()