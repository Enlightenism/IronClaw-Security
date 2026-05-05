from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.actionexecuteservice import get_action_execute_service

router = APIRouter(prefix="/action", tags=["action-usage"])


class ActionUsageResponse(BaseModel):
    ownerkey: str
    snapshot: dict[str, Any] = Field(
        default_factory=dict,
        description="Current prepaid usage and entitlement snapshot for the owner.",
    )


@router.get("/usage/{ownerkey}", response_model=ActionUsageResponse)
def getactionusage(ownerkey: str) -> ActionUsageResponse:
    normalized_ownerkey = ownerkey.strip()
    if not normalized_ownerkey:
        raise HTTPException(status_code=400, detail="ownerkey must not be empty")

    service = get_action_execute_service()
    snapshot = service.get_usage_snapshot(owner_key=normalized_ownerkey)

    if snapshot is None:
        snapshot = {}

    return ActionUsageResponse(
        ownerkey=normalized_ownerkey,
        snapshot=snapshot,
    )