from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.auth import require_api_key
from app.services.quarantinestore import quarantine_store

router = APIRouter(
    prefix="/quarantine",
    tags=["quarantine"],
    dependencies=[Depends(require_api_key)],
)


@router.get("")
def list_quarantine_items(
    status_filter: Optional[str] = Query(
        default=None,
        alias="status",
        pattern="^(isolated|underreview|released|destroyed)$",
    ),
    source: Optional[str] = Query(
        default=None,
        pattern="^(scan|guard|sandbox|review|system)$",
    ),
    risk_level: Optional[str] = Query(
        default=None,
        alias="riskLevel",
        pattern="^(low|medium|high|critical)$",
    ),
):
    return quarantine_store.list_items(
        status=status_filter,
        source=source,
        risk_level=risk_level,
    )


@router.post("", status_code=status.HTTP_201_CREATED)
def create_quarantine_item(payload: dict):
    return quarantine_store.create_item(payload)


@router.get("/{quarantine_id}")
def get_quarantine_item(quarantine_id: str):
    item = quarantine_store.get_item(quarantine_id)
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Quarantine item not found.",
        )
    return item


@router.post("/{quarantine_id}/review")
def review_quarantine_item(quarantine_id: str, payload: dict):
    item = quarantine_store.review_item(quarantine_id, payload)
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Quarantine item not found.",
        )
    return item


@router.post("/{quarantine_id}/release")
def release_quarantine_item(quarantine_id: str, payload: dict):
    item = quarantine_store.release_item(quarantine_id, payload)
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Quarantine item not found.",
        )
    return item


@router.post("/{quarantine_id}/destroy")
def destroy_quarantine_item(quarantine_id: str, payload: dict):
    item = quarantine_store.destroy_item(quarantine_id, payload)
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Quarantine item not found.",
        )
    return item