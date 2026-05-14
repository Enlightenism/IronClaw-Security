from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.core.auth import require_api_key
from app.services.quarantine_store import (
    QuarantineRecord as StoredQuarantineRecord,
)
from app.services.quarantine_store import (
    get_quarantine_store,
)

router = APIRouter(
    prefix="/quarantine",
    tags=["quarantine"],
    dependencies=[Depends(require_api_key)],
)


QuarantineStatus = Literal["isolated", "under_review", "released", "destroyed"]
QuarantineSource = Literal["scan", "guard", "sandbox", "review", "system"]
RiskLevel = Literal["low", "medium", "high", "critical"]


class QuarantineItemView(BaseModel):
    quarantine_id: str
    status: QuarantineStatus
    source: QuarantineSource
    title: str
    summary: str
    risk_level: RiskLevel
    created_at: str
    updated_at: str
    request_id: str | None = None
    trace_id: str | None = None
    incident_id: str | None = None
    asset_ref: str | None = None
    owner: str | None = None
    release_reason: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class QuarantineListResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    total: int
    items: list[QuarantineItemView] = Field(default_factory=list)


class QuarantineCreateRequest(BaseModel):
    source: QuarantineSource
    title: str = Field(min_length=3, max_length=200)
    summary: str = Field(min_length=3, max_length=2000)
    risk_level: RiskLevel
    status: QuarantineStatus = "isolated"
    request_id: str | None = Field(default=None, max_length=200)
    trace_id: str | None = Field(default=None, max_length=200)
    incident_id: str | None = Field(default=None, max_length=200)
    asset_ref: str | None = Field(default=None, max_length=500)
    owner: str | None = Field(default=None, max_length=120)
    release_reason: str | None = Field(default=None, max_length=500)
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class QuarantineReviewRequest(BaseModel):
    owner: str = Field(min_length=1, max_length=120)
    metadata: dict[str, Any] = Field(default_factory=dict)


class QuarantineReleaseRequest(BaseModel):
    release_reason: str = Field(min_length=3, max_length=500)
    released_by: str = Field(min_length=1, max_length=120)
    metadata: dict[str, Any] = Field(default_factory=dict)


class QuarantineDestroyRequest(BaseModel):
    destroyed_by: str = Field(min_length=1, max_length=120)
    destroy_reason: str = Field(min_length=3, max_length=500)
    metadata: dict[str, Any] = Field(default_factory=dict)


class QuarantineActionResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    item: QuarantineItemView


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _to_view(item: StoredQuarantineRecord) -> QuarantineItemView:
    return QuarantineItemView(**item.to_dict())


def _find_item_or_404(quarantine_id: str) -> StoredQuarantineRecord:
    item = get_quarantine_store().get_item(quarantine_id)
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown quarantine item: {quarantine_id}",
        )
    return item


@router.get("/", response_model=QuarantineListResponse)
def list_quarantine_items(
    status_filter: QuarantineStatus | None = Query(default=None, alias="status"),
    source: QuarantineSource | None = Query(default=None),
    risk_level: RiskLevel | None = Query(default=None),
) -> QuarantineListResponse:
    items = get_quarantine_store().list_items(
        status=status_filter,
        source=source,
        risk_level=risk_level,
    )

    return QuarantineListResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        total=len(items),
        items=[_to_view(item) for item in items],
    )


@router.get("/{quarantine_id}", response_model=QuarantineActionResponse)
def get_quarantine_item(quarantine_id: str) -> QuarantineActionResponse:
    item = _find_item_or_404(quarantine_id)
    return QuarantineActionResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        item=_to_view(item),
    )


@router.post("/", response_model=QuarantineActionResponse, status_code=status.HTTP_201_CREATED)
def create_quarantine_item(payload: QuarantineCreateRequest) -> QuarantineActionResponse:
    item = get_quarantine_store().create_item(
        source=payload.source,
        title=payload.title,
        summary=payload.summary,
        risk_level=payload.risk_level,
        status=payload.status,
        request_id=payload.request_id,
        trace_id=payload.trace_id,
        incident_id=payload.incident_id,
        asset_ref=payload.asset_ref,
        owner=payload.owner,
        release_reason=payload.release_reason,
        metadata=payload.metadata,
        tags=payload.tags,
    )

    return QuarantineActionResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        item=_to_view(item),
    )


@router.post("/{quarantine_id}/review", response_model=QuarantineActionResponse)
def review_quarantine_item(
    quarantine_id: str,
    payload: QuarantineReviewRequest,
) -> QuarantineActionResponse:
    item = _find_item_or_404(quarantine_id)

    if item.status in {"released", "destroyed"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Released or destroyed quarantine items cannot return to review.",
        )

    updated = get_quarantine_store().update_item(
        quarantine_id,
        status="under_review",
        owner=payload.owner.strip(),
        metadata={
            **payload.metadata,
            "reviewed_by": payload.owner.strip(),
        },
    )
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown quarantine item: {quarantine_id}",
        )

    return QuarantineActionResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        item=_to_view(updated),
    )


@router.post("/{quarantine_id}/release", response_model=QuarantineActionResponse)
def release_quarantine_item(
    quarantine_id: str,
    payload: QuarantineReleaseRequest,
) -> QuarantineActionResponse:
    item = _find_item_or_404(quarantine_id)

    if item.status == "destroyed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Destroyed quarantine items cannot be released.",
        )

    updated = get_quarantine_store().update_item(
        quarantine_id,
        status="released",
        owner=payload.released_by.strip(),
        release_reason=payload.release_reason.strip(),
        metadata={
            **payload.metadata,
            "released_by": payload.released_by.strip(),
            "release_reason": payload.release_reason.strip(),
        },
    )
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown quarantine item: {quarantine_id}",
        )

    return QuarantineActionResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        item=_to_view(updated),
    )


@router.post("/{quarantine_id}/destroy", response_model=QuarantineActionResponse)
def destroy_quarantine_item(
    quarantine_id: str,
    payload: QuarantineDestroyRequest,
) -> QuarantineActionResponse:
    item = _find_item_or_404(quarantine_id)

    if item.status == "released":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Released quarantine items cannot be destroyed.",
        )

    updated = get_quarantine_store().update_item(
        quarantine_id,
        status="destroyed",
        owner=payload.destroyed_by.strip(),
        metadata={
            **payload.metadata,
            "destroyed_by": payload.destroyed_by.strip(),
            "destroy_reason": payload.destroy_reason.strip(),
        },
    )
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown quarantine item: {quarantine_id}",
        )

    return QuarantineActionResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        item=_to_view(updated),
    )
