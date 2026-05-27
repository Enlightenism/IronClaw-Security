from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.core.auth import require_api_key
from app.services.organization_store import (
    OrganizationMemberRecord as StoredOrganizationMemberRecord,
)
from app.services.organization_store import (
    OrganizationRecord as StoredOrganizationRecord,
)
from app.services.organization_store import (
    OrganizationStore,
    get_store,
)

router = APIRouter(
    prefix="/organizations",
    tags=["organizations"],
    dependencies=[Depends(require_api_key)],
)


OrganizationRole = Literal["owner", "admin", "analyst", "viewer"]
OrganizationStatus = Literal["active", "suspended", "invited"]


class OrganizationMemberView(BaseModel):
    member_id: str
    email: str
    display_name: str
    role: OrganizationRole
    status: OrganizationStatus
    created_at: str
    updated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class OrganizationView(BaseModel):
    organization_id: str
    name: str
    slug: str
    status: Literal["active", "suspended"]
    created_at: str
    updated_at: str
    owner_email: str
    members: list[OrganizationMemberView] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class OrganizationListResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    total: int
    items: list[OrganizationView] = Field(default_factory=list)


class OrganizationCreateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    slug: str = Field(min_length=2, max_length=120)
    owner_email: str = Field(min_length=3, max_length=255)
    owner_display_name: str = Field(min_length=1, max_length=120)
    metadata: dict[str, Any] = Field(default_factory=dict)


class OrganizationMemberCreateRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    display_name: str = Field(min_length=1, max_length=120)
    role: OrganizationRole
    metadata: dict[str, Any] = Field(default_factory=dict)


class OrganizationResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    organization: OrganizationView


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _member_to_view(member: StoredOrganizationMemberRecord) -> OrganizationMemberView:
    return OrganizationMemberView(**member.to_dict())


def _organization_to_view(organization: StoredOrganizationRecord) -> OrganizationView:
    data = organization.to_dict()
    return OrganizationView(
        organization_id=data["organization_id"],
        name=data["name"],
        slug=data["slug"],
        status=data["status"],
        created_at=data["created_at"],
        updated_at=data["updated_at"],
        owner_email=data["owner_email"],
        members=[OrganizationMemberView(**member) for member in data["members"]],
        metadata=data["metadata"],
    )


@router.get("", response_model=OrganizationListResponse)
def list_organizations(
    status_filter: Literal["active", "suspended"] | None = Query(default=None, alias="status"),
    store: OrganizationStore = Depends(get_store),
) -> OrganizationListResponse:
    items = store.list_all() if status_filter is None else store.list_by_status(status_filter)
    return OrganizationListResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        total=len(items),
        items=[_organization_to_view(item) for item in items],
    )


@router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
def create_organization(
    payload: OrganizationCreateRequest,
    store: OrganizationStore = Depends(get_store),
) -> OrganizationResponse:
    result = store.create(
        name=payload.name,
        slug=payload.slug,
        owner_email=payload.owner_email,
        owner_display_name=payload.owner_display_name,
        metadata=payload.metadata,
    )

    if isinstance(result, tuple):
        _, normalized_slug = result
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Organization slug already exists: {normalized_slug}",
        )

    return OrganizationResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        organization=_organization_to_view(result),
    )


@router.get("/{organization_id}", response_model=OrganizationResponse)
def get_organization(
    organization_id: str,
    store: OrganizationStore = Depends(get_store),
) -> OrganizationResponse:
    organization = store.get_by_id(organization_id)
    if organization is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown organization: {organization_id}",
        )
    return OrganizationResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        organization=_organization_to_view(organization),
    )


@router.post(
    "/{organization_id}/members",
    response_model=OrganizationResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_organization_member(
    organization_id: str,
    payload: OrganizationMemberCreateRequest,
    store: OrganizationStore = Depends(get_store),
) -> OrganizationResponse:
    result = store.add_member(
        organization_id,
        email=payload.email,
        display_name=payload.display_name,
        role=payload.role,
        metadata=payload.metadata,
    )

    if isinstance(result, tuple):
        error_type, value = result
        if error_type == "member_exists":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Organization member already exists: {value}",
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown organization: {value}",
        )

    return OrganizationResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        organization=_organization_to_view(result),
    )
