from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.services.organizationstore import (
    OrganizationMemberRecord as StoredOrganizationMemberRecord,
)
from app.services.organizationstore import (
    OrganizationRecord as StoredOrganizationRecord,
)
from app.services.organizationstore import (
    getorganizationstore,
)

router = APIRouter(
    prefix="/organizations",
    tags=["organizations"],
)

OrganizationRole = Literal["owner", "admin", "analyst", "viewer"]
OrganizationMemberStatus = Literal["active", "suspended", "invited"]
OrganizationStatus = Literal["active", "suspended"]


class OrganizationMemberView(BaseModel):
    memberid: str
    email: str
    displayname: str
    role: OrganizationRole
    status: OrganizationMemberStatus
    createdat: str
    updatedat: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class OrganizationView(BaseModel):
    organizationid: str
    name: str
    slug: str
    status: OrganizationStatus
    createdat: str
    updatedat: str
    owneremail: str
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
    owneremail: str = Field(min_length=3, max_length=255)
    ownerdisplayname: str = Field(min_length=1, max_length=120)
    metadata: dict[str, Any] = Field(default_factory=dict)


class OrganizationMemberCreateRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    displayname: str = Field(min_length=1, max_length=120)
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
    payload = member.to_dict()
    return OrganizationMemberView(
        memberid=payload["memberid"],
        email=payload["email"],
        displayname=payload["displayname"],
        role=payload["role"],
        status=payload["status"],
        createdat=payload["createdat"],
        updatedat=payload["updatedat"],
        metadata=dict(payload.get("metadata") or {}),
    )


def _organization_to_view(organization: StoredOrganizationRecord) -> OrganizationView:
    payload = organization.to_dict()
    return OrganizationView(
        organizationid=payload["organizationid"],
        name=payload["name"],
        slug=payload["slug"],
        status=payload["status"],
        createdat=payload["createdat"],
        updatedat=payload["updatedat"],
        owneremail=payload["owneremail"],
        members=[_member_to_view(member) for member in organization.members],
        metadata=dict(payload.get("metadata") or {}),
    )


def _find_organization_or_404(organizationid: str) -> StoredOrganizationRecord:
    organization = getorganizationstore().getorganization(organizationid)
    if organization is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown organization: {organizationid}",
        )
    return organization


@router.get("", response_model=OrganizationListResponse)
def list_organizations(
    status_filter: OrganizationStatus | None = Query(default=None, alias="status"),
) -> OrganizationListResponse:
    items = getorganizationstore().listorganizations(status=status_filter)
    return OrganizationListResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        total=len(items),
        items=[_organization_to_view(item) for item in items],
    )


@router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
def create_organization(payload: OrganizationCreateRequest) -> OrganizationResponse:
    result = getorganizationstore().createorganization(
        name=payload.name,
        slug=payload.slug,
        owneremail=payload.owneremail,
        ownerdisplayname=payload.ownerdisplayname,
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


@router.get("/{organizationid}", response_model=OrganizationResponse)
def get_organization(organizationid: str) -> OrganizationResponse:
    organization = _find_organization_or_404(organizationid)
    return OrganizationResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        organization=_organization_to_view(organization),
    )


@router.post(
    "/{organizationid}/members",
    response_model=OrganizationResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_organization_member(
    organizationid: str,
    payload: OrganizationMemberCreateRequest,
) -> OrganizationResponse:
    result = getorganizationstore().addmember(
        organizationid,
        email=payload.email,
        displayname=payload.displayname,
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
