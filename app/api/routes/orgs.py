from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.core.auth import require_api_key
from app.services.org_store import (
    OrgMemberRecord as StoredOrgMemberRecord,
    OrganizationRecord as StoredOrganizationRecord,
    get_org_store,
)

router = APIRouter(
    prefix="/orgs",
    tags=["orgs"],
    dependencies=[Depends(require_api_key)],
)

OrgRole = Literal["owner", "admin", "analyst", "viewer"]
OrgMemberStatus = Literal["active", "invited", "suspended"]
OrgStatus = Literal["active", "trialing", "suspended"]


class OrgMemberView(BaseModel):
    member_id: str
    user_id: str
    email: str
    display_name: str
    role: OrgRole
    status: OrgMemberStatus
    joined_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class OrganizationView(BaseModel):
    org_id: str
    name: str
    slug: str
    status: OrgStatus
    created_at: str
    updated_at: str
    owner_user_id: str
    plan_name: str
    members: list[OrgMemberView] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class OrgListResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    total: int
    items: list[OrganizationView] = Field(default_factory=list)


class OrgResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    org: OrganizationView


class CreateOrgRequest(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    slug: str = Field(min_length=2, max_length=120)
    owner_user_id: str = Field(min_length=1, max_length=120)
    owner_email: str = Field(min_length=3, max_length=200)
    owner_display_name: str = Field(min_length=1, max_length=120)
    plan_name: str = Field(min_length=1, max_length=80)
    status: OrgStatus = "trialing"
    metadata: dict[str, Any] = Field(default_factory=dict)


class AddOrgMemberRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=120)
    email: str = Field(min_length=3, max_length=200)
    display_name: str = Field(min_length=1, max_length=120)
    role: OrgRole
    status: OrgMemberStatus = "invited"
    metadata: dict[str, Any] = Field(default_factory=dict)


class UpdateOrgMemberRequest(BaseModel):
    role: OrgRole
    status: OrgMemberStatus | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class UpdateOrgStatusRequest(BaseModel):
    status: OrgStatus
    plan_name: str | None = Field(default=None, min_length=1, max_length=80)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _member_to_view(member: StoredOrgMemberRecord) -> OrgMemberView:
    payload = member.to_dict()
    return OrgMemberView(
        member_id=payload["member_id"],
        user_id=payload["user_id"],
        email=payload["email"],
        display_name=payload["display_name"],
        role=payload["role"],
        status=payload["status"],
        joined_at=payload["joined_at"],
        metadata=dict(payload.get("metadata") or {}),
    )


def _org_to_view(org: StoredOrganizationRecord) -> OrganizationView:
    payload = org.to_dict()
    return OrganizationView(
        org_id=payload["org_id"],
        name=payload["name"],
        slug=payload["slug"],
        status=payload["status"],
        created_at=payload["created_at"],
        updated_at=payload["updated_at"],
        owner_user_id=payload["owner_user_id"],
        plan_name=payload["plan_name"],
        members=[_member_to_view(member) for member in org.members],
        metadata=dict(payload.get("metadata") or {}),
    )


def _find_org_or_404(org_id: str) -> StoredOrganizationRecord:
    org = get_org_store().get_org(org_id)
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown organization: {org_id}",
        )
    return org


@router.get("/", response_model=OrgListResponse)
def list_orgs(
    status_filter: OrgStatus | None = Query(default=None, alias="status"),
) -> OrgListResponse:
    items = get_org_store().list_orgs(status=status_filter)
    return OrgListResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        total=len(items),
        items=[_org_to_view(item) for item in items],
    )


@router.get("/{org_id}", response_model=OrgResponse)
def get_org(org_id: str) -> OrgResponse:
    org = _find_org_or_404(org_id)
    return OrgResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        org=_org_to_view(org),
    )


@router.post("/", response_model=OrgResponse, status_code=status.HTTP_201_CREATED)
def create_org(payload: CreateOrgRequest) -> OrgResponse:
    org = get_org_store().create_org(
        name=payload.name,
        slug=payload.slug,
        owner_user_id=payload.owner_user_id,
        owner_email=payload.owner_email,
        owner_display_name=payload.owner_display_name,
        plan_name=payload.plan_name,
        status=payload.status,
        metadata=payload.metadata,
    )
    return OrgResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        org=_org_to_view(org),
    )


@router.post(
    "/{org_id}/members",
    response_model=OrgResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_org_member(
    org_id: str,
    payload: AddOrgMemberRequest,
) -> OrgResponse:
    _find_org_or_404(org_id)
    org = get_org_store().add_member(
        org_id,
        user_id=payload.user_id,
        email=payload.email,
        display_name=payload.display_name,
        role=payload.role,
        status=payload.status,
        metadata=payload.metadata,
    )
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown organization: {org_id}",
        )
    return OrgResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        org=_org_to_view(org),
    )


@router.put("/{org_id}/members/{member_id}", response_model=OrgResponse)
def update_org_member(
    org_id: str,
    member_id: str,
    payload: UpdateOrgMemberRequest,
) -> OrgResponse:
    _find_org_or_404(org_id)
    org = get_org_store().update_member_role(
        org_id,
        member_id,
        role=payload.role,
        status=payload.status,
        metadata=payload.metadata,
    )
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown org/member combination: {org_id}/{member_id}",
        )
    return OrgResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        org=_org_to_view(org),
    )


@router.put("/{org_id}/status", response_model=OrgResponse)
def update_org_status(
    org_id: str,
    payload: UpdateOrgStatusRequest,
) -> OrgResponse:
    _find_org_or_404(org_id)
    org = get_org_store().update_org_status(
        org_id,
        status=payload.status,
        plan_name=payload.plan_name,
        metadata=payload.metadata,
    )
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown organization: {org_id}",
        )
    return OrgResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        org=_org_to_view(org),
    )