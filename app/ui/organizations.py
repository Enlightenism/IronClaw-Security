from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from app.services.organization_store import OrganizationStore, get_store

router = APIRouter(tags=["ui-organizations"])


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def _coerce_member_count(record: dict[str, Any]) -> int:
    members = record.get("members")
    if isinstance(members, list):
        return len(members)

    member_count = record.get("member_count")
    if isinstance(member_count, int):
        return max(member_count, 0)

    return 0


def _coerce_created_at(record: dict[str, Any], fallback: str) -> str:
    value = record.get("created_at") or record.get("createdAt") or fallback
    return value if isinstance(value, str) and value else fallback


def _coerce_metadata(record: dict[str, Any]) -> dict[str, Any]:
    metadata = record.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def _organization_item(record: dict[str, Any], fallback_timestamp: str) -> dict[str, Any]:
    org_id = str(record.get("organization_id") or record.get("id") or "").strip()
    name = str(record.get("name") or org_id or "Unknown organization").strip()
    slug = str(record.get("slug") or "").strip()
    status = str(record.get("status") or "active").strip() or "active"
    created_at = _coerce_created_at(record, fallback_timestamp)
    member_count = _coerce_member_count(record)
    metadata = _coerce_metadata(record)
    owner_email = str(
        record.get("owner_email") or metadata.get("owner_email") or metadata.get("ownerEmail") or "",
    ).strip()

    return {
        "organization_id": org_id,
        "name": name,
        "slug": slug,
        "status": status,
        "owner_email": owner_email,
        "member_count": member_count,
        "created_at": created_at,
        "detail_route": f"/organizations/{org_id}" if org_id else "/organizations",
        "members_route": f"/organizations/{org_id}/members" if org_id else "/organizations",
        "metadata": metadata,
    }


def _empty_response(timestamp: str) -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "ironclaw-security",
        "timestamp": timestamp,
        "summary": {
            "total": 0,
            "active": 0,
            "suspended": 0,
            "member_total": 0,
        },
        "items": [],
        "actions": {
            "list_route": "/organizations",
            "create_route": "/organizations",
        },
    }


class CreateOrganizationRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    slug: str = Field(..., min_length=1, max_length=128)
    owner_email: str = Field(..., min_length=3, max_length=254)
    owner_display_name: str = Field(..., min_length=1, max_length=256)
    metadata: dict[str, Any] | None = None

    @field_validator("owner_email")
    @classmethod
    def _normalize_email(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v:
            raise ValueError("Invalid email address")
        return v


@router.get("/ui/organizations")
def get_ui_organizations(
    store: OrganizationStore = Depends(get_store),
) -> dict[str, Any]:
    timestamp = _utcnow_iso()

    try:
        raw_records = store.list_all()
    except Exception:
        raw_records = []

    if not isinstance(raw_records, list):
        raw_records = []

    records = [r.to_dict() if hasattr(r, "to_dict") else r for r in raw_records]
    items = [_organization_item(record, timestamp) for record in records if isinstance(record, dict)]

    if not items:
        return _empty_response(timestamp)

    status_counts = Counter(item["status"] for item in items)
    member_total = sum(item["member_count"] for item in items)

    return {
        "status": "ok",
        "service": "ironclaw-security",
        "timestamp": timestamp,
        "summary": {
            "total": len(items),
            "active": status_counts.get("active", 0),
            "suspended": status_counts.get("suspended", 0),
            "member_total": member_total,
        },
        "items": sorted(
            items,
            key=lambda item: (item["name"].lower(), item["organization_id"]),
        ),
        "actions": {
            "list_route": "/organizations",
            "create_route": "/organizations",
        },
    }


@router.post("/ui/organizations", status_code=201)
def create_ui_organization(
    payload: CreateOrganizationRequest,
    store: OrganizationStore = Depends(get_store),
) -> dict[str, Any]:
    timestamp = _utcnow_iso()

    result = store.create(
        name=payload.name,
        slug=payload.slug,
        owner_email=payload.owner_email,
        owner_display_name=payload.owner_display_name,
        metadata=payload.metadata,
    )

    if isinstance(result, tuple):
        error_code, detail = result
        if error_code == "slug_exists":
            raise HTTPException(
                status_code=409,
                detail=f"Organization slug already exists: {detail}",
            )
        raise HTTPException(status_code=400, detail=f"Create failed: {error_code}")

    return {
        "status": "ok",
        "service": "ironclaw-security",
        "timestamp": timestamp,
        "organization": result.as_response_dict(),
    }


@router.get("/ui/organizations/{organization_id}")
def get_ui_organization_by_id(
    organization_id: str,
    store: OrganizationStore = Depends(get_store),
) -> dict[str, Any]:
    timestamp = _utcnow_iso()

    record = store.get_by_id(organization_id)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=f"Organization not found: {organization_id}",
        )

    return {
        "status": "ok",
        "service": "ironclaw-security",
        "timestamp": timestamp,
        "organization": record.as_response_dict(),
    }
