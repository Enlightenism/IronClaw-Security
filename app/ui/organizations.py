from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from app.core.unit_wallet import TOKEN_CHUNK_SIZE, UNIT_PACKAGE_CATALOG
from app.services.organization_store import OrganizationStore, get_store

router = APIRouter(tags=["ui-organizations"])

# ---------------------------------------------------------------------------
# Supabase client (service-role, read-only enrichment — non-blocking)
# ---------------------------------------------------------------------------
try:
    from supabase import Client as SupabaseClient
    from supabase import create_client

    _SUPABASE_URL: str = os.environ["SUPABASE_URL"]
    _SUPABASE_SERVICE_KEY: str = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
    _supabase: SupabaseClient = create_client(_SUPABASE_URL, _SUPABASE_SERVICE_KEY)
    _SUPABASE_AVAILABLE = True
except Exception:
    _supabase = None  # type: ignore[assignment]
    _SUPABASE_AVAILABLE = False

# ---------------------------------------------------------------------------
# Canonical package/pricing constants — TOKEN_CHUNK_SIZE is the single source
# of truth (app.core.unit_wallet.TOKEN_CHUNK_SIZE).
# ---------------------------------------------------------------------------
_TOKENS_PER_UNIT = TOKEN_CHUNK_SIZE
_ORDERED_PACKAGE_IDS = ["pkg_5000", "pkg_25000", "pkg_60000"]
_FEATURED_PACKAGE_ID = "pkg_25000"

_PRICING_FALLBACK: dict[str, tuple[int, float, str, str]] = {
    "pkg_5000": (
        5_000,
        20.00,
        "Starter",
        "5,000 units — $20.00",
    ),
    "pkg_25000": (
        25_000,
        90.00,
        "Team",
        "25,000 units — $90.00",
    ),
    "pkg_60000": (
        60_000,
        180.00,
        "Enterprise",
        "60,000 units — $180.00",
    ),
}


def _get_package_metadata(package_id: str) -> dict[str, Any]:
    package = UNIT_PACKAGE_CATALOG.get(package_id)
    if package is not None:
        price_usd = float(package["price_usd"])
        included_units = int(package["unit_amount"])
        name = str(package["name"])
        display_label = str(package.get("display_label", ""))
    else:
        fallback = _PRICING_FALLBACK.get(package_id)
        if fallback is None:
            return {}
        included_units, price_usd, name, display_label = fallback

    price_per_1k = round((price_usd / included_units) * 1_000, 4) if included_units > 0 else 0.0
    return {
        "package_id": package_id,
        "name": name,
        "display_label": display_label,
        "price_usd": price_usd,
        "price_display": f"${price_usd:.2f}",
        "included_units": included_units,
        "units_display": f"{included_units:,} units",
        "tokens_per_unit": _TOKENS_PER_UNIT,
        # Renamed from max_tokens_covered: communicates tokens paid for in this
        # package, not a scan ceiling. Scans are unlimited; units auto-deduct.
        "tokens_in_wallet": included_units * _TOKENS_PER_UNIT,
        "effective_price_per_1k_units": price_per_1k,
        "featured": package_id == _FEATURED_PACKAGE_ID,
    }


def _billing_catalog() -> dict[str, Any]:
    return {
        "tokens_per_unit": _TOKENS_PER_UNIT,
        "featured_package_id": _FEATURED_PACKAGE_ID,
        "unit_consumption_model": (f"1 unit covers up to {_TOKENS_PER_UNIT:,} tokens; additional units consumed in 25,000-token chunks."),
        "packages": {pkg_id: _get_package_metadata(pkg_id) for pkg_id in _ORDERED_PACKAGE_IDS},
    }


# ---------------------------------------------------------------------------
# Supabase enrichment — looks up wallet_units for an org owner_email
# Non-blocking: returns {} on any failure
# ---------------------------------------------------------------------------
def _fetch_owner_wallet(owner_email: str) -> dict[str, Any]:
    if not _SUPABASE_AVAILABLE or _supabase is None or not owner_email:
        return {}
    try:
        result = _supabase.table("users").select("id, email, wallet_units, has_paid, last_payment").eq("email", owner_email).limit(1).execute()
        rows: list[dict[str, Any]] = result.data or []
        if not rows:
            return {}
        row = rows[0]
        wallet_units: int = int(row.get("wallet_units") or 0)
        has_paid: bool = bool(row.get("has_paid", False))
        last_payment: dict[str, Any] = row.get("last_payment") or {}
        active_package_id: str = last_payment.get("package_id", _FEATURED_PACKAGE_ID)
        if active_package_id not in _ORDERED_PACKAGE_IDS:
            active_package_id = _FEATURED_PACKAGE_ID
        return {
            "user_id": str(row.get("id", "")),
            "wallet_units": wallet_units,
            "has_paid": has_paid,
            "active_package_id": active_package_id,
            "active_package": _get_package_metadata(active_package_id),
            # Renamed from max_tokens_covered: current token-equivalent balance
            # in the wallet, not a scan ceiling.
            "tokens_in_wallet": wallet_units * _TOKENS_PER_UNIT,
            "tokens_per_unit": _TOKENS_PER_UNIT,
        }
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Internal helpers (preserved exactly)
# ---------------------------------------------------------------------------
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

    wallet = _fetch_owner_wallet(owner_email)

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
        "billing": wallet,
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
        "billing_catalog": _billing_catalog(),
        "actions": {
            "list_route": "/organizations",
            "create_route": "/organizations",
        },
        "notes": [
            "No organizations found.",
            "Billing is sold as prepaid protection-unit bundles: $20 for 5,000 units (Starter), $90 for 25,000 units (Team), $180 for 60,000 units (Enterprise).",
            f"Each unit covers up to {_TOKENS_PER_UNIT:,} tokens; larger token volumes consume additional units in {_TOKENS_PER_UNIT:,}-token chunks.",
        ],
    }


# ---------------------------------------------------------------------------
# Request model (preserved exactly)
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Routes (logic preserved exactly; billing_catalog added to list response)
# ---------------------------------------------------------------------------
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
        "billing_catalog": _billing_catalog(),
        "actions": {
            "list_route": "/organizations",
            "create_route": "/organizations",
        },
        "notes": [
            "Billing is sold as prepaid protection-unit bundles: $20 for 5,000 units (Starter), $90 for 25,000 units (Team), $180 for 60,000 units (Enterprise).",
            f"Each unit covers up to {_TOKENS_PER_UNIT:,} tokens; larger token volumes consume additional units in {_TOKENS_PER_UNIT:,}-token chunks.",
            "Owner wallet data is enriched from Supabase users table where available; billing block is empty if owner email has no matching user record.",
        ],
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

    record_dict = record.to_dict()
    owner_email = str(record_dict.get("owner_email") or "").strip()
    wallet = _fetch_owner_wallet(owner_email)

    response = record.as_response_dict()
    response["billing"] = wallet
    response["billing_catalog"] = _billing_catalog()

    return {
        "status": "ok",
        "service": "ironclaw-security",
        "timestamp": timestamp,
        "organization": response,
    }
