from __future__ import annotations

from datetime import UTC, datetime
import os
from typing import Any

from fastapi import APIRouter, Path
from pydantic import BaseModel, Field

try:
    from app.core.unit_wallet import TOKEN_CHUNK_SIZE, UNIT_PACKAGE_CATALOG, units_required_for_tokens
except Exception:
    UNIT_PACKAGE_CATALOG: dict[str, Any] = {}
    TOKEN_CHUNK_SIZE: int = 25_000

    def units_required_for_tokens(token_count: int) -> int:
        if token_count <= 0:
            return 0
        import math

        return math.ceil(token_count / TOKEN_CHUNK_SIZE)


router = APIRouter(prefix="/customer-keys/detail", tags=["customer-key-detail"])

# ---------------------------------------------------------------------------
# Supabase client (service-role key, used only for server-side key lookup)
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
# of truth (app.core.unit_wallet.TOKEN_CHUNK_SIZE). Local alias kept for
# backwards-compat with existing serialisation field names.
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


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _token_coverage_metadata(wallet_units: int) -> dict[str, Any]:
    # tokens_in_wallet: token-equivalent balance for the units currently in
    # the wallet.  Scans are unlimited; units auto-deduct — this is NOT a cap.
    return {
        "tokens_per_unit": _TOKENS_PER_UNIT,
        "wallet_units": wallet_units,
        "tokens_in_wallet": wallet_units * _TOKENS_PER_UNIT,
        "unit_consumption_model": (f"1 unit covers up to {_TOKENS_PER_UNIT:,} tokens; " "additional units are consumed in 25,000-token chunks."),
    }


# ---------------------------------------------------------------------------
# Package metadata helper
# ---------------------------------------------------------------------------
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
        # Renamed from max_tokens_covered: communicates "tokens paid for in
        # this package" not a scan ceiling. Scans are unlimited; units
        # auto-deduct in TOKEN_CHUNK_SIZE chunks with no ceiling.
        "tokens_in_wallet": included_units * _TOKENS_PER_UNIT,
        "effective_price_per_1k_units": price_per_1k,
        "featured": package_id == _FEATURED_PACKAGE_ID,
    }


# ---------------------------------------------------------------------------
# Pydantic view models
# ---------------------------------------------------------------------------
class CustomerKeyDetailOwnerView(BaseModel):
    owner_type: str
    owner_id: str
    owner_display_name: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class CustomerKeyDetailUsageView(BaseModel):
    last_used_at: str | None = None
    total_requests: int
    total_scans: int
    total_blocks: int
    total_warnings: int
    metadata: dict[str, Any] = Field(default_factory=dict)


class CustomerKeyDetailPolicyView(BaseModel):
    scopes: list[str] = Field(default_factory=list)
    environment: str
    rotation_due: bool
    revocable: bool
    metadata: dict[str, Any] = Field(default_factory=dict)


class CustomerKeyDetailActionView(BaseModel):
    action_id: str
    label: str
    method: str
    path: str
    description: str
    requires_api_key: bool = True


class CustomerKeyDetailResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    key_id: str
    label: str
    key_status: str
    masked_key: str
    created_at: str
    owner: CustomerKeyDetailOwnerView
    usage: CustomerKeyDetailUsageView
    policy: CustomerKeyDetailPolicyView
    billing: dict[str, Any] = Field(default_factory=dict)
    actions: list[CustomerKeyDetailActionView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _build_actions(key_id: str) -> list[CustomerKeyDetailActionView]:
    return [
        CustomerKeyDetailActionView(
            action_id="list-customer-keys",
            label="List customer keys",
            method="GET",
            path="/ui/customer-keys",
            description="Returns the customer key inventory view.",
            requires_api_key=False,
        ),
        CustomerKeyDetailActionView(
            action_id="read-customer-key",
            label="Read customer key detail",
            method="GET",
            path=f"/ui/customer-keys/detail/{key_id}",
            description="Returns the detailed UI view for the selected customer key.",
            requires_api_key=False,
        ),
        CustomerKeyDetailActionView(
            action_id="revoke-customer-key",
            label="Revoke customer key",
            method="POST",
            path=f"/customer-keys/{key_id}/revoke",
            description="Revokes the selected customer API key.",
        ),
    ]


def _lookup_key_record(key_id: str) -> dict[str, Any] | None:
    """Query Supabase users table by user_token (key_id). Returns row dict or None."""
    if not _SUPABASE_AVAILABLE or _supabase is None:
        return None
    try:
        result = _supabase.table("users").select("id, email, user_token, wallet_units, has_paid, last_payment, created_at").eq("user_token", key_id).limit(1).execute()
        rows = result.data or []
        return rows[0] if rows else None
    except Exception:
        return None


def _build_usage_from_supabase(user_id: str) -> CustomerKeyDetailUsageView:
    """Query security_events for lifetime usage stats for the given user_id."""
    if not _SUPABASE_AVAILABLE or _supabase is None:
        return CustomerKeyDetailUsageView(
            last_used_at=None,
            total_requests=0,
            total_scans=0,
            total_blocks=0,
            total_warnings=0,
            metadata={"usage_state": "no-activity", "window": "lifetime"},
        )
    try:
        result = _supabase.table("security_events").select("verdict, units_used, timestamp").eq("user_id", user_id).order("timestamp", desc=True).execute()
        rows: list[dict[str, Any]] = result.data or []
        total_requests = len(rows)
        total_scans = total_requests
        total_blocks = sum(1 for r in rows if r.get("verdict") == "block")
        total_warnings = sum(1 for r in rows if r.get("verdict") == "warn")
        last_used_at: str | None = rows[0].get("timestamp") if rows else None
        usage_state = "no-activity" if total_requests == 0 else "active"
        return CustomerKeyDetailUsageView(
            last_used_at=last_used_at,
            total_requests=total_requests,
            total_scans=total_scans,
            total_blocks=total_blocks,
            total_warnings=total_warnings,
            metadata={"usage_state": usage_state, "window": "lifetime"},
        )
    except Exception:
        return CustomerKeyDetailUsageView(
            last_used_at=None,
            total_requests=0,
            total_scans=0,
            total_blocks=0,
            total_warnings=0,
            metadata={"usage_state": "lookup-error", "window": "lifetime"},
        )


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------
@router.get("/{key_id}", response_model=CustomerKeyDetailResponse)
def get_customer_key_detail(
    key_id: str = Path(..., min_length=1, max_length=255),
) -> CustomerKeyDetailResponse:
    normalized_key_id = key_id.strip()

    key_record = _lookup_key_record(normalized_key_id)

    if key_record is not None:
        owner_id: str = key_record.get("id", "unknown")
        owner_display_name: str = key_record.get("email", "Unknown Customer")
        key_created_at: str = str(key_record.get("created_at") or _utc_now_iso())
        wallet_units: int = int(key_record.get("wallet_units") or 0)
        has_paid: bool = bool(key_record.get("has_paid", False))
        last_payment: dict[str, Any] = key_record.get("last_payment") or {}
        key_status = "active" if has_paid else "pending"
        source = "supabase"
    else:
        owner_id = "default-customer"
        owner_display_name = "Default Customer"
        key_created_at = _utc_now_iso()
        wallet_units = 0
        has_paid = False
        last_payment = {}
        key_status = "active"
        source = "fallback"

    # Determine active package from last_payment if present
    active_package_id: str = last_payment.get("package_id", _FEATURED_PACKAGE_ID)
    if active_package_id not in _ORDERED_PACKAGE_IDS:
        active_package_id = _FEATURED_PACKAGE_ID

    package_meta = _get_package_metadata(active_package_id)
    token_meta = _token_coverage_metadata(wallet_units)

    usage = (
        _build_usage_from_supabase(owner_id)
        if key_record is not None
        else CustomerKeyDetailUsageView(
            last_used_at=None,
            total_requests=0,
            total_scans=0,
            total_blocks=0,
            total_warnings=0,
            metadata={"usage_state": "no-activity", "window": "lifetime"},
        )
    )

    units_required_example = units_required_for_tokens(50_000)

    return CustomerKeyDetailResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        key_id=normalized_key_id,
        label="Customer Key Detail",
        key_status=key_status,
        masked_key=(f"{normalized_key_id[:12]}..." if len(normalized_key_id) > 12 else normalized_key_id),
        created_at=key_created_at,
        owner=CustomerKeyDetailOwnerView(
            owner_type="customer",
            owner_id=owner_id,
            owner_display_name=owner_display_name,
            metadata={
                "tenant_state": "active" if has_paid else "inactive",
                "source": source,
                "has_paid": has_paid,
            },
        ),
        usage=usage,
        policy=CustomerKeyDetailPolicyView(
            scopes=["scan:write", "history:read", "billing:read"],
            environment="production",
            rotation_due=False,
            revocable=True,
            metadata={
                "policy_profile": "default-customer-access",
                "supports_billing": True,
                "tokens_per_unit": _TOKENS_PER_UNIT,
                "token_consumption_model": (f"1 unit covers up to {_TOKENS_PER_UNIT:,} tokens; " "additional units consumed in 25,000-token chunks."),
            },
        ),
        billing={
            "wallet_units": wallet_units,
            "active_package_id": active_package_id,
            "package": package_meta,
            "token_coverage": token_meta,
            "units_required_example": {
                "token_count": 50_000,
                "units_required": units_required_example,
                "note": "50,000 tokens requires 2 units (2 × 25,000-token chunks).",
            },
            "packages_catalog": {pkg_id: _get_package_metadata(pkg_id) for pkg_id in _ORDERED_PACKAGE_IDS},
            "featured_package_id": _FEATURED_PACKAGE_ID,
        },
        actions=_build_actions(normalized_key_id),
        notes=[
            "Customer key detail gives operators a focused view of ownership, usage, and access scope.",
            "Masked key material is returned for identification without exposing the full secret.",
            "Key lookup is performed against the Supabase users table via user_token; falls back to defaults if not found.",
            "Billing is sold as prepaid protection-unit bundles: $20 for 5,000 units (Starter), $90 for 25,000 units (Team), $180 for 60,000 units (Enterprise).",
            f"Each unit covers up to {_TOKENS_PER_UNIT:,} tokens; token volumes exceeding one unit consume additional units in {_TOKENS_PER_UNIT:,}-token chunks.",
            "Example: 50,000 tokens = 2 units consumed (2 × 25,000-token chunks).",
            "tokens_per_unit and full token coverage metadata are surfaced in both the policy and billing blocks.",
        ],
    )
