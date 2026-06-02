from __future__ import annotations

from datetime import UTC, datetime
import logging
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.core.auth import require_api_key
from app.core.supabase import SupabaseAPIError, get_supabase_client

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/ui/billing",
    tags=["unit-ledger"],
    dependencies=[Depends(require_api_key)],
)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


LedgerEntryType = Literal["purchase", "debit", "credit", "adjustment", "refund"]

# ---------------------------------------------------------------------------
# Canonical package pricing — single source of truth for this module.
# ---------------------------------------------------------------------------
_PACKAGE_PRICING_NOTE = "Package pricing: 10,000 units for $20.00 USD | " "50,000 units for $90.00 USD | " "100,000 units for $150.00 USD."


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class UnitLedgerItem(BaseModel):
    entry_id: str
    timestamp: str
    entry_type: LedgerEntryType
    units: int
    balance_after: int = Field(ge=0)
    amount_usd: float | None = Field(default=None, ge=0)
    description: str
    reference_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class UnitLedgerTotalsView(BaseModel):
    total_entries: int = Field(ge=0)
    purchase_entries: int = Field(ge=0)
    debit_entries: int = Field(ge=0)
    credit_entries: int = Field(ge=0)
    adjustment_entries: int = Field(ge=0)
    refund_entries: int = Field(ge=0)
    total_purchased_units: int = Field(ge=0)
    total_consumed_units: int = Field(ge=0)
    total_credited_units: int = Field(ge=0)
    total_refunded_units: int = Field(ge=0)
    total_purchase_amount_usd: float = Field(ge=0)
    current_balance_units: int = Field(ge=0)


class UnitLedgerListResponse(BaseModel):
    generated_at: str
    total: int = Field(ge=0)
    applied_filters: dict[str, Any] = Field(default_factory=dict)
    totals: UnitLedgerTotalsView
    items: list[UnitLedgerItem] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class UnitLedgerDetailResponse(BaseModel):
    generated_at: str
    item: UnitLedgerItem
    notes: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Corrected canonical sample ledger (fallback when Supabase is unavailable).
# balance_after chain (ascending from ledger_001):
#   ledger_001: start 6,200 debit → balance 0
#   ledger_002: +50,000 purchase → balance 50,000
#   ledger_003: -600 debit → balance 49,400
#   ledger_004: +1,200 adjustment → balance 50,600
#   ledger_005: +100,000 purchase → balance 150,600
#   ledger_006: -880 debit → balance 149,720
# ---------------------------------------------------------------------------
_SAMPLE_LEDGER: list[UnitLedgerItem] = [
    UnitLedgerItem(
        entry_id="ledger_006",
        timestamp="2026-04-22T18:10:00Z",
        entry_type="debit",
        units=-880,
        balance_after=149_720,
        amount_usd=None,
        description="Usage debit for guarded execution, telemetry, and prompt protection traffic.",
        reference_id="usage_evt_006",
        metadata={"request_count": 22, "route_group": "guard"},
    ),
    UnitLedgerItem(
        entry_id="ledger_005",
        timestamp="2026-04-22T17:42:00Z",
        entry_type="purchase",
        units=100_000,
        balance_after=150_600,
        amount_usd=150.0,
        description="Package purchase credited to wallet.",
        reference_id="order_005",
        metadata={"package_id": "pkg_100000", "package_name": "100,000 Units", "quantity": 1},
    ),
    UnitLedgerItem(
        entry_id="ledger_004",
        timestamp="2026-04-22T16:15:00Z",
        entry_type="adjustment",
        units=1_200,
        balance_after=50_600,
        amount_usd=None,
        description="Manual unit adjustment applied for account reconciliation.",
        reference_id="adj_004",
        metadata={"reason": "reconciliation", "approved_by": "system"},
    ),
    UnitLedgerItem(
        entry_id="ledger_003",
        timestamp="2026-04-22T15:25:00Z",
        entry_type="debit",
        units=-600,
        balance_after=49_400,
        amount_usd=None,
        description="Usage debit for scan, policy evaluation, and execution traffic.",
        reference_id="usage_evt_003",
        metadata={"request_count": 16, "route_group": "scan"},
    ),
    UnitLedgerItem(
        entry_id="ledger_002",
        timestamp="2026-04-22T14:50:00Z",
        entry_type="purchase",
        units=50_000,
        balance_after=50_000,
        amount_usd=90.0,
        description="Package purchase credited to wallet.",
        reference_id="order_002",
        metadata={"package_id": "pkg_50000", "package_name": "50,000 Units", "quantity": 1},
    ),
    UnitLedgerItem(
        entry_id="ledger_001",
        timestamp="2026-04-22T13:10:00Z",
        entry_type="debit",
        units=-6_200,
        balance_after=0,
        amount_usd=None,
        description="Usage debit for prior execution, audit, and review activity.",
        reference_id="usage_evt_001",
        metadata={"request_count": 125, "route_group": "ui"},
    ),
]


# ---------------------------------------------------------------------------
# Supabase data layer
# ---------------------------------------------------------------------------


def _row_to_item(row: dict[str, Any]) -> UnitLedgerItem:
    return UnitLedgerItem(
        entry_id=row["entry_id"],
        timestamp=row["timestamp"],
        entry_type=row["entry_type"],
        units=row["units"],
        balance_after=row["balance_after"],
        amount_usd=row.get("amount_usd"),
        description=row.get("description", ""),
        reference_id=row.get("reference_id"),
        metadata=row.get("metadata") or {},
    )


def _fetch_from_supabase(
    entry_type: LedgerEntryType | None,
    reference_id: str | None,
    limit: int,
) -> list[UnitLedgerItem] | None:
    """
    Query unit_ledger table in Supabase. Returns None on any error so the
    caller can fall back to _SAMPLE_LEDGER without crashing the route.
    """
    try:
        client = get_supabase_client()
        query = client.table("unit_ledger").select("*").order("timestamp", desc=True).limit(limit)
        if entry_type is not None:
            query = query.eq("entry_type", entry_type)
        if reference_id:
            query = query.ilike("reference_id", f"%{reference_id.strip()}%")

        response = query.execute()
        if response.data is None:
            return None
        return [_row_to_item(row) for row in response.data]
    except SupabaseAPIError as exc:
        logger.warning("unit_ledger Supabase query failed: %s", exc)
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning("unit_ledger unexpected db error: %s", exc)
        return None


def _fetch_entry_from_supabase(entry_id: str) -> UnitLedgerItem | None:
    try:
        client = get_supabase_client()
        response = client.table("unit_ledger").select("*").eq("entry_id", entry_id).limit(1).execute()
        if response.data:
            return _row_to_item(response.data[0])
        return None
    except SupabaseAPIError as exc:
        logger.warning("unit_ledger detail Supabase query failed: %s", exc)
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning("unit_ledger detail unexpected db error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _filter_items(
    items: list[UnitLedgerItem],
    entry_type: LedgerEntryType | None = None,
    reference_id: str | None = None,
) -> list[UnitLedgerItem]:
    filtered = items
    if entry_type is not None:
        filtered = [item for item in filtered if item.entry_type == entry_type]
    if reference_id:
        reference_value = reference_id.strip().lower()
        filtered = [item for item in filtered if item.reference_id and reference_value in item.reference_id.lower()]
    return filtered


def _build_totals(items: list[UnitLedgerItem], all_items: list[UnitLedgerItem]) -> UnitLedgerTotalsView:
    purchase_entries = sum(1 for item in items if item.entry_type == "purchase")
    debit_entries = sum(1 for item in items if item.entry_type == "debit")
    credit_entries = sum(1 for item in items if item.entry_type == "credit")
    adjustment_entries = sum(1 for item in items if item.entry_type == "adjustment")
    refund_entries = sum(1 for item in items if item.entry_type == "refund")

    total_purchased_units = sum(item.units for item in items if item.entry_type == "purchase")
    total_consumed_units = sum(abs(item.units) for item in items if item.entry_type == "debit")
    total_credited_units = sum(item.units for item in items if item.entry_type in {"credit", "adjustment"})
    total_refunded_units = sum(item.units for item in items if item.entry_type == "refund")
    total_purchase_amount_usd = round(
        sum(item.amount_usd or 0 for item in items if item.entry_type == "purchase"),
        2,
    )

    # current_balance derived from the full unfiltered set, not the filtered slice.
    current_balance_units = max(sum(item.units for item in all_items), 0)

    return UnitLedgerTotalsView(
        total_entries=len(items),
        purchase_entries=purchase_entries,
        debit_entries=debit_entries,
        credit_entries=credit_entries,
        adjustment_entries=adjustment_entries,
        refund_entries=refund_entries,
        total_purchased_units=max(total_purchased_units, 0),
        total_consumed_units=total_consumed_units,
        total_credited_units=max(total_credited_units, 0),
        total_refunded_units=max(total_refunded_units, 0),
        total_purchase_amount_usd=total_purchase_amount_usd,
        current_balance_units=current_balance_units,
    )


def _find_entry(entry_id: str) -> UnitLedgerItem | None:
    for item in _SAMPLE_LEDGER:
        if item.entry_id == entry_id:
            return item
    return None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/ledger", response_model=UnitLedgerListResponse)
def get_unit_ledger(
    entry_type: LedgerEntryType | None = Query(default=None),
    reference_id: str | None = Query(default=None, min_length=1, max_length=120),
    limit: int = Query(default=50, ge=1, le=200),
) -> UnitLedgerListResponse:
    db_items = _fetch_from_supabase(entry_type, reference_id, limit)
    using_live_data = db_items is not None

    if using_live_data:
        # Supabase already applied filters + limit; fetch full unfiltered set for balance.
        all_items_raw = _fetch_from_supabase(None, None, 1000) or db_items
        filtered_items = db_items
        limited_items = db_items
    else:
        all_items_raw = _SAMPLE_LEDGER
        filtered_items = _filter_items(_SAMPLE_LEDGER, entry_type=entry_type, reference_id=reference_id)
        limited_items = filtered_items[:limit]

    data_source_note = "Live ledger data served from Supabase." if using_live_data else "Fallback: sample data returned — Supabase unavailable or table not yet seeded."

    return UnitLedgerListResponse(
        generated_at=_utc_now_iso(),
        total=len(filtered_items),
        applied_filters={
            "entry_type": entry_type,
            "reference_id": reference_id,
            "limit": limit,
        },
        totals=_build_totals(filtered_items, all_items_raw),
        items=limited_items,
        notes=[
            "Ledger route provides UI-facing billing activity for wallet purchases, usage debits, and manual adjustments.",
            _PACKAGE_PRICING_NOTE,
            data_source_note,
        ],
    )


@router.get("/ledger/{entry_id}", response_model=UnitLedgerDetailResponse)
def get_unit_ledger_entry(entry_id: str) -> UnitLedgerDetailResponse:
    item = _fetch_entry_from_supabase(entry_id)
    using_live_data = item is not None

    if not using_live_data:
        item = _find_entry(entry_id)

    if item is None:
        raise HTTPException(status_code=404, detail="Ledger entry not found")

    data_source_note = "Live entry served from Supabase." if using_live_data else "Fallback: sample data returned — Supabase unavailable or entry not in live table."

    return UnitLedgerDetailResponse(
        generated_at=_utc_now_iso(),
        item=item,
        notes=[
            "Ledger detail route returns a single wallet activity record for UI drill-down views.",
            data_source_note,
        ],
    )
