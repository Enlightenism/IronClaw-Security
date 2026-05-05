from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.core.auth import require_api_key


router = APIRouter(
    prefix="/ui/billing",
    tags=["unit-ledger"],
    dependencies=[Depends(require_api_key)],
)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


LedgerEntryType = Literal["purchase", "debit", "credit", "adjustment", "refund"]


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


_SAMPLE_LEDGER: list[UnitLedgerItem] = [
    UnitLedgerItem(
        entry_id="ledger_006",
        timestamp="2026-04-22T18:10:00Z",
        entry_type="debit",
        units=-880,
        balance_after=293_520,
        amount_usd=None,
        description="Usage debit for guarded execution, telemetry, and prompt protection traffic.",
        reference_id="usage_evt_006",
        metadata={"request_count": 22, "route_group": "guard"},
    ),
    UnitLedgerItem(
        entry_id="ledger_005",
        timestamp="2026-04-22T17:42:00Z",
        entry_type="purchase",
        units=200_000,
        balance_after=294_400,
        amount_usd=150.0,
        description="Package purchase credited to wallet.",
        reference_id="order_005",
        metadata={"package_id": "pkg_200000", "package_name": "200,000 Units", "quantity": 1},
    ),
    UnitLedgerItem(
        entry_id="ledger_004",
        timestamp="2026-04-22T16:15:00Z",
        entry_type="adjustment",
        units=1_200,
        balance_after=94_400,
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
        balance_after=93_200,
        amount_usd=None,
        description="Usage debit for scan, policy evaluation, and execution traffic.",
        reference_id="usage_evt_003",
        metadata={"request_count": 16, "route_group": "scan"},
    ),
    UnitLedgerItem(
        entry_id="ledger_002",
        timestamp="2026-04-22T14:50:00Z",
        entry_type="purchase",
        units=100_000,
        balance_after=93_800,
        amount_usd=90.0,
        description="Package purchase credited to wallet.",
        reference_id="order_002",
        metadata={"package_id": "pkg_100000", "package_name": "100,000 Units", "quantity": 1},
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
        filtered = [
            item
            for item in filtered
            if item.reference_id and reference_value in item.reference_id.lower()
        ]

    return filtered


def _build_totals(items: list[UnitLedgerItem]) -> UnitLedgerTotalsView:
    purchase_entries = sum(1 for item in items if item.entry_type == "purchase")
    debit_entries = sum(1 for item in items if item.entry_type == "debit")
    credit_entries = sum(1 for item in items if item.entry_type == "credit")
    adjustment_entries = sum(1 for item in items if item.entry_type == "adjustment")
    refund_entries = sum(1 for item in items if item.entry_type == "refund")

    total_purchased_units = sum(item.units for item in items if item.entry_type == "purchase")
    total_consumed_units = sum(abs(item.units) for item in items if item.entry_type == "debit")
    total_credited_units = sum(
        item.units for item in items if item.entry_type in {"credit", "adjustment"}
    )
    total_refunded_units = sum(item.units for item in items if item.entry_type == "refund")
    total_purchase_amount_usd = round(
        sum(item.amount_usd or 0 for item in items if item.entry_type == "purchase"),
        2,
    )

    current_balance_units = max(sum(item.units for item in _SAMPLE_LEDGER), 0)

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


@router.get("/ledger", response_model=UnitLedgerListResponse)
def get_unit_ledger(
    entry_type: LedgerEntryType | None = Query(default=None),
    reference_id: str | None = Query(default=None, min_length=1, max_length=120),
    limit: int = Query(default=50, ge=1, le=200),
) -> UnitLedgerListResponse:
    filtered_items = _filter_items(
        _SAMPLE_LEDGER,
        entry_type=entry_type,
        reference_id=reference_id,
    )
    limited_items = filtered_items[:limit]

    return UnitLedgerListResponse(
        generated_at=_utc_now_iso(),
        total=len(filtered_items),
        applied_filters={
            "entry_type": entry_type,
            "reference_id": reference_id,
            "limit": limit,
        },
        totals=_build_totals(filtered_items),
        items=limited_items,
        notes=[
            "Ledger route provides UI-facing billing activity for wallet purchases, usage debits, and manual adjustments.",
            "Sample data is returned from in-memory entries for scaffolding and frontend integration.",
            "Package pricing reflected in related purchase entries includes 100,000 units for $90.00 USD and 200,000 units for $150.00 USD.",
        ],
    )


@router.get("/ledger/{entry_id}", response_model=UnitLedgerDetailResponse)
def get_unit_ledger_entry(entry_id: str) -> UnitLedgerDetailResponse:
    item = _find_entry(entry_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Ledger entry not found")

    return UnitLedgerDetailResponse(
        generated_at=_utc_now_iso(),
        item=item,
        notes=[
            "Ledger detail route returns a single wallet activity record for UI drill-down views.",
            "This scaffold currently serves in-memory sample data only.",
        ],
    )