from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from app.core.unit_wallet import get_unit_wallet_registry

router = APIRouter(prefix="/billing-wallet", tags=["billing-wallet"])


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class BillingWalletBalanceView(BaseModel):
    wallet_id: str
    owner_key: str
    balance_units: int
    total_purchased_units: int
    total_consumed_units: int
    updated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class BillingWalletLedgerPreviewItem(BaseModel):
    entry_id: str
    entry_type: str
    units: int
    balance_after: int
    created_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class BillingWalletSummaryView(BaseModel):
    owner_key: str
    has_activity: bool
    ledger_entry_count: int
    latest_entry_type: str | None = None
    latest_entry_at: str | None = None


class BillingWalletResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    wallet: BillingWalletBalanceView
    summary: BillingWalletSummaryView
    recent_entries: list[BillingWalletLedgerPreviewItem] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _wallet_to_view(wallet: Any) -> BillingWalletBalanceView:
    return BillingWalletBalanceView(
        wallet_id=wallet.wallet_id,
        owner_key=wallet.owner_key,
        balance_units=wallet.balance_units,
        total_purchased_units=wallet.total_purchased_units,
        total_consumed_units=wallet.total_consumed_units,
        updated_at=wallet.updated_at.isoformat().replace("+00:00", "Z"),
        metadata=wallet.metadata,
    )


def _ledger_entry_to_view(entry: Any) -> BillingWalletLedgerPreviewItem:
    return BillingWalletLedgerPreviewItem(
        entry_id=entry.entry_id,
        entry_type=entry.entry_type,
        units=entry.units,
        balance_after=entry.balance_after,
        created_at=entry.created_at.isoformat().replace("+00:00", "Z"),
        metadata=entry.metadata,
    )


@router.get("", response_model=BillingWalletResponse)
def get_billing_wallet(
    owner_key: str = Query(..., min_length=1, max_length=255),
    limit: int = Query(default=5, ge=1, le=20),
) -> BillingWalletResponse:
    normalized_owner_key = owner_key.strip().lower()
    wallet_registry = get_unit_wallet_registry()
    wallet = wallet_registry.get_wallet(normalized_owner_key)

    if wallet is None:
        wallet = wallet_registry.get_or_create_wallet(owner_key=normalized_owner_key)

    entries = wallet_registry.list_ledger_entries(owner_key=normalized_owner_key, limit=limit)
    latest_entry = entries[0] if entries else None

    return BillingWalletResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        wallet=_wallet_to_view(wallet),
        summary=BillingWalletSummaryView(
            owner_key=normalized_owner_key,
            has_activity=bool(entries),
            ledger_entry_count=len(entries),
            latest_entry_type=getattr(latest_entry, "entry_type", None),
            latest_entry_at=(latest_entry.created_at.isoformat().replace("+00:00", "Z") if latest_entry is not None else None),
        ),
        recent_entries=[_ledger_entry_to_view(entry) for entry in entries],
        notes=[
            "Billing wallet reflects prepaid protection-unit balance state for a specific owner key.",
            "Recent entries provide a lightweight preview of purchase and debit activity.",
            "Use the billing ledger routes for deeper wallet activity inspection.",
        ],
    )
