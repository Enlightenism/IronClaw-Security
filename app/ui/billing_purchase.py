from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Body, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from app.core.billing import TOKENS_PER_UNIT
from app.core.unit_wallet import RegistryUnitLedgerEntry, UnitWalletRegistry, get_unit_wallet_registry

router = APIRouter(prefix="/billing-purchase", tags=["billing-purchase"])


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class BillingPurchaseRequest(BaseModel):
    owner_key: str = Field(..., min_length=1, max_length=255)
    units: int = Field(..., ge=1, le=10_000_000)
    source: str = Field(default="manual_purchase", min_length=1, max_length=128)
    reference_id: str | None = Field(default=None, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("owner_key")
    @classmethod
    def normalize_owner_key(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("source")
    @classmethod
    def normalize_source(cls, v: str) -> str:
        return v.strip()


class BillingPurchaseLedgerEntryView(BaseModel):
    entry_id: str
    wallet_id: str
    owner_key: str
    entry_type: str
    units: int
    balance_after: int
    created_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class BillingPurchaseWalletView(BaseModel):
    wallet_id: str
    owner_key: str
    balance_units: int
    total_purchased_units: int
    total_consumed_units: int
    updated_at: str


class BillingPurchaseResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    ledger_entry: BillingPurchaseLedgerEntryView
    wallet: BillingPurchaseWalletView
    notes: list[str] = Field(default_factory=list)


def _entry_to_view(entry: RegistryUnitLedgerEntry) -> BillingPurchaseLedgerEntryView:
    return BillingPurchaseLedgerEntryView(
        entry_id=entry.entry_id,
        wallet_id=entry.wallet_id,
        owner_key=entry.owner_key,
        entry_type=entry.entry_type,
        units=entry.units,
        balance_after=entry.balance_after,
        created_at=entry.created_at.isoformat().replace("+00:00", "Z"),
        metadata=entry.metadata,
    )


def _get_registry() -> UnitWalletRegistry:
    return get_unit_wallet_registry()


@router.post(
    "",
    response_model=BillingPurchaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Purchase protection units",
    description=("Credits a prepaid unit balance for the given owner_key. Returns the resulting ledger entry and updated wallet state. Idempotent per reference_id — repeated calls with the same reference_id produce a new ledger entry; deduplication is the caller's responsibility."),
)
def purchase_units(
    payload: BillingPurchaseRequest = Body(...),
) -> BillingPurchaseResponse:
    registry = _get_registry()

    try:
        wallet = registry.credit_units(
            owner_key=payload.owner_key,
            units=payload.units,
            metadata={
                "source": payload.source,
                "tokens_per_unit": TOKENS_PER_UNIT,
                **({"reference_id": payload.reference_id} if payload.reference_id else {}),
                **payload.metadata,
            },
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to credit units: {exc}",
        ) from exc

    entries = registry.list_ledger_entries(owner_key=payload.owner_key, limit=1)
    if not entries:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Purchase recorded but ledger entry could not be retrieved.",
        )

    ledger_entry = entries[-1]

    return BillingPurchaseResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        ledger_entry=_entry_to_view(ledger_entry),
        wallet=BillingPurchaseWalletView(
            wallet_id=wallet.wallet_id,
            owner_key=wallet.owner_key,
            balance_units=wallet.balance_units,
            total_purchased_units=wallet.total_purchased_units,
            total_consumed_units=wallet.total_consumed_units,
            updated_at=wallet.updated_at.isoformat().replace("+00:00", "Z"),
        ),
        notes=[
            "Units have been credited to the wallet balance immediately.",
            f"Each protection unit covers up to {TOKENS_PER_UNIT:,} tokens; larger token volumes consume additional units in {TOKENS_PER_UNIT:,}-token chunks.",
            "Use GET /ui/billing-wallet to inspect the full ledger history.",
            "The ledger_entry.entry_type will always be 'credit' for purchase operations.",
        ],
    )
