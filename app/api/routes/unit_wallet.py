from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.auth import require_api_key

router = APIRouter(
    prefix="/ui/billing",
    tags=["unit-wallet"],
    dependencies=[Depends(require_api_key)],
)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class UnitPackageView(BaseModel):
    package_id: str
    name: str
    unit_count: int = Field(ge=1)
    price_usd: float = Field(ge=0)
    price_display: str
    active: bool = True
    featured: bool = False
    description: str | None = None
    effective_price_per_1k_units: float = Field(ge=0)


class UnitWalletBalanceView(BaseModel):
    balance_units: int = Field(ge=0)
    lifetime_purchased_units: int = Field(ge=0)
    lifetime_consumed_units: int = Field(ge=0)
    pending_units: int = Field(ge=0)
    last_updated_at: str


class UnitUsageSummaryView(BaseModel):
    total_requests: int = Field(ge=0)
    total_units: int = Field(ge=0)
    average_units_per_request: float = Field(ge=0)
    last_seen_at: str | None = None


class UnitLedgerItem(BaseModel):
    entry_id: str
    timestamp: str
    entry_type: Literal["purchase", "debit", "credit", "adjustment", "refund"]
    units: int
    balance_after: int = Field(ge=0)
    amount_usd: float | None = Field(default=None, ge=0)
    description: str
    reference_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class UnitPurchaseRequest(BaseModel):
    package_id: str = Field(min_length=1, max_length=120)
    quantity: int = Field(default=1, ge=1, le=100)


class UnitPurchaseResponse(BaseModel):
    status: Literal["ok"]
    purchased_package: UnitPackageView
    quantity: int = Field(ge=1)
    credited_units: int = Field(ge=1)
    amount_usd: float = Field(ge=0)
    wallet: UnitWalletBalanceView
    ledger_entry: UnitLedgerItem


class UnitWalletResponse(BaseModel):
    generated_at: str
    currency: Literal["USD"] = "USD"
    wallet: UnitWalletBalanceView
    usage: UnitUsageSummaryView
    packages: list[UnitPackageView] = Field(default_factory=list)
    recent_ledger: list[UnitLedgerItem] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _price_per_1k_units(price_usd: float, unit_count: int) -> float:
    return round((price_usd / unit_count) * 1000, 4)


_SAMPLE_PACKAGES: list[UnitPackageView] = [
    UnitPackageView(
        package_id="pkg_20000",
        name="20,000 Units",
        unit_count=20_000,
        price_usd=20.0,
        price_display="$20.00",
        active=True,
        featured=False,
        description="Entry package for light usage and initial production traffic.",
        effective_price_per_1k_units=_price_per_1k_units(20.0, 20_000),
    ),
    UnitPackageView(
        package_id="pkg_100000",
        name="100,000 Units",
        unit_count=100_000,
        price_usd=90.0,
        price_display="$90.00",
        active=True,
        featured=True,
        description="Best balance for growing workloads and regular operational usage.",
        effective_price_per_1k_units=_price_per_1k_units(90.0, 100_000),
    ),
    UnitPackageView(
        package_id="pkg_200000",
        name="200,000 Units",
        unit_count=200_000,
        price_usd=150.0,
        price_display="$150.00",
        active=True,
        featured=False,
        description="High-volume prepaid package for heavier sustained usage.",
        effective_price_per_1k_units=_price_per_1k_units(150.0, 200_000),
    ),
]


_SAMPLE_LEDGER: list[UnitLedgerItem] = [
    UnitLedgerItem(
        entry_id="ledger_003",
        timestamp=_utc_now_iso(),
        entry_type="debit",
        units=-640,
        balance_after=94_360,
        amount_usd=None,
        description="Usage debit for guarded execution and prompt protection activity.",
        reference_id="usage_evt_003",
        metadata={"request_count": 16},
    ),
    UnitLedgerItem(
        entry_id="ledger_002",
        timestamp=_utc_now_iso(),
        entry_type="purchase",
        units=100_000,
        balance_after=95_000,
        amount_usd=90.0,
        description="Package purchase credited to wallet.",
        reference_id="order_002",
        metadata={"package_id": "pkg_100000", "package_name": "100,000 Units"},
    ),
    UnitLedgerItem(
        entry_id="ledger_001",
        timestamp=_utc_now_iso(),
        entry_type="debit",
        units=-5_000,
        balance_after=0,
        amount_usd=None,
        description="Usage debit for prior scan, review, and execution activity.",
        reference_id="usage_evt_001",
        metadata={"request_count": 125},
    ),
]


def _build_wallet_balance() -> UnitWalletBalanceView:
    purchased_units = sum(item.units for item in _SAMPLE_LEDGER if item.entry_type == "purchase")
    credited_units = sum(
        item.units for item in _SAMPLE_LEDGER if item.entry_type in {"credit", "adjustment", "refund"}
    )
    consumed_units = sum(abs(item.units) for item in _SAMPLE_LEDGER if item.entry_type == "debit")
    balance_units = max(sum(item.units for item in _SAMPLE_LEDGER), 0)

    return UnitWalletBalanceView(
        balance_units=balance_units,
        lifetime_purchased_units=max(purchased_units + credited_units, 0),
        lifetime_consumed_units=consumed_units,
        pending_units=0,
        last_updated_at=_utc_now_iso(),
    )


def _build_usage_summary() -> UnitUsageSummaryView:
    total_units = sum(abs(item.units) for item in _SAMPLE_LEDGER if item.entry_type == "debit")
    total_requests = sum(
        int(item.metadata.get("request_count", 0))
        for item in _SAMPLE_LEDGER
        if item.entry_type == "debit"
    )
    average_units_per_request = round(total_units / total_requests, 2) if total_requests else 0.0
    last_seen_at = _SAMPLE_LEDGER[0].timestamp if _SAMPLE_LEDGER else None

    return UnitUsageSummaryView(
        total_requests=total_requests,
        total_units=total_units,
        average_units_per_request=average_units_per_request,
        last_seen_at=last_seen_at,
    )


def _find_package(package_id: str) -> UnitPackageView | None:
    for package in _SAMPLE_PACKAGES:
        if package.package_id == package_id:
            return package
    return None


@router.get("/wallet", response_model=UnitWalletResponse)
def get_unit_wallet() -> UnitWalletResponse:
    return UnitWalletResponse(
        generated_at=_utc_now_iso(),
        wallet=_build_wallet_balance(),
        usage=_build_usage_summary(),
        packages=_SAMPLE_PACKAGES,
        recent_ledger=_SAMPLE_LEDGER,
        notes=[
            "Prepaid wallet model: units are purchased in fixed packages and consumed by usage.",
            "Available packages are 20,000 units for $20.00 USD, 100,000 units for $90.00 USD, and 200,000 units for $150.00 USD.",
            "No recurring subscription state is tracked in this route.",
            "Current implementation returns in-memory sample data for UI scaffolding.",
        ],
    )


@router.post("/purchase", response_model=UnitPurchaseResponse)
def purchase_units(payload: UnitPurchaseRequest) -> UnitPurchaseResponse:
    package = _find_package(payload.package_id)
    if package is None:
        package = UnitPackageView(
            package_id=payload.package_id,
            name="20,000 Units",
            unit_count=20_000,
            price_usd=20.0,
            price_display="$20.00",
            active=True,
            featured=False,
            description="Fallback package for unknown package ids in the UI scaffold.",
            effective_price_per_1k_units=_price_per_1k_units(20.0, 20_000),
        )

    credited_units = package.unit_count * payload.quantity
    amount_usd = round(package.price_usd * payload.quantity, 2)

    current_balance = _build_wallet_balance()
    new_balance = current_balance.balance_units + credited_units
    timestamp = _utc_now_iso()

    ledger_entry = UnitLedgerItem(
        entry_id=f"ledger_purchase_{payload.package_id}_{payload.quantity}",
        timestamp=timestamp,
        entry_type="purchase",
        units=credited_units,
        balance_after=new_balance,
        amount_usd=amount_usd,
        description=f"Purchased {payload.quantity} x {package.name}.",
        reference_id=f"order_{payload.package_id}_{payload.quantity}",
        metadata={
            "package_id": package.package_id,
            "package_name": package.name,
            "quantity": payload.quantity,
        },
    )

    wallet = UnitWalletBalanceView(
        balance_units=new_balance,
        lifetime_purchased_units=current_balance.lifetime_purchased_units + credited_units,
        lifetime_consumed_units=current_balance.lifetime_consumed_units,
        pending_units=current_balance.pending_units,
        last_updated_at=timestamp,
    )

    return UnitPurchaseResponse(
        status="ok",
        purchased_package=package,
        quantity=payload.quantity,
        credited_units=credited_units,
        amount_usd=amount_usd,
        wallet=wallet,
        ledger_entry=ledger_entry,
    )