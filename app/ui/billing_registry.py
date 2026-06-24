from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.core.unit_wallet import UNIT_PACKAGE_CATALOG

router = APIRouter(prefix="/billing-registry", tags=["billing-registry"])


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class BillingRegistryPackageView(BaseModel):
    package_id: str
    name: str
    price_usd: float
    included_units: int
    description: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class BillingRegistryRouteView(BaseModel):
    name: str
    method: str
    path: str
    purpose: str
    requires_api_key: bool = True


class BillingRegistrySummaryView(BaseModel):
    total_packages: int
    lowest_price_usd: float
    highest_price_usd: float
    total_available_units: int
    featured_package_id: str
    currency: str
    model: str


class BillingRegistryResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    summary: BillingRegistrySummaryView
    packages: list[BillingRegistryPackageView] = Field(default_factory=list)
    routes: list[BillingRegistryRouteView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


_TOKENS_PER_UNIT = 25_000
_ORDERED_PACKAGE_IDS = ["pkg_5000", "pkg_25000", "pkg_60000"]
_FEATURED_PACKAGE_ID = "pkg_25000"


def _build_packages() -> list[BillingRegistryPackageView]:
    packages: list[BillingRegistryPackageView] = []

    for package_id in _ORDERED_PACKAGE_IDS:
        package = UNIT_PACKAGE_CATALOG.get(package_id)
        if package is None:
            continue

        price_usd = float(package["price_usd"])
        included_units = int(package["unit_amount"])
        unit_price_per_1k = round((price_usd / included_units) * 1000, 4) if included_units > 0 else 0.0
        display_label = str(package.get("display_label", f"{included_units:,} units — ${price_usd:.2f}"))

        packages.append(
            BillingRegistryPackageView(
                package_id=package_id,
                name=str(package["name"]),
                price_usd=price_usd,
                included_units=included_units,
                description=str(package.get("description", "")),
                metadata={
                    "price_display": f"${price_usd:.2f}",
                    "units_display": f"{included_units:,} units",
                    "display_label": display_label,
                    "effective_price_per_1k_units": unit_price_per_1k,
                    "featured": package_id == _FEATURED_PACKAGE_ID,
                    "tokens_per_unit": _TOKENS_PER_UNIT,
                },
            ),
        )

    return packages


def _build_summary(packages: list[BillingRegistryPackageView]) -> BillingRegistrySummaryView:
    if not packages:
        return BillingRegistrySummaryView(
            total_packages=0,
            lowest_price_usd=0.0,
            highest_price_usd=0.0,
            total_available_units=0,
            featured_package_id=_FEATURED_PACKAGE_ID,
            currency="USD",
            model="prepaid-protection-units",
        )

    return BillingRegistrySummaryView(
        total_packages=len(packages),
        lowest_price_usd=min(package.price_usd for package in packages),
        highest_price_usd=max(package.price_usd for package in packages),
        total_available_units=sum(package.included_units for package in packages),
        featured_package_id=_FEATURED_PACKAGE_ID,
        currency="USD",
        model="prepaid-protection-units",
    )


def _build_routes() -> list[BillingRegistryRouteView]:
    return [
        BillingRegistryRouteView(
            name="List billing packages",
            method="GET",
            path="/billing/packages",
            purpose="Returns the prepaid protection unit catalog and unit policy.",
        ),
        BillingRegistryRouteView(
            name="Purchase billing package",
            method="POST",
            path="/billing/packages/purchase",
            purpose="Creates a billing purchase and credits units into the buyer wallet.",
        ),
        BillingRegistryRouteView(
            name="Wallet balance",
            method="GET",
            path="/billing/wallet/{owner_key}",
            purpose="Returns the current prepaid unit wallet balance for the owner key.",
        ),
        BillingRegistryRouteView(
            name="Billing ledger",
            method="GET",
            path="/billing/ledger",
            purpose="Returns wallet ledger activity with optional owner filtering.",
        ),
        BillingRegistryRouteView(
            name="UI billing index",
            method="GET",
            path="/ui/billing-index",
            purpose="Top-level billing index with package catalog and links to all billing surfaces.",
            requires_api_key=False,
        ),
        BillingRegistryRouteView(
            name="UI billing registry",
            method="GET",
            path="/ui/billing-registry",
            purpose="Registry view of billing packages, pricing summary, and full route inventory.",
            requires_api_key=False,
        ),
        BillingRegistryRouteView(
            name="UI billing manifest",
            method="GET",
            path="/ui/billing-manifest",
            purpose="Provides UI-facing billing catalog and actions metadata.",
            requires_api_key=False,
        ),
        BillingRegistryRouteView(
            name="UI billing summary",
            method="GET",
            path="/ui/billing-summary",
            purpose="High-level billing totals, package metrics, and pricing rollups.",
            requires_api_key=False,
        ),
        BillingRegistryRouteView(
            name="UI billing wallet",
            method="GET",
            path="/ui/billing-wallet",
            purpose="Wallet balance and recent prepaid protection-unit ledger activity.",
            requires_api_key=False,
        ),
        BillingRegistryRouteView(
            name="UI billing overview",
            method="GET",
            path="/ui/billing/overview",
            purpose="Full billing overview with KPIs, recent invoices, and package summaries.",
            requires_api_key=False,
        ),
        BillingRegistryRouteView(
            name="UI billing packages",
            method="GET",
            path="/ui/billing/packages",
            purpose="Dedicated package list page with filtering, pagination, and per-org package management.",
            requires_api_key=False,
        ),
        BillingRegistryRouteView(
            name="UI billing invoices",
            method="GET",
            path="/ui/billing/invoices",
            purpose="Full invoice list with filtering, pagination, and status breakdown.",
            requires_api_key=False,
        ),
        BillingRegistryRouteView(
            name="UI billing invoice detail",
            method="GET",
            path="/ui/billing/invoices/{invoice_id}",
            purpose="Per-invoice detail view with line items, package snapshot, and payment method snapshot.",
            requires_api_key=False,
        ),
        BillingRegistryRouteView(
            name="UI billing payment methods",
            method="GET",
            path="/ui/billing/payment-methods",
            purpose="Saved payment methods list with card details and default method designation.",
            requires_api_key=False,
        ),
        BillingRegistryRouteView(
            name="UI billing plan change",
            method="GET",
            path="/ui/billing/plan-change",
            purpose="Plan change preview and upgrade/downgrade options for the current organization.",
            requires_api_key=False,
        ),
    ]


@router.get("", response_model=BillingRegistryResponse)
def get_billing_registry() -> BillingRegistryResponse:
    packages = _build_packages()
    routes = _build_routes()

    return BillingRegistryResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        summary=_build_summary(packages),
        packages=packages,
        routes=routes,
        notes=[
            "Billing is modeled as prepaid protection-unit bundles.",
            "Available package pricing is $20 for 5,000 units, $90 for 25,000 units, and $180 for 60,000 units.",
            "Each protection unit covers up to 25,000 tokens; larger token volumes consume additional units in 25,000-token chunks.",
            "Team is the featured package for balanced ongoing usage.",
            "All active billing API and UI routes are enumerated here for full system discoverability.",
            "requires_api_key=False denotes UI-layer routes served without an API key requirement.",
        ],
        metadata={
            "source_catalog": "app.core.unit_wallet.UNIT_PACKAGE_CATALOG",
            "featured_package_id": _FEATURED_PACKAGE_ID,
            "route_count": len(routes),
        },
    )
