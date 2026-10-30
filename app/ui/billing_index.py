from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.core.billing import FEATURED_PACKAGE_ID, TOKENS_PER_UNIT, UNIT_PACKAGE_IDS
from app.core.unit_wallet import UNIT_PACKAGE_CATALOG

router = APIRouter(prefix="/billing-index", tags=["billing-index"])


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class BillingIndexPackageView(BaseModel):
    package_id: str
    name: str
    description: str
    price_usd: float
    included_units: int
    display_label: str
    featured: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class BillingIndexLinkView(BaseModel):
    label: str
    path: str
    description: str


class BillingIndexSummaryView(BaseModel):
    title: str
    subtitle: str
    featured_package_id: str
    package_count: int
    links_count: int
    currency: str
    pricing_model: str


class BillingIndexResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    summary: BillingIndexSummaryView
    packages: list[BillingIndexPackageView] = Field(default_factory=list)
    links: list[BillingIndexLinkView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _build_packages() -> list[BillingIndexPackageView]:
    packages: list[BillingIndexPackageView] = []

    for package_id in UNIT_PACKAGE_IDS:
        package = UNIT_PACKAGE_CATALOG[package_id]
        price_usd = float(package["price_usd"])
        included_units = int(package["unit_amount"])
        name = str(package["name"])
        display_label = str(package["display_label"])
        description = str(package["description"])

        price_per_1k = round((price_usd / included_units) * 1_000, 4) if included_units > 0 else 0.0

        packages.append(
            BillingIndexPackageView(
                package_id=package_id,
                name=name,
                description=description,
                price_usd=price_usd,
                included_units=included_units,
                display_label=display_label,
                featured=bool(package["featured"]),
                metadata={
                    "price_display": f"${price_usd:.2f}",
                    "units_display": f"{included_units:,} units",
                    "effective_price_per_1k_units": price_per_1k,
                    "tokens_per_unit": int(package["tokens_per_unit"]),
                    "token_coverage": int(package["token_coverage"]),
                    "aliases": list(package["aliases"]),
                },
            )
        )

    return packages


def _build_links() -> list[BillingIndexLinkView]:
    return [
        BillingIndexLinkView(
            label="Billing manifest",
            path="/ui/billing-manifest",
            description="UI-facing package catalog, pricing KPIs, and billing actions.",
        ),
        BillingIndexLinkView(
            label="Billing registry",
            path="/ui/billing-registry",
            description="Registry view of billing packages and route inventory.",
        ),
        BillingIndexLinkView(
            label="Billing summary",
            path="/ui/billing-summary",
            description="High-level billing totals, package metrics, and pricing rollups.",
        ),
        BillingIndexLinkView(
            label="Billing wallet",
            path="/ui/billing-wallet?owner_key=default",
            description="Wallet balance and recent prepaid protection-unit ledger activity.",
        ),
        BillingIndexLinkView(
            label="Billing overview",
            path="/ui/billing/overview",
            description="Full billing overview with KPIs, recent invoices, and package summaries.",
        ),
        BillingIndexLinkView(
            label="Billing packages",
            path="/ui/billing/packages",
            description="Dedicated package list page with filtering, pagination, and per-org package management.",
        ),
        BillingIndexLinkView(
            label="Billing invoices",
            path="/ui/billing/invoices",
            description="Full invoice list with filtering, pagination, and status breakdown.",
        ),
        BillingIndexLinkView(
            label="Billing invoice detail",
            path="/ui/billing/invoices/{invoice_id}",
            description="Per-invoice detail view with line items, package snapshot, and payment method snapshot.",
        ),
        BillingIndexLinkView(
            label="Billing payment methods",
            path="/ui/billing/payment-methods",
            description="Saved payment methods list with card details and default method designation.",
        ),
        BillingIndexLinkView(
            label="Billing plan change",
            path="/ui/billing/plan-change",
            description="Plan change preview and upgrade/downgrade options for the current organization.",
        ),
        BillingIndexLinkView(
            label="Billing packages API",
            path="/billing/packages",
            description="Authenticated prepaid protection-unit package catalog.",
        ),
        BillingIndexLinkView(
            label="Billing ledger API",
            path="/billing/ledger",
            description="Authenticated wallet ledger activity feed.",
        ),
        BillingIndexLinkView(
            label="Billing wallet API",
            path="/billing/wallet",
            description="Authenticated wallet balance lookup for a specific owner key.",
        ),
    ]


@router.get("", response_model=BillingIndexResponse)
def get_billing_index() -> BillingIndexResponse:
    packages = _build_packages()
    links = _build_links()
    current_pricing = ", ".join(f"${float(package['price_usd']):.2f} for {int(package['unit_amount']):,} units" for package in UNIT_PACKAGE_CATALOG.values())
    featured_package = UNIT_PACKAGE_CATALOG[FEATURED_PACKAGE_ID]

    return BillingIndexResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        summary=BillingIndexSummaryView(
            title="Billing Overview",
            subtitle="Prepaid protection-unit pricing and related billing surfaces.",
            featured_package_id=FEATURED_PACKAGE_ID,
            package_count=len(packages),
            links_count=len(links),
            currency="USD",
            pricing_model="prepaid-protection-units",
        ),
        packages=packages,
        links=links,
        notes=[
            "Billing is sold as prepaid protection-unit bundles.",
            f"Current package pricing: {current_pricing}.",
            f"Each protection unit covers up to {TOKENS_PER_UNIT:,} tokens; larger token volumes consume additional units in {TOKENS_PER_UNIT:,}-token chunks.",
            f"{featured_package['name']} ({FEATURED_PACKAGE_ID}) is the featured package for balanced usage growth.",
            "All active UI billing surfaces are enumerated in the links list for full discoverability.",
            "invoice_id in /ui/billing/invoices/{invoice_id} must be a valid invoice ID from the invoice list.",
        ],
    )
