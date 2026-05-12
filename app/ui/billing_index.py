from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.api.routes.billing import PACKAGE_CATALOG

router = APIRouter(prefix="/billing-index", tags=["billing-index"])


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class BillingIndexPackageView(BaseModel):
    package_id: str
    name: str
    price_usd: float
    included_units: int
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
    ordered_package_ids = ["single-user", "team-security", "enterprise-security"]
    featured_package_id = "team-security"
    packages: list[BillingIndexPackageView] = []

    for package_id in ordered_package_ids:
        package = PACKAGE_CATALOG.get(package_id)
        if package is None:
            continue

        price_usd = float(package["price_usd"])
        included_units = int(package["included_units"])

        packages.append(
            BillingIndexPackageView(
                package_id=package_id,
                name=str(package["name"]),
                price_usd=price_usd,
                included_units=included_units,
                featured=package_id == featured_package_id,
                metadata={
                    "price_display": f"${price_usd:.2f}",
                    "units_display": f"{included_units:,} units",
                    "effective_price_per_1k_units": round((price_usd / included_units) * 1000, 4),
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

    return BillingIndexResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        summary=BillingIndexSummaryView(
            title="Billing Overview",
            subtitle="Prepaid protection-unit pricing and related billing surfaces.",
            featured_package_id="team-security",
            package_count=len(packages),
            currency="USD",
            pricing_model="prepaid-protection-units",
        ),
        packages=packages,
        links=_build_links(),
        notes=[
            "Billing is sold as prepaid protection-unit bundles.",
            "Current package pricing is $20 for 20,000 units, $90 for 100,000 units, and $150 for 200,000 units.",
            "Team Security is the featured package for balanced usage growth.",
            "Billing wallet access is now part of the linked billing surface set.",
        ],
    )