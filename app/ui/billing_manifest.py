from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.api.routes.billing import PACKAGE_CATALOG

router = APIRouter(prefix="/billing-manifest", tags=["billing-manifest"])


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class BillingManifestPackageView(BaseModel):
    package_id: str
    name: str
    price_usd: float
    included_units: int
    description: str
    featured: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class BillingManifestKpiView(BaseModel):
    label: str
    value: str
    detail: str | None = None


class BillingManifestPricingView(BaseModel):
    currency: str
    model: str
    packages: list[BillingManifestPackageView] = Field(default_factory=list)
    kpis: list[BillingManifestKpiView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class BillingManifestActionView(BaseModel):
    action_id: str
    label: str
    method: str
    path: str
    description: str
    requires_api_key: bool = True


class BillingManifestResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    pricing: BillingManifestPricingView
    actions: list[BillingManifestActionView] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _build_packages() -> list[BillingManifestPackageView]:
    featured_package_id = "team-security"
    ordered_package_ids = ["single-user", "team-security", "enterprise-security"]

    packages: list[BillingManifestPackageView] = []
    for package_id in ordered_package_ids:
        package = PACKAGE_CATALOG.get(package_id)
        if package is None:
            continue

        price_usd = float(package["price_usd"])
        included_units = int(package["included_units"])
        unit_price_per_1k = round((price_usd / included_units) * 1000, 4)

        packages.append(
            BillingManifestPackageView(
                package_id=package_id,
                name=str(package["name"]),
                price_usd=price_usd,
                included_units=included_units,
                description=str(package["description"]),
                featured=package_id == featured_package_id,
                metadata={
                    "price_display": f"${price_usd:.2f}",
                    "units_display": f"{included_units:,} units",
                    "effective_price_per_1k_units": unit_price_per_1k,
                },
            ),
        )

    return packages


def _build_kpis(packages: list[BillingManifestPackageView]) -> list[BillingManifestKpiView]:
    if not packages:
        return []

    lowest_price = min(package.price_usd for package in packages)
    highest_units = max(package.included_units for package in packages)
    featured = next((package for package in packages if package.featured), packages[0])

    return [
        BillingManifestKpiView(
            label="Entry package",
            value=f"${lowest_price:.2f}",
            detail="Starts at 10,000 prepaid protection units.",
        ),
        BillingManifestKpiView(
            label="Featured package",
            value=featured.name,
            detail="Balanced pricing for growing guarded workloads.",
        ),
        BillingManifestKpiView(
            label="Largest bundle",
            value=f"{highest_units:,} units",
            detail="High-volume prepaid protection capacity.",
        ),
    ]


@router.get("", response_model=BillingManifestResponse)
def get_billing_manifest() -> BillingManifestResponse:
    packages = _build_packages()

    return BillingManifestResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        pricing=BillingManifestPricingView(
            currency="USD",
            model="prepaid-protection-units",
            packages=packages,
            kpis=_build_kpis(packages),
            notes=[
                "Billing is sold as prepaid protection-unit bundles.",
                "Current package pricing is $20 for 10,000 units, $90 for 50,000 units, and $150 for 100,000 units.",
                "The featured package is Team Security for balanced operational usage.",
            ],
        ),
        actions=[
            BillingManifestActionView(
                action_id="list-packages",
                label="List billing packages",
                method="GET",
                path="/billing/packages",
                description="Returns the full prepaid package catalog and unit policy.",
            ),
            BillingManifestActionView(
                action_id="purchase-package",
                label="Purchase billing package",
                method="POST",
                path="/billing/packages/purchase",
                description="Creates a package purchase and credits units to the buyer wallet.",
            ),
            BillingManifestActionView(
                action_id="wallet-balance",
                label="Get wallet balance",
                method="GET",
                path="/billing/wallet/{owner_key}",
                description="Returns the current prepaid unit wallet for a buyer key.",
            ),
            BillingManifestActionView(
                action_id="ledger-list",
                label="List wallet ledger",
                method="GET",
                path="/billing/ledger",
                description="Returns ledger activity for wallet credit and debit tracking.",
            ),
        ],
        metadata={
            "source": "app.api.routes.billing",
            "package_count": len(packages),
            "featured_package_id": "team-security",
        },
    )
