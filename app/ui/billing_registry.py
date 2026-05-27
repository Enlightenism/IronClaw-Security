from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.api.routes.billing import PACKAGE_CATALOG

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


def _build_packages() -> list[BillingRegistryPackageView]:
    ordered_package_ids = ["single-user", "team-security", "enterprise-security"]
    packages: list[BillingRegistryPackageView] = []

    for package_id in ordered_package_ids:
        package = PACKAGE_CATALOG.get(package_id)
        if package is None:
            continue

        price_usd = float(package["price_usd"])
        included_units = int(package["included_units"])
        unit_price_per_1k = round((price_usd / included_units) * 1000, 4)

        packages.append(
            BillingRegistryPackageView(
                package_id=package_id,
                name=str(package["name"]),
                price_usd=price_usd,
                included_units=included_units,
                description=str(package["description"]),
                metadata={
                    "price_display": f"${price_usd:.2f}",
                    "units_display": f"{included_units:,} units",
                    "effective_price_per_1k_units": unit_price_per_1k,
                    "featured": package_id == "team-security",
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
            featured_package_id="team-security",
            currency="USD",
            model="prepaid-protection-units",
        )

    return BillingRegistrySummaryView(
        total_packages=len(packages),
        lowest_price_usd=min(package.price_usd for package in packages),
        highest_price_usd=max(package.price_usd for package in packages),
        total_available_units=sum(package.included_units for package in packages),
        featured_package_id="team-security",
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
            name="UI billing overview",
            method="GET",
            path="/ui/billing/overview",
            purpose="Returns UI-facing package state summary including active package, unit consumption, and wallet balance.",
            requires_api_key=False,
        ),
        BillingRegistryRouteView(
            name="UI billing manifest",
            method="GET",
            path="/ui/billing-manifest",
            purpose="Provides UI-facing billing catalog and actions metadata.",
            requires_api_key=False,
        ),
    ]


@router.get("", response_model=BillingRegistryResponse)
def get_billing_registry() -> BillingRegistryResponse:
    packages = _build_packages()

    return BillingRegistryResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        summary=_build_summary(packages),
        packages=packages,
        routes=_build_routes(),
        notes=[
            "Billing is modeled as prepaid protection-unit bundles.",
            "Available package pricing is $20 for 20,000 units, $90 for 100,000 units, and $150 for 200,000 units.",
            "Team Security is the featured package for balanced ongoing usage.",
        ],
        metadata={
            "source_catalog": "app.api.routes.billing.PACKAGE_CATALOG",
            "featured_package_id": "team-security",
            "route_count": 6,
        },
    )
