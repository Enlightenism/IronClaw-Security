from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.api.routes.billing import PACKAGE_CATALOG

router = APIRouter(prefix="/billing-summary", tags=["billing-summary"])


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class BillingSummaryKpiView(BaseModel):
    label: str
    value: str
    detail: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class BillingSummaryPackageView(BaseModel):
    package_id: str
    name: str
    price_usd: float
    included_units: int
    featured: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class BillingSummaryLinkView(BaseModel):
    label: str
    path: str
    description: str


class BillingSummaryResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    title: str
    subtitle: str
    kpis: list[BillingSummaryKpiView] = Field(default_factory=list)
    packages: list[BillingSummaryPackageView] = Field(default_factory=list)
    links: list[BillingSummaryLinkView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _build_packages() -> list[BillingSummaryPackageView]:
    ordered_package_ids = ["single-user", "team-security", "enterprise-security"]
    featured_package_id = "team-security"
    packages: list[BillingSummaryPackageView] = []

    for package_id in ordered_package_ids:
        package = PACKAGE_CATALOG.get(package_id)
        if package is None:
            continue

        price_usd = float(package["price_usd"])
        included_units = int(package["included_units"])

        packages.append(
            BillingSummaryPackageView(
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


def _build_kpis(packages: list[BillingSummaryPackageView]) -> list[BillingSummaryKpiView]:
    if not packages:
        return []

    featured = next((package for package in packages if package.featured), packages[0])
    lowest = min(package.price_usd for package in packages)
    highest_units = max(package.included_units for package in packages)

    return [
        BillingSummaryKpiView(
            label="Entry price",
            value=f"${lowest:.2f}",
            detail="Starts with 20,000 prepaid protection units.",
            metadata={"kind": "entry-price"},
        ),
        BillingSummaryKpiView(
            label="Featured package",
            value=featured.name,
            detail="Recommended for balanced operational growth.",
            metadata={"package_id": featured.package_id},
        ),
        BillingSummaryKpiView(
            label="Largest bundle",
            value=f"{highest_units:,} units",
            detail="Highest prepaid unit package currently available.",
            metadata={"kind": "largest-bundle"},
        ),
    ]


def _build_links() -> list[BillingSummaryLinkView]:
    return [
        BillingSummaryLinkView(
            label="Billing index",
            path="/ui/billing-index",
            description="Top-level billing overview and route navigation entry point.",
        ),
        BillingSummaryLinkView(
            label="Billing manifest",
            path="/ui/billing-manifest",
            description="UI package catalog, pricing presentation, and billing actions.",
        ),
        BillingSummaryLinkView(
            label="Billing registry",
            path="/ui/billing-registry",
            description="Billing route inventory and package registry surface.",
        ),
        BillingSummaryLinkView(
            label="Billing wallet",
            path="/ui/billing-wallet?owner_key=default",
            description="Wallet balance and recent ledger activity preview for an owner key.",
        ),
    ]


@router.get("", response_model=BillingSummaryResponse)
def get_billing_summary() -> BillingSummaryResponse:
    packages = _build_packages()

    return BillingSummaryResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        title="Billing Summary",
        subtitle="Prepaid protection-unit pricing overview for UI consumption.",
        kpis=_build_kpis(packages),
        packages=packages,
        links=_build_links(),
        notes=[
            "Billing is sold as prepaid protection-unit bundles.",
            "Current package pricing is $20 for 20,000 units, $90 for 100,000 units, and $150 for 200,000 units.",
            "Team Security is the featured package for balanced usage growth.",
            "Billing summary now links directly to the wallet-facing UI surface.",
        ],
    )