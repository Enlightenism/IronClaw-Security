from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.core.billing import (
    FEATURED_PACKAGE_ID as _FEATURED_PACKAGE_ID,
)
from app.core.billing import (
    TOKENS_PER_UNIT,
)
from app.core.billing import (
    UNIT_PACKAGE_IDS as _ORDERED_PACKAGE_IDS,
)
from app.core.unit_wallet import UNIT_PACKAGE_CATALOG

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
    packages: list[BillingSummaryPackageView] = []

    for package_id in _ORDERED_PACKAGE_IDS:
        package = UNIT_PACKAGE_CATALOG.get(package_id)
        if package is None:
            continue

        price_usd = float(package["price_usd"])
        included_units = int(package["unit_amount"])
        effective_price_per_1k_units = round((price_usd / included_units) * 1000, 4) if included_units > 0 else 0.0
        display_label = str(package["display_label"])

        packages.append(
            BillingSummaryPackageView(
                package_id=package_id,
                name=str(package["name"]),
                price_usd=price_usd,
                included_units=included_units,
                featured=bool(package["featured"]),
                metadata={
                    "price_display": f"${price_usd:.2f}",
                    "units_display": f"{included_units:,} units",
                    "display_label": display_label,
                    "effective_price_per_1k_units": effective_price_per_1k_units,
                    "tokens_per_unit": int(package["tokens_per_unit"]),
                    "token_coverage": int(package["token_coverage"]),
                    "aliases": list(package["aliases"]),
                },
            ),
        )

    return packages


def _build_kpis(packages: list[BillingSummaryPackageView]) -> list[BillingSummaryKpiView]:
    if not packages:
        return []

    featured = next((package for package in packages if package.featured), packages[0])
    lowest_package = min(packages, key=lambda package: package.price_usd)
    highest_units = max(package.included_units for package in packages)

    return [
        BillingSummaryKpiView(
            label="Entry price",
            value=f"${lowest_package.price_usd:.2f}",
            detail=f"Starts with {lowest_package.included_units:,} prepaid protection units.",
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
    current_pricing = ", ".join(f"${package.price_usd:.2f} for {package.included_units:,} units" for package in packages)
    featured_package = next(package for package in packages if package.package_id == _FEATURED_PACKAGE_ID)

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
            f"Current package pricing is {current_pricing}.",
            f"Each protection unit covers up to {TOKENS_PER_UNIT:,} tokens; larger token volumes consume additional units in {TOKENS_PER_UNIT:,}-token chunks.",
            f"{featured_package.name} is the featured package for balanced usage growth.",
            "Billing summary now links directly to the wallet-facing UI surface.",
        ],
    )
