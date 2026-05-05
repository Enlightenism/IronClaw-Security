from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.api.routes.billing import PACKAGE_CATALOG


router = APIRouter(prefix="/billing-packages", tags=["billing-packages"])


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class BillingPackagesItemView(BaseModel):
    package_id: str
    name: str
    price_usd: float
    included_units: int
    description: str
    featured: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class BillingPackagesResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    total: int
    items: list[BillingPackagesItemView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _build_package_items() -> list[BillingPackagesItemView]:
    ordered_package_ids = ["single-user", "team-security", "enterprise-security"]
    featured_package_id = "team-security"
    items: list[BillingPackagesItemView] = []

    for package_id in ordered_package_ids:
        package = PACKAGE_CATALOG.get(package_id)
        if package is None:
            continue

        price_usd = float(package["price_usd"])
        included_units = int(package["included_units"])

        items.append(
            BillingPackagesItemView(
                package_id=package_id,
                name=str(package["name"]),
                price_usd=price_usd,
                included_units=included_units,
                description=str(package["description"]),
                featured=package_id == featured_package_id,
                metadata={
                    "price_display": f"${price_usd:.2f}",
                    "units_display": f"{included_units:,} units",
                    "effective_price_per_1k_units": round((price_usd / included_units) * 1000, 4),
                },
            )
        )

    return items


@router.get("", response_model=BillingPackagesResponse)
def get_billing_packages() -> BillingPackagesResponse:
    items = _build_package_items()

    return BillingPackagesResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        total=len(items),
        items=items,
        notes=[
            "Billing is sold as prepaid protection-unit bundles.",
            "Current package pricing is $20 for 20,000 units, $90 for 100,000 units, and $150 for 200,000 units.",
            "Team Security is the featured package for balanced operational usage.",
        ],
        metadata={
            "source_catalog": "app.api.routes.billing.PACKAGE_CATALOG",
            "featured_package_id": "team-security",
        },
    )