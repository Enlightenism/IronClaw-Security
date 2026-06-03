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


_TOKENS_PER_UNIT = 25_000
_ORDERED_PACKAGE_IDS = ["pkg_5000", "pkg_25000", "pkg_60000"]
_FEATURED_PACKAGE_ID = "pkg_25000"


def _build_package_items() -> list[BillingPackagesItemView]:
    items: list[BillingPackagesItemView] = []

    for package_id in _ORDERED_PACKAGE_IDS:
        package = PACKAGE_CATALOG.get(package_id)
        if package is None:
            continue

        price_usd = float(package["price_usd"])
        included_units = int(package["included_units"])
        effective_price_per_1k_units = round((price_usd / included_units) * 1000, 4) if included_units > 0 else 0.0
        display_label = str(package.get("display_label", f"{included_units:,} units — ${price_usd:.2f}"))

        items.append(
            BillingPackagesItemView(
                package_id=package_id,
                name=str(package["name"]),
                price_usd=price_usd,
                included_units=included_units,
                description=str(package["description"]),
                featured=package_id == _FEATURED_PACKAGE_ID,
                metadata={
                    "price_display": f"${price_usd:.2f}",
                    "units_display": f"{included_units:,} units",
                    "display_label": display_label,
                    "effective_price_per_1k_units": effective_price_per_1k_units,
                    "tokens_per_unit": _TOKENS_PER_UNIT,
                },
            ),
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
            "Current package pricing is $20 for 5,000 units, $90 for 25,000 units, and $180 for 60,000 units.",
            "Each protection unit covers up to 25,000 tokens; larger token volumes consume additional units in 25,000-token chunks.",
            "Team is the featured package for balanced operational usage.",
        ],
        metadata={
            "source_catalog": "app.api.routes.billing.PACKAGE_CATALOG",
            "featured_package_id": _FEATURED_PACKAGE_ID,
        },
    )
