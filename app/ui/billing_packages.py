from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.api.routes.billing import PACKAGE_CATALOG
from app.core.billing import FEATURED_PACKAGE_ID, TOKENS_PER_UNIT, UNIT_PACKAGE_IDS

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
    items: list[BillingPackagesItemView] = []

    for package_id in UNIT_PACKAGE_IDS:
        package = PACKAGE_CATALOG.get(package_id)
        if package is None:
            continue

        price_usd = float(package["price_usd"])
        included_units = int(package["included_units"])
        effective_price_per_1k_units = round((price_usd / included_units) * 1000, 4) if included_units > 0 else 0.0
        display_label = str(package["display_label"])

        items.append(
            BillingPackagesItemView(
                package_id=package_id,
                name=str(package["name"]),
                price_usd=price_usd,
                included_units=included_units,
                description=str(package["description"]),
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

    return items


@router.get("", response_model=BillingPackagesResponse)
def get_billing_packages() -> BillingPackagesResponse:
    items = _build_package_items()
    featured_package = next(item for item in items if item.package_id == FEATURED_PACKAGE_ID)

    return BillingPackagesResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        total=len(items),
        items=items,
        notes=[
            "Billing is sold as prepaid protection-unit bundles.",
            "Current package pricing: " + ", ".join(f"${item.price_usd:.2f} for {item.included_units:,} units" for item in items) + ".",
            f"Each protection unit covers up to {TOKENS_PER_UNIT:,} tokens; larger token volumes consume additional units in {TOKENS_PER_UNIT:,}-token chunks.",
            f"{featured_package.name} is the featured package for balanced operational usage.",
        ],
        metadata={
            "source_catalog": "app.api.routes.billing.PACKAGE_CATALOG",
            "featured_package_id": FEATURED_PACKAGE_ID,
        },
    )
