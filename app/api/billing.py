from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.core.auth import require_api_key

router = APIRouter(
    prefix="/billing",
    tags=["billing"],
    dependencies=[Depends(require_api_key)],
)


PACKAGE_CATALOG: dict[str, dict[str, Any]] = {
    "single-user": {
        "name": "Single User",
        "price_usd": 20,
        "included_units": 5_000,
        "description": ("Prepaid protection units for individual builders who want guarded prompt handling, " "tool-call review, source inspection, and safe response release."),
    },
    "team-security": {
        "name": "Team Security",
        "price_usd": 90,
        "included_units": 25_000,
        "description": ("Prepaid protection units for teams running higher volumes of AI-assisted development, " "research, and guarded agent workflows."),
    },
    "enterprise-security": {
        "name": "Enterprise Security",
        "price_usd": 180,
        "included_units": 60_000,
        "description": ("Prepaid protection units for organizations protecting large-scale agent operations, " "sensitive workflows, and high-frequency prompt activity."),
    },
}


class BillingPackageView(BaseModel):
    package_id: str
    name: str
    price_usd: float
    included_units: int
    description: str


class ProtectionValueView(BaseModel):
    title: str
    detail: str


class UnitPolicyView(BaseModel):
    unit_definition: str
    delivery_model: str
    buyer_positioning: str
    protection_layers: list[ProtectionValueView] = Field(default_factory=list)
    market_context: list[str] = Field(default_factory=list)


class BillingPackagePurchaseRequest(BaseModel):
    package_id: str = Field(min_length=1, max_length=120)
    buyer_name: str = Field(min_length=1, max_length=120)
    buyer_email: str = Field(min_length=3, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)


class BillingPackagePurchaseView(BaseModel):
    purchase_id: str
    package_id: str
    package_name: str
    buyer_name: str
    buyer_email: str
    price_usd: float
    granted_units: int
    created_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class BillingPackagesResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    packages: list[BillingPackageView] = Field(default_factory=list)
    unit_policy: UnitPolicyView


class BillingPackagePurchaseResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    purchase: BillingPackagePurchaseView


_PURCHASES: list[BillingPackagePurchaseView] = []


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _package_to_view(package_id: str, package_data: dict[str, Any]) -> BillingPackageView:
    return BillingPackageView(package_id=package_id, **package_data)


def _require_known_package(package_id: str) -> tuple[str, dict[str, Any]]:
    normalized = package_id.strip().lower()
    package = PACKAGE_CATALOG.get(normalized)
    if package is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown billing package: {package_id!r}",
        )
    return normalized, package


def _build_unit_policy() -> UnitPolicyView:
    return UnitPolicyView(
        unit_definition="1 protection unit = 1 IronClaw protection event.",
        delivery_model="All packages are prepaid unit bundles with no recurring subscription requirement.",
        buyer_positioning=("Customers are buying protected AI usage, not raw API calls. Each unit funds layered " "security checks around prompts, tool activity, returned content, and release decisions."),
        protection_layers=[
            ProtectionValueView(
                title="Prompt ingress protection",
                detail="Screens incoming prompts before risky instructions begin spreading through the workflow.",
            ),
            ProtectionValueView(
                title="Tool-call guardrails",
                detail="Reviews agent actions before external tools, files, or execution paths are allowed to continue.",
            ),
            ProtectionValueView(
                title="Source inspection",
                detail="Checks returned web or external content for hostile prompt-injection patterns and suspicious payloads.",
            ),
            ProtectionValueView(
                title="Response release control",
                detail="Applies final safety review before content is released back into the user session or downstream agent flow.",
            ),
            ProtectionValueView(
                title="Sandbox-backed isolation",
                detail="Pairs AI judgment with runtime boundaries so suspicious content can be contained instead of trusted.",
            ),
        ],
        market_context=[
            "Agent platforms process untrusted instructions from websites, files, repositories, docs, and generated artifacts.",
            "Prompt-injection attacks target AI systems specifically because they can redirect tools, leak data, or manipulate autonomous workflows.",
            "IronClaw protection units are designed to add security coverage around every stage where hostile content can enter or spread.",
        ],
    )


@router.get("/packages", response_model=BillingPackagesResponse)
def list_billing_packages() -> BillingPackagesResponse:
    packages = [_package_to_view(package_id, package_data) for package_id, package_data in PACKAGE_CATALOG.items()]
    return BillingPackagesResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        packages=packages,
        unit_policy=_build_unit_policy(),
    )


@router.post(
    "/packages/purchase",
    response_model=BillingPackagePurchaseResponse,
    status_code=status.HTTP_201_CREATED,
)
def purchase_billing_package(
    payload: BillingPackagePurchaseRequest,
) -> BillingPackagePurchaseResponse:
    package_id, package = _require_known_package(payload.package_id)
    purchase = BillingPackagePurchaseView(
        purchase_id=f"pkg_{len(_PURCHASES) + 1}",
        package_id=package_id,
        package_name=str(package["name"]),
        buyer_name=payload.buyer_name.strip(),
        buyer_email=payload.buyer_email.strip(),
        price_usd=float(package["price_usd"]),
        granted_units=int(package["included_units"]),
        created_at=_utc_now_iso(),
        metadata=payload.metadata,
    )
    _PURCHASES.append(purchase)

    return BillingPackagePurchaseResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        purchase=purchase,
    )
