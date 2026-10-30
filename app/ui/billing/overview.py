from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.core.billing import TOKENS_PER_UNIT
from app.ui.billing.package import (
    PACKAGE_CATALOGUE,
    StripeStatus,
    _get_environment,
    _get_stripe_status,
)

router = APIRouter(
    prefix="/ui/billing",
    tags=["billing-overview"],
)

_PLAN_PRICES_CENTS: dict[str, int] = {plan: int(meta["price_cents"]) for plan, meta in PACKAGE_CATALOGUE.items()}

_PLAN_INCLUDED_UNITS: dict[str, dict[str, int]] = {plan: {"protectionunits": int(meta["units"])} for plan, meta in PACKAGE_CATALOGUE.items()}

_UNIT_LABELS: dict[str, str] = {
    "protectionunits": "units",
}


class BillingKpiView(BaseModel):
    label: str
    value: int
    trendlabel: str | None = None
    status: str = "neutral"


class BillingCurrencyAmountView(BaseModel):
    currency: str
    amountcents: int
    displayamount: str


class BillingUsageBucketView(BaseModel):
    metric: str
    used: int
    included: int
    overage: int
    unit: str
    status: str


class BillingInvoiceView(BaseModel):
    invoiceid: str
    organizationid: str
    organizationname: str
    status: str
    issuedat: str
    dueat: str
    periodstart: str
    periodend: str
    subtotal: BillingCurrencyAmountView
    tax: BillingCurrencyAmountView
    total: BillingCurrencyAmountView


class BillingPackageView(BaseModel):
    packageid: str
    organizationid: str
    organizationname: str
    plan: str
    status: str
    purchasedat: str
    expiresat: str | None = None
    packageprice: BillingCurrencyAmountView
    planchangeurl: str
    usage: list[BillingUsageBucketView] = Field(default_factory=list)


class BillingPlanCount(BaseModel):
    plan: str
    count: int


class BillingInvoiceStatusCount(BaseModel):
    status: str
    count: int


class BillingOverviewResponse(BaseModel):
    generatedat: str
    environment: str
    stripe: StripeStatus
    overallstatus: str
    kpis: list[BillingKpiView] = Field(default_factory=list)
    plancounts: list[BillingPlanCount] = Field(default_factory=list)
    invoicestatuscounts: list[BillingInvoiceStatusCount] = Field(default_factory=list)
    packages: list[BillingPackageView] = Field(default_factory=list)
    invoices: list[BillingInvoiceView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _utc_iso(year: int, month: int, day: int, hour: int, minute: int = 0) -> str:
    return datetime(year, month, day, hour, minute, 0, tzinfo=UTC).isoformat()


def _usd(amountcents: int) -> BillingCurrencyAmountView:
    dollars = amountcents / 100
    return BillingCurrencyAmountView(
        currency="USD",
        amountcents=amountcents,
        displayamount=f"${dollars:,.2f}",
    )


def _plan_change_url(plan: str) -> str:
    return f"/ui/billing/plan-change?currentplan={plan}"


def _sample_packages() -> list[BillingPackageView]:
    return [
        BillingPackageView(
            packageid="pkg-001",
            organizationid="org-001",
            organizationname="Alpha Security Lab",
            plan="team",
            status="active",
            purchasedat=_utc_iso(2026, 4, 10, 9, 0),
            expiresat=None,
            packageprice=_usd(_PLAN_PRICES_CENTS["team"]),
            planchangeurl=_plan_change_url("team"),
            usage=[
                BillingUsageBucketView(
                    metric="protectionunits",
                    used=18_340,
                    included=_PLAN_INCLUDED_UNITS["team"]["protectionunits"],
                    overage=0,
                    unit=_UNIT_LABELS["protectionunits"],
                    status="healthy",
                ),
            ],
        ),
        BillingPackageView(
            packageid="pkg-002",
            organizationid="org-002",
            organizationname="Beta Runtime Defense",
            plan="starter",
            status="trialing",
            purchasedat=_utc_iso(2026, 4, 12, 14, 20),
            expiresat=None,
            packageprice=_usd(_PLAN_PRICES_CENTS["starter"]),
            planchangeurl=_plan_change_url("starter"),
            usage=[
                BillingUsageBucketView(
                    metric="protectionunits",
                    used=4_120,
                    included=_PLAN_INCLUDED_UNITS["starter"]["protectionunits"],
                    overage=0,
                    unit=_UNIT_LABELS["protectionunits"],
                    status="warning",
                ),
            ],
        ),
        BillingPackageView(
            packageid="pkg-003",
            organizationid="org-003",
            organizationname="Gamma Internal QA",
            plan="enterprise",
            status="past_due",
            purchasedat=_utc_iso(2026, 4, 8, 8, 45),
            expiresat=None,
            packageprice=_usd(_PLAN_PRICES_CENTS["enterprise"]),
            planchangeurl=_plan_change_url("enterprise"),
            usage=[
                BillingUsageBucketView(
                    metric="protectionunits",
                    used=61_200,
                    included=_PLAN_INCLUDED_UNITS["enterprise"]["protectionunits"],
                    overage=1_200,
                    unit=_UNIT_LABELS["protectionunits"],
                    status="critical",
                ),
            ],
        ),
    ]


def _sample_invoices() -> list[BillingInvoiceView]:
    return [
        BillingInvoiceView(
            invoiceid="inv-001",
            organizationid="org-001",
            organizationname="Alpha Security Lab",
            status="paid",
            issuedat=_utc_iso(2026, 4, 10, 9, 5),
            dueat=_utc_iso(2026, 4, 17, 9, 5),
            periodstart=_utc_iso(2026, 4, 1, 0, 0),
            periodend=_utc_iso(2026, 4, 30, 23, 59),
            subtotal=_usd(_PLAN_PRICES_CENTS["team"]),
            tax=_usd(0),
            total=_usd(_PLAN_PRICES_CENTS["team"]),
        ),
        BillingInvoiceView(
            invoiceid="inv-002",
            organizationid="org-002",
            organizationname="Beta Runtime Defense",
            status="draft",
            issuedat=_utc_iso(2026, 4, 12, 14, 25),
            dueat=_utc_iso(2026, 4, 26, 14, 25),
            periodstart=_utc_iso(2026, 4, 12, 0, 0),
            periodend=_utc_iso(2026, 5, 11, 23, 59),
            subtotal=_usd(_PLAN_PRICES_CENTS["starter"]),
            tax=_usd(0),
            total=_usd(_PLAN_PRICES_CENTS["starter"]),
        ),
        BillingInvoiceView(
            invoiceid="inv-003",
            organizationid="org-003",
            organizationname="Gamma Internal QA",
            status="past_due",
            issuedat=_utc_iso(2026, 4, 8, 8, 50),
            dueat=_utc_iso(2026, 4, 15, 8, 50),
            periodstart=_utc_iso(2026, 4, 1, 0, 0),
            periodend=_utc_iso(2026, 4, 30, 23, 59),
            subtotal=_usd(_PLAN_PRICES_CENTS["enterprise"]),
            tax=_usd(0),
            total=_usd(_PLAN_PRICES_CENTS["enterprise"]),
        ),
    ]


def _build_plan_counts(packages: list[BillingPackageView]) -> list[BillingPlanCount]:
    counts = Counter(package.plan for package in packages)
    return [BillingPlanCount(plan=plan, count=count) for plan, count in sorted(counts.items())]


def _build_invoice_status_counts(
    invoices: list[BillingInvoiceView],
) -> list[BillingInvoiceStatusCount]:
    counts = Counter(invoice.status for invoice in invoices)
    return [BillingInvoiceStatusCount(status=status, count=count) for status, count in sorted(counts.items())]


@router.get("/overview", response_model=BillingOverviewResponse)
def get_billing_overview() -> BillingOverviewResponse:
    stripe = _get_stripe_status()
    packages = _sample_packages()
    invoices = _sample_invoices()

    totalpackages = len(packages)
    activepackages = sum(1 for p in packages if p.status == "active")
    pastduepackages = sum(1 for p in packages if p.status == "past_due")
    trialingpackages = sum(1 for p in packages if p.status == "trialing")
    totalrevenuecents = sum(invoice.total.amountcents for invoice in invoices if invoice.status == "paid")

    kpis = [
        BillingKpiView(
            label="totalpackages",
            value=totalpackages,
            trendlabel="Total package records across all organizations",
            status="healthy" if totalpackages > 0 else "warning",
        ),
        BillingKpiView(
            label="activepackages",
            value=activepackages,
            trendlabel="Organizations with active prepaid packages",
            status="healthy" if activepackages > 0 else "warning",
        ),
        BillingKpiView(
            label="pastduepackages",
            value=pastduepackages,
            trendlabel="Packages with outstanding past-due invoices",
            status="error" if pastduepackages > 0 else "healthy",
        ),
        BillingKpiView(
            label="totalrevenuecents",
            value=totalrevenuecents,
            trendlabel="Total collected revenue in cents (paid invoices only)",
            status="healthy" if totalrevenuecents > 0 else "warning",
        ),
    ]

    overallstatus = "healthy"
    if pastduepackages > 0:
        overallstatus = "attention"
    elif trialingpackages > 0:
        overallstatus = "notice"

    return BillingOverviewResponse(
        generatedat=datetime.now(UTC).isoformat(),
        environment=_get_environment(),
        stripe=stripe,
        overallstatus=overallstatus,
        kpis=kpis,
        plancounts=_build_plan_counts(packages),
        invoicestatuscounts=_build_invoice_status_counts(invoices),
        packages=packages,
        invoices=invoices,
        notes=[
            "Billing overview exposes prepaid package state, package pricing, usage against included unit limits, and invoice lifecycle visibility.",
            "Package pricing is " + ", ".join(f"{meta['label']} ${meta['price_usd']} for {meta['units']:,} units" for meta in PACKAGE_CATALOGUE.values()) + ".",
            f"Each protection unit covers up to {TOKENS_PER_UNIT:,} tokens; larger token volumes consume additional units in {TOKENS_PER_UNIT:,}-token chunks.",
            "planchangeurl on each package provides a direct link to the plan-change surface for that organization's current package.",
            "overallstatus is 'attention' when any package is past_due, 'notice' when any package is trialing, 'healthy' otherwise.",
            "totalrevenuecents KPI counts paid invoices only — draft and past_due invoices are excluded.",
            "Dedicated invoice list surface available at /ui/billing/invoices.",
            stripe.note,
            "All values are placeholder UI contract data for the current local-first Gen1 build.",
        ],
    )
