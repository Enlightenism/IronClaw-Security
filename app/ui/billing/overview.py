from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/billing",
    tags=["billing-overview"],
)

_PLAN_PRICES_CENTS: dict[str, int] = {
    "starter": 9_900,
    "pro": 29_900,
    "enterprise": 149_900,
}

_PLAN_INCLUDED_UNITS: dict[str, dict[str, int]] = {
    "starter": {
        "guardedexecutions": 10_000,
        "manualreviews": 1_000,
        "securityalerts": 2_500,
    },
    "pro": {
        "guardedexecutions": 50_000,
        "manualreviews": 5_000,
        "securityalerts": 10_000,
    },
    "enterprise": {
        "guardedexecutions": 250_000,
        "manualreviews": 25_000,
        "securityalerts": 50_000,
    },
}

_UNIT_LABELS: dict[str, str] = {
    "guardedexecutions": "requests",
    "manualreviews": "items",
    "securityalerts": "alerts",
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
            plan="pro",
            status="active",
            purchasedat=_utc_iso(2026, 4, 10, 9, 0),
            expiresat=None,
            packageprice=_usd(_PLAN_PRICES_CENTS["pro"]),
            planchangeurl=_plan_change_url("pro"),
            usage=[
                BillingUsageBucketView(
                    metric="guardedexecutions",
                    used=18340,
                    included=_PLAN_INCLUDED_UNITS["pro"]["guardedexecutions"],
                    overage=0,
                    unit=_UNIT_LABELS["guardedexecutions"],
                    status="healthy",
                ),
                BillingUsageBucketView(
                    metric="manualreviews",
                    used=1220,
                    included=_PLAN_INCLUDED_UNITS["pro"]["manualreviews"],
                    overage=0,
                    unit=_UNIT_LABELS["manualreviews"],
                    status="healthy",
                ),
                BillingUsageBucketView(
                    metric="securityalerts",
                    used=3870,
                    included=_PLAN_INCLUDED_UNITS["pro"]["securityalerts"],
                    overage=0,
                    unit=_UNIT_LABELS["securityalerts"],
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
                    metric="guardedexecutions",
                    used=4120,
                    included=_PLAN_INCLUDED_UNITS["starter"]["guardedexecutions"],
                    overage=0,
                    unit=_UNIT_LABELS["guardedexecutions"],
                    status="healthy",
                ),
                BillingUsageBucketView(
                    metric="manualreviews",
                    used=620,
                    included=_PLAN_INCLUDED_UNITS["starter"]["manualreviews"],
                    overage=0,
                    unit=_UNIT_LABELS["manualreviews"],
                    status="warning",
                ),
                BillingUsageBucketView(
                    metric="securityalerts",
                    used=2010,
                    included=_PLAN_INCLUDED_UNITS["starter"]["securityalerts"],
                    overage=0,
                    unit=_UNIT_LABELS["securityalerts"],
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
                    metric="guardedexecutions",
                    used=271400,
                    included=_PLAN_INCLUDED_UNITS["enterprise"]["guardedexecutions"],
                    overage=21400,
                    unit=_UNIT_LABELS["guardedexecutions"],
                    status="critical",
                ),
                BillingUsageBucketView(
                    metric="manualreviews",
                    used=26110,
                    included=_PLAN_INCLUDED_UNITS["enterprise"]["manualreviews"],
                    overage=1110,
                    unit=_UNIT_LABELS["manualreviews"],
                    status="critical",
                ),
                BillingUsageBucketView(
                    metric="securityalerts",
                    used=41200,
                    included=_PLAN_INCLUDED_UNITS["enterprise"]["securityalerts"],
                    overage=0,
                    unit=_UNIT_LABELS["securityalerts"],
                    status="healthy",
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
            subtotal=_usd(29900),
            tax=_usd(0),
            total=_usd(29900),
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
            subtotal=_usd(9900),
            tax=_usd(0),
            total=_usd(9900),
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
            subtotal=_usd(149900),
            tax=_usd(0),
            total=_usd(149900),
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
            trendlabel="Organizations with active subscriptions",
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
        environment="local",
        overallstatus=overallstatus,
        kpis=kpis,
        plancounts=_build_plan_counts(packages),
        invoicestatuscounts=_build_invoice_status_counts(invoices),
        packages=packages,
        invoices=invoices,
        notes=[
            "Billing overview exposes subscription state, canonical plan data, usage against plan limits, and invoice lifecycle visibility.",
            "Plan names (starter, pro, enterprise) and included unit counts match the canonical plan catalog at /ui/billing/plan-change.",
            "planchangeurl on each package provides a direct link to the plan-change surface for that organization's current plan.",
            "overallstatus is 'attention' when any package is past_due, 'notice' when any package is trialing, 'healthy' otherwise.",
            "totalrevenuecents KPI counts paid invoices only — draft and past_due invoices are excluded.",
            "Dedicated invoice list surface available at /ui/billing/invoices.",
            "All values are placeholder UI contract data for the current local-first Gen1 build.",
            "This page is ready to be wired to live billing providers, metering pipelines, and package enforcement services.",
        ],
    )
