from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/billing",
    tags=["billing-overview"],
)


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


def _sample_packages() -> list[BillingPackageView]:
    return [
        BillingPackageView(
            packageid="pkg-001",
            organizationid="org-001",
            organizationname="Alpha Security Lab",
            plan="team-security",
            status="active",
            purchasedat=_utc_iso(2026, 4, 10, 9, 0),
            expiresat=None,
            packageprice=_usd(9000),
            usage=[
                BillingUsageBucketView(
                    metric="guardedexecutions",
                    used=18340,
                    included=100000,
                    overage=0,
                    unit="units",
                    status="healthy",
                ),
                BillingUsageBucketView(
                    metric="manualreviews",
                    used=1220,
                    included=100000,
                    overage=0,
                    unit="units",
                    status="healthy",
                ),
                BillingUsageBucketView(
                    metric="securityalerts",
                    used=3870,
                    included=100000,
                    overage=0,
                    unit="units",
                    status="healthy",
                ),
            ],
        ),
        BillingPackageView(
            packageid="pkg-002",
            organizationid="org-002",
            organizationname="Beta Runtime Defense",
            plan="single-user",
            status="active",
            purchasedat=_utc_iso(2026, 4, 12, 14, 20),
            expiresat=None,
            packageprice=_usd(2000),
            usage=[
                BillingUsageBucketView(
                    metric="guardedexecutions",
                    used=4120,
                    included=20000,
                    overage=0,
                    unit="units",
                    status="healthy",
                ),
                BillingUsageBucketView(
                    metric="manualreviews",
                    used=620,
                    included=20000,
                    overage=0,
                    unit="units",
                    status="healthy",
                ),
                BillingUsageBucketView(
                    metric="securityalerts",
                    used=2010,
                    included=20000,
                    overage=0,
                    unit="units",
                    status="warning",
                ),
            ],
        ),
        BillingPackageView(
            packageid="pkg-003",
            organizationid="org-003",
            organizationname="Gamma Internal QA",
            plan="enterprise-security",
            status="units_exhausted",
            purchasedat=_utc_iso(2026, 4, 8, 8, 45),
            expiresat=None,
            packageprice=_usd(15000),
            usage=[
                BillingUsageBucketView(
                    metric="guardedexecutions",
                    used=200000,
                    included=200000,
                    overage=0,
                    unit="units",
                    status="critical",
                ),
                BillingUsageBucketView(
                    metric="manualreviews",
                    used=200000,
                    included=200000,
                    overage=0,
                    unit="units",
                    status="critical",
                ),
                BillingUsageBucketView(
                    metric="securityalerts",
                    used=180000,
                    included=200000,
                    overage=0,
                    unit="units",
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
            periodstart=_utc_iso(2026, 4, 10, 0, 0),
            periodend=_utc_iso(2026, 5, 9, 23, 59),
            subtotal=_usd(9000),
            tax=_usd(0),
            total=_usd(9000),
        ),
        BillingInvoiceView(
            invoiceid="inv-002",
            organizationid="org-002",
            organizationname="Beta Runtime Defense",
            status="paid",
            issuedat=_utc_iso(2026, 4, 12, 14, 25),
            dueat=_utc_iso(2026, 4, 19, 14, 25),
            periodstart=_utc_iso(2026, 4, 12, 0, 0),
            periodend=_utc_iso(2026, 4, 12, 23, 59),
            subtotal=_usd(2000),
            tax=_usd(0),
            total=_usd(2000),
        ),
        BillingInvoiceView(
            invoiceid="inv-003",
            organizationid="org-003",
            organizationname="Gamma Internal QA",
            status="paid",
            issuedat=_utc_iso(2026, 4, 8, 9, 0),
            dueat=_utc_iso(2026, 4, 15, 9, 0),
            periodstart=_utc_iso(2026, 4, 8, 0, 0),
            periodend=_utc_iso(2026, 4, 8, 23, 59),
            subtotal=_usd(15000),
            tax=_usd(0),
            total=_usd(15000),
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
    activepackages = sum(1 for package in packages if package.status == "active")
    exhaustedpackages = sum(1 for package in packages if package.status == "units_exhausted")
    totalrevenuecents = sum(invoice.total.amountcents for invoice in invoices)

    kpis = [
        BillingKpiView(
            label="totalpackages",
            value=totalpackages,
            trendlabel="Total package purchase records",
            status="healthy" if totalpackages > 0 else "warning",
        ),
        BillingKpiView(
            label="activepackages",
            value=activepackages,
            trendlabel="Organizations with units remaining",
            status="healthy" if activepackages > 0 else "warning",
        ),
        BillingKpiView(
            label="exhaustedpackages",
            value=exhaustedpackages,
            trendlabel="Packages fully consumed — repurchase opportunities",
            status="warning" if exhaustedpackages > 0 else "healthy",
        ),
        BillingKpiView(
            label="totalrevenuecents",
            value=totalrevenuecents,
            trendlabel="Total package purchase revenue in cents",
            status="healthy" if totalrevenuecents > 0 else "warning",
        ),
    ]

    overallstatus = "healthy"
    if exhaustedpackages > 0:
        overallstatus = "attention"

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
            "Billing overview exposes package state, usage against purchased unit limits, and invoice lifecycle visibility.",
            "All values are placeholder UI contract data for the current local-first Gen1 build.",
            "This page is ready to be wired to live billing providers, metering pipelines, and package enforcement services.",
            "Dedicated invoice list surface available at /ui/billing/invoices.",
        ],
    )
