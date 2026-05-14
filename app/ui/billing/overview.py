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


class BillingSubscriptionView(BaseModel):
    subscriptionid: str
    organizationid: str
    organizationname: str
    plan: str
    status: str
    billinginterval: str
    startedat: str
    renewsat: str
    monthlybaseprice: BillingCurrencyAmountView
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
    subscriptions: list[BillingSubscriptionView] = Field(default_factory=list)
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


def _sample_subscriptions() -> list[BillingSubscriptionView]:
    return [
        BillingSubscriptionView(
            subscriptionid="sub-001",
            organizationid="org-001",
            organizationname="Alpha Security Lab",
            plan="pro",
            status="active",
            billinginterval="monthly",
            startedat=_utc_iso(2026, 4, 10, 9, 0),
            renewsat=_utc_iso(2026, 5, 10, 9, 0),
            monthlybaseprice=_usd(29900),
            usage=[
                BillingUsageBucketView(
                    metric="guardedexecutions",
                    used=18340,
                    included=50000,
                    overage=0,
                    unit="requests",
                    status="healthy",
                ),
                BillingUsageBucketView(
                    metric="manualreviews",
                    used=1220,
                    included=5000,
                    overage=0,
                    unit="items",
                    status="healthy",
                ),
                BillingUsageBucketView(
                    metric="securityalerts",
                    used=3870,
                    included=10000,
                    overage=0,
                    unit="alerts",
                    status="healthy",
                ),
            ],
        ),
        BillingSubscriptionView(
            subscriptionid="sub-002",
            organizationid="org-002",
            organizationname="Beta Runtime Defense",
            plan="starter",
            status="trialing",
            billinginterval="monthly",
            startedat=_utc_iso(2026, 4, 12, 14, 20),
            renewsat=_utc_iso(2026, 4, 26, 14, 20),
            monthlybaseprice=_usd(9900),
            usage=[
                BillingUsageBucketView(
                    metric="guardedexecutions",
                    used=4120,
                    included=10000,
                    overage=0,
                    unit="requests",
                    status="healthy",
                ),
                BillingUsageBucketView(
                    metric="manualreviews",
                    used=620,
                    included=1000,
                    overage=0,
                    unit="items",
                    status="warning",
                ),
                BillingUsageBucketView(
                    metric="securityalerts",
                    used=2010,
                    included=2500,
                    overage=0,
                    unit="alerts",
                    status="warning",
                ),
            ],
        ),
        BillingSubscriptionView(
            subscriptionid="sub-003",
            organizationid="org-003",
            organizationname="Gamma Internal QA",
            plan="enterprise",
            status="past_due",
            billinginterval="monthly",
            startedat=_utc_iso(2026, 4, 8, 8, 45),
            renewsat=_utc_iso(2026, 5, 8, 8, 45),
            monthlybaseprice=_usd(149900),
            usage=[
                BillingUsageBucketView(
                    metric="guardedexecutions",
                    used=271400,
                    included=250000,
                    overage=21400,
                    unit="requests",
                    status="critical",
                ),
                BillingUsageBucketView(
                    metric="manualreviews",
                    used=26110,
                    included=25000,
                    overage=1110,
                    unit="items",
                    status="critical",
                ),
                BillingUsageBucketView(
                    metric="securityalerts",
                    used=41200,
                    included=50000,
                    overage=0,
                    unit="alerts",
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
            issuedat=_utc_iso(2026, 4, 8, 9, 0),
            dueat=_utc_iso(2026, 4, 15, 9, 0),
            periodstart=_utc_iso(2026, 4, 8, 0, 0),
            periodend=_utc_iso(2026, 5, 7, 23, 59),
            subtotal=_usd(149900),
            tax=_usd(0),
            total=_usd(149900),
        ),
    ]


def _build_plan_counts(subscriptions: list[BillingSubscriptionView]) -> list[BillingPlanCount]:
    counts = Counter(subscription.plan for subscription in subscriptions)
    return [BillingPlanCount(plan=plan, count=count) for plan, count in sorted(counts.items())]


def _build_invoice_status_counts(
    invoices: list[BillingInvoiceView],
) -> list[BillingInvoiceStatusCount]:
    counts = Counter(invoice.status for invoice in invoices)
    return [BillingInvoiceStatusCount(status=status, count=count) for status, count in sorted(counts.items())]


@router.get("/overview", response_model=BillingOverviewResponse)
def get_billing_overview() -> BillingOverviewResponse:
    subscriptions = _sample_subscriptions()
    invoices = _sample_invoices()

    totalsubscriptions = len(subscriptions)
    activepaid = sum(1 for subscription in subscriptions if subscription.status == "active")
    trialing = sum(1 for subscription in subscriptions if subscription.status == "trialing")
    pastdue = sum(1 for subscription in subscriptions if subscription.status == "past_due")
    monthlyrevenuecents = sum(subscription.monthlybaseprice.amountcents for subscription in subscriptions if subscription.status in {"active", "past_due"})

    kpis = [
        BillingKpiView(
            label="totalsubscriptions",
            value=totalsubscriptions,
            trendlabel="Current subscription records",
            status="healthy" if totalsubscriptions > 0 else "warning",
        ),
        BillingKpiView(
            label="activepaid",
            value=activepaid,
            trendlabel="Paying organizations on active plans",
            status="healthy" if activepaid > 0 else "warning",
        ),
        BillingKpiView(
            label="trialing",
            value=trialing,
            trendlabel="Trials available for revenue conversion",
            status="warning" if trialing > 0 else "healthy",
        ),
        BillingKpiView(
            label="monthlyrecurringrevenuecents",
            value=monthlyrevenuecents,
            trendlabel="Base recurring revenue in cents",
            status="warning" if pastdue > 0 else "healthy",
        ),
    ]

    overallstatus = "healthy"
    if pastdue > 0:
        overallstatus = "attention"

    return BillingOverviewResponse(
        generatedat=datetime.now(UTC).isoformat(),
        environment="local",
        overallstatus=overallstatus,
        kpis=kpis,
        plancounts=_build_plan_counts(subscriptions),
        invoicestatuscounts=_build_invoice_status_counts(invoices),
        subscriptions=subscriptions,
        invoices=invoices,
        notes=[
            "Billing overview exposes subscription state, usage against plan limits, and invoice lifecycle visibility.",
            "All values are placeholder UI contract data for the current local-first Gen1 build.",
            "This page is ready to be wired to live billing providers, metering pipelines, and plan enforcement services.",
        ],
    )
