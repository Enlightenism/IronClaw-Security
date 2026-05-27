from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/billing",
    tags=["billing-invoice-detail"],
)

_STATUS_COLOR: dict[str, str] = {
    "paid": "success",
    "draft": "neutral",
    "past_due": "error",
    "void": "warning",
}


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


class BillingPackageSnapshotView(BaseModel):
    packageid: str
    organizationid: str
    organizationname: str
    plan: str
    status: str
    startedat: str
    purchasedat: str
    packageprice: BillingCurrencyAmountView
    usage: list[BillingUsageBucketView] = Field(default_factory=list)


class BillingPaymentMethodSnapshotView(BaseModel):
    methodid: str
    brand: str
    last4: str
    expmonth: int
    expyear: int


class BillingInvoiceLineItem(BaseModel):
    description: str
    quantity: int
    unitprice: BillingCurrencyAmountView
    linetotal: BillingCurrencyAmountView
    type: str


class BillingInvoiceDetailResponse(BaseModel):
    status: str
    invoiceid: str
    organizationid: str
    organizationname: str
    invoicestatus: str
    statuscolor: str
    issuedat: str
    dueat: str
    periodstart: str
    periodend: str
    paidat: str | None = None
    subtotal: BillingCurrencyAmountView
    tax: BillingCurrencyAmountView
    total: BillingCurrencyAmountView
    lineitems: list[BillingInvoiceLineItem] = Field(default_factory=list)
    paymentmethod: BillingPaymentMethodSnapshotView | None = None
    downloadurl: str | None = None
    package: BillingPackageSnapshotView | None = None
    generatedat: str = ""
    environment: str = "local"
    notes: list[str] = Field(default_factory=list)


class BillingInvoiceNotFoundResponse(BaseModel):
    status: str
    invoiceid: str
    message: str
    generatedat: str
    environment: str


def _utc_iso(year: int, month: int, day: int, hour: int, minute: int = 0) -> str:
    return datetime(year, month, day, hour, minute, 0, tzinfo=UTC).isoformat()


def _usd(amountcents: int) -> BillingCurrencyAmountView:
    dollars = amountcents / 100
    return BillingCurrencyAmountView(
        currency="USD",
        amountcents=amountcents,
        displayamount=f"${dollars:,.2f}",
    )


def _status_color(status: str) -> str:
    return _STATUS_COLOR.get(status, "neutral")


def _package_alpha() -> BillingPackageSnapshotView:
    return BillingPackageSnapshotView(
        packageid="pkg-001",
        organizationid="org-001",
        organizationname="Alpha Security Lab",
        plan="pro",
        status="active",
        startedat=_utc_iso(2026, 4, 10, 9, 0),
        purchasedat=_utc_iso(2026, 4, 10, 9, 0),
        packageprice=_usd(29900),
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
    )


def _package_beta() -> BillingPackageSnapshotView:
    return BillingPackageSnapshotView(
        packageid="pkg-002",
        organizationid="org-002",
        organizationname="Beta Runtime Defense",
        plan="starter",
        status="trialing",
        startedat=_utc_iso(2026, 4, 12, 14, 20),
        purchasedat=_utc_iso(2026, 4, 12, 14, 20),
        packageprice=_usd(9900),
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
    )


def _package_gamma() -> BillingPackageSnapshotView:
    return BillingPackageSnapshotView(
        packageid="pkg-003",
        organizationid="org-003",
        organizationname="Gamma Internal QA",
        plan="enterprise",
        status="past_due",
        startedat=_utc_iso(2026, 4, 8, 8, 45),
        purchasedat=_utc_iso(2026, 4, 8, 8, 45),
        packageprice=_usd(149900),
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
    )


# Invoice definitions are factories so generatedat is always request-time, never module-load-time.


def _invoice_001() -> BillingInvoiceDetailResponse:
    return BillingInvoiceDetailResponse(
        status="ok",
        invoiceid="inv-001",
        organizationid="org-001",
        organizationname="Alpha Security Lab",
        invoicestatus="paid",
        statuscolor=_status_color("paid"),
        issuedat=_utc_iso(2026, 4, 10, 9, 5),
        dueat=_utc_iso(2026, 4, 17, 9, 5),
        periodstart=_utc_iso(2026, 4, 1, 0, 0),
        periodend=_utc_iso(2026, 4, 30, 23, 59),
        paidat=_utc_iso(2026, 4, 11, 14, 32),
        subtotal=_usd(29900),
        tax=_usd(0),
        total=_usd(29900),
        lineitems=[
            BillingInvoiceLineItem(
                description="Pro Plan — Monthly Base Fee (April 2026)",
                quantity=1,
                unitprice=_usd(29900),
                linetotal=_usd(29900),
                type="base_plan",
            ),
        ],
        paymentmethod=BillingPaymentMethodSnapshotView(
            methodid="pm-001",
            brand="visa",
            last4="4242",
            expmonth=9,
            expyear=2027,
        ),
        downloadurl="/ui/billing/invoices/inv-001/download",
        package=_package_alpha(),
        generatedat=datetime.now(UTC).isoformat(),
        environment="local",
        notes=[
            "inv-001 is a fully paid Pro plan invoice with no overage charges.",
            "Payment was collected via Visa card ending in 4242 (pm-001, active).",
            "Line items reflect a single base plan fee for the April 2026 billing period.",
        ],
    )


def _invoice_002() -> BillingInvoiceDetailResponse:
    return BillingInvoiceDetailResponse(
        status="ok",
        invoiceid="inv-002",
        organizationid="org-002",
        organizationname="Beta Runtime Defense",
        invoicestatus="draft",
        statuscolor=_status_color("draft"),
        issuedat=_utc_iso(2026, 4, 12, 14, 25),
        dueat=_utc_iso(2026, 4, 26, 14, 25),
        periodstart=_utc_iso(2026, 4, 12, 0, 0),
        periodend=_utc_iso(2026, 5, 11, 23, 59),
        paidat=None,
        subtotal=_usd(9900),
        tax=_usd(0),
        total=_usd(9900),
        lineitems=[
            BillingInvoiceLineItem(
                description="Starter Plan — Monthly Base Fee (April–May 2026)",
                quantity=1,
                unitprice=_usd(9900),
                linetotal=_usd(9900),
                type="base_plan",
            ),
        ],
        paymentmethod=BillingPaymentMethodSnapshotView(
            methodid="pm-002",
            brand="mastercard",
            last4="5555",
            expmonth=3,
            expyear=2026,
        ),
        downloadurl=None,
        package=_package_beta(),
        generatedat=datetime.now(UTC).isoformat(),
        environment="local",
        notes=[
            "inv-002 is a draft Starter plan invoice; no payment has been collected yet.",
            "Payment method pm-002 (Mastercard 5555) has status 'expired' in the payment catalog — update required before this invoice can be collected.",
            "manualreviews and securityalerts usage buckets are at warning level for org-002.",
            "Line items reflect a single base plan fee for the April–May 2026 billing period.",
        ],
    )


def _invoice_003() -> BillingInvoiceDetailResponse:
    return BillingInvoiceDetailResponse(
        status="ok",
        invoiceid="inv-003",
        organizationid="org-003",
        organizationname="Gamma Internal QA",
        invoicestatus="past_due",
        statuscolor=_status_color("past_due"),
        issuedat=_utc_iso(2026, 4, 8, 8, 50),
        dueat=_utc_iso(2026, 4, 15, 8, 50),
        periodstart=_utc_iso(2026, 4, 1, 0, 0),
        periodend=_utc_iso(2026, 4, 30, 23, 59),
        paidat=None,
        subtotal=_usd(149900),
        tax=_usd(0),
        total=_usd(149900),
        lineitems=[
            BillingInvoiceLineItem(
                description="Enterprise Plan — Monthly Base Fee (April 2026)",
                quantity=1,
                unitprice=_usd(149900),
                linetotal=_usd(149900),
                type="base_plan",
            ),
            BillingInvoiceLineItem(
                description="Guarded Executions Overage — 21,400 requests @ $0.002",
                quantity=21400,
                unitprice=_usd(0),
                linetotal=_usd(4280),
                type="overage",
            ),
            BillingInvoiceLineItem(
                description="Manual Reviews Overage — 1,110 items @ $0.05",
                quantity=1110,
                unitprice=_usd(5),
                linetotal=_usd(555),
                type="overage",
            ),
        ],
        paymentmethod=BillingPaymentMethodSnapshotView(
            methodid="pm-003",
            brand="amex",
            last4="0005",
            expmonth=11,
            expyear=2027,
        ),
        downloadurl="/ui/billing/invoices/inv-003/download",
        package=_package_gamma(),
        generatedat=datetime.now(UTC).isoformat(),
        environment="local",
        notes=[
            "inv-003 is a past-due Enterprise invoice with overage charges on guardedexecutions and manualreviews.",
            "Payment method pm-003 (Amex 0005, active) is the default method for org-003.",
            "guardedexecutions and manualreviews usage buckets are at critical level for org-003.",
            "Total due includes base plan fee plus overage line items.",
        ],
    )


_VALID_INVOICE_IDS: frozenset[str] = frozenset({"inv-001", "inv-002", "inv-003"})

_INVOICE_FACTORIES: dict[str, object] = {
    "inv-001": _invoice_001,
    "inv-002": _invoice_002,
    "inv-003": _invoice_003,
}


@router.get(
    "/invoices/{invoiceid}",
    response_model=BillingInvoiceDetailResponse | BillingInvoiceNotFoundResponse,
)
def get_invoice_detail(
    invoiceid: str,
) -> BillingInvoiceDetailResponse | BillingInvoiceNotFoundResponse:
    if invoiceid not in _VALID_INVOICE_IDS:
        return BillingInvoiceNotFoundResponse(
            status="not_found",
            invoiceid=invoiceid,
            message=f"Invoice '{invoiceid}' was not found. Valid sample IDs are: inv-001, inv-002, inv-003.",
            generatedat=datetime.now(UTC).isoformat(),
            environment="local",
        )
    factory = _INVOICE_FACTORIES[invoiceid]
    return factory()  # type: ignore[operator]
