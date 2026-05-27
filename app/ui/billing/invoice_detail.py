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

_VALID_INVOICE_IDS: frozenset[str] = frozenset(
    {
        "inv-001",
        "inv-002",
        "inv-003",
        "inv-004",
        "inv-005",
        "inv-006",
        "inv-007",
        "inv-008",
        "inv-009",
        "inv-010",
    }
)


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


# ---------------------------------------------------------------------------
# Package snapshot factories
# ---------------------------------------------------------------------------


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


def _package_delta() -> BillingPackageSnapshotView:
    return BillingPackageSnapshotView(
        packageid="pkg-004",
        organizationid="org-004",
        organizationname="Delta Threat Ops",
        plan="starter",
        status="active",
        startedat=_utc_iso(2026, 3, 1, 8, 0),
        purchasedat=_utc_iso(2026, 3, 1, 8, 0),
        packageprice=_usd(9900),
        usage=[
            BillingUsageBucketView(
                metric="guardedexecutions",
                used=6800,
                included=10000,
                overage=0,
                unit="requests",
                status="healthy",
            ),
            BillingUsageBucketView(
                metric="manualreviews",
                used=410,
                included=1000,
                overage=0,
                unit="items",
                status="healthy",
            ),
            BillingUsageBucketView(
                metric="securityalerts",
                used=1120,
                included=2500,
                overage=0,
                unit="alerts",
                status="healthy",
            ),
        ],
    )


def _package_epsilon() -> BillingPackageSnapshotView:
    return BillingPackageSnapshotView(
        packageid="pkg-005",
        organizationid="org-005",
        organizationname="Epsilon Red Team",
        plan="pro",
        status="past_due",
        startedat=_utc_iso(2026, 3, 15, 10, 0),
        purchasedat=_utc_iso(2026, 3, 15, 10, 0),
        packageprice=_usd(29900),
        usage=[
            BillingUsageBucketView(
                metric="guardedexecutions",
                used=31200,
                included=50000,
                overage=0,
                unit="requests",
                status="healthy",
            ),
            BillingUsageBucketView(
                metric="manualreviews",
                used=3900,
                included=5000,
                overage=0,
                unit="items",
                status="warning",
            ),
            BillingUsageBucketView(
                metric="securityalerts",
                used=8700,
                included=10000,
                overage=0,
                unit="alerts",
                status="warning",
            ),
        ],
    )


# ---------------------------------------------------------------------------
# Invoice detail factories
# ---------------------------------------------------------------------------


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
            "Payment method pm-002 (Mastercard 5555) has status 'expired' — update required before collection.",
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
        issuedat=_utc_iso(2026, 4, 8, 9, 0),
        dueat=_utc_iso(2026, 4, 15, 9, 0),
        periodstart=_utc_iso(2026, 4, 1, 0, 0),
        periodend=_utc_iso(2026, 4, 30, 23, 59),
        paidat=None,
        subtotal=_usd(154680),
        tax=_usd(0),
        total=_usd(154680),
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
            "subtotal reflects base plan ($1,499.00) plus overage line items ($42.80 + $5.55 = $48.35); total $1,546.80.",
            "Payment method pm-003 (Amex 0005, active) is the default method for org-003.",
            "guardedexecutions and manualreviews usage buckets are at critical level for org-003.",
        ],
    )


def _invoice_004() -> BillingInvoiceDetailResponse:
    return BillingInvoiceDetailResponse(
        status="ok",
        invoiceid="inv-004",
        organizationid="org-001",
        organizationname="Alpha Security Lab",
        invoicestatus="paid",
        statuscolor=_status_color("paid"),
        issuedat=_utc_iso(2026, 3, 10, 9, 5),
        dueat=_utc_iso(2026, 3, 17, 9, 5),
        periodstart=_utc_iso(2026, 3, 1, 0, 0),
        periodend=_utc_iso(2026, 3, 31, 23, 59),
        paidat=_utc_iso(2026, 3, 11, 10, 14),
        subtotal=_usd(29900),
        tax=_usd(0),
        total=_usd(29900),
        lineitems=[
            BillingInvoiceLineItem(
                description="Pro Plan — Monthly Base Fee (March 2026)",
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
        downloadurl="/ui/billing/invoices/inv-004/download",
        package=_package_alpha(),
        generatedat=datetime.now(UTC).isoformat(),
        environment="local",
        notes=[
            "inv-004 is a fully paid Pro plan invoice for org-001 (March 2026 billing period).",
            "Payment collected via Visa card ending in 4242 (pm-001, active).",
        ],
    )


def _invoice_005() -> BillingInvoiceDetailResponse:
    return BillingInvoiceDetailResponse(
        status="ok",
        invoiceid="inv-005",
        organizationid="org-004",
        organizationname="Delta Threat Ops",
        invoicestatus="paid",
        statuscolor=_status_color("paid"),
        issuedat=_utc_iso(2026, 4, 1, 8, 0),
        dueat=_utc_iso(2026, 4, 8, 8, 0),
        periodstart=_utc_iso(2026, 3, 1, 0, 0),
        periodend=_utc_iso(2026, 3, 31, 23, 59),
        paidat=_utc_iso(2026, 4, 2, 9, 45),
        subtotal=_usd(9900),
        tax=_usd(0),
        total=_usd(9900),
        lineitems=[
            BillingInvoiceLineItem(
                description="Starter Plan — Monthly Base Fee (March 2026)",
                quantity=1,
                unitprice=_usd(9900),
                linetotal=_usd(9900),
                type="base_plan",
            ),
        ],
        paymentmethod=BillingPaymentMethodSnapshotView(
            methodid="pm-004",
            brand="visa",
            last4="1234",
            expmonth=6,
            expyear=2028,
        ),
        downloadurl="/ui/billing/invoices/inv-005/download",
        package=_package_delta(),
        generatedat=datetime.now(UTC).isoformat(),
        environment="local",
        notes=[
            "inv-005 is a fully paid Starter plan invoice for org-004 (March 2026 billing period).",
            "Payment collected via Visa card ending in 1234 (pm-004, active).",
        ],
    )


def _invoice_006() -> BillingInvoiceDetailResponse:
    return BillingInvoiceDetailResponse(
        status="ok",
        invoiceid="inv-006",
        organizationid="org-004",
        organizationname="Delta Threat Ops",
        invoicestatus="draft",
        statuscolor=_status_color("draft"),
        issuedat=_utc_iso(2026, 5, 1, 8, 0),
        dueat=_utc_iso(2026, 5, 8, 8, 0),
        periodstart=_utc_iso(2026, 4, 1, 0, 0),
        periodend=_utc_iso(2026, 4, 30, 23, 59),
        paidat=None,
        subtotal=_usd(9900),
        tax=_usd(0),
        total=_usd(9900),
        lineitems=[
            BillingInvoiceLineItem(
                description="Starter Plan — Monthly Base Fee (April 2026)",
                quantity=1,
                unitprice=_usd(9900),
                linetotal=_usd(9900),
                type="base_plan",
            ),
        ],
        paymentmethod=BillingPaymentMethodSnapshotView(
            methodid="pm-004",
            brand="visa",
            last4="1234",
            expmonth=6,
            expyear=2028,
        ),
        downloadurl=None,
        package=_package_delta(),
        generatedat=datetime.now(UTC).isoformat(),
        environment="local",
        notes=[
            "inv-006 is a draft Starter plan invoice for org-004 (April 2026 billing period).",
            "No payment collected yet; invoice is pending finalization.",
        ],
    )


def _invoice_007() -> BillingInvoiceDetailResponse:
    return BillingInvoiceDetailResponse(
        status="ok",
        invoiceid="inv-007",
        organizationid="org-005",
        organizationname="Epsilon Red Team",
        invoicestatus="void",
        statuscolor=_status_color("void"),
        issuedat=_utc_iso(2026, 3, 15, 10, 0),
        dueat=_utc_iso(2026, 3, 22, 10, 0),
        periodstart=_utc_iso(2026, 3, 1, 0, 0),
        periodend=_utc_iso(2026, 3, 31, 23, 59),
        paidat=None,
        subtotal=_usd(29900),
        tax=_usd(0),
        total=_usd(29900),
        lineitems=[
            BillingInvoiceLineItem(
                description="Pro Plan — Monthly Base Fee (March 2026)",
                quantity=1,
                unitprice=_usd(29900),
                linetotal=_usd(29900),
                type="base_plan",
            ),
        ],
        paymentmethod=BillingPaymentMethodSnapshotView(
            methodid="pm-005",
            brand="mastercard",
            last4="9876",
            expmonth=1,
            expyear=2027,
        ),
        downloadurl=None,
        package=_package_epsilon(),
        generatedat=datetime.now(UTC).isoformat(),
        environment="local",
        notes=[
            "inv-007 is a voided Pro plan invoice for org-005 (March 2026 billing period).",
            "Invoice was voided before payment was collected; no charges applied.",
        ],
    )


def _invoice_008() -> BillingInvoiceDetailResponse:
    return BillingInvoiceDetailResponse(
        status="ok",
        invoiceid="inv-008",
        organizationid="org-003",
        organizationname="Gamma Internal QA",
        invoicestatus="paid",
        statuscolor=_status_color("paid"),
        issuedat=_utc_iso(2026, 3, 8, 9, 0),
        dueat=_utc_iso(2026, 3, 15, 9, 0),
        periodstart=_utc_iso(2026, 3, 1, 0, 0),
        periodend=_utc_iso(2026, 3, 31, 23, 59),
        paidat=_utc_iso(2026, 3, 9, 11, 20),
        subtotal=_usd(149900),
        tax=_usd(0),
        total=_usd(149900),
        lineitems=[
            BillingInvoiceLineItem(
                description="Enterprise Plan — Monthly Base Fee (March 2026)",
                quantity=1,
                unitprice=_usd(149900),
                linetotal=_usd(149900),
                type="base_plan",
            ),
        ],
        paymentmethod=BillingPaymentMethodSnapshotView(
            methodid="pm-003",
            brand="amex",
            last4="0005",
            expmonth=11,
            expyear=2027,
        ),
        downloadurl="/ui/billing/invoices/inv-008/download",
        package=_package_gamma(),
        generatedat=datetime.now(UTC).isoformat(),
        environment="local",
        notes=[
            "inv-008 is a fully paid Enterprise plan invoice for org-003 (March 2026 billing period).",
            "Payment collected via Amex card ending in 0005 (pm-003, active).",
        ],
    )


def _invoice_009() -> BillingInvoiceDetailResponse:
    return BillingInvoiceDetailResponse(
        status="ok",
        invoiceid="inv-009",
        organizationid="org-005",
        organizationname="Epsilon Red Team",
        invoicestatus="past_due",
        statuscolor=_status_color("past_due"),
        issuedat=_utc_iso(2026, 4, 15, 10, 0),
        dueat=_utc_iso(2026, 4, 22, 10, 0),
        periodstart=_utc_iso(2026, 4, 1, 0, 0),
        periodend=_utc_iso(2026, 4, 30, 23, 59),
        paidat=None,
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
            methodid="pm-005",
            brand="mastercard",
            last4="9876",
            expmonth=1,
            expyear=2027,
        ),
        downloadurl="/ui/billing/invoices/inv-009/download",
        package=_package_epsilon(),
        generatedat=datetime.now(UTC).isoformat(),
        environment="local",
        notes=[
            "inv-009 is a past-due Pro plan invoice for org-005 (April 2026 billing period).",
            "Payment method pm-005 (Mastercard 9876) is active; payment collection has not yet succeeded.",
            "manualreviews and securityalerts usage buckets are at warning level for org-005.",
        ],
    )


def _invoice_010() -> BillingInvoiceDetailResponse:
    return BillingInvoiceDetailResponse(
        status="ok",
        invoiceid="inv-010",
        organizationid="org-002",
        organizationname="Beta Runtime Defense",
        invoicestatus="void",
        statuscolor=_status_color("void"),
        issuedat=_utc_iso(2026, 3, 12, 14, 0),
        dueat=_utc_iso(2026, 3, 19, 14, 0),
        periodstart=_utc_iso(2026, 3, 1, 0, 0),
        periodend=_utc_iso(2026, 3, 31, 23, 59),
        paidat=None,
        subtotal=_usd(9900),
        tax=_usd(0),
        total=_usd(9900),
        lineitems=[
            BillingInvoiceLineItem(
                description="Starter Plan — Monthly Base Fee (March 2026)",
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
            "inv-010 is a voided Starter plan invoice for org-002 (March 2026 billing period).",
            "Invoice was voided before payment was collected; no charges applied.",
            "Payment method pm-002 (Mastercard 5555) is expired.",
        ],
    )


_INVOICE_FACTORIES: dict[str, object] = {
    "inv-001": _invoice_001,
    "inv-002": _invoice_002,
    "inv-003": _invoice_003,
    "inv-004": _invoice_004,
    "inv-005": _invoice_005,
    "inv-006": _invoice_006,
    "inv-007": _invoice_007,
    "inv-008": _invoice_008,
    "inv-009": _invoice_009,
    "inv-010": _invoice_010,
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
            message=f"Invoice '{invoiceid}' was not found. Valid sample IDs are: inv-001 through inv-010.",
            generatedat=datetime.now(UTC).isoformat(),
            environment="local",
        )
    factory = _INVOICE_FACTORIES[invoiceid]
    return factory()  # type: ignore[operator]
