from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/billing",
    tags=["billing-invoices"],
)

_STATUS_COLOR: dict[str, str] = {
    "paid": "success",
    "draft": "neutral",
    "past_due": "error",
    "void": "warning",
}

_SORT_FIELDS = {"issuedat", "dueat", "total", "status", "organizationid"}

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


class BillingInvoiceStatusCount(BaseModel):
    status: str
    count: int
    statuscolor: str


class BillingInvoiceListItem(BaseModel):
    invoiceid: str
    organizationid: str
    organizationname: str
    status: str
    statuscolor: str
    issuedat: str
    dueat: str
    periodstart: str
    periodend: str
    total: BillingCurrencyAmountView
    downloadurl: str | None = None


class BillingInvoiceListFilters(BaseModel):
    status: str | None = None
    organizationid: str | None = None
    page: int = 1
    pagesize: int = 25
    sortby: str = "issuedat"
    sortdir: Literal["asc", "desc"] = "desc"


class BillingInvoiceListResponse(BaseModel):
    generatedat: str
    environment: str
    totalcount: int
    page: int
    pagesize: int
    totalpages: int
    totalrevenuecents: int
    totalrevenuedisplay: str
    filters: BillingInvoiceListFilters
    invoices: list[BillingInvoiceListItem] = Field(default_factory=list)
    statuscounts: list[BillingInvoiceStatusCount] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class BillingInvoiceDownloadResponse(BaseModel):
    invoiceid: str
    downloadurl: str | None
    available: bool
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


def _all_invoices() -> list[BillingInvoiceListItem]:
    return [
        BillingInvoiceListItem(
            invoiceid="inv-001",
            organizationid="org-001",
            organizationname="Alpha Security Lab",
            status="paid",
            statuscolor=_status_color("paid"),
            issuedat=_utc_iso(2026, 4, 10, 9, 5),
            dueat=_utc_iso(2026, 4, 17, 9, 5),
            periodstart=_utc_iso(2026, 4, 1, 0, 0),
            periodend=_utc_iso(2026, 4, 30, 23, 59),
            total=_usd(29900),
            downloadurl="/ui/billing/invoices/inv-001/download",
        ),
        BillingInvoiceListItem(
            invoiceid="inv-002",
            organizationid="org-002",
            organizationname="Beta Runtime Defense",
            status="draft",
            statuscolor=_status_color("draft"),
            issuedat=_utc_iso(2026, 4, 12, 14, 25),
            dueat=_utc_iso(2026, 4, 26, 14, 25),
            periodstart=_utc_iso(2026, 4, 12, 0, 0),
            periodend=_utc_iso(2026, 5, 11, 23, 59),
            total=_usd(9900),
            downloadurl=None,
        ),
        BillingInvoiceListItem(
            invoiceid="inv-003",
            organizationid="org-003",
            organizationname="Gamma Internal QA",
            status="past_due",
            statuscolor=_status_color("past_due"),
            issuedat=_utc_iso(2026, 4, 8, 9, 0),
            dueat=_utc_iso(2026, 4, 15, 9, 0),
            periodstart=_utc_iso(2026, 4, 1, 0, 0),
            periodend=_utc_iso(2026, 4, 30, 23, 59),
            total=_usd(149900),
            downloadurl="/ui/billing/invoices/inv-003/download",
        ),
        BillingInvoiceListItem(
            invoiceid="inv-004",
            organizationid="org-001",
            organizationname="Alpha Security Lab",
            status="paid",
            statuscolor=_status_color("paid"),
            issuedat=_utc_iso(2026, 3, 10, 9, 5),
            dueat=_utc_iso(2026, 3, 17, 9, 5),
            periodstart=_utc_iso(2026, 3, 1, 0, 0),
            periodend=_utc_iso(2026, 3, 31, 23, 59),
            total=_usd(29900),
            downloadurl="/ui/billing/invoices/inv-004/download",
        ),
        BillingInvoiceListItem(
            invoiceid="inv-005",
            organizationid="org-004",
            organizationname="Delta Threat Ops",
            status="paid",
            statuscolor=_status_color("paid"),
            issuedat=_utc_iso(2026, 4, 1, 8, 0),
            dueat=_utc_iso(2026, 4, 8, 8, 0),
            periodstart=_utc_iso(2026, 3, 1, 0, 0),
            periodend=_utc_iso(2026, 3, 31, 23, 59),
            total=_usd(9900),
            downloadurl="/ui/billing/invoices/inv-005/download",
        ),
        BillingInvoiceListItem(
            invoiceid="inv-006",
            organizationid="org-004",
            organizationname="Delta Threat Ops",
            status="draft",
            statuscolor=_status_color("draft"),
            issuedat=_utc_iso(2026, 5, 1, 8, 0),
            dueat=_utc_iso(2026, 5, 8, 8, 0),
            periodstart=_utc_iso(2026, 4, 1, 0, 0),
            periodend=_utc_iso(2026, 4, 30, 23, 59),
            total=_usd(9900),
            downloadurl=None,
        ),
        BillingInvoiceListItem(
            invoiceid="inv-007",
            organizationid="org-005",
            organizationname="Epsilon Red Team",
            status="void",
            statuscolor=_status_color("void"),
            issuedat=_utc_iso(2026, 3, 15, 10, 0),
            dueat=_utc_iso(2026, 3, 22, 10, 0),
            periodstart=_utc_iso(2026, 3, 1, 0, 0),
            periodend=_utc_iso(2026, 3, 31, 23, 59),
            total=_usd(29900),
            downloadurl=None,
        ),
        BillingInvoiceListItem(
            invoiceid="inv-008",
            organizationid="org-003",
            organizationname="Gamma Internal QA",
            status="paid",
            statuscolor=_status_color("paid"),
            issuedat=_utc_iso(2026, 3, 8, 9, 0),
            dueat=_utc_iso(2026, 3, 15, 9, 0),
            periodstart=_utc_iso(2026, 3, 1, 0, 0),
            periodend=_utc_iso(2026, 3, 31, 23, 59),
            total=_usd(149900),
            downloadurl="/ui/billing/invoices/inv-008/download",
        ),
        BillingInvoiceListItem(
            invoiceid="inv-009",
            organizationid="org-005",
            organizationname="Epsilon Red Team",
            status="past_due",
            statuscolor=_status_color("past_due"),
            issuedat=_utc_iso(2026, 4, 15, 10, 0),
            dueat=_utc_iso(2026, 4, 22, 10, 0),
            periodstart=_utc_iso(2026, 4, 1, 0, 0),
            periodend=_utc_iso(2026, 4, 30, 23, 59),
            total=_usd(29900),
            downloadurl="/ui/billing/invoices/inv-009/download",
        ),
        BillingInvoiceListItem(
            invoiceid="inv-010",
            organizationid="org-002",
            organizationname="Beta Runtime Defense",
            status="void",
            statuscolor=_status_color("void"),
            issuedat=_utc_iso(2026, 3, 12, 14, 0),
            dueat=_utc_iso(2026, 3, 19, 14, 0),
            periodstart=_utc_iso(2026, 3, 1, 0, 0),
            periodend=_utc_iso(2026, 3, 31, 23, 59),
            total=_usd(9900),
            downloadurl=None,
        ),
    ]


def _build_status_counts(invoices: list[BillingInvoiceListItem]) -> list[BillingInvoiceStatusCount]:
    counts = Counter(inv.status for inv in invoices)
    return [
        BillingInvoiceStatusCount(
            status=status,
            count=count,
            statuscolor=_status_color(status),
        )
        for status, count in sorted(counts.items())
    ]


def _apply_filters(
    invoices: list[BillingInvoiceListItem],
    status: str | None,
    organizationid: str | None,
) -> list[BillingInvoiceListItem]:
    if status:
        invoices = [inv for inv in invoices if inv.status == status]
    if organizationid:
        invoices = [inv for inv in invoices if inv.organizationid == organizationid]
    return invoices


def _apply_sort(
    invoices: list[BillingInvoiceListItem],
    sortby: str,
    sortdir: str,
) -> list[BillingInvoiceListItem]:
    field = sortby if sortby in _SORT_FIELDS else "issuedat"
    reverse = sortdir == "desc"
    if field == "total":
        return sorted(invoices, key=lambda inv: inv.total.amountcents, reverse=reverse)
    return sorted(invoices, key=lambda inv: getattr(inv, field, ""), reverse=reverse)


def _paginate(
    invoices: list[BillingInvoiceListItem],
    page: int,
    pagesize: int,
) -> list[BillingInvoiceListItem]:
    start = (page - 1) * pagesize
    return invoices[start : start + pagesize]


def _total_revenue(invoices: list[BillingInvoiceListItem]) -> BillingCurrencyAmountView:
    cents = sum(inv.total.amountcents for inv in invoices if inv.status == "paid")
    return _usd(cents)


@router.get("/invoices", response_model=BillingInvoiceListResponse)
def get_billing_invoices(
    status: str | None = None,
    organizationid: str | None = None,
    page: int = 1,
    pagesize: int = 25,
    sortby: str = "issuedat",
    sortdir: Literal["asc", "desc"] = "desc",
) -> BillingInvoiceListResponse:
    all_inv = _all_invoices()
    status_counts = _build_status_counts(all_inv)
    filtered = _apply_filters(all_inv, status, organizationid)
    sorted_inv = _apply_sort(filtered, sortby, sortdir)
    totalcount = len(sorted_inv)
    page = max(1, page)
    pagesize = max(1, min(pagesize, 100))
    totalpages = max(1, -(-totalcount // pagesize))
    revenue = _total_revenue(filtered)
    paginated = _paginate(sorted_inv, page, pagesize)

    return BillingInvoiceListResponse(
        generatedat=datetime.now(UTC).isoformat(),
        environment="local",
        totalcount=totalcount,
        page=page,
        pagesize=pagesize,
        totalpages=totalpages,
        totalrevenuecents=revenue.amountcents,
        totalrevenuedisplay=revenue.displayamount,
        filters=BillingInvoiceListFilters(
            status=status,
            organizationid=organizationid,
            page=page,
            pagesize=pagesize,
            sortby=sortby,
            sortdir=sortdir,
        ),
        invoices=paginated,
        statuscounts=status_counts,
        notes=[
            "Invoice list supports filtering by status (paid, draft, past_due, void) and organizationid.",
            "statuscounts reflect the full unfiltered dataset for badge rendering.",
            "statuscolor maps invoice status to a UI hint: success, warning, error, or neutral.",
            "Pagination is 1-indexed. Default pagesize is 25, maximum is 100. totalpages is always >= 1.",
            "sortby accepts: issuedat, dueat, total, status, organizationid. Default: issuedat desc.",
            "totalrevenuecents and totalrevenuedisplay reflect paid invoices in the filtered (pre-pagination) set.",
            "downloadurl is present for paid invoices; null for draft and void invoices.",
            "All values are placeholder UI contract data for the current local-first Gen1 build.",
            "This page is ready to be wired to a live invoice persistence layer.",
        ],
    )


@router.get(
    "/invoices/{invoiceid}/download",
    response_model=BillingInvoiceDownloadResponse,
)
def get_invoice_download(invoiceid: str) -> BillingInvoiceDownloadResponse:
    if invoiceid not in _VALID_INVOICE_IDS:
        return BillingInvoiceDownloadResponse(
            invoiceid=invoiceid,
            downloadurl=None,
            available=False,
            message=f"Invoice '{invoiceid}' was not found.",
            generatedat=datetime.now(UTC).isoformat(),
            environment="local",
        )
    inv_map = {inv.invoiceid: inv for inv in _all_invoices()}
    inv = inv_map.get(invoiceid)
    has_download = inv is not None and inv.downloadurl is not None
    return BillingInvoiceDownloadResponse(
        invoiceid=invoiceid,
        downloadurl=inv.downloadurl if has_download else None,
        available=has_download,
        message=(f"Download available for invoice '{invoiceid}'." if has_download else f"No PDF download available for invoice '{invoiceid}' (status: {inv.status if inv else 'unknown'})."),
        generatedat=datetime.now(UTC).isoformat(),
        environment="local",
    )
