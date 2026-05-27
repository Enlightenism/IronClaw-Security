from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/billing",
    tags=["billing-packages"],
)

_STATUS_COLOR: dict[str, str] = {
    "active": "success",
    "units_exhausted": "error",
    "suspended": "warning",
    "cancelled": "neutral",
    "pending": "neutral",
}

_USAGE_STATUS_COLOR: dict[str, str] = {
    "healthy": "success",
    "warning": "warning",
    "critical": "error",
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
    statuscolor: str
    percentused: float


class BillingPackageListItem(BaseModel):
    packageid: str
    organizationid: str
    organizationname: str
    plan: str
    status: str
    statuscolor: str
    purchasedat: str
    expiresat: str | None = None
    packageprice: BillingCurrencyAmountView
    usage: list[BillingUsageBucketView] = Field(default_factory=list)
    overallusagestatus: str
    invoiceid: str | None = None


class BillingPackageListFilters(BaseModel):
    status: str | None = None
    plan: str | None = None
    organizationid: str | None = None
    page: int = 1
    pagesize: int = 25


class BillingPackageStatusCount(BaseModel):
    status: str
    count: int
    statuscolor: str


class BillingPackagePlanCount(BaseModel):
    plan: str
    count: int


class BillingPackageListResponse(BaseModel):
    generatedat: str
    environment: str
    totalcount: int
    page: int
    pagesize: int
    filters: BillingPackageListFilters
    packages: list[BillingPackageListItem] = Field(default_factory=list)
    statuscounts: list[BillingPackageStatusCount] = Field(default_factory=list)
    plancounts: list[BillingPackagePlanCount] = Field(default_factory=list)
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


def _status_color(status: str) -> str:
    return _STATUS_COLOR.get(status, "neutral")


def _usage_status_color(status: str) -> str:
    return _USAGE_STATUS_COLOR.get(status, "neutral")


def _percent_used(used: int, included: int) -> float:
    if included <= 0:
        return 100.0
    return round(min((used / included) * 100, 100.0), 2)


def _overall_usage_status(buckets: list[BillingUsageBucketView]) -> str:
    statuses = {b.status for b in buckets}
    if "critical" in statuses:
        return "critical"
    if "warning" in statuses:
        return "warning"
    return "healthy"


def _build_usage(
    metric: str,
    used: int,
    included: int,
    overage: int,
    unit: str,
    status: str,
) -> BillingUsageBucketView:
    return BillingUsageBucketView(
        metric=metric,
        used=used,
        included=included,
        overage=overage,
        unit=unit,
        status=status,
        statuscolor=_usage_status_color(status),
        percentused=_percent_used(used, included),
    )


def _all_packages() -> list[BillingPackageListItem]:
    packages: list[BillingPackageListItem] = []

    # pkg-001 — Alpha Security Lab — team-security — active
    usage_001 = [
        _build_usage("guardedexecutions", 18340, 100000, 0, "units", "healthy"),
        _build_usage("manualreviews", 1220, 100000, 0, "units", "healthy"),
        _build_usage("securityalerts", 3870, 100000, 0, "units", "healthy"),
    ]
    packages.append(
        BillingPackageListItem(
            packageid="pkg-001",
            organizationid="org-001",
            organizationname="Alpha Security Lab",
            plan="team-security",
            status="active",
            statuscolor=_status_color("active"),
            purchasedat=_utc_iso(2026, 4, 10, 9, 0),
            expiresat=None,
            packageprice=_usd(9000),
            usage=usage_001,
            overallusagestatus=_overall_usage_status(usage_001),
            invoiceid="inv-001",
        )
    )

    # pkg-002 — Beta Runtime Defense — single-user — active
    usage_002 = [
        _build_usage("guardedexecutions", 4120, 20000, 0, "units", "healthy"),
        _build_usage("manualreviews", 620, 20000, 0, "units", "healthy"),
        _build_usage("securityalerts", 2010, 20000, 0, "units", "warning"),
    ]
    packages.append(
        BillingPackageListItem(
            packageid="pkg-002",
            organizationid="org-002",
            organizationname="Beta Runtime Defense",
            plan="single-user",
            status="active",
            statuscolor=_status_color("active"),
            purchasedat=_utc_iso(2026, 4, 12, 14, 20),
            expiresat=None,
            packageprice=_usd(2000),
            usage=usage_002,
            overallusagestatus=_overall_usage_status(usage_002),
            invoiceid="inv-002",
        )
    )

    # pkg-003 — Gamma Internal QA — enterprise-security — units_exhausted
    usage_003 = [
        _build_usage("guardedexecutions", 200000, 200000, 0, "units", "critical"),
        _build_usage("manualreviews", 200000, 200000, 0, "units", "critical"),
        _build_usage("securityalerts", 180000, 200000, 0, "units", "healthy"),
    ]
    packages.append(
        BillingPackageListItem(
            packageid="pkg-003",
            organizationid="org-003",
            organizationname="Gamma Internal QA",
            plan="enterprise-security",
            status="units_exhausted",
            statuscolor=_status_color("units_exhausted"),
            purchasedat=_utc_iso(2026, 4, 8, 8, 45),
            expiresat=None,
            packageprice=_usd(15000),
            usage=usage_003,
            overallusagestatus=_overall_usage_status(usage_003),
            invoiceid="inv-003",
        )
    )

    # pkg-004 — Delta Threat Ops — single-user — active
    usage_004 = [
        _build_usage("guardedexecutions", 7810, 20000, 0, "units", "healthy"),
        _build_usage("manualreviews", 430, 20000, 0, "units", "healthy"),
        _build_usage("securityalerts", 1260, 20000, 0, "units", "healthy"),
    ]
    packages.append(
        BillingPackageListItem(
            packageid="pkg-004",
            organizationid="org-004",
            organizationname="Delta Threat Ops",
            plan="single-user",
            status="active",
            statuscolor=_status_color("active"),
            purchasedat=_utc_iso(2026, 3, 20, 11, 0),
            expiresat=None,
            packageprice=_usd(2000),
            usage=usage_004,
            overallusagestatus=_overall_usage_status(usage_004),
            invoiceid="inv-005",
        )
    )

    # pkg-005 — Epsilon Red Team — team-security — suspended
    usage_005 = [
        _build_usage("guardedexecutions", 0, 100000, 0, "units", "healthy"),
        _build_usage("manualreviews", 0, 100000, 0, "units", "healthy"),
        _build_usage("securityalerts", 0, 100000, 0, "units", "healthy"),
    ]
    packages.append(
        BillingPackageListItem(
            packageid="pkg-005",
            organizationid="org-005",
            organizationname="Epsilon Red Team",
            plan="team-security",
            status="suspended",
            statuscolor=_status_color("suspended"),
            purchasedat=_utc_iso(2026, 3, 15, 10, 0),
            expiresat=_utc_iso(2026, 6, 15, 10, 0),
            packageprice=_usd(9000),
            usage=usage_005,
            overallusagestatus=_overall_usage_status(usage_005),
            invoiceid="inv-007",
        )
    )

    # pkg-006 — Alpha Security Lab — enterprise-security — active (second purchase)
    usage_006 = [
        _build_usage("guardedexecutions", 161200, 200000, 0, "units", "warning"),
        _build_usage("manualreviews", 18900, 200000, 0, "units", "healthy"),
        _build_usage("securityalerts", 44100, 200000, 0, "units", "healthy"),
    ]
    packages.append(
        BillingPackageListItem(
            packageid="pkg-006",
            organizationid="org-001",
            organizationname="Alpha Security Lab",
            plan="enterprise-security",
            status="active",
            statuscolor=_status_color("active"),
            purchasedat=_utc_iso(2026, 5, 1, 8, 30),
            expiresat=None,
            packageprice=_usd(15000),
            usage=usage_006,
            overallusagestatus=_overall_usage_status(usage_006),
            invoiceid="inv-004",
        )
    )

    # pkg-007 — Beta Runtime Defense — team-security — cancelled
    usage_007 = [
        _build_usage("guardedexecutions", 3200, 100000, 0, "units", "healthy"),
        _build_usage("manualreviews", 210, 100000, 0, "units", "healthy"),
        _build_usage("securityalerts", 880, 100000, 0, "units", "healthy"),
    ]
    packages.append(
        BillingPackageListItem(
            packageid="pkg-007",
            organizationid="org-002",
            organizationname="Beta Runtime Defense",
            plan="team-security",
            status="cancelled",
            statuscolor=_status_color("cancelled"),
            purchasedat=_utc_iso(2026, 2, 14, 9, 0),
            expiresat=_utc_iso(2026, 3, 14, 9, 0),
            packageprice=_usd(9000),
            usage=usage_007,
            overallusagestatus=_overall_usage_status(usage_007),
            invoiceid="inv-010",
        )
    )

    return packages


def _build_status_counts(
    packages: list[BillingPackageListItem],
) -> list[BillingPackageStatusCount]:
    counts = Counter(pkg.status for pkg in packages)
    return [
        BillingPackageStatusCount(
            status=status,
            count=count,
            statuscolor=_status_color(status),
        )
        for status, count in sorted(counts.items())
    ]


def _build_plan_counts(
    packages: list[BillingPackageListItem],
) -> list[BillingPackagePlanCount]:
    counts = Counter(pkg.plan for pkg in packages)
    return [BillingPackagePlanCount(plan=plan, count=count) for plan, count in sorted(counts.items())]


def _apply_filters(
    packages: list[BillingPackageListItem],
    status: str | None,
    plan: str | None,
    organizationid: str | None,
) -> list[BillingPackageListItem]:
    if status:
        packages = [pkg for pkg in packages if pkg.status == status]
    if plan:
        packages = [pkg for pkg in packages if pkg.plan == plan]
    if organizationid:
        packages = [pkg for pkg in packages if pkg.organizationid == organizationid]
    return packages


def _paginate_packages(
    packages: list[BillingPackageListItem],
    page: int,
    pagesize: int,
) -> list[BillingPackageListItem]:
    start = (page - 1) * pagesize
    return packages[start : start + pagesize]


@router.get("/packages", response_model=BillingPackageListResponse)
def get_billing_packages(
    status: str | None = None,
    plan: str | None = None,
    organizationid: str | None = None,
    page: int = 1,
    pagesize: int = 25,
) -> BillingPackageListResponse:
    all_packages = _all_packages()
    status_counts = _build_status_counts(all_packages)
    plan_counts = _build_plan_counts(all_packages)
    filtered = _apply_filters(all_packages, status, plan, organizationid)
    totalcount = len(filtered)
    page = max(1, page)
    pagesize = max(1, min(pagesize, 100))
    paginated = _paginate_packages(filtered, page, pagesize)

    return BillingPackageListResponse(
        generatedat=datetime.now(UTC).isoformat(),
        environment="local",
        totalcount=totalcount,
        page=page,
        pagesize=pagesize,
        filters=BillingPackageListFilters(
            status=status,
            plan=plan,
            organizationid=organizationid,
            page=page,
            pagesize=pagesize,
        ),
        packages=paginated,
        statuscounts=status_counts,
        plancounts=plan_counts,
        notes=[
            "Package list supports filtering by status (active, units_exhausted, suspended, cancelled, pending), plan, and organizationid.",
            "statuscounts and plancounts reflect the full unfiltered dataset for badge and summary rendering.",
            "statuscolor maps package status to a UI hint: success (active), error (units_exhausted), warning (suspended), neutral (cancelled, pending).",
            "overallusagestatus reflects the worst usage bucket status across all metrics for that package.",
            "percentused is pre-computed per usage bucket: (used / included) * 100, capped at 100.",
            "Pagination is 1-indexed. Default pagesize is 25, maximum is 100.",
            "All values are placeholder UI contract data for the current local-first Gen1 build.",
            "This page is ready to be wired to a live package persistence and metering layer.",
            "Dedicated billing overview available at /ui/billing/overview. Invoice list available at /ui/billing/invoices.",
        ],
    )
