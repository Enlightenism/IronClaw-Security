from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
import logging
import math
import os
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.supabaseclient import (
    BILLING_TIER_5K_PRICE_USD,
    BILLING_TIER_5K_UNITS,
    BILLING_TIER_25K_PRICE_USD,
    BILLING_TIER_25K_UNITS,
    BILLING_TIER_60K_PRICE_USD,
    BILLING_TIER_60K_UNITS,
    TOKENS_PER_UNIT,
    get_supabase_client,
    is_supabase_configured,
)

logger = logging.getLogger(__name__)

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

_VALID_STATUSES: frozenset[str] = frozenset(_STATUS_COLOR.keys())
_VALID_PLANS: frozenset[str] = frozenset({"starter", "team", "enterprise"})

# ---------------------------------------------------------------------------
# Base package catalogue — no stripe_price_id defaults.
# stripe_price_id is always resolved from env at call time via
# _build_package_catalogue(); the base dict intentionally omits the key so
# that an unset env var always produces "" and never a stale hardcoded value.
# starter    :  5,000 units → $20 USD
# team       : 25,000 units → $90 USD
# enterprise : 60,000 units → $180 USD
# ---------------------------------------------------------------------------

_BASE_PACKAGE_CATALOGUE: dict[str, dict[str, Any]] = {
    "starter": {
        "label": "Starter",
        "units": BILLING_TIER_5K_UNITS,
        "price_usd": BILLING_TIER_5K_PRICE_USD,
        "price_cents": BILLING_TIER_5K_PRICE_USD * 100,
        "tokens_per_unit": TOKENS_PER_UNIT,
        "token_coverage": BILLING_TIER_5K_UNITS * TOKENS_PER_UNIT,
        "notes": (f"{BILLING_TIER_5K_UNITS:,} units · ${BILLING_TIER_5K_PRICE_USD} USD · each unit protects up to {TOKENS_PER_UNIT:,} tokens"),
    },
    "team": {
        "label": "Team",
        "units": BILLING_TIER_25K_UNITS,
        "price_usd": BILLING_TIER_25K_PRICE_USD,
        "price_cents": BILLING_TIER_25K_PRICE_USD * 100,
        "tokens_per_unit": TOKENS_PER_UNIT,
        "token_coverage": BILLING_TIER_25K_UNITS * TOKENS_PER_UNIT,
        "notes": (f"{BILLING_TIER_25K_UNITS:,} units · ${BILLING_TIER_25K_PRICE_USD} USD · each unit protects up to {TOKENS_PER_UNIT:,} tokens"),
    },
    "enterprise": {
        "label": "Enterprise",
        "units": BILLING_TIER_60K_UNITS,
        "price_usd": BILLING_TIER_60K_PRICE_USD,
        "price_cents": BILLING_TIER_60K_PRICE_USD * 100,
        "tokens_per_unit": TOKENS_PER_UNIT,
        "token_coverage": BILLING_TIER_60K_UNITS * TOKENS_PER_UNIT,
        "notes": (f"{BILLING_TIER_60K_UNITS:,} units · ${BILLING_TIER_60K_PRICE_USD} USD · each unit protects up to {TOKENS_PER_UNIT:,} tokens"),
    },
}


def _build_package_catalogue() -> dict[str, dict[str, Any]]:
    """
    Build the package catalogue fresh on every call.
    stripe_price_id is always resolved from os.environ at call time;
    the base dict is intentionally omitted so that an unset env var
    always produces "" — never a stale hardcoded default.
    """
    catalogue: dict[str, dict[str, Any]] = {}
    for key, base in _BASE_PACKAGE_CATALOGUE.items():
        entry = dict(base)
        entry["stripe_price_id"] = os.environ.get(f"STRIPE_PRICE_ID_{key.upper()}", "")
        catalogue[key] = entry
    return catalogue


# Module-level symbol kept for direct imports and backward compatibility.
# Routes always call _build_package_catalogue() directly so env patches are
# picked up on every request.
PACKAGE_CATALOGUE: dict[str, dict[str, Any]] = _build_package_catalogue()

_PLAN_UNITS: dict[str, int] = {plan: meta["units"] for plan, meta in _BASE_PACKAGE_CATALOGUE.items()}
_PLAN_PRICE_CENTS: dict[str, int] = {plan: meta["price_cents"] for plan, meta in _BASE_PACKAGE_CATALOGUE.items()}


# ---------------------------------------------------------------------------
# Stripe mode detection — single source of truth for this module
# ---------------------------------------------------------------------------


class StripeStatus(BaseModel):
    configured: bool
    mode: str  # "live" | "test" | "unconfigured"
    note: str


def _get_stripe_status() -> StripeStatus:
    """
    Inspect STRIPE_SECRET_KEY and return a structured StripeStatus.
    - sk_live_* → live mode (production)
    - sk_test_* → test mode
    - anything else → unconfigured
    """
    key = os.environ.get("STRIPE_SECRET_KEY", "").strip()
    if key.startswith("sk_live_"):
        return StripeStatus(
            configured=True,
            mode="live",
            note="Stripe is connected and active (mode: live). Real payment processing is enabled.",
        )
    if key.startswith("sk_test_"):
        return StripeStatus(
            configured=True,
            mode="test",
            note="Stripe is connected in test mode. Switch to a live key before going to production.",
        )
    return StripeStatus(
        configured=False,
        mode="unconfigured",
        note="Stripe API key is not configured — payment processing is unavailable.",
    )


# ---------------------------------------------------------------------------
# Public helper
# ---------------------------------------------------------------------------


def units_for_tokens(token_count: int) -> int:
    """
    Return the number of protection units required to cover token_count tokens.
    Each unit covers up to TOKENS_PER_UNIT (25,000) tokens.
    Partial chunks consume a full unit (ceiling division).

    Examples:
        units_for_tokens(1)       -> 1
        units_for_tokens(25_000)  -> 1
        units_for_tokens(25_001)  -> 2
        units_for_tokens(75_000)  -> 3
    """
    if token_count <= 0:
        return 0
    return math.ceil(token_count / TOKENS_PER_UNIT)


def _get_environment() -> str:
    return os.environ.get("IRONCLAW_ENV", os.environ.get("APP_ENV", "production"))


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


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
    tokens_per_unit: int
    token_coverage: int


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


class PackageCatalogueEntry(BaseModel):
    label: str
    units: int
    price_usd: int
    price_cents: int
    tokens_per_unit: int
    token_coverage: int
    stripe_price_id: str = ""
    notes: str


class BillingPackageListResponse(BaseModel):
    generatedat: str
    environment: str
    stripe: StripeStatus
    totalcount: int
    page: int
    pagesize: int
    filters: BillingPackageListFilters
    packages: list[BillingPackageListItem] = Field(default_factory=list)
    statuscounts: list[BillingPackageStatusCount] = Field(default_factory=list)
    plancounts: list[BillingPackagePlanCount] = Field(default_factory=list)
    tokens_per_unit: int
    package_catalogue: dict[str, PackageCatalogueEntry] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


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


def _usage_status_for_percent(pct: float) -> str:
    if pct >= 100.0:
        return "critical"
    if pct >= 80.0:
        return "warning"
    return "healthy"


def _make_item(
    packageid: str,
    organizationid: str,
    organizationname: str,
    plan: str,
    status: str,
    purchasedat: str,
    usage: list[BillingUsageBucketView],
    invoiceid: str | None = None,
    expiresat: str | None = None,
) -> BillingPackageListItem:
    plan_units = _PLAN_UNITS.get(plan, BILLING_TIER_5K_UNITS)
    price_cents = _PLAN_PRICE_CENTS.get(plan, BILLING_TIER_5K_PRICE_USD * 100)
    return BillingPackageListItem(
        packageid=packageid,
        organizationid=organizationid,
        organizationname=organizationname,
        plan=plan,
        status=status,
        statuscolor=_status_color(status),
        purchasedat=purchasedat,
        expiresat=expiresat,
        packageprice=_usd(price_cents),
        usage=usage,
        overallusagestatus=_overall_usage_status(usage),
        invoiceid=invoiceid,
        tokens_per_unit=TOKENS_PER_UNIT,
        token_coverage=plan_units * TOKENS_PER_UNIT,
    )


def _fetch_packages_from_supabase() -> list[BillingPackageListItem] | None:
    """
    Query Supabase for all package records.
    Returns a list on success, None if Supabase is not configured or query fails.
    """
    if not is_supabase_configured():
        return None
    try:
        client = get_supabase_client()
        rows = client.table("billing_packages").select("*").order("purchased_at", desc=False).execute().data
        if rows is None:
            return None
        items: list[BillingPackageListItem] = []
        for row in rows:
            plan = str(row.get("plan", "starter"))
            plan_units = _PLAN_UNITS.get(plan, BILLING_TIER_5K_UNITS)
            used_units = int(row.get("used_units", 0))
            pct = _percent_used(used_units, plan_units)
            usage = [
                _build_usage(
                    "guardedexecutions",
                    used_units,
                    plan_units,
                    0,
                    "units",
                    _usage_status_for_percent(pct),
                )
            ]
            items.append(
                _make_item(
                    packageid=str(row.get("id", "")),
                    organizationid=str(row.get("organization_id", "")),
                    organizationname=str(row.get("organization_name", row.get("organization_id", ""))),
                    plan=plan,
                    status=str(row.get("status", "active")),
                    purchasedat=str(row.get("purchased_at", datetime.now(UTC).isoformat())),
                    usage=usage,
                    invoiceid=row.get("invoice_id"),
                    expiresat=row.get("expires_at"),
                )
            )
        return items
    except Exception:
        logger.exception("Failed to fetch billing packages from Supabase")
        return None


def _static_fallback_packages() -> list[BillingPackageListItem]:
    """
    Static demo packages using canonical plan IDs and correct pricing.
    Used only when Supabase is not configured.
    """
    starter_units = BILLING_TIER_5K_UNITS
    team_units = BILLING_TIER_25K_UNITS
    enterprise_units = BILLING_TIER_60K_UNITS

    packages: list[BillingPackageListItem] = []

    usage_001 = [
        _build_usage("guardedexecutions", 3240, team_units, 0, "units", "healthy"),
        _build_usage("manualreviews", 810, team_units, 0, "units", "healthy"),
        _build_usage("securityalerts", 1580, team_units, 0, "units", "healthy"),
    ]
    packages.append(
        _make_item(
            packageid="pkg-001",
            organizationid="org-001",
            organizationname="Alpha Security Lab",
            plan="team",
            status="active",
            purchasedat=_utc_iso(2026, 4, 10, 9, 0),
            usage=usage_001,
            invoiceid="inv-001",
        )
    )

    usage_002 = [
        _build_usage("guardedexecutions", 2100, starter_units, 0, "units", "healthy"),
        _build_usage("manualreviews", 310, starter_units, 0, "units", "healthy"),
        _build_usage("securityalerts", 4010, starter_units, 0, "units", "warning"),
    ]
    packages.append(
        _make_item(
            packageid="pkg-002",
            organizationid="org-002",
            organizationname="Beta Runtime Defense",
            plan="starter",
            status="active",
            purchasedat=_utc_iso(2026, 4, 12, 14, 20),
            usage=usage_002,
            invoiceid="inv-002",
        )
    )

    usage_003 = [
        _build_usage("guardedexecutions", enterprise_units, enterprise_units, 0, "units", "critical"),
        _build_usage("manualreviews", enterprise_units, enterprise_units, 0, "units", "critical"),
        _build_usage("securityalerts", 55000, enterprise_units, 0, "units", "healthy"),
    ]
    packages.append(
        _make_item(
            packageid="pkg-003",
            organizationid="org-003",
            organizationname="Gamma Internal QA",
            plan="enterprise",
            status="units_exhausted",
            purchasedat=_utc_iso(2026, 4, 8, 8, 45),
            usage=usage_003,
            invoiceid="inv-003",
        )
    )

    usage_004 = [
        _build_usage("guardedexecutions", 1810, starter_units, 0, "units", "healthy"),
        _build_usage("manualreviews", 430, starter_units, 0, "units", "healthy"),
        _build_usage("securityalerts", 960, starter_units, 0, "units", "healthy"),
    ]
    packages.append(
        _make_item(
            packageid="pkg-004",
            organizationid="org-004",
            organizationname="Delta Threat Ops",
            plan="starter",
            status="active",
            purchasedat=_utc_iso(2026, 3, 20, 11, 0),
            usage=usage_004,
            invoiceid="inv-005",
        )
    )

    usage_005 = [
        _build_usage("guardedexecutions", 0, team_units, 0, "units", "healthy"),
        _build_usage("manualreviews", 0, team_units, 0, "units", "healthy"),
        _build_usage("securityalerts", 0, team_units, 0, "units", "healthy"),
    ]
    packages.append(
        _make_item(
            packageid="pkg-005",
            organizationid="org-005",
            organizationname="Epsilon Red Team",
            plan="team",
            status="suspended",
            purchasedat=_utc_iso(2026, 3, 15, 10, 0),
            usage=usage_005,
            invoiceid="inv-007",
            expiresat=_utc_iso(2026, 6, 15, 10, 0),
        )
    )

    usage_006 = [
        _build_usage("guardedexecutions", 49200, enterprise_units, 0, "units", "warning"),
        _build_usage("manualreviews", 8900, enterprise_units, 0, "units", "healthy"),
        _build_usage("securityalerts", 14100, enterprise_units, 0, "units", "healthy"),
    ]
    packages.append(
        _make_item(
            packageid="pkg-006",
            organizationid="org-001",
            organizationname="Alpha Security Lab",
            plan="enterprise",
            status="active",
            purchasedat=_utc_iso(2026, 5, 1, 8, 30),
            usage=usage_006,
            invoiceid="inv-004",
        )
    )

    usage_007 = [
        _build_usage("guardedexecutions", 3200, team_units, 0, "units", "healthy"),
        _build_usage("manualreviews", 210, team_units, 0, "units", "healthy"),
        _build_usage("securityalerts", 880, team_units, 0, "units", "healthy"),
    ]
    packages.append(
        _make_item(
            packageid="pkg-007",
            organizationid="org-002",
            organizationname="Beta Runtime Defense",
            plan="team",
            status="cancelled",
            purchasedat=_utc_iso(2026, 2, 14, 9, 0),
            usage=usage_007,
            invoiceid="inv-010",
            expiresat=_utc_iso(2026, 3, 14, 9, 0),
        )
    )

    return packages


def _all_packages() -> list[BillingPackageListItem]:
    live = _fetch_packages_from_supabase()
    if live is not None:
        return live
    return _static_fallback_packages()


def _build_status_counts(
    packages: list[BillingPackageListItem],
) -> list[BillingPackageStatusCount]:
    counts = Counter(pkg.status for pkg in packages)
    return [
        BillingPackageStatusCount(
            status=s,
            count=c,
            statuscolor=_status_color(s),
        )
        for s, c in sorted(counts.items())
    ]


def _build_plan_counts(
    packages: list[BillingPackageListItem],
) -> list[BillingPackagePlanCount]:
    counts = Counter(pkg.plan for pkg in packages)
    return [BillingPackagePlanCount(plan=p, count=c) for p, c in sorted(counts.items())]


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


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------


@router.get("/packages", response_model=BillingPackageListResponse)
def get_billing_packages(
    status: str | None = Query(default=None),
    plan: str | None = Query(default=None),
    organizationid: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    pagesize: int = Query(default=25, ge=1, le=100),
) -> BillingPackageListResponse:
    if status is not None and status not in _VALID_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status '{status}'. Valid values: {sorted(_VALID_STATUSES)}",
        )
    if plan is not None and plan not in _VALID_PLANS:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid plan '{plan}'. Valid values: {sorted(_VALID_PLANS)}",
        )

    all_pkgs = _all_packages()
    status_counts = _build_status_counts(all_pkgs)
    plan_counts = _build_plan_counts(all_pkgs)
    filtered = _apply_filters(all_pkgs, status, plan, organizationid)
    totalcount = len(filtered)
    paginated = _paginate_packages(filtered, page, pagesize)

    # Build fresh on every request so env patches in tests are always picked up.
    live_catalogue = _build_package_catalogue()
    catalogue_out: dict[str, PackageCatalogueEntry] = {k: PackageCatalogueEntry(**v) for k, v in live_catalogue.items()}

    stripe = _get_stripe_status()

    return BillingPackageListResponse(
        generatedat=datetime.now(UTC).isoformat(),
        environment=_get_environment(),
        stripe=stripe,
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
        tokens_per_unit=TOKENS_PER_UNIT,
        package_catalogue=catalogue_out,
        notes=[
            "Package list supports filtering by status (active, units_exhausted, suspended, cancelled, pending), plan, and organizationid.",
            "statuscounts and plancounts reflect the full unfiltered dataset for badge and summary rendering.",
            "statuscolor maps package status to a UI hint: success (active), error (units_exhausted), warning (suspended), neutral (cancelled, pending).",
            "overallusagestatus reflects the worst usage bucket status across all metrics for that package.",
            "percentused is pre-computed per usage bucket: (used / included) * 100, capped at 100.",
            f"Each protection unit covers up to {TOKENS_PER_UNIT:,} tokens. Partial token chunks consume a full additional unit (ceiling division).",
            f"Canonical plans: starter ({BILLING_TIER_5K_UNITS:,} units / ${BILLING_TIER_5K_PRICE_USD}), team ({BILLING_TIER_25K_UNITS:,} units / ${BILLING_TIER_25K_PRICE_USD}), enterprise ({BILLING_TIER_60K_UNITS:,} units / ${BILLING_TIER_60K_PRICE_USD}).",
            "Pagination is 1-indexed. Default pagesize is 25, maximum is 100.",
            stripe.note,
            "Dedicated billing overview available at /ui/billing/overview. Invoice list available at /ui/billing/invoices.",
        ],
    )
