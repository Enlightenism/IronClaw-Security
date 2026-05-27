from __future__ import annotations

from datetime import UTC, datetime, timedelta
import math

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/billing",
    tags=["billing-plan-change"],
)

_BILLING_DAY_OF_MONTH = 10
_DAYS_IN_BILLING_PERIOD = 30

_PLAN_PRICES_CENTS: dict[str, int] = {
    "starter": 9_900,
    "pro": 29_900,
    "enterprise": 149_900,
}

_PLAN_TIER_ORDER: dict[str, int] = {
    "starter": 0,
    "pro": 1,
    "enterprise": 2,
}


class BillingCurrencyAmountView(BaseModel):
    currency: str
    amountcents: int
    displayamount: str


class BillingPlanOptionView(BaseModel):
    planid: str
    name: str
    tier: str
    monthlypricecents: BillingCurrencyAmountView
    includedunits: dict[str, int]
    features: list[str] = Field(default_factory=list)
    recommended: bool
    iscurrent: bool


class BillingPlanChangePreviewView(BaseModel):
    fromplan: str
    toplan: str
    direction: str
    proratedcreditcents: BillingCurrencyAmountView
    proratedchargecents: BillingCurrencyAmountView
    netchangecents: BillingCurrencyAmountView
    effectivedate: str
    warningflags: list[str] = Field(default_factory=list)


class BillingPlanChangeResponse(BaseModel):
    generatedat: str
    environment: str
    currentplan: BillingPlanOptionView
    availableplans: list[BillingPlanOptionView] = Field(default_factory=list)
    changepreviews: list[BillingPlanChangePreviewView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class BillingPlanChangeNotFoundResponse(BaseModel):
    status: str
    requestedplan: str
    message: str
    generatedat: str
    environment: str


def _usd(amountcents: int) -> BillingCurrencyAmountView:
    sign = "-" if amountcents < 0 else ""
    abs_cents = abs(amountcents)
    dollars = abs_cents / 100
    return BillingCurrencyAmountView(
        currency="USD",
        amountcents=amountcents,
        displayamount=f"{sign}${dollars:,.2f}",
    )


def _next_day_iso(current_day: int) -> str:
    now = datetime.now(UTC)
    base = now.replace(day=current_day, hour=0, minute=0, second=0, microsecond=0)
    next_day = base + timedelta(days=1)
    return next_day.isoformat()


def _days_remaining_in_period(current_day: int) -> int:
    remaining = _BILLING_DAY_OF_MONTH - current_day
    if remaining <= 0:
        remaining = _DAYS_IN_BILLING_PERIOD + remaining
    return max(remaining, 1)


def _prorated_cents(pricecents: int, days_remaining: int) -> int:
    daily_rate = pricecents / _DAYS_IN_BILLING_PERIOD
    return math.ceil(daily_rate * days_remaining)


def _change_direction(from_tier: str, to_tier: str) -> str:
    from_order = _PLAN_TIER_ORDER[from_tier]
    to_order = _PLAN_TIER_ORDER[to_tier]
    if to_order > from_order:
        return "upgrade"
    if to_order < from_order:
        return "downgrade"
    return "lateral"


def _downgrade_warning_flags(
    from_tier: str,
    to_tier: str,
    current_usage: dict[str, int],
    to_plan: BillingPlanOptionView,
) -> list[str]:
    flags: list[str] = []
    for metric, included in to_plan.includedunits.items():
        current = current_usage.get(metric, 0)
        if current > included:
            overage = current - included
            flags.append(f"Current {metric} usage ({current:,}) exceeds {to_tier} plan included units " f"({included:,}). Overage of {overage:,} units will incur charges immediately.")
    if _PLAN_TIER_ORDER[from_tier] > _PLAN_TIER_ORDER[to_tier]:
        flags.append("Downgrading removes access to higher-tier features. Review feature compatibility " "before confirming this change.")
        flags.append("Active security policies, guardrail rules, and audit configurations exceeding " f"{to_tier} plan limits will be suspended at the effective date.")
    return flags


def _build_plan_catalog() -> dict[str, BillingPlanOptionView]:
    return {
        "starter": BillingPlanOptionView(
            planid="plan-starter",
            name="Starter",
            tier="starter",
            monthlypricecents=_usd(_PLAN_PRICES_CENTS["starter"]),
            includedunits={
                "guardedexecutions": 10_000,
                "manualreviews": 1_000,
                "securityalerts": 2_500,
                "agents": 3,
                "policies": 10,
            },
            features=[
                "Prompt injection detection",
                "Basic tool call guardrails",
                "Audit log (30-day retention)",
                "3 agents",
                "10 security policies",
                "Email support",
            ],
            recommended=False,
            iscurrent=False,
        ),
        "pro": BillingPlanOptionView(
            planid="plan-pro",
            name="Pro",
            tier="pro",
            monthlypricecents=_usd(_PLAN_PRICES_CENTS["pro"]),
            includedunits={
                "guardedexecutions": 50_000,
                "manualreviews": 5_000,
                "securityalerts": 10_000,
                "agents": 20,
                "policies": 100,
            },
            features=[
                "All Starter features",
                "Advanced prompt injection + data exfiltration detection",
                "Full MCP tool call policy enforcement",
                "Sandboxed execution environments",
                "Audit log (1-year retention)",
                "Review workflows and approval queues",
                "20 agents",
                "100 security policies",
                "Priority support",
            ],
            recommended=True,
            iscurrent=False,
        ),
        "enterprise": BillingPlanOptionView(
            planid="plan-enterprise",
            name="Enterprise",
            tier="enterprise",
            monthlypricecents=_usd(_PLAN_PRICES_CENTS["enterprise"]),
            includedunits={
                "guardedexecutions": 250_000,
                "manualreviews": 25_000,
                "securityalerts": 50_000,
                "agents": -1,
                "policies": -1,
            },
            features=[
                "All Pro features",
                "Unlimited agents and security policies",
                "Custom guardrail rule authoring",
                "SIEM and SOC integrations",
                "Dedicated telemetry pipeline",
                "Trust collapse detection and automated containment",
                "SLA-backed response time",
                "Audit log (unlimited retention)",
                "Dedicated security engineering support",
                "SSO and RBAC",
            ],
            recommended=False,
            iscurrent=False,
        ),
    }


_SAMPLE_CURRENT_PLAN = "pro"

_SAMPLE_CURRENT_USAGE: dict[str, int] = {
    "guardedexecutions": 18_340,
    "manualreviews": 1_220,
    "securityalerts": 3_870,
    "agents": 7,
    "policies": 34,
}


def _sample_current_day() -> int:
    return datetime.now(UTC).day


def _build_preview(
    from_tier: str,
    to_tier: str,
    catalog: dict[str, BillingPlanOptionView],
    current_usage: dict[str, int],
    current_day: int,
) -> BillingPlanChangePreviewView:
    days_remaining = _days_remaining_in_period(current_day)

    from_price = _PLAN_PRICES_CENTS[from_tier]
    to_price = _PLAN_PRICES_CENTS[to_tier]

    credit_cents = _prorated_cents(from_price, days_remaining)
    charge_cents = _prorated_cents(to_price, days_remaining)
    net_cents = charge_cents - credit_cents

    direction = _change_direction(from_tier, to_tier)

    effective_date = _next_day_iso(current_day)

    flags: list[str] = []
    if direction == "downgrade":
        flags = _downgrade_warning_flags(
            from_tier,
            to_tier,
            current_usage,
            catalog[to_tier],
        )
    elif direction == "upgrade":
        flags = [
            f"Upgrade to {to_tier} takes effect immediately at the effective date.",
            "New plan limits and features are available instantly after confirmation.",
        ]

    return BillingPlanChangePreviewView(
        fromplan=from_tier,
        toplan=to_tier,
        direction=direction,
        proratedcreditcents=_usd(credit_cents),
        proratedchargecents=_usd(charge_cents),
        netchangecents=_usd(net_cents),
        effectivedate=effective_date,
        warningflags=flags,
    )


_VALID_PLAN_IDS: frozenset[str] = frozenset(_PLAN_PRICES_CENTS.keys())


@router.get(
    "/plan-change",
    response_model=BillingPlanChangeResponse | BillingPlanChangeNotFoundResponse,
)
def get_plan_change(
    currentplan: str = _SAMPLE_CURRENT_PLAN,
) -> BillingPlanChangeResponse | BillingPlanChangeNotFoundResponse:
    if currentplan not in _VALID_PLAN_IDS:
        return BillingPlanChangeNotFoundResponse(
            status="not_found",
            requestedplan=currentplan,
            message=(f"Plan '{currentplan}' is not a recognized IronClaw plan. " "Valid values are: starter, pro, enterprise."),
            generatedat=datetime.now(UTC).isoformat(),
            environment="local",
        )

    current_day = _sample_current_day()
    catalog = _build_plan_catalog()

    current_plan_view = catalog[currentplan].model_copy(update={"iscurrent": True})

    available = [
        catalog[tier].model_copy(
            update={
                "iscurrent": tier == currentplan,
                "recommended": tier == "pro" and currentplan != "pro",
            }
        )
        for tier in ("starter", "pro", "enterprise")
        if tier != currentplan
    ]

    previews: list[BillingPlanChangePreviewView] = []

    tier_order = _PLAN_TIER_ORDER[currentplan]

    for tier in ("starter", "pro", "enterprise"):
        if tier == currentplan:
            continue
        preview = _build_preview(
            from_tier=currentplan,
            to_tier=tier,
            catalog=catalog,
            current_usage=_SAMPLE_CURRENT_USAGE,
            current_day=current_day,
        )
        previews.append(preview)

    previews.sort(key=lambda p: _PLAN_TIER_ORDER[p.toplan], reverse=(tier_order == 2))

    days_remaining = _days_remaining_in_period(current_day)

    return BillingPlanChangeResponse(
        generatedat=datetime.now(UTC).isoformat(),
        environment="local",
        currentplan=current_plan_view,
        availableplans=available,
        changepreviews=previews,
        notes=[
            f"Current plan is '{currentplan}'. Proration is calculated on {days_remaining} days " f"remaining in the current {_DAYS_IN_BILLING_PERIOD}-day billing period.",
            "Prorated credit is the unused portion of the current plan refunded at change time.",
            "Prorated charge is the cost of the new plan for the remainder of the current period.",
            "Net change = prorated charge minus prorated credit. Negative values indicate a net credit.",
            "Downgrade warnings reflect current usage against the target plan's included unit limits.",
            "All values are placeholder UI contract data for the local-first Gen1 build.",
            "This page is ready to be wired to a live billing provider and metering pipeline.",
        ],
    )
