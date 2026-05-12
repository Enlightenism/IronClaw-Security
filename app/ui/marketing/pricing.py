from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/marketing",
    tags=["marketing-pricing"],
)


class PricingHeroView(BaseModel):
    badge: str
    title: str
    subtitle: str
    cta_primary_label: str
    cta_primary_href: str
    cta_secondary_label: str
    cta_secondary_href: str


class PricingPlanFeatureView(BaseModel):
    label: str
    included: bool = True
    detail: str | None = None


class PricingPlanView(BaseModel):
    planid: str
    name: str
    tagline: str
    monthlypricecents: int
    annualpricecents: int
    highlighted: bool = False
    audience: str
    cta_label: str
    cta_href: str
    executionlimit: int
    reviewlimit: int
    alertlimit: int
    features: list[PricingPlanFeatureView] = Field(default_factory=list)


class PricingFaqItem(BaseModel):
    question: str
    answer: str


class PricingProofPointView(BaseModel):
    label: str
    value: str
    description: str


class PricingPageResponse(BaseModel):
    generatedat: str
    environment: str
    hero: PricingHeroView
    proofpoints: list[PricingProofPointView] = Field(default_factory=list)
    plans: list[PricingPlanView] = Field(default_factory=list)
    faq: list[PricingFaqItem] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@router.get("/pricing", response_model=PricingPageResponse)
def get_marketing_pricing() -> PricingPageResponse:
    hero = PricingHeroView(
        badge="IronClaw-Security pricing",
        title="Guard AI actions before they become incidents.",
        subtitle=(
            "Choose a plan that matches your runtime volume, review workload, and alerting needs "
            "while keeping high-risk tool calls under strict policy control."
        ),
        cta_primary_label="Start protected trial",
        cta_primary_href="/signup",
        cta_secondary_label="Book live demo",
        cta_secondary_href="/demo",
    )

    proofpoints = [
        PricingProofPointView(
            label="Deployment model",
            value="Local-first or managed",
            description="Start with local guarded execution and expand into team and organization controls.",
        ),
        PricingProofPointView(
            label="Core value",
            value="Guard, review, quarantine, audit",
            description="Monetize the complete runtime safety workflow instead of a single scanner endpoint.",
        ),
        PricingProofPointView(
            label="Best fit",
            value="AI agents and tool-using systems",
            description="Built for teams that need policy enforcement around prompt, tool, and execution risk.",
        ),
    ]

    plans = [
        PricingPlanView(
            planid="starter",
            name="Starter",
            tagline="For solo builders and early product teams.",
            monthlypricecents=9900,
            annualpricecents=95040,
            highlighted=False,
            audience="Indie builders, prototypes, and first guarded deployments",
            cta_label="Start starter trial",
            cta_href="/signup?plan=starter",
            executionlimit=10000,
            reviewlimit=1000,
            alertlimit=2500,
            features=[
                PricingPlanFeatureView(label="10,000 guarded executions per month"),
                PricingPlanFeatureView(label="1,000 manual review items per month"),
                PricingPlanFeatureView(label="2,500 security alerts per month"),
                PricingPlanFeatureView(label="Review queue and audit explorer"),
                PricingPlanFeatureView(label="Single production environment"),
                PricingPlanFeatureView(
                    label="Email and webhook alerts",
                    detail="Basic operational notifications for early deployments.",
                ),
            ],
        ),
        PricingPlanView(
            planid="pro",
            name="Pro",
            tagline="For teams shipping production AI systems.",
            monthlypricecents=29900,
            annualpricecents=287040,
            highlighted=True,
            audience="Growing teams that need full runtime safety workflows",
            cta_label="Start pro trial",
            cta_href="/signup?plan=pro",
            executionlimit=50000,
            reviewlimit=5000,
            alertlimit=10000,
            features=[
                PricingPlanFeatureView(label="50,000 guarded executions per month"),
                PricingPlanFeatureView(label="5,000 manual review items per month"),
                PricingPlanFeatureView(label="10,000 security alerts per month"),
                PricingPlanFeatureView(label="Incidents, quarantine, policy settings, and execution explorer"),
                PricingPlanFeatureView(label="Multiple environments and team roles"),
                PricingPlanFeatureView(
                    label="Priority support and advanced alert routing",
                    detail="Built for active production use and faster response loops.",
                ),
            ],
        ),
        PricingPlanView(
            planid="enterprise",
            name="Enterprise",
            tagline="For large-scale protected AI operations.",
            monthlypricecents=149900,
            annualpricecents=1439040,
            highlighted=False,
            audience="Organizations with large execution volume and strict control requirements",
            cta_label="Talk to sales",
            cta_href="/contact-sales?plan=enterprise",
            executionlimit=250000,
            reviewlimit=25000,
            alertlimit=50000,
            features=[
                PricingPlanFeatureView(label="250,000 guarded executions per month"),
                PricingPlanFeatureView(label="25,000 manual review items per month"),
                PricingPlanFeatureView(label="50,000 security alerts per month"),
                PricingPlanFeatureView(label="Advanced tenant controls and custom policy workflows"),
                PricingPlanFeatureView(label="Dedicated onboarding and architecture support"),
                PricingPlanFeatureView(
                    label="Custom retention, reporting, and integration packages",
                    detail="Designed for regulated or high-volume environments.",
                ),
            ],
        ),
    ]

    faq = [
        PricingFaqItem(
            question="What counts as a guarded execution?",
            answer="A guarded execution is any protected action evaluated through IronClaw before the tool or runtime step is allowed to proceed.",
        ),
        PricingFaqItem(
            question="What happens if we exceed our monthly limits?",
            answer="Usage above plan limits can be blocked, queued for upgrade, or billed as overage depending on the plan and enforcement settings.",
        ),
        PricingFaqItem(
            question="Do all plans include review and audit visibility?",
            answer="Yes, every paid plan includes core review and audit visibility, while higher tiers unlock deeper operational controls.",
        ),
        PricingFaqItem(
            question="Can we start local-first and upgrade later?",
            answer="Yes, the pricing model supports starting with local guarded workflows and expanding into broader team and organization management later.",
        ),
    ]

    return PricingPageResponse(
        generatedat=_utc_now(),
        environment="local",
        hero=hero,
        proofpoints=proofpoints,
        plans=plans,
        faq=faq,
        notes=[
            "Pricing page exposes the monetization contract for guarded execution, review volume, and alert-driven operations.",
            "All values are placeholder UI contract data for the current local-first Gen1 build.",
            "This page is ready to be wired to live signup, billing checkout, and sales handoff flows.",
        ],
    )