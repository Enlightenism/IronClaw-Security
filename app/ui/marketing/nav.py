from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel, Field


router = APIRouter(
    prefix="/ui/marketing",
    tags=["marketing-nav"],
)


class MarketingNavBrandView(BaseModel):
    name: str
    tagline: str
    homehref: str


class MarketingNavItemView(BaseModel):
    itemid: str
    label: str
    href: str
    kind: str
    description: str


class MarketingNavGroupView(BaseModel):
    groupid: str
    label: str
    summary: str
    items: list[MarketingNavItemView] = Field(default_factory=list)


class MarketingNavCtaView(BaseModel):
    label: str
    href: str
    style: str


class MarketingNavMobileView(BaseModel):
    triggerlabel: str
    paneltitle: str
    supporttext: str
    quicklinks: list[MarketingNavItemView] = Field(default_factory=list)


class MarketingNavRuleView(BaseModel):
    ruleid: str
    title: str
    description: str


class MarketingNavPageResponse(BaseModel):
    generatedat: str
    environment: str
    brand: MarketingNavBrandView
    topitems: list[MarketingNavItemView] = Field(default_factory=list)
    groups: list[MarketingNavGroupView] = Field(default_factory=list)
    primarycta: MarketingNavCtaView
    secondarycta: MarketingNavCtaView
    mobile: MarketingNavMobileView
    rules: list[MarketingNavRuleView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@router.get("/nav", response_model=MarketingNavPageResponse)
def get_marketing_nav() -> MarketingNavPageResponse:
    topitems = [
        MarketingNavItemView(
            itemid="top-platform",
            label="Platform",
            href="/ui/marketing/platform",
            kind="top-level",
            description="Core platform overview and buyer-facing product narrative.",
        ),
        MarketingNavItemView(
            itemid="top-features",
            label="Features",
            href="/ui/marketing/features",
            kind="top-level",
            description="AI-native security capabilities and runtime-control features.",
        ),
        MarketingNavItemView(
            itemid="top-trust",
            label="Trust",
            href="/ui/marketing/trust",
            kind="top-level",
            description="Trust and security proof for serious evaluators and buyers.",
        ),
        MarketingNavItemView(
            itemid="top-pricing",
            label="Pricing",
            href="/ui/marketing/pricing",
            kind="top-level",
            description="Plan structure and monetization contract for adoption.",
        ),
        MarketingNavItemView(
            itemid="top-docs",
            label="Docs",
            href="/ui/docs/quickstart",
            kind="top-level",
            description="Quickstart and implementation-facing documentation entry point.",
        ),
    ]

    groups = [
        MarketingNavGroupView(
            groupid="group-company",
            label="Why IronClaw",
            summary="Narrative pages that explain the mission, differentiation, and buyer trust story.",
            items=[
                MarketingNavItemView(
                    itemid="why-ironclaw",
                    label="Why IronClaw",
                    href="/ui/marketing/why-ironclaw",
                    kind="group-link",
                    description="Why AI-native runtime defense is needed now.",
                ),
                MarketingNavItemView(
                    itemid="about",
                    label="About",
                    href="/ui/marketing/about",
                    kind="group-link",
                    description="Mission, philosophy, and long-term direction.",
                ),
                MarketingNavItemView(
                    itemid="customers",
                    label="Customers",
                    href="/ui/marketing/customers",
                    kind="group-link",
                    description="Customer stories and proof of buyer adoption.",
                ),
            ],
        ),
        MarketingNavGroupView(
            groupid="group-security",
            label="Security",
            summary="Technical and trust-centered pages for evaluators focused on architecture and controls.",
            items=[
                MarketingNavItemView(
                    itemid="architecture",
                    label="Architecture",
                    href="/ui/marketing/architecture",
                    kind="group-link",
                    description="Security architecture, boundaries, and enforcement model.",
                ),
                MarketingNavItemView(
                    itemid="trust",
                    label="Trust & Security",
                    href="/ui/marketing/trust",
                    kind="group-link",
                    description="Prompt injection, operator risk, and AI trust problems.",
                ),
                MarketingNavItemView(
                    itemid="faq",
                    label="FAQ",
                    href="/ui/marketing/faq",
                    kind="group-link",
                    description="Answers to buyer objections and security questions.",
                ),
            ],
        ),
        MarketingNavGroupView(
            groupid="group-conversion",
            label="Get started",
            summary="Pages that move visitors from interest into evaluation, onboarding, and conversion.",
            items=[
                MarketingNavItemView(
                    itemid="contact-sales",
                    label="Contact Sales",
                    href="/contact-sales",
                    kind="group-link",
                    description="High-intent buyer route for live evaluation.",
                ),
                MarketingNavItemView(
                    itemid="signup",
                    label="Start trial",
                    href="/signup",
                    kind="group-link",
                    description="Self-serve onboarding into a protected workspace.",
                ),
                MarketingNavItemView(
                    itemid="demo-success",
                    label="Demo success",
                    href="/ui/marketing/demo-success",
                    kind="group-link",
                    description="Confirmation state after evaluation request.",
                ),
            ],
        ),
    ]

    primarycta = MarketingNavCtaView(
        label="Request demo",
        href="/contact-sales",
        style="primary",
    )

    secondarycta = MarketingNavCtaView(
        label="Start protected trial",
        href="/signup",
        style="secondary",
    )

    mobile = MarketingNavMobileView(
        triggerlabel="Open navigation",
        paneltitle="Explore IronClaw-Security",
        supporttext="Quick paths for buyers, evaluators, and builders reviewing the platform.",
        quicklinks=[
            MarketingNavItemView(
                itemid="mobile-platform",
                label="Platform",
                href="/ui/marketing/platform",
                kind="mobile-link",
                description="See the full platform overview.",
            ),
            MarketingNavItemView(
                itemid="mobile-features",
                label="Features",
                href="/ui/marketing/features",
                kind="mobile-link",
                description="Review the runtime security capabilities.",
            ),
            MarketingNavItemView(
                itemid="mobile-trust",
                label="Trust",
                href="/ui/marketing/trust",
                kind="mobile-link",
                description="Read the trust and security case.",
            ),
            MarketingNavItemView(
                itemid="mobile-contact",
                label="Request demo",
                href="/contact-sales",
                kind="mobile-link",
                description="Talk to the evaluation team.",
            ),
        ],
    )

    rules = [
        MarketingNavRuleView(
            ruleid="rule-1",
            title="Keep the primary navigation focused",
            description=(
                "The main bar should stay limited to the most valuable destinations so buyers understand the offering without overload."
            ),
        ),
        MarketingNavRuleView(
            ruleid="rule-2",
            title="Use clear and descriptive labels",
            description=(
                "Navigation labels should match what the page contains instead of relying on vague category words."
            ),
        ),
        MarketingNavRuleView(
            ruleid="rule-3",
            title="Keep the structure consistent across pages",
            description=(
                "The same labels, order, and CTA placement should appear throughout the marketing experience."
            ),
        ),
        MarketingNavRuleView(
            ruleid="rule-4",
            title="Support accessibility from the shell outward",
            description=(
                "Navigation should use semantic structure, visible focus states, keyboard support, and predictable behavior on desktop and mobile."
            ),
        ),
        MarketingNavRuleView(
            ruleid="rule-5",
            title="Balance buyer exploration with conversion",
            description=(
                "The shell should help visitors explore trust, platform, and features while always preserving a strong evaluation path."
            ),
        ),
    ]

    return MarketingNavPageResponse(
        generatedat=_utc_now(),
        environment="local",
        brand=MarketingNavBrandView(
            name="IronClaw-Security",
            tagline="Runtime protection for AI systems and the people behind them.",
            homehref="/ui/marketing",
        ),
        topitems=topitems,
        groups=groups,
        primarycta=primarycta,
        secondarycta=secondarycta,
        mobile=mobile,
        rules=rules,
        notes=[
            "Navigation best-practice guidance recommends clear labels, a limited number of top-level items, consistent structure across pages, and ordering by importance. [web:705]",
            "SaaS design guidance emphasizes intuitive navigation, straightforward layouts, and visible call-to-action buttons so users can move through the product story easily. [web:686][web:707]",
            "SaaS navigation structure guidance recommends about five top-level items, grouped secondary links, and menu language that maps to user needs rather than internal jargon. [web:710][web:711][web:708]",
            "Accessible navigation guidance recommends semantic HTML such as nav and lists, keyboard support, predictable submenu behavior, visible focus states, and mobile controls that meet touch-target expectations. [web:709][web:712]",
            "This page is structured as the shared marketing navigation shell contract for the current local-first IronClaw-Security build.",
        ],
    )