from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/marketing",
    tags=["marketing-layout"],
)


class MarketingLayoutHeroView(BaseModel):
    eyebrow: str
    title: str
    subtitle: str
    primaryctalabel: str
    primaryctahref: str
    secondaryctalabel: str
    secondaryctahref: str


class MarketingLayoutTokenView(BaseModel):
    tokenid: str
    category: str
    name: str
    value: str
    purpose: str


class MarketingSectionView(BaseModel):
    sectionid: str
    title: str
    summary: str
    blocks: list[str] = Field(default_factory=list)


class MarketingPrincipleView(BaseModel):
    principleid: str
    title: str
    description: str


class MarketingNavItemView(BaseModel):
    itemid: str
    label: str
    href: str
    emphasis: str


class MarketingLayoutPageResponse(BaseModel):
    generatedat: str
    environment: str
    hero: MarketingLayoutHeroView
    navigation: list[MarketingNavItemView] = Field(default_factory=list)
    tokens: list[MarketingLayoutTokenView] = Field(default_factory=list)
    sections: list[MarketingSectionView] = Field(default_factory=list)
    principles: list[MarketingPrincipleView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@router.get("/layout", response_model=MarketingLayoutPageResponse)
def get_marketing_layout() -> MarketingLayoutPageResponse:
    hero = MarketingLayoutHeroView(
        eyebrow="Marketing layout system",
        title="A design system for premium AI-security storytelling and buyer trust.",
        subtitle=("This layout model defines the shared navigation, spacing, hierarchy, tokens, and content rhythm for the IronClaw-Security marketing experience so every page feels consistent, modern, high-conviction, and enterprise ready."),
        primaryctalabel="See platform overview",
        primaryctahref="/ui/marketing/platform",
        secondaryctalabel="Contact sales",
        secondaryctahref="/contact-sales",
    )

    navigation = [
        MarketingNavItemView(
            itemid="nav-1",
            label="Platform",
            href="/ui/marketing/platform",
            emphasis="primary",
        ),
        MarketingNavItemView(
            itemid="nav-2",
            label="Features",
            href="/ui/marketing/features",
            emphasis="primary",
        ),
        MarketingNavItemView(
            itemid="nav-3",
            label="Trust",
            href="/ui/marketing/trust",
            emphasis="primary",
        ),
        MarketingNavItemView(
            itemid="nav-4",
            label="Architecture",
            href="/ui/marketing/architecture",
            emphasis="secondary",
        ),
        MarketingNavItemView(
            itemid="nav-5",
            label="Customers",
            href="/ui/marketing/customers",
            emphasis="secondary",
        ),
        MarketingNavItemView(
            itemid="nav-6",
            label="Pricing",
            href="/ui/marketing/pricing",
            emphasis="secondary",
        ),
        MarketingNavItemView(
            itemid="nav-7",
            label="FAQ",
            href="/ui/marketing/faq",
            emphasis="secondary",
        ),
        MarketingNavItemView(
            itemid="nav-8",
            label="Request demo",
            href="/contact-sales",
            emphasis="cta",
        ),
    ]

    tokens = [
        MarketingLayoutTokenView(
            tokenid="token-1",
            category="color",
            name="canvas",
            value="graphite-black / deep-iron gradient",
            purpose="Creates a premium high-trust foundation with futuristic depth.",
        ),
        MarketingLayoutTokenView(
            tokenid="token-2",
            category="color",
            name="signal",
            value="electric-cyan",
            purpose="Used sparingly for high-value emphasis, trust indicators, and interactive focus states.",
        ),
        MarketingLayoutTokenView(
            tokenid="token-3",
            category="color",
            name="alert",
            value="threat-amber",
            purpose="Reserved for risk, warning, and threat-surface storytelling blocks.",
        ),
        MarketingLayoutTokenView(
            tokenid="token-4",
            category="typography",
            name="display",
            value="high-contrast futuristic headline scale",
            purpose="Used for hero statements, page titles, and premium differentiation moments.",
        ),
        MarketingLayoutTokenView(
            tokenid="token-5",
            category="typography",
            name="body",
            value="clean enterprise sans",
            purpose="Supports dense information, scannability, and buyer-grade readability.",
        ),
        MarketingLayoutTokenView(
            tokenid="token-6",
            category="spacing",
            name="section-spacing",
            value="80px to 144px vertical rhythm",
            purpose="Creates breathing room and makes high-conviction sections feel premium instead of crowded.",
        ),
        MarketingLayoutTokenView(
            tokenid="token-7",
            category="surface",
            name="glass-panel",
            value="translucent dark layered card",
            purpose="Used for proof stats, customer blocks, architecture layers, and conversion panels.",
        ),
        MarketingLayoutTokenView(
            tokenid="token-8",
            category="motion",
            name="micro-motion",
            value="subtle elevation, glow, and reveal",
            purpose="Reinforces a futuristic feel without looking gimmicky or unstable.",
        ),
    ]

    sections = [
        MarketingSectionView(
            sectionid="section-1",
            title="Hero shell",
            summary=("Every major page begins with a conviction-driven hero that explains the stakes, names the threat, and gives the buyer a clear next step."),
            blocks=[
                "Eyebrow label",
                "Premium headline",
                "Security-focused supporting copy",
                "Primary CTA and secondary CTA",
                "Optional proof strip or trust stat cluster",
            ],
        ),
        MarketingSectionView(
            sectionid="section-2",
            title="Proof layer",
            summary=("Buyers need evidence quickly, so pages should surface trusted stats, standards, or operational proof early."),
            blocks=[
                "Threat statistics",
                "Standards-based trust references",
                "Runtime-control proof cards",
                "Audit and review evidence highlights",
            ],
        ),
        MarketingSectionView(
            sectionid="section-3",
            title="Narrative grid",
            summary=("The middle of each page should explain what is dangerous, why it matters, and how IronClaw changes the outcome."),
            blocks=[
                "Threat explanation panels",
                "Feature capability cards",
                "Comparison rows",
                "Customer outcome narratives",
            ],
        ),
        MarketingSectionView(
            sectionid="section-4",
            title="Decision support layer",
            summary=("Each page should make it easier for a serious buyer to continue the evaluation without hunting for context."),
            blocks=[
                "FAQs",
                "Architecture steps",
                "Evaluation expectations",
                "Related page links",
            ],
        ),
        MarketingSectionView(
            sectionid="section-5",
            title="Conversion footer",
            summary=("The page should end with clarity, not drift, using one strong final CTA oriented around demo, trust review, or buyer action."),
            blocks=[
                "Single conversion-focused CTA",
                "Short trust reinforcement line",
                "Optional contact or next-step link",
            ],
        ),
    ]

    principles = [
        MarketingPrincipleView(
            principleid="principle-1",
            title="Lead with risk and value immediately",
            description=("Landing and marketing experiences work best when the visitor understands who the product is for, what problem it solves, and why it matters within seconds."),
        ),
        MarketingPrincipleView(
            principleid="principle-2",
            title="Use reusable systems, not page-by-page improvisation",
            description=("Scalable SaaS experiences depend on repeatable layout patterns, consistent tokens, and modular content blocks."),
        ),
        MarketingPrincipleView(
            principleid="principle-3",
            title="Maintain clear hierarchy and uncluttered structure",
            description=("Strong B2B pages reduce clutter, emphasize the most important message, and guide the eye with spacing and content order."),
        ),
        MarketingPrincipleView(
            principleid="principle-4",
            title="Make accessibility part of the visual system",
            description=("Readable contrast, operable controls, understandable structure, and robust layouts are core to trust, not optional polish."),
        ),
        MarketingPrincipleView(
            principleid="principle-5",
            title="Feel futuristic without becoming generic AI design",
            description=("The layout should feel advanced and premium while staying disciplined, readable, and enterprise credible."),
        ),
    ]

    return MarketingLayoutPageResponse(
        generatedat=_utc_now(),
        environment="local",
        hero=hero,
        navigation=navigation,
        tokens=tokens,
        sections=sections,
        principles=principles,
        notes=[
            "SaaS UX guidance says users decide quickly whether to engage, so pages should immediately communicate who the product is for, what problem it solves, and why it matters. [web:685]",
            "Design guidance for scalable SaaS systems emphasizes reusable components, layout systems, modular architecture, and consistency across touchpoints. [web:685][web:686][web:689][web:692]",
            "B2B SaaS site guidance stresses clear hierarchy, uncluttered structure, simple navigation, and strong spacing to help visitors scan and understand the message. [web:690][web:693]",
            "Accessibility guidance says interfaces should be perceivable, operable, understandable, and robust, with readable contrast, large targets, and layouts that respond well to zoom and varied user needs. [web:694][web:691]",
            "This page is structured as the shared design-system and layout contract for the IronClaw-Security marketing UI in the current local-first Gen1 build.",
        ],
    )
