from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel, Field


router = APIRouter(
    prefix="/ui/marketing",
    tags=["marketing-home"],
)


class HomeHeroView(BaseModel):
    eyebrow: str
    title: str
    subtitle: str
    primaryctalabel: str
    primaryctahref: str
    secondaryctalabel: str
    secondaryctahref: str
    trustline: str


class HomeProofStatView(BaseModel):
    statid: str
    value: str
    label: str
    context: str
    source: str


class HomeSectionLinkView(BaseModel):
    sectionid: str
    title: str
    summary: str
    href: str
    emphasis: str


class HomeNavigationView(BaseModel):
    label: str
    href: str
    style: str


class HomePageResponse(BaseModel):
    generatedat: str
    environment: str
    route: str
    hero: HomeHeroView
    navigation: list[HomeNavigationView] = Field(default_factory=list)
    proofstats: list[HomeProofStatView] = Field(default_factory=list)
    sections: list[HomeSectionLinkView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@router.get("", response_model=HomePageResponse)
@router.get("/", response_model=HomePageResponse)
def get_marketing_home() -> HomePageResponse:
    hero = HomeHeroView(
        eyebrow="IronClaw-Security",
        title="Stop dangerous AI actions before they reach the user's machine.",
        subtitle=(
            "IronClaw-Security is an AI-native runtime protection platform for prompt injection, unsafe tool use, "
            "excessive agent autonomy, hostile external content, and the hidden trust failures that happen when AI systems "
            "are connected to files, browsers, APIs, workflows, and real machines."
        ),
        primaryctalabel="Request live demo",
        primaryctahref="/contact-sales",
        secondaryctalabel="Explore platform",
        secondaryctahref="/ui/marketing/platform",
        trustline="Built for teams who know AI safety claims are not the same thing as runtime control.",
    )

    navigation = [
        HomeNavigationView(label="Platform", href="/ui/marketing/platform", style="primary"),
        HomeNavigationView(label="Features", href="/ui/marketing/features", style="primary"),
        HomeNavigationView(label="Trust", href="/ui/marketing/trust", style="primary"),
        HomeNavigationView(label="Architecture", href="/ui/marketing/architecture", style="secondary"),
        HomeNavigationView(label="Customers", href="/ui/marketing/customers", style="secondary"),
        HomeNavigationView(label="Pricing", href="/ui/marketing/pricing", style="secondary"),
        HomeNavigationView(label="FAQ", href="/ui/marketing/faq", style="secondary"),
        HomeNavigationView(label="Request demo", href="/contact-sales", style="cta"),
    ]

    proofstats = [
        HomeProofStatView(
            statid="prompt-injection-rank",
            value="LLM01",
            label="Prompt injection is the top-ranked LLM application risk",
            context=(
                "OWASP identifies prompt injection as LLM01 and warns it can lead to unauthorized access, "
                "sensitive data disclosure, arbitrary command execution, and manipulated decisions."
            ),
            source="OWASP GenAI Security Project",
        ),
        HomeProofStatView(
            statid="security-concern",
            value="92%",
            label="Security teams are concerned about AI agents in the workforce",
            context=(
                "Darktrace reports that 92% of security professionals are concerned about the impact of AI agents on security."
            ),
            source="Darktrace State of AI Cybersecurity 2026",
        ),
        HomeProofStatView(
            statid="buyer-trust",
            value="Proof-first",
            label="Enterprise homepages convert better when trust and evidence appear early",
            context=(
                "B2B homepage guidance recommends showing trust elements and evidence near the top so buyers understand why the vendor is credible."
            ),
            source="Forbes B2B homepage guidance",
        ),
        HomeProofStatView(
            statid="zero-click",
            value="Zero-click",
            label="Prompt injection can trigger compromise without user action",
            context=(
                "A 2026 enterprise AI security writeup described a zero-click prompt-injection path that enabled data compromise and unauthorized commands from upstream content."
            ),
            source="Doeren Mayhew enterprise AI prompt injection analysis",
        ),
    ]

    sections = [
        HomeSectionLinkView(
            sectionid="section-1",
            title="Platform overview",
            summary=(
                "See how IronClaw acts as a runtime security and governance platform for AI systems connected to tools, content, and real environments."
            ),
            href="/ui/marketing/platform",
            emphasis="core",
        ),
        HomeSectionLinkView(
            sectionid="section-2",
            title="Security features",
            summary=(
                "Review the capabilities that allow, review, quarantine, and block risky AI actions before they execute."
            ),
            href="/ui/marketing/features",
            emphasis="core",
        ),
        HomeSectionLinkView(
            sectionid="section-3",
            title="Trust and security",
            summary=(
                "Understand why prompt injection, excessive agency, and operator risk make AI trust a first-order security problem."
            ),
            href="/ui/marketing/trust",
            emphasis="core",
        ),
        HomeSectionLinkView(
            sectionid="section-4",
            title="Security architecture",
            summary=(
                "Explore the policy, boundary, review, and audit model behind IronClaw's protection approach."
            ),
            href="/ui/marketing/architecture",
            emphasis="supporting",
        ),
        HomeSectionLinkView(
            sectionid="section-5",
            title="Why IronClaw",
            summary=(
                "Read the case for AI-native runtime defense instead of relying on generic legacy security approaches."
            ),
            href="/ui/marketing/why-ironclaw",
            emphasis="supporting",
        ),
        HomeSectionLinkView(
            sectionid="section-6",
            title="Customer stories",
            summary=(
                "See why teams adopt IronClaw when AI moves from internal experimentation to operational exposure."
            ),
            href="/ui/marketing/customers",
            emphasis="supporting",
        ),
        HomeSectionLinkView(
            sectionid="section-7",
            title="Quickstart docs",
            summary=(
                "Move from interest to implementation with the onboarding and protected runtime quickstart flow."
            ),
            href="/ui/docs/quickstart",
            emphasis="supporting",
        ),
        HomeSectionLinkView(
            sectionid="section-8",
            title="Talk to sales",
            summary=(
                "Start a serious buyer conversation about prompt injection, user-machine exposure, and secure AI rollout."
            ),
            href="/contact-sales",
            emphasis="conversion",
        ),
    ]

    return HomePageResponse(
        generatedat=_utc_now(),
        environment="local",
        route="/ui/marketing",
        hero=hero,
        navigation=navigation,
        proofstats=proofstats,
        sections=sections,
        notes=[
            "Modern SaaS homepage guidance emphasizes sharp, category-specific hero copy, modular proof sections, and minimal decorative filler so complex products stay clear. [web:695]",
            "High-converting SaaS homepages increasingly use interactive or structured product storytelling above the fold and place trust architecture elements early for enterprise buyers. [web:697][web:698][web:702]",
            "B2B homepage guidance recommends integrating trust and evidence near the top of the page so buyers quickly understand why a vendor is credible. [web:701][web:703]",
            "OWASP identifies prompt injection as the top LLM risk and says it can enable unauthorized access, arbitrary command execution, sensitive disclosure, and manipulated decisions. [web:586]",
            "A 2026 enterprise AI security analysis described a zero-click prompt-injection scenario where upstream content led to protected-data compromise and unauthorized commands without employee action. [web:700]",
            "This page serves as the primary marketing homepage router payload for the current local-first IronClaw-Security build.",
        ],
    )