from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel, Field


router = APIRouter(
    prefix="/ui/marketing",
    tags=["marketing-demo-success"],
)


class DemoSuccessHeroView(BaseModel):
    eyebrow: str
    title: str
    subtitle: str
    statuslabel: str


class DemoSuccessProofStatView(BaseModel):
    statid: str
    value: str
    label: str
    context: str
    source: str


class DemoSuccessStepView(BaseModel):
    stepid: str
    title: str
    description: str


class DemoSuccessResourceView(BaseModel):
    resourceid: str
    title: str
    description: str
    href: str
    kind: str


class DemoSuccessExpectationView(BaseModel):
    itemid: str
    title: str
    description: str


class DemoSuccessPageResponse(BaseModel):
    generatedat: str
    environment: str
    hero: DemoSuccessHeroView
    proofstats: list[DemoSuccessProofStatView] = Field(default_factory=list)
    nextsteps: list[DemoSuccessStepView] = Field(default_factory=list)
    resources: list[DemoSuccessResourceView] = Field(default_factory=list)
    expectations: list[DemoSuccessExpectationView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@router.get("/demo-success", response_model=DemoSuccessPageResponse)
def get_marketing_demo_success() -> DemoSuccessPageResponse:
    hero = DemoSuccessHeroView(
        eyebrow="Demo requested",
        title="Your IronClaw evaluation is in motion.",
        subtitle=(
            "Your request has been received. This page confirms the next step in a serious security conversation about "
            "prompt injection, unsafe agent autonomy, tool-connected risk, and how IronClaw-Security can protect real users and machines."
        ),
        statuslabel="Request confirmed",
    )

    proofstats = [
        DemoSuccessProofStatView(
            statid="thank-you-purpose",
            value="Core",
            label="Post-conversion pages should confirm, reassure, and guide next steps",
            context=(
                "B2B and SaaS guidance consistently recommends that thank-you pages confirm successful submission, "
                "set expectations, and keep high-intent prospects engaged with relevant next actions."
            ),
            source="Productive Shop and Incredo guidance",
        ),
        DemoSuccessProofStatView(
            statid="high-intent",
            value="High-intent",
            label="Demo request pages capture bottom-of-funnel buyers",
            context=(
                "Demo request pages are positioned for prospects who have already evaluated alternatives and want a closer look."
            ),
            source="Genesys Growth demo request page guide",
        ),
        DemoSuccessProofStatView(
            statid="next-step",
            value="Required",
            label="Clear follow-up improves conversion momentum",
            context=(
                "Best-practice demo experiences set a clear next action, such as a follow-up call, proof-of-concept step, or prep guidance."
            ),
            source="Demostack and SaaS conversion guidance",
        ),
        DemoSuccessProofStatView(
            statid="conversion-lift",
            value="5x-10x",
            label="Demo leads often convert better than non-demo leads",
            context=(
                "SaaS funnel analysis reports that demo leads can convert at materially higher rates than those who never request a demo."
            ),
            source="SaaS Funnel Lab research summary",
        ),
    ]

    nextsteps = [
        DemoSuccessStepView(
            stepid="step-1",
            title="We review your request",
            description=(
                "The IronClaw team reviews your role, AI use case, security concerns, and environment details so the conversation starts with your real threat surface."
            ),
        ),
        DemoSuccessStepView(
            stepid="step-2",
            title="We prepare a risk-relevant walkthrough",
            description=(
                "Your evaluation is tailored around prompt injection, runtime policy enforcement, review, quarantine, and the exact places your AI system touches tools or user machines."
            ),
        ),
        DemoSuccessStepView(
            stepid="step-3",
            title="We align on next adoption steps",
            description=(
                "If there is a fit, the outcome is a clear path forward for technical evaluation, buyer review, and secure rollout."
            ),
        ),
    ]

    resources = [
        DemoSuccessResourceView(
            resourceid="resource-1",
            title="Trust and security",
            description="Read how IronClaw approaches prompt injection, excessive agency, and AI-native runtime protection.",
            href="/ui/marketing/trust",
            kind="internal",
        ),
        DemoSuccessResourceView(
            resourceid="resource-2",
            title="Security features",
            description="Review the product capabilities buyers use to evaluate real control instead of AI safety claims.",
            href="/ui/marketing/features",
            kind="internal",
        ),
        DemoSuccessResourceView(
            resourceid="resource-3",
            title="Docs quickstart",
            description="See the operational path from protected onboarding to your first guarded execution flow.",
            href="/ui/docs/quickstart",
            kind="internal",
        ),
        DemoSuccessResourceView(
            resourceid="resource-4",
            title="Customer stories",
            description="Explore the kinds of teams that move to IronClaw when AI risk becomes operationally real.",
            href="/ui/marketing/customers",
            kind="internal",
        ),
    ]

    expectations = [
        DemoSuccessExpectationView(
            itemid="expectation-1",
            title="No generic sales motion",
            description=(
                "This is not meant to feel like a standard software pitch. The evaluation should focus on the AI risk your team is actually carrying."
            ),
        ),
        DemoSuccessExpectationView(
            itemid="expectation-2",
            title="Security-first conversation",
            description=(
                "The most important discussion points are prompt injection, unsafe actions, user-machine exposure, runtime policy, and operational trust."
            ),
        ),
        DemoSuccessExpectationView(
            itemid="expectation-3",
            title="Buyer-grade clarity",
            description=(
                "You should leave the conversation understanding what IronClaw controls, what it helps prevent, and why that matters before AI gets more autonomy in your environment."
            ),
        ),
    ]

    return DemoSuccessPageResponse(
        generatedat=_utc_now(),
        environment="local",
        hero=hero,
        proofstats=proofstats,
        nextsteps=nextsteps,
        resources=resources,
        expectations=expectations,
        notes=[
            "Thank-you pages are recommended because they confirm successful submission, show appreciation, and keep high-intent visitors engaged with next steps and relevant resources. [web:663][web:667]",
            "Genesys Growth says demo request pages target bottom-of-funnel visitors who have already evaluated alternatives and decided the product deserves a closer look. [web:664]",
            "Demostack recommends ending demo flows with a clear next step such as follow-up scheduling or progression toward deeper evaluation. [web:668]",
            "SaaS Funnel Lab reports that demo-request leads can convert at 5x to 10x the rate of leads who do not go through a demo request flow. [web:665]",
            "This page is structured as a premium post-conversion confirmation surface for IronClaw-Security and is ready to connect to scheduling, CRM, and lifecycle follow-up flows.",
        ],
    )