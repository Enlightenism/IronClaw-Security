from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel, Field


router = APIRouter(
    prefix="/ui/marketing",
    tags=["marketing-about"],
)


class AboutHeroView(BaseModel):
    eyebrow: str
    title: str
    subtitle: str
    primaryctalabel: str
    primaryctahref: str
    secondaryctalabel: str
    secondaryctahref: str


class AboutBeliefView(BaseModel):
    beliefid: str
    title: str
    description: str


class AboutMissionView(BaseModel):
    title: str
    statement: str
    supportingpoints: list[str] = Field(default_factory=list)


class AboutProofStatView(BaseModel):
    statid: str
    value: str
    label: str
    context: str
    source: str


class AboutPillarView(BaseModel):
    pillarid: str
    title: str
    summary: str
    bullets: list[str] = Field(default_factory=list)


class AboutPrincipleView(BaseModel):
    principleid: str
    title: str
    description: str


class AboutFutureView(BaseModel):
    title: str
    description: str


class AboutPageResponse(BaseModel):
    generatedat: str
    environment: str
    hero: AboutHeroView
    mission: AboutMissionView
    beliefs: list[AboutBeliefView] = Field(default_factory=list)
    proofstats: list[AboutProofStatView] = Field(default_factory=list)
    pillars: list[AboutPillarView] = Field(default_factory=list)
    principles: list[AboutPrincipleView] = Field(default_factory=list)
    future: AboutFutureView
    notes: list[str] = Field(default_factory=list)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@router.get("/about", response_model=AboutPageResponse)
def get_marketing_about() -> AboutPageResponse:
    hero = AboutHeroView(
        eyebrow="About IronClaw",
        title="We are building the trust layer AI systems should have had from the beginning.",
        subtitle=(
            "IronClaw-Security exists because the world moved from using AI as a text interface to connecting it with "
            "files, browsers, tools, workflows, and real machines faster than most people understood the risk."
        ),
        primaryctalabel="Talk to our team",
        primaryctahref="/contact-sales",
        secondaryctalabel="Read trust and security",
        secondaryctahref="/ui/marketing/trust",
    )

    mission = AboutMissionView(
        title="Mission",
        statement=(
            "Protect people, teams, and machines from unsafe AI behavior by making prompt injection, autonomous misuse, "
            "and tool-connected risk visible, enforceable, and stoppable before damage is done."
        ),
        supportingpoints=[
            "Protect the operator, not just the model.",
            "Treat external AI context as untrusted by default.",
            "Prefer safe friction over silent compromise.",
            "Keep evolving as AI threats evolve.",
        ],
    )

    beliefs = [
        AboutBeliefView(
            beliefid="belief-1",
            title="AI trust is being granted too cheaply",
            description=(
                "People sign into AI platforms, connect tools, upload files, and delegate actions long before they know "
                "what protections truly exist between the model and their machine."
            ),
        ),
        AboutBeliefView(
            beliefid="belief-2",
            title="The real risk surface is bigger than most buyers realize",
            description=(
                "Prompt injection is only one part of the problem. The deeper issue is what happens when manipulated AI "
                "behavior reaches tools, browsers, credentials, file systems, or automated workflows."
            ),
        ),
        AboutBeliefView(
            beliefid="belief-3",
            title="Legacy security was not designed for agentic AI",
            description=(
                "Traditional controls were built for endpoints, applications, and networks, not models that interpret "
                "untrusted context and immediately turn output into actions."
            ),
        ),
    ]

    proofstats = [
        AboutProofStatView(
            statid="trustworthy-ai",
            value="7",
            label="NIST defines seven core characteristics of trustworthy AI",
            context=(
                "NIST says trustworthy AI should be valid and reliable, safe, secure and resilient, accountable and "
                "transparent, explainable and interpretable, privacy enhanced, and fair with harmful bias managed."
            ),
            source="NIST AI RMF 1.0",
        ),
        AboutProofStatView(
            statid="prompt-injection-rank",
            value="#1",
            label="Prompt injection is OWASP's top 2025 LLM risk",
            context=(
                "OWASP places prompt injection at LLM01 and warns that it can lead to sensitive information disclosure, "
                "unauthorized function access, arbitrary command execution, and manipulated decisions."
            ),
            source="OWASP GenAI Security Project",
        ),
        AboutProofStatView(
            statid="agent-security-shift",
            value="New class",
            label="AI agent security now requires controls beyond traditional app security",
            context=(
                "Recent AI agent security analysis highlights prompt injection, token compromise, excessive privilege, "
                "shadow deployments, and data exfiltration as distinct risks in autonomous systems."
            ),
            source="AI agent security landscape analysis",
        ),
        AboutProofStatView(
            statid="isolation-pattern",
            value="Recurring",
            label="Weak trust boundaries and isolation failures keep appearing across AI systems",
            context=(
                "A 2026 practitioner review says recurring patterns include prompt injection, weak authentication at trust "
                "boundaries, and insufficient isolation between AI operations and sensitive resources."
            ),
            source="Practitioner guide to AI agent security incidents",
        ),
    ]

    pillars = [
        AboutPillarView(
            pillarid="pillar-1",
            title="Protect the machine behind the model",
            summary=(
                "The operator's machine, browser session, credentials, tools, and files are often the real prize. "
                "IronClaw is built around defending that downstream surface."
            ),
            bullets=[
                "Focus on what the AI can cause, not just what it can say",
                "Treat model-to-tool transitions as security boundaries",
                "Reduce the blast radius of agent autonomy",
            ],
        ),
        AboutPillarView(
            pillarid="pillar-2",
            title="Enforcement beats awareness",
            summary=(
                "Security claims mean very little if the system cannot actually allow, review, quarantine, or block risky behavior."
            ),
            bullets=[
                "Runtime policy enforcement before action execution",
                "Human review for suspicious or high-consequence behavior",
                "Quarantine paths for containment and analysis",
            ],
        ),
        AboutPillarView(
            pillarid="pillar-3",
            title="AI-native security needs AI-native design",
            summary=(
                "IronClaw is being built for prompt injection, indirect context abuse, excessive agency, and chained tool actions "
                "because these are the threats shaping the next generation of AI systems."
            ),
            bullets=[
                "Designed for agentic systems and autonomous workflows",
                "Built for external content risk and hidden instruction channels",
                "Structured to evolve as the AI threat landscape changes",
            ],
        ),
        AboutPillarView(
            pillarid="pillar-4",
            title="Trust should be earned with evidence",
            summary=(
                "Security adoption happens faster when teams can see why a decision happened and what controls are active."
            ),
            bullets=[
                "Audit evidence for allow, review, quarantine, and block paths",
                "Operational visibility for buyers, builders, and defenders",
                "Clearer trust posture during procurement and deployment",
            ],
        ),
    ]

    principles = [
        AboutPrincipleView(
            principleid="principle-1",
            title="Assume AI can be manipulated",
            description=(
                "If the system consumes prompts, web pages, files, emails, or retrieved knowledge, it can be influenced by an attacker."
            ),
        ),
        AboutPrincipleView(
            principleid="principle-2",
            title="Assume unsafe autonomy will spread faster than safe autonomy",
            description=(
                "The market rewards speed, which means AI builders often connect powerful actions before they add durable controls."
            ),
        ),
        AboutPrincipleView(
            principleid="principle-3",
            title="Assume users are over-trusting vendors",
            description=(
                "Many people believe paying for an AI platform means they are protected, even when the actual execution risk lands on their own systems."
            ),
        ),
        AboutPrincipleView(
            principleid="principle-4",
            title="Assume the defense must keep adapting",
            description=(
                "Static security stories will not be enough in a field where model behavior, agent design, and attack methods change rapidly."
            ),
        ),
    ]

    future = AboutFutureView(
        title="Where we are headed",
        description=(
            "IronClaw is being shaped as a long-term protection layer for local apps, autonomous agent builders, browser-based AI workflows, "
            "and future AI platforms that still need a hard security boundary between intelligence and action."
        ),
    )

    return AboutPageResponse(
        generatedat=_utc_now(),
        environment="local",
        hero=hero,
        mission=mission,
        beliefs=beliefs,
        proofstats=proofstats,
        pillars=pillars,
        principles=principles,
        future=future,
        notes=[
            "NIST AI RMF says trustworthy AI is characterized by validity and reliability, safety, security and resilience, accountability and transparency, explainability and interpretability, privacy enhancement, and fairness with harmful biases managed. [web:635][web:636][web:638][web:642]",
            "OWASP identifies prompt injection as the top LLM risk in 2025 and says it can lead to unauthorized function access, command execution, sensitive disclosure, and manipulation of critical decisions. [web:586]",
            "Recent AI agent security analysis says autonomous systems face distinct risks including prompt injection, token compromise, excessive privilege, shadow deployments, and data exfiltration that traditional security often misses. [web:641]",
            "A 2026 practitioner review reports recurring security patterns across AI agents including prompt injection, weak trust-boundary authentication, and insufficient isolation between AI operations and sensitive resources. [web:643]",
            "This page is written as a high-conviction brand and mission surface for IronClaw-Security and is ready to drive premium buyer trust and product narrative in the current local-first Gen1 build.",
        ],
    )