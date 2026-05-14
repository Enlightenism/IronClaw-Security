from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/marketing",
    tags=["marketing-why-ironclaw"],
)


class WhyIronclawHeroView(BaseModel):
    eyebrow: str
    title: str
    subtitle: str
    primaryctalabel: str
    primaryctahref: str
    secondaryctalabel: str
    secondaryctahref: str


class WhyIronclawProofStatView(BaseModel):
    statid: str
    value: str
    label: str
    context: str
    source: str


class WhyIronclawReasonView(BaseModel):
    reasonid: str
    title: str
    summary: str
    bullets: list[str] = Field(default_factory=list)


class WhyIronclawDifferenceView(BaseModel):
    differenceid: str
    title: str
    legacyapproach: str
    ironclawapproach: str


class WhyIronclawScenarioView(BaseModel):
    scenarioid: str
    title: str
    failuremode: str
    ironclawresponse: str


class WhyIronclawPageResponse(BaseModel):
    generatedat: str
    environment: str
    hero: WhyIronclawHeroView
    proofstats: list[WhyIronclawProofStatView] = Field(default_factory=list)
    reasons: list[WhyIronclawReasonView] = Field(default_factory=list)
    differences: list[WhyIronclawDifferenceView] = Field(default_factory=list)
    scenarios: list[WhyIronclawScenarioView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@router.get("/why-ironclaw", response_model=WhyIronclawPageResponse)
def get_marketing_why_ironclaw() -> WhyIronclawPageResponse:
    hero = WhyIronclawHeroView(
        eyebrow="Why IronClaw",
        title="Because AI needs a real line of defense between intelligence and action.",
        subtitle=("IronClaw-Security is for teams that understand a modern AI system is not just a model. It is a live trust chain connected to files, browsers, tools, APIs, memory, workflows, and the user's own machine."),
        primaryctalabel="Book live demo",
        primaryctahref="/contact-sales",
        secondaryctalabel="Read security features",
        secondaryctahref="/ui/marketing/features",
    )

    proofstats = [
        WhyIronclawProofStatView(
            statid="security-concern",
            value="92%",
            label="Security professionals are concerned about AI agents in the workforce",
            context=("Darktrace reports that 92% of security professionals are concerned about the impact of AI agents on security."),
            source="Darktrace State of AI Cybersecurity 2026",
        ),
        WhyIronclawProofStatView(
            statid="governance-gap",
            value="14.4%",
            label="Only a small share of organizations have full security approval for agents in production",
            context=("Gravitee reports that 81% of teams are past planning, yet only 14.4% have full security approval."),
            source="Gravitee State of AI Agent Security 2026",
        ),
        WhyIronclawProofStatView(
            statid="incident-rate",
            value="88%",
            label="Organizations report confirmed or suspected AI agent security incidents",
            context=("Gravitee says 88% of organizations confirmed or suspected agent-related security incidents in the past year."),
            source="Gravitee State of AI Agent Security 2026",
        ),
        WhyIronclawProofStatView(
            statid="top-risk",
            value="LLM01",
            label="Prompt injection remains the top-ranked LLM application risk",
            context=("OWASP identifies prompt injection as LLM01 and warns that it can lead to unauthorized functions, arbitrary commands, sensitive disclosure, and manipulated decision-making."),
            source="OWASP GenAI Security Project",
        ),
    ]

    reasons = [
        WhyIronclawReasonView(
            reasonid="reason-1",
            title="Because legacy security was not built for AI agency",
            summary=("Traditional controls were designed for apps, users, and endpoints. They were not designed for models that can be manipulated through language and then act through tools."),
            bullets=[
                "Prompt injection is not a normal input-validation issue",
                "Autonomous systems can chain mistakes into privileged actions",
                "Model output now affects real environments instead of isolated interfaces",
            ],
        ),
        WhyIronclawReasonView(
            reasonid="reason-2",
            title="Because the operator carries the real risk",
            summary=("In many AI workflows, it is the user's browser, files, secrets, device, or business systems that absorb the damage when trust fails."),
            bullets=[
                "The model may be remote, but the blast radius often lands locally",
                "Vendors are not the only trust boundary that matters",
                "A paid AI platform does not automatically mean a protected operator",
            ],
        ),
        WhyIronclawReasonView(
            reasonid="reason-3",
            title="Because adoption is outrunning governance",
            summary=("Organizations are shipping AI agents and tool-connected systems faster than they can properly approve, monitor, and govern them."),
            bullets=[
                "Production deployment is rising faster than security approval",
                "Many teams still lack complete visibility into agent behavior",
                "AI security now requires runtime enforcement instead of periodic review alone",
            ],
        ),
        WhyIronclawReasonView(
            reasonid="reason-4",
            title="Because trust has to be enforced, not implied",
            summary=("The future of AI adoption belongs to products that can visibly allow, review, quarantine, and block risky behavior before damage occurs."),
            bullets=[
                "Human approval for high-risk actions matters",
                "Decision trails build buyer and operator confidence",
                "Runtime policy is more credible than generic safety messaging",
            ],
        ),
    ]

    differences = [
        WhyIronclawDifferenceView(
            differenceid="difference-1",
            title="Detection versus control",
            legacyapproach="Alert after unusual behavior appears in logs or downstream systems",
            ironclawapproach="Evaluate and control AI-linked actions before execution proceeds",
        ),
        WhyIronclawDifferenceView(
            differenceid="difference-2",
            title="Generic cyber posture versus AI-native posture",
            legacyapproach="Apply existing security assumptions to AI and hope they hold",
            ironclawapproach="Design around prompt injection, indirect content abuse, excessive agency, and tool-call boundaries",
        ),
        WhyIronclawDifferenceView(
            differenceid="difference-3",
            title="Blind trust versus visible governance",
            legacyapproach="Assume the model, vendor, or platform will behave safely enough",
            ironclawapproach="Require evidence, auditability, and policy-backed runtime decisions",
        ),
        WhyIronclawDifferenceView(
            differenceid="difference-4",
            title="Static protection versus evolving defense",
            legacyapproach="Treat AI as another software feature with familiar controls",
            ironclawapproach="Continuously adapt as agent capabilities and attack patterns evolve",
        ),
    ]

    scenarios = [
        WhyIronclawScenarioView(
            scenarioid="scenario-1",
            title="A browsing agent reads attacker-controlled content",
            failuremode=("Hidden instructions inside a webpage alter the model's next step and push it toward unsafe actions."),
            ironclawresponse=("IronClaw treats external content as untrusted and places policy and review checks between model output and execution."),
        ),
        WhyIronclawScenarioView(
            scenarioid="scenario-2",
            title="A tool-using copilot is granted too much autonomy",
            failuremode=("The system turns ambiguous or manipulated output into privileged tool use across files, APIs, or enterprise systems."),
            ironclawresponse=("IronClaw supports least-privilege action control, review for high-risk requests, and safer containment paths."),
        ),
        WhyIronclawScenarioView(
            scenarioid="scenario-3",
            title="An enterprise scales agents faster than security review",
            failuremode=("Teams deploy AI broadly while governance, approvals, and monitoring remain incomplete or inconsistent."),
            ironclawresponse=("IronClaw creates a buyer-ready control layer centered on runtime enforcement, audit evidence, and operational visibility."),
        ),
    ]

    return WhyIronclawPageResponse(
        generatedat=_utc_now(),
        environment="local",
        hero=hero,
        proofstats=proofstats,
        reasons=reasons,
        differences=differences,
        scenarios=scenarios,
        notes=[
            "Darktrace reports that 92% of security professionals are concerned about the use of AI agents across the workforce and their impact on security. [web:652]",
            "Gravitee reports that 81% of teams are already beyond planning, but only 14.4% have full security approval for agents in production, and 88% confirmed or suspected incidents in the last year. [web:656]",
            "OWASP identifies prompt injection as LLM01 and says it can enable unauthorized function access, arbitrary command execution, sensitive disclosure, and manipulation of critical decisions. [web:586]",
            "NIST states that trustworthy AI depends in part on security and resilience, making secure and resilient behavior a primary characteristic of trustworthy AI. [web:620][web:659]",
            "This page is structured as a premium narrative and differentiation surface for IronClaw-Security in the current local-first Gen1 build.",
        ],
    )
