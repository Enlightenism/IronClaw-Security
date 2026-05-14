from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/marketing",
    tags=["marketing-architecture"],
)


class ArchitectureHeroView(BaseModel):
    eyebrow: str
    title: str
    subtitle: str
    primaryctalabel: str
    primaryctahref: str
    secondaryctalabel: str
    secondaryctahref: str


class ArchitectureProofStatView(BaseModel):
    statid: str
    value: str
    label: str
    context: str
    source: str


class ArchitectureLayerView(BaseModel):
    layerid: str
    title: str
    summary: str
    functions: list[str] = Field(default_factory=list)


class ArchitectureFlowStepView(BaseModel):
    stepid: str
    title: str
    description: str


class ArchitecturePrincipleView(BaseModel):
    principleid: str
    title: str
    description: str


class ArchitecturePageResponse(BaseModel):
    generatedat: str
    environment: str
    hero: ArchitectureHeroView
    proofstats: list[ArchitectureProofStatView] = Field(default_factory=list)
    layers: list[ArchitectureLayerView] = Field(default_factory=list)
    requestflow: list[ArchitectureFlowStepView] = Field(default_factory=list)
    principles: list[ArchitecturePrincipleView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@router.get("/architecture", response_model=ArchitecturePageResponse)
def get_marketing_architecture() -> ArchitecturePageResponse:
    hero = ArchitectureHeroView(
        eyebrow="Security architecture",
        title="An AI security architecture built to interrupt dangerous actions before they execute.",
        subtitle=("IronClaw-Security is designed as a runtime decision layer between AI intent and system action, using policy enforcement, least-privilege boundaries, review controls, quarantine paths, and audit evidence to protect people, machines, and organizations from unsafe AI behavior."),
        primaryctalabel="Request architecture walkthrough",
        primaryctahref="/contact-sales",
        secondaryctalabel="Explore trust page",
        secondaryctahref="/ui/marketing/trust",
    )

    proofstats = [
        ArchitectureProofStatView(
            statid="zero-trust",
            value="Per-request",
            label="NIST says zero trust is built on accurate least-privilege per-request decisions",
            context=("NIST defines zero trust as minimizing uncertainty by enforcing accurate, least-privilege, per-request access decisions."),
            source="NIST SP 800-207",
        ),
        ArchitectureProofStatView(
            statid="least-privilege",
            value="Minimum",
            label="Least privilege means giving only the resources and authorizations needed",
            context=("NIST defines least privilege as granting the minimum system resources and authorizations necessary to perform a function."),
            source="NIST glossary",
        ),
        ArchitectureProofStatView(
            statid="prompt-mitigation",
            value="Scoped",
            label="OWASP recommends separating prompts and limiting external access",
            context=("OWASP recommends keeping system prompts separate, limiting response scope, and reducing external access as prompt injection mitigations."),
            source="OWASP prompt injection guidance",
        ),
        ArchitectureProofStatView(
            statid="runtime-position",
            value="Inline",
            label="Runtime interception is becoming a core governance pattern for AI agents",
            context=("Policy-based AI agent governance patterns increasingly place a security service between agents and target resources to intercept requests in real time."),
            source="AI agent governance technical analysis",
        ),
    ]

    layers = [
        ArchitectureLayerView(
            layerid="layer-1",
            title="Context intake layer",
            summary=("Every prompt, document, retrieved artifact, tool output, and external source is treated as potential attack-bearing context."),
            functions=[
                "Separates trusted and untrusted inputs",
                "Preserves visibility into external content influence",
                "Prepares action requests for downstream policy evaluation",
            ],
        ),
        ArchitectureLayerView(
            layerid="layer-2",
            title="Policy decision layer",
            summary=("This is the core of IronClaw. It decides whether an AI-linked action should be allowed, reviewed, quarantined, or denied."),
            functions=[
                "Applies runtime policy to each sensitive request",
                "Supports deterministic enforcement before execution",
                "Reduces trust from assumption to explicit decision",
            ],
        ),
        ArchitectureLayerView(
            layerid="layer-3",
            title="Execution boundary layer",
            summary=("Tool calls, file operations, network actions, and downstream effects are treated as security boundaries, not normal app flow."),
            functions=[
                "Creates a hard decision point before powerful actions",
                "Supports least-privilege execution paths",
                "Limits blast radius when models behave unsafely",
            ],
        ),
        ArchitectureLayerView(
            layerid="layer-4",
            title="Review and quarantine layer",
            summary=("High-risk actions should not disappear into logs. They need containment and human judgment."),
            functions=[
                "Routes suspicious items into manual review queues",
                "Quarantines risky artifacts or requests for analysis",
                "Creates a slower, safer path for ambiguous behavior",
            ],
        ),
        ArchitectureLayerView(
            layerid="layer-5",
            title="Audit and operations layer",
            summary=("Serious buyers and defenders need evidence. The architecture captures why a decision happened and what the system did next."),
            functions=[
                "Records policy and execution outcomes",
                "Supports forensic review and governance workflows",
                "Improves buyer trust with visible control evidence",
            ],
        ),
    ]

    requestflow = [
        ArchitectureFlowStepView(
            stepid="flow-1",
            title="AI intent enters the system",
            description=("A model generates an intended action after processing prompts, files, web content, or other context."),
        ),
        ArchitectureFlowStepView(
            stepid="flow-2",
            title="Context and action are evaluated",
            description=("IronClaw inspects the requested behavior in light of risk, policy, tool class, environment sensitivity, and trust boundaries."),
        ),
        ArchitectureFlowStepView(
            stepid="flow-3",
            title="A policy decision is made",
            description=("The action is explicitly allowed, routed to review, quarantined, or denied before execution reaches sensitive resources."),
        ),
        ArchitectureFlowStepView(
            stepid="flow-4",
            title="Execution is controlled at the boundary",
            description=("Only approved actions proceed, and those actions remain constrained by least-privilege and operational safeguards."),
        ),
        ArchitectureFlowStepView(
            stepid="flow-5",
            title="Evidence is captured for operators",
            description=("The system stores reviewable traces so teams can understand what happened, why it happened, and how to improve controls."),
        ),
    ]

    principles = [
        ArchitecturePrincipleView(
            principleid="principle-1",
            title="No implicit trust",
            description=("The architecture assumes prompts, retrieved context, files, and model outputs can all be manipulated."),
        ),
        ArchitecturePrincipleView(
            principleid="principle-2",
            title="Least privilege by default",
            description=("AI systems should get the minimum practical authority needed for the current task, not broad standing power."),
        ),
        ArchitecturePrincipleView(
            principleid="principle-3",
            title="Enforcement before execution",
            description=("Security value comes from intercepting dangerous actions before they happen, not only documenting them afterwards."),
        ),
        ArchitecturePrincipleView(
            principleid="principle-4",
            title="Containment for ambiguous risk",
            description=("If a request is suspicious or unclear, the architecture should slow it down, isolate it, and make it reviewable."),
        ),
        ArchitecturePrincipleView(
            principleid="principle-5",
            title="Architecture that evolves with AI",
            description=("As agent capabilities, tools, and attacks evolve, the decision model and protection surfaces must evolve with them."),
        ),
    ]

    return ArchitecturePageResponse(
        generatedat=_utc_now(),
        environment="local",
        hero=hero,
        proofstats=proofstats,
        layers=layers,
        requestflow=requestflow,
        principles=principles,
        notes=[
            "NIST SP 800-207 defines zero trust as enforcing accurate, least-privilege, per-request access decisions and says no asset is inherently trusted. [web:670][web:671]",
            "NIST defines least privilege as giving each entity only the minimum resources and authorizations needed to perform its function. [web:676]",
            "OWASP recommends keeping system prompts separate, limiting scope, and reducing external access to mitigate prompt injection risk. [web:621]",
            "Additional architectural guidance for LLM security emphasizes segregating external content, constraining model behavior, and regularly adversarially testing the system. [web:594]",
            "Policy-based agent governance patterns increasingly place runtime interception between agents and target resources so tool invocation requests can be controlled in real time. [web:677]",
            "This page is structured as a premium buyer-facing architecture narrative for the current local-first IronClaw-Security build.",
        ],
    )
