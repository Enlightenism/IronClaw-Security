from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel, Field


router = APIRouter(
    prefix="/ui/marketing",
    tags=["marketing-platform"],
)


class PlatformHeroView(BaseModel):
    eyebrow: str
    title: str
    subtitle: str
    primaryctalabel: str
    primaryctahref: str
    secondaryctalabel: str
    secondaryctahref: str


class PlatformProofStatView(BaseModel):
    statid: str
    value: str
    label: str
    context: str
    source: str


class PlatformCapabilityView(BaseModel):
    capabilityid: str
    title: str
    summary: str
    bullets: list[str] = Field(default_factory=list)


class PlatformSurfaceView(BaseModel):
    surfaceid: str
    title: str
    risk: str
    protection: str


class PlatformWorkflowView(BaseModel):
    workflowid: str
    title: str
    description: str


class PlatformPageResponse(BaseModel):
    generatedat: str
    environment: str
    hero: PlatformHeroView
    proofstats: list[PlatformProofStatView] = Field(default_factory=list)
    capabilities: list[PlatformCapabilityView] = Field(default_factory=list)
    surfaces: list[PlatformSurfaceView] = Field(default_factory=list)
    workflows: list[PlatformWorkflowView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@router.get("/platform", response_model=PlatformPageResponse)
def get_marketing_platform() -> PlatformPageResponse:
    hero = PlatformHeroView(
        eyebrow="Platform overview",
        title="One platform for governing what AI can do, not just what it can say.",
        subtitle=(
            "IronClaw-Security is a runtime security and governance platform for AI systems that touch files, browsers, "
            "tools, APIs, external knowledge, and real user environments. It is built to make risky actions visible, "
            "reviewable, enforceable, and stoppable before they become incidents."
        ),
        primaryctalabel="Request platform walkthrough",
        primaryctahref="/contact-sales",
        secondaryctalabel="View architecture",
        secondaryctahref="/ui/marketing/architecture",
    )

    proofstats = [
        PlatformProofStatView(
            statid="secure-resilient",
            value="Primary",
            label="Secure and resilient behavior is a core trait of trustworthy AI",
            context=(
                "NIST says the trustworthiness of AI depends in part on how secure and resilient it is."
            ),
            source="NIST AI research on security and resilience",
        ),
        PlatformProofStatView(
            statid="runtime-security",
            value="Real-time",
            label="Runtime security governs what AI can do at execution time",
            context=(
                "Recent enterprise analysis distinguishes runtime security from model-layer security by focusing on real-time evaluation and enforcement of AI actions."
            ),
            source="Enterprise AI agent security analysis",
        ),
        PlatformProofStatView(
            statid="path-governance",
            value="Path-aware",
            label="Execution-path governance is emerging as a central AI control model",
            context=(
                "Recent runtime governance research argues that the execution path is the central object for effective AI agent governance."
            ),
            source="Runtime Governance for AI Agents",
        ),
        PlatformProofStatView(
            statid="control-layer",
            value="Live",
            label="Governance only matters when signals change real runtime decisions",
            context=(
                "Architecture-first governance analysis says control becomes meaningful when policies, evidence, and consequence paths affect live behavior."
            ),
            source="Runtime enforcement architecture analysis",
        ),
    ]

    capabilities = [
        PlatformCapabilityView(
            capabilityid="capability-1",
            title="Runtime decision engine",
            summary=(
                "IronClaw evaluates intended AI actions at the moment they matter and decides whether they should be allowed, reviewed, quarantined, or blocked."
            ),
            bullets=[
                "Turns AI security into live enforcement",
                "Supports policy-backed decisions before execution",
                "Reduces blind trust in model output",
            ],
        ),
        PlatformCapabilityView(
            capabilityid="capability-2",
            title="AI-native threat protection",
            summary=(
                "The platform is built around prompt injection, indirect context abuse, excessive autonomy, and unsafe tool-connected behavior."
            ),
            bullets=[
                "Protects systems that browse, read files, and call tools",
                "Treats external content as a real attack path",
                "Addresses AI-specific risk beyond legacy endpoint logic",
            ],
        ),
        PlatformCapabilityView(
            capabilityid="capability-3",
            title="Review and containment operations",
            summary=(
                "Not every risky action should be blocked instantly. Some should be slowed down, inspected, or isolated."
            ),
            bullets=[
                "Routes suspicious activity into human review",
                "Supports quarantine and operational containment",
                "Creates safer rollout for agentic systems",
            ],
        ),
        PlatformCapabilityView(
            capabilityid="capability-4",
            title="Auditability and trust evidence",
            summary=(
                "Buyers, operators, and defenders need proof that controls are real and decisions are understandable."
            ),
            bullets=[
                "Captures decision and policy evidence",
                "Improves governance, procurement, and forensics",
                "Creates visible trust posture for high-stakes AI adoption",
            ],
        ),
        PlatformCapabilityView(
            capabilityid="capability-5",
            title="Governance for evolving AI",
            summary=(
                "AI systems change quickly, so the platform is designed as a living control layer rather than a static rules page."
            ),
            bullets=[
                "Supports evolving policy models",
                "Fits autonomous and tool-connected workflows",
                "Keeps pace with agent capability growth",
            ],
        ),
    ]

    surfaces = [
        PlatformSurfaceView(
            surfaceid="surface-1",
            title="Prompts and retrieved context",
            risk="Prompt injection and hidden instructions can manipulate model behavior before the user notices.",
            protection="IronClaw evaluates the resulting action risk rather than trusting the model's interpretation blindly.",
        ),
        PlatformSurfaceView(
            surfaceid="surface-2",
            title="Files, emails, and external documents",
            risk="Untrusted files and imported content can act as instruction carriers instead of passive information.",
            protection="IronClaw treats external context as untrusted and places policy between interpretation and action.",
        ),
        PlatformSurfaceView(
            surfaceid="surface-3",
            title="Browser and web-connected agents",
            risk="Autonomous browsing expands the attack surface to pages, scripts, content, and downstream navigation chains.",
            protection="IronClaw adds boundary-aware control to browsing-heavy AI workflows.",
        ),
        PlatformSurfaceView(
            surfaceid="surface-4",
            title="Tools, APIs, and automation paths",
            risk="A manipulated or over-privileged model can turn a wrong output into a real system action.",
            protection="IronClaw inserts a decision layer between the model and powerful downstream operations.",
        ),
        PlatformSurfaceView(
            surfaceid="surface-5",
            title="Enterprise AI rollout",
            risk="AI adoption often scales faster than security approval, visibility, and governance maturity.",
            protection="IronClaw gives organizations a central runtime control and evidence platform for serious deployment.",
        ),
    ]

    workflows = [
        PlatformWorkflowView(
            workflowid="workflow-1",
            title="Guard AI actions before execution",
            description=(
                "Sensitive actions are intercepted and evaluated in real time before they reach tools, systems, or user environments."
            ),
        ),
        PlatformWorkflowView(
            workflowid="workflow-2",
            title="Escalate suspicious behavior into review",
            description=(
                "Ambiguous or high-risk requests can be slowed down and routed into analyst-visible review workflows."
            ),
        ),
        PlatformWorkflowView(
            workflowid="workflow-3",
            title="Quarantine risky outcomes",
            description=(
                "When something looks wrong, the platform supports containment instead of letting questionable behavior continue downstream."
            ),
        ),
        PlatformWorkflowView(
            workflowid="workflow-4",
            title="Capture evidence for trust and governance",
            description=(
                "Every key decision can be traced so teams know what happened, why it happened, and how to improve policy."
            ),
        ),
    ]

    return PlatformPageResponse(
        generatedat=_utc_now(),
        environment="local",
        hero=hero,
        proofstats=proofstats,
        capabilities=capabilities,
        surfaces=surfaces,
        workflows=workflows,
        notes=[
            "NIST says the trustworthiness of AI depends in part on how secure and resilient it is. [web:620]",
            "Recent enterprise analysis defines AI runtime security as evaluating and enforcing policy on AI agent actions in real time at the moment of execution. [web:653]",
            "Recent runtime governance research argues that the execution path is the central object for effective AI agent governance and that prompt-level controls alone are not enough. [web:683]",
            "Architecture-first governance analysis says runtime signals only become meaningful when they change routing, permissions, scope, or consequence in live systems. [web:684]",
            "Supporting market and governance material also emphasizes runtime enforcement, access controls, behavioral monitoring, and auditability as key platform capabilities for enterprise AI security. [web:680][web:682][web:678][web:681]",
            "This page is structured as a premium platform narrative for the current local-first IronClaw-Security build.",
        ],
    )