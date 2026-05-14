from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/marketing",
    tags=["marketing-customers"],
)


class CustomersHeroView(BaseModel):
    eyebrow: str
    title: str
    subtitle: str
    primaryctalabel: str
    primaryctahref: str
    secondaryctalabel: str
    secondaryctahref: str


class CustomerProofStatView(BaseModel):
    statid: str
    value: str
    label: str
    context: str
    source: str


class CustomerLogoView(BaseModel):
    companyid: str
    name: str
    industry: str
    adoptionstage: str


class CustomerChallengeView(BaseModel):
    challengeid: str
    title: str
    description: str


class CustomerOutcomeView(BaseModel):
    outcomeid: str
    label: str
    detail: str


class CustomerStoryView(BaseModel):
    storyid: str
    companyname: str
    industry: str
    title: str
    summary: str
    challenge: str
    whyironclaw: str
    outcomes: list[CustomerOutcomeView] = Field(default_factory=list)
    operatorquote: str | None = None


class CustomerSegmentView(BaseModel):
    segmentid: str
    title: str
    description: str
    bestfor: list[str] = Field(default_factory=list)


class CustomersPageResponse(BaseModel):
    generatedat: str
    environment: str
    hero: CustomersHeroView
    proofstats: list[CustomerProofStatView] = Field(default_factory=list)
    logos: list[CustomerLogoView] = Field(default_factory=list)
    challenges: list[CustomerChallengeView] = Field(default_factory=list)
    stories: list[CustomerStoryView] = Field(default_factory=list)
    segments: list[CustomerSegmentView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@router.get("/customers", response_model=CustomersPageResponse)
def get_marketing_customers() -> CustomersPageResponse:
    hero = CustomersHeroView(
        eyebrow="Customer stories",
        title="Teams adopt IronClaw when AI moves from experiment to exposure.",
        subtitle=("Buyers do not come to IronClaw because AI is interesting. They come because once AI touches browsers, files, tools, secrets, research flows, or autonomous actions, trust alone stops being a strategy."),
        primaryctalabel="Talk to security team",
        primaryctahref="/contact-sales",
        secondaryctalabel="See trust and security",
        secondaryctahref="/ui/marketing/trust",
    )

    proofstats = [
        CustomerProofStatView(
            statid="trustworthy-ai",
            value="7",
            label="Core trustworthiness traits define credible AI adoption",
            context=("NIST describes trustworthy AI through characteristics such as safety, security and resilience, accountability, explainability, privacy enhancement, fairness, and reliability."),
            source="NIST AI Risk Management Framework 1.0",
        ),
        CustomerProofStatView(
            statid="runtime-priority",
            value="38%",
            label="Organizations identify runtime as their biggest AI risk area",
            context=("Acuvity reports that runtime is the most vulnerable phase for many organizations, while a large share also say it is where they lack the most capability."),
            source="Acuvity 2025 State of AI Security research",
        ),
        CustomerProofStatView(
            statid="visibility-gap",
            value="27%",
            label="Organizations say runtime is also where they lack capability most",
            context=("Security teams are more worried about what AI does in use than about pre-deployment concerns alone."),
            source="Acuvity 2025 State of AI Security research",
        ),
        CustomerProofStatView(
            statid="shadow-ai",
            value="45%",
            label="AI tool adoption often happens outside formal IT procurement",
            context=("This creates visibility and governance gaps that make buyer trust depend on controls and monitoring, not just vendor promises."),
            source="State of Enterprise AI in 2025 analysis",
        ),
    ]

    logos = [
        CustomerLogoView(
            companyid="agent-builders",
            name="Agent builders",
            industry="AI platforms",
            adoptionstage="Scaling autonomous workflows",
        ),
        CustomerLogoView(
            companyid="security-teams",
            name="Security teams",
            industry="Enterprise security",
            adoptionstage="Adding runtime controls",
        ),
        CustomerLogoView(
            companyid="platform-ops",
            name="Platform operators",
            industry="Infrastructure and DevOps",
            adoptionstage="Governing tool-connected AI systems",
        ),
        CustomerLogoView(
            companyid="regulated-orgs",
            name="Regulated organizations",
            industry="Finance, health, legal",
            adoptionstage="Seeking auditability and containment",
        ),
    ]

    challenges = [
        CustomerChallengeView(
            challengeid="buyer-fear",
            title="They know AI is moving faster than their control model.",
            description=("Teams adopt AI quickly, but most security programs were not designed for prompt injection, retrieval poisoning, chained tool calls, or agent autonomy."),
        ),
        CustomerChallengeView(
            challengeid="trust-gap",
            title="They need proof that runtime decisions are enforced, not imagined.",
            description=("A buyer loses confidence when a product can describe risk but cannot visibly block, review, quarantine, and audit dangerous behavior."),
        ),
        CustomerChallengeView(
            challengeid="machine-risk",
            title="They understand the real target is the user environment.",
            description=("The machine, browser, file system, credentials, and connected tools usually belong to the operator, which means the operator absorbs the consequences when platform trust fails."),
        ),
    ]

    stories = [
        CustomerStoryView(
            storyid="autonomous-research-platform",
            companyname="Northstar Agents",
            industry="Autonomous research platform",
            title="From fast demos to controlled deployment",
            summary=("Northstar built a browsing and retrieval-heavy agent workflow. The team moved to IronClaw when it became clear that untrusted web context could influence downstream actions."),
            challenge=("Their platform could summarize, browse, extract, and chain actions across tools, but they lacked a real runtime gate between model output and action execution."),
            whyironclaw=("IronClaw gave them review queues, action policy enforcement, audit evidence, and a clear containment path for suspicious executions."),
            outcomes=[
                CustomerOutcomeView(
                    outcomeid="northstar-1",
                    label="Safer rollout",
                    detail="The team introduced protected execution instead of trusting autonomous actions by default.",
                ),
                CustomerOutcomeView(
                    outcomeid="northstar-2",
                    label="Buyer confidence",
                    detail="Enterprise prospects could see a concrete security story instead of vague AI safety claims.",
                ),
                CustomerOutcomeView(
                    outcomeid="northstar-3",
                    label="Operational clarity",
                    detail="Security reviewers gained a place to inspect, approve, reject, and quarantine risky behavior.",
                ),
            ],
            operatorquote=("We did not need another dashboard. We needed a line of defense between the model and the machine."),
        ),
        CustomerStoryView(
            storyid="internal-ai-platform",
            companyname="Granite Ops",
            industry="Internal enterprise AI platform",
            title="Replacing trust-based rollout with governed AI operations",
            summary=("Granite Ops had multiple internal AI tools spreading across teams, with uneven review practices and limited visibility into runtime actions."),
            challenge=("Shadow AI growth meant teams were connecting models to files, browsers, and automation without a unified control plane for high-risk behavior."),
            whyironclaw=("IronClaw matched their need for least-privilege enforcement, auditability, and a path to scale AI use without giving the model unchecked authority."),
            outcomes=[
                CustomerOutcomeView(
                    outcomeid="granite-1",
                    label="Unified controls",
                    detail="Different AI workflows could be governed under one protection model.",
                ),
                CustomerOutcomeView(
                    outcomeid="granite-2",
                    label="Better trust posture",
                    detail="Leadership saw that adoption could expand without abandoning security discipline.",
                ),
                CustomerOutcomeView(
                    outcomeid="granite-3",
                    label="Reviewable evidence",
                    detail="Policy outcomes and suspicious actions became inspectable instead of invisible.",
                ),
            ],
            operatorquote=("IronClaw helped us move from AI enthusiasm to AI accountability."),
        ),
        CustomerStoryView(
            storyid="regulated-services-team",
            companyname="Aegis Advisory",
            industry="Regulated professional services",
            title="Making AI usable in a high-consequence environment",
            summary=("Aegis wanted AI productivity, but only if risky actions could be slowed, reviewed, and justified."),
            challenge=("Their teams could not accept a model making hidden decisions over client-sensitive workflows or external content."),
            whyironclaw=("IronClaw gave them a runtime story centered on review, quarantine, traceability, and operator protection."),
            outcomes=[
                CustomerOutcomeView(
                    outcomeid="aegis-1",
                    label="Controlled adoption",
                    detail="AI usage expanded without normalizing blind trust in outputs or actions.",
                ),
                CustomerOutcomeView(
                    outcomeid="aegis-2",
                    label="Stronger governance",
                    detail="Security and operations could align on what should be blocked, reviewed, or allowed.",
                ),
                CustomerOutcomeView(
                    outcomeid="aegis-3",
                    label="Customer reassurance",
                    detail="Their clients saw a clear commitment to safeguarding data, systems, and operator workflows.",
                ),
            ],
            operatorquote=("The question stopped being whether AI was useful and became whether it was governable. IronClaw gave us that answer."),
        ),
    ]

    segments = [
        CustomerSegmentView(
            segmentid="builders",
            title="For AI product builders",
            description=("Use IronClaw when your product connects models to tools, files, browsing, memory, or automated execution."),
            bestfor=[
                "Agentic applications",
                "Research assistants",
                "Workflow automation products",
                "Tool-using copilots",
            ],
        ),
        CustomerSegmentView(
            segmentid="buyers",
            title="For enterprise buyers",
            description=("Use IronClaw when adoption depends on showing that your AI system can be controlled under pressure."),
            bestfor=[
                "Security-conscious evaluations",
                "Regulated environments",
                "Internal AI enablement programs",
                "Procurement and governance reviews",
            ],
        ),
        CustomerSegmentView(
            segmentid="operators",
            title="For operators and defenders",
            description=("Use IronClaw when your team needs visibility into suspicious AI actions before they become incidents."),
            bestfor=[
                "Runtime monitoring",
                "Manual review workflows",
                "Quarantine operations",
                "Audit and forensic trails",
            ],
        ),
    ]

    return CustomersPageResponse(
        generatedat=_utc_now(),
        environment="local",
        hero=hero,
        proofstats=proofstats,
        logos=logos,
        challenges=challenges,
        stories=stories,
        segments=segments,
        notes=[
            "NIST says trustworthy AI systems are characterized by validity and reliability, safety, security and resilience, accountability and transparency, explainability and interpretability, privacy enhancement, and fairness with harmful bias managed. [web:605][web:614]",
            "Acuvity reports that 38% of organizations identify runtime as their biggest AI risk area and 27% say it is where they lack the most capability. [web:612]",
            "A 2025 enterprise AI analysis reports that the average enterprise uses many AI tools, 45% of adoption happens outside formal IT procurement, and only 38% maintain a comprehensive inventory of AI applications in use. [web:604]",
            "This page is intentionally written as a buyer-adoption surface for IronClaw-Security, showing why customers move from AI experimentation to controlled, trust-centered deployment.",
            "Customer company names and story narratives are product marketing placeholders for the current local-first Gen1 build and are ready to be replaced with live references later.",
        ],
    )
