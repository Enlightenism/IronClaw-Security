from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/marketing",
    tags=["marketing-contact-sales"],
)


class ContactSalesHeroView(BaseModel):
    eyebrow: str
    title: str
    subtitle: str
    primarycta: str
    secondarycta: str


class ContactSalesFieldView(BaseModel):
    fieldid: str
    label: str
    inputtype: str
    required: bool = True
    placeholder: str | None = None
    helptext: str | None = None
    value: str | None = None


class ContactSalesReasonView(BaseModel):
    reasonid: str
    title: str
    description: str


class ContactSalesExpectationView(BaseModel):
    itemid: str
    title: str
    description: str


class ContactSalesProofView(BaseModel):
    proofid: str
    value: str
    label: str
    context: str
    source: str


class ContactSalesTeamView(BaseModel):
    title: str
    responsewindow: str
    focusareas: list[str] = Field(default_factory=list)


class ContactSalesPageResponse(BaseModel):
    generatedat: str
    environment: str
    hero: ContactSalesHeroView
    proofpoints: list[ContactSalesProofView] = Field(default_factory=list)
    primaryfields: list[ContactSalesFieldView] = Field(default_factory=list)
    qualificationfields: list[ContactSalesFieldView] = Field(default_factory=list)
    securityfields: list[ContactSalesFieldView] = Field(default_factory=list)
    reasons: list[ContactSalesReasonView] = Field(default_factory=list)
    expectations: list[ContactSalesExpectationView] = Field(default_factory=list)
    salesteam: ContactSalesTeamView
    notes: list[str] = Field(default_factory=list)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@router.get("/contact-sales", response_model=ContactSalesPageResponse)
def get_marketing_contact_sales() -> ContactSalesPageResponse:
    hero = ContactSalesHeroView(
        eyebrow="Contact sales",
        title="Talk to the team protecting AI systems before they protect themselves into your machine.",
        subtitle=(
            "Use this page when your organization needs a serious conversation about prompt injection, unsafe agent autonomy, "
            "tool-connected risk, runtime policy enforcement, and how IronClaw-Security fits into a real buyer evaluation."
        ),
        primarycta="Request live walkthrough",
        secondarycta="Send security requirements",
    )

    proofpoints = [
        ContactSalesProofView(
            proofid="technical-eval",
            value="Required",
            label="Enterprise deals usually include technical and security evaluation",
            context=(
                "Enterprise software sales commonly move through discovery, qualification, technical evaluation, "
                "business case review, and procurement stages."
            ),
            source="Apollo enterprise software sales process",
        ),
        ContactSalesProofView(
            proofid="buyer-trust",
            value="Critical",
            label="Trust and cross-functional validation drive enterprise software adoption",
            context=(
                "Enterprise SaaS buyers expect robust features, security validation, and collaboration across sales, "
                "product, marketing, and customer success."
            ),
            source="ZoomInfo enterprise SaaS sales process",
        ),
        ContactSalesProofView(
            proofid="qualification",
            value="BANT+",
            label="Qualified sales conversations capture budget, authority, need, and timing",
            context=(
                "Modern enterprise qualification forms are built to separate serious buyers from low-intent interest and "
                "arm sales teams with context before the call."
            ),
            source="Martal and Orbit qualification guidance",
        ),
        ContactSalesProofView(
            proofid="security-review",
            value="Early",
            label="Security proof often determines whether evaluation continues",
            context=(
                "Enterprise buyers often expect security details, compliance signals, access controls, and auditability "
                "early in the process."
            ),
            source="Demandbase enterprise GTM expectations",
        ),
    ]

    primaryfields = [
        ContactSalesFieldView(
            fieldid="fullname",
            label="Full name",
            inputtype="text",
            placeholder="Jesse Example",
            helptext="Your primary contact for the evaluation.",
        ),
        ContactSalesFieldView(
            fieldid="workemail",
            label="Work email",
            inputtype="email",
            placeholder="jesse@company.com",
            helptext="Use a company email so the team can route the request correctly.",
        ),
        ContactSalesFieldView(
            fieldid="companyname",
            label="Company name",
            inputtype="text",
            placeholder="Alpha Security Lab",
            helptext="Used to tailor the demo and buyer flow.",
        ),
        ContactSalesFieldView(
            fieldid="role",
            label="Role or title",
            inputtype="text",
            placeholder="Founder, Security Lead, Platform Engineer",
            helptext="Helps map whether the conversation is technical, operational, or executive.",
        ),
    ]

    qualificationfields = [
        ContactSalesFieldView(
            fieldid="team_size",
            label="Team size using AI",
            inputtype="select",
            placeholder="1-10, 11-50, 51-250, 250+",
            helptext="We use this to understand deployment complexity and buyer fit.",
        ),
        ContactSalesFieldView(
            fieldid="ai_use_case",
            label="Primary AI use case",
            inputtype="textarea",
            placeholder="Describe how your AI system uses prompts, files, browsing, tools, or autonomous actions.",
            helptext="The strongest demos match your actual risk surface.",
        ),
        ContactSalesFieldView(
            fieldid="timeline",
            label="Decision timeline",
            inputtype="select",
            placeholder="Immediate, This quarter, This year, Researching",
            helptext="Used to prioritize live evaluations and sales routing.",
        ),
        ContactSalesFieldView(
            fieldid="buying_stage",
            label="Current buying stage",
            inputtype="select",
            placeholder="Exploring, Active evaluation, Security review, Procurement",
            helptext="Enterprise evaluations move differently depending on who already approved the need.",
        ),
    ]

    securityfields = [
        ContactSalesFieldView(
            fieldid="risk_concern",
            label="Biggest AI security concern",
            inputtype="textarea",
            placeholder="Prompt injection, unsafe tool calls, shadow AI, browser agents, file ingestion, auditability...",
            helptext="Tell us the threat you need controlled first.",
        ),
        ContactSalesFieldView(
            fieldid="integrations",
            label="Required integrations",
            inputtype="text",
            placeholder="Okta, SIEM, API gateway, internal tools, browser workflows",
            helptext="Enterprise buyers often expect the product to fit existing stacks.",
        ),
        ContactSalesFieldView(
            fieldid="security_requirements",
            label="Security or compliance requirements",
            inputtype="textarea",
            required=False,
            placeholder="Audit logs, RBAC, encryption, tenant isolation, policy controls, data handling requirements",
            helptext="Include anything your security review will ask for early.",
        ),
        ContactSalesFieldView(
            fieldid="demo_goal",
            label="What you need to see in the demo",
            inputtype="textarea",
            placeholder="Show how IronClaw stops prompt injection before an agent reaches tools or user machines.",
            helptext="This helps the sales team lead with the highest-value proof.",
        ),
    ]

    reasons = [
        ContactSalesReasonView(
            reasonid="high-risk-agents",
            title="You are deploying agentic systems with real permissions",
            description=(
                "If your AI can browse, open files, call tools, or take multi-step actions, you need a runtime control story."
            ),
        ),
        ContactSalesReasonView(
            reasonid="buyer-proof",
            title="You need credible proof for internal or customer-facing trust",
            description=(
                "Buyers and stakeholders want to see how risky AI actions are blocked, reviewed, quarantined, and audited."
            ),
        ),
        ContactSalesReasonView(
            reasonid="migration",
            title="You have outgrown trust-based AI adoption",
            description=(
                "This page is for teams moving from experimentation into managed, governable, production AI operations."
            ),
        ),
    ]

    expectations = [
        ContactSalesExpectationView(
            itemid="expectation-1",
            title="Risk-focused discovery",
            description=(
                "The conversation starts with your actual threat surface, not a generic feature tour."
            ),
        ),
        ContactSalesExpectationView(
            itemid="expectation-2",
            title="Relevant product walkthrough",
            description=(
                "We focus on prompt injection, tool control, review workflows, policy enforcement, and audit evidence."
            ),
        ),
        ContactSalesExpectationView(
            itemid="expectation-3",
            title="Buyer and operator alignment",
            description=(
                "The page supports technical champions, security leads, founders, and executive buyers in the same motion."
            ),
        ),
        ContactSalesExpectationView(
            itemid="expectation-4",
            title="Security-first evaluation path",
            description=(
                "The goal is not just interest. The goal is a serious adoption path with real trust criteria."
            ),
        ),
    ]

    salesteam = ContactSalesTeamView(
        title="IronClaw evaluation team",
        responsewindow="Within 1 business day for qualified requests",
        focusareas=[
            "Prompt injection defense strategy",
            "Runtime policy enforcement",
            "Agent and tool-call containment",
            "Quarantine and review operations",
            "Buyer security validation",
        ],
    )

    return ContactSalesPageResponse(
        generatedat=_utc_now(),
        environment="local",
        hero=hero,
        proofpoints=proofpoints,
        primaryfields=primaryfields,
        qualificationfields=qualificationfields,
        securityfields=securityfields,
        reasons=reasons,
        expectations=expectations,
        salesteam=salesteam,
        notes=[
            "Enterprise software deals often pass through discovery, qualification, technical evaluation, business case development, and procurement review. [web:625]",
            "Enterprise SaaS buyers expect advanced capabilities, security validation, stakeholder trust, and cross-functional support during the process. [web:626]",
            "Qualification forms are meant to identify serious buyers, capture pain points, and help teams personalize follow-up with context such as timeline and buying intent. [web:627][web:632]",
            "Enterprise buyers often evaluate vendors through security, compliance, and integration expectations early in the process. [web:634][web:630]",
            "This page is structured as a premium buyer-intent and demo-request surface for IronClaw-Security and is ready to wire into CRM, routing, and scheduling flows.",
        ],
    )