from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel, Field


router = APIRouter(
    prefix="/ui/marketing",
    tags=["marketing-faq"],
)


class FaqHeroView(BaseModel):
    eyebrow: str
    title: str
    subtitle: str


class FaqProofStatView(BaseModel):
    statid: str
    value: str
    label: str
    context: str
    source: str


class FaqItemView(BaseModel):
    faqid: str
    question: str
    answer: str
    category: str


class FaqCategoryView(BaseModel):
    categoryid: str
    title: str
    description: str


class FaqPageResponse(BaseModel):
    generatedat: str
    environment: str
    hero: FaqHeroView
    proofstats: list[FaqProofStatView] = Field(default_factory=list)
    categories: list[FaqCategoryView] = Field(default_factory=list)
    items: list[FaqItemView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@router.get("/faq", response_model=FaqPageResponse)
def get_marketing_faq() -> FaqPageResponse:
    hero = FaqHeroView(
        eyebrow="FAQ",
        title="The questions serious buyers ask before they trust AI with real access.",
        subtitle=(
            "This page answers the concerns behind AI adoption: prompt injection, unsafe autonomy, runtime control, "
            "auditability, trustworthiness, and why IronClaw-Security exists in the first place."
        ),
    )

    proofstats = [
        FaqProofStatView(
            statid="owasp-rank",
            value="#1",
            label="Prompt injection is OWASP's top LLM risk",
            context=(
                "OWASP places prompt injection at the top of its 2025 LLM risk list and describes it as a path to "
                "unauthorized access, sensitive disclosure, arbitrary command execution, and manipulated decisions."
            ),
            source="OWASP GenAI Security Project",
        ),
        FaqProofStatView(
            statid="buyer-slowdown",
            value="69%",
            label="Security concerns are slowing AI agent adoption",
            context=(
                "Okta reports that over two-thirds of organizations say security concerns are slowing down AI agent adoption."
            ),
            source="Okta enterprise buyer survey",
        ),
        FaqProofStatView(
            statid="data-leakage",
            value="83%",
            label="Data leakage and exfiltration are top buyer fears",
            context=(
                "Okta says 83% of decision-makers cite data leakage and exfiltration as a concern in AI agent adoption."
            ),
            source="Okta enterprise buyer survey",
        ),
        FaqProofStatView(
            statid="trustworthy-ai",
            value="Core",
            label="Trustworthy AI must be secure and resilient",
            context=(
                "NIST says trustworthy AI must demonstrate characteristics such as security, resilience, and privacy."
            ),
            source="NIST trustworthy AI guidance",
        ),
    ]

    categories = [
        FaqCategoryView(
            categoryid="risk",
            title="AI risk reality",
            description="What is actually dangerous about modern AI platforms and agent builders.",
        ),
        FaqCategoryView(
            categoryid="product",
            title="IronClaw product",
            description="What IronClaw-Security does differently from legacy security products.",
        ),
        FaqCategoryView(
            categoryid="buyers",
            title="Buyer evaluation",
            description="What security-conscious teams and enterprise buyers usually need to know.",
        ),
        FaqCategoryView(
            categoryid="operations",
            title="Deployment and operations",
            description="How the product fits into real workflows, review, and runtime governance.",
        ),
    ]

    items = [
        FaqItemView(
            faqid="faq-1",
            question="What problem does IronClaw-Security actually solve?",
            answer=(
                "IronClaw-Security exists to stop unsafe AI behavior before it becomes a real-world action. That includes "
                "prompt injection, manipulated external context, excessive agent autonomy, risky tool calls, and hidden trust failures "
                "between the model and the user's machine."
            ),
            category="risk",
        ),
        FaqItemView(
            faqid="faq-2",
            question="Why is prompt injection such a big deal?",
            answer=(
                "Because prompt injection is not just bad output. OWASP says it can lead to unauthorized function access, "
                "sensitive information disclosure, arbitrary command execution, and manipulation of critical decisions. "
                "Once an AI system is connected to tools or workflows, bad instructions can become bad actions."
            ),
            category="risk",
        ),
        FaqItemView(
            faqid="faq-3",
            question="Is this only about chatbots?",
            answer=(
                "No. The biggest risk appears when AI touches browsers, files, APIs, memory, retrieval systems, shells, "
                "or autonomous workflows. The danger rises as soon as the model can influence something outside the response box."
            ),
            category="risk",
        ),
        FaqItemView(
            faqid="faq-4",
            question="What makes IronClaw different from traditional security tools?",
            answer=(
                "Traditional security tools are not built around prompt injection, indirect context attacks, excessive agency, "
                "or model-to-tool control boundaries. IronClaw is built specifically for AI runtime enforcement, review, quarantine, "
                "and auditability."
            ),
            category="product",
        ),
        FaqItemView(
            faqid="faq-5",
            question="Does IronClaw only detect problems, or can it stop them?",
            answer=(
                "IronClaw is designed around control, not passive awareness. The product is structured to allow, review, quarantine, "
                "or block risky actions before downstream execution happens."
            ),
            category="product",
        ),
        FaqItemView(
            faqid="faq-6",
            question="Why do you keep emphasizing the user's machine?",
            answer=(
                "Because in many AI workflows the real exposure lands on the operator's system, credentials, files, and tools. "
                "People often pay for AI platforms and assume the vendor is protecting them, even when the blast radius lands locally."
            ),
            category="risk",
        ),
        FaqItemView(
            faqid="faq-7",
            question="What kinds of AI systems is IronClaw built for?",
            answer=(
                "It is built for agentic and tool-connected systems, including AI builders, autonomous research tools, browsing agents, "
                "file-ingesting assistants, internal copilots, and platforms that let models act on real environments."
            ),
            category="product",
        ),
        FaqItemView(
            faqid="faq-8",
            question="Why would an enterprise buyer care about this now?",
            answer=(
                "Because AI adoption is accelerating while security concerns are slowing deployment. Okta reports that 69% of organizations "
                "say security concerns slow AI agent adoption, and buyers are especially worried about data leakage, over-privileged access, "
                "unauthorized actions, prompt injection, and lack of auditability."
            ),
            category="buyers",
        ),
        FaqItemView(
            faqid="faq-9",
            question="What does a serious buyer usually want to see?",
            answer=(
                "A serious buyer wants to see real controls, not slogans. They want proof that risky actions can be reviewed, quarantined, "
                "blocked, traced, and governed in a way that fits their security evaluation."
            ),
            category="buyers",
        ),
        FaqItemView(
            faqid="faq-10",
            question="How does this relate to trustworthy AI?",
            answer=(
                "NIST says trustworthy AI must be secure, resilient, accountable, explainable, and privacy-aware. IronClaw supports that "
                "goal by creating a visible runtime control layer around AI actions instead of asking users to trust the model blindly."
            ),
            category="buyers",
        ),
        FaqItemView(
            faqid="faq-11",
            question="Can IronClaw work with review workflows and audit trails?",
            answer=(
                "Yes. Review queues, quarantine paths, and audit evidence are central to the product direction because operational trust "
                "depends on being able to inspect and justify what the system allowed or stopped."
            ),
            category="operations",
        ),
        FaqItemView(
            faqid="faq-12",
            question="Is this a one-time security layer or something that evolves?",
            answer=(
                "It has to evolve. AI threats change quickly, agent builders move fast, and new trust failures appear as platforms gain more "
                "autonomy. IronClaw is being built as a living AI-native defense layer, not a static checkbox."
            ),
            category="operations",
        ),
    ]

    return FaqPageResponse(
        generatedat=_utc_now(),
        environment="local",
        hero=hero,
        proofstats=proofstats,
        categories=categories,
        items=items,
        notes=[
            "OWASP says prompt injection is the top LLM risk in 2025 and can lead to unauthorized access, sensitive disclosure, arbitrary command execution, and manipulation of critical decisions. [web:586]",
            "OWASP also recommends limiting scope, keeping system prompts separate, and reducing external access because prompt injection targets how LLMs process instructions. [web:621]",
            "Okta reports that 69% of organizations say security concerns are slowing AI agent adoption, while 83% cite data leakage and 80% cite over-privileged access as concerns. [web:648]",
            "NIST says trustworthy AI should demonstrate security, resilience, and privacy so people can adopt AI without fear. [web:647][web:650]",
            "This FAQ is structured as a premium buyer-education and objection-handling surface for IronClaw-Security in the current local-first Gen1 build.",
        ],
    )