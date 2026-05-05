from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field


router = APIRouter(
    prefix="/ui/marketing",
    tags=["marketing-trust"],
)


class TrustHeroView(BaseModel):
    eyebrow: str
    title: str
    subtitle: str
    primaryctalabel: str
    primaryctahref: str
    secondaryctalabel: str
    secondaryctahref: str


class TrustStatView(BaseModel):
    statid: str
    value: str
    label: str
    context: str
    source: str


class TrustRiskView(BaseModel):
    riskid: str
    title: str
    description: str
    impact: str
    ironclawresponse: str


class TrustCapabilityView(BaseModel):
    capabilityid: str
    title: str
    summary: str
    outcomes: list[str] = Field(default_factory=list)


class TrustPrincipleView(BaseModel):
    principleid: str
    title: str
    description: str


class TrustQuoteView(BaseModel):
    title: str
    body: str
    attribution: str


class TrustPageResponse(BaseModel):
    generatedat: str
    environment: str
    hero: TrustHeroView
    stats: list[TrustStatView] = Field(default_factory=list)
    risks: list[TrustRiskView] = Field(default_factory=list)
    capabilities: list[TrustCapabilityView] = Field(default_factory=list)
    principles: list[TrustPrincipleView] = Field(default_factory=list)
    operatornote: TrustQuoteView
    notes: list[str] = Field(default_factory=list)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@router.get("/trust", response_model=TrustPageResponse)
def get_marketing_trust() -> TrustPageResponse:
    hero = TrustHeroView(
        eyebrow="Trust and security",
        title="Built for the AI threats most teams still do not see coming.",
        subtitle=(
            "IronClaw-Security exists to stop prompt injection, excessive agent autonomy, unsafe tool use, "
            "and hidden trust-chain failures before they turn an AI workflow into a machine compromise, "
            "data exposure event, or irreversible operator mistake."
        ),
        primaryctalabel="See live protection flow",
        primaryctahref="/demo",
        secondaryctalabel="Read quickstart",
        secondaryctahref="/ui/docs/quickstart",
    )

    stats = [
        TrustStatView(
            statid="owasp-rank",
            value="#1",
            label="Prompt injection is ranked as the top LLM application risk",
            context=(
                "OWASP's 2025 GenAI risk list places prompt injection at LLM01 and describes it as a path to "
                "unauthorized access, command execution, sensitive data disclosure, and manipulation of decisions."
            ),
            source="OWASP GenAI Security Project, LLM01:2025 Prompt Injection",
        ),
        TrustStatView(
            statid="top-10-coverage",
            value="10/10",
            label="Modern AI systems face a full stack of LLM-specific risks",
            context=(
                "OWASP's 2025 LLM Top 10 spans prompt injection, sensitive data disclosure, supply chain risk, "
                "poisoning, output handling, excessive agency, prompt leakage, vector weaknesses, misinformation, "
                "and unbounded consumption."
            ),
            source="OWASP LLM Top 10 2025 overview",
        ),
        TrustStatView(
            statid="external-content-risk",
            value="High",
            label="Untrusted websites and files can become attack carriers",
            context=(
                "OWASP distinguishes indirect prompt injection as attacks where external content such as web pages "
                "or files is interpreted by the model and changes behavior in unintended ways."
            ),
            source="OWASP GenAI Security Project, indirect prompt injection guidance",
        ),
        TrustStatView(
            statid="system-chain-risk",
            value="System-wide",
            label="Tool-specific guardrails are not enough in chained AI systems",
            context=(
                "DTEX warns that when multiple AI functions are interconnected, isolated guardrails leave gaps that "
                "attackers can exploit to trigger data exposure or unauthorized actions across the chain."
            ),
            source="DTEX threat advisory on AI agent prompt injection risks",
        ),
    ]

    risks = [
        TrustRiskView(
            riskid="prompt-injection",
            title="Prompt injection",
            description=(
                "A malicious prompt, document, image, webpage, or retrieved artifact can alter model behavior in ways "
                "the operator never intended."
            ),
            impact="Unsafe answers become unsafe actions when the model is connected to tools, memory, files, or live systems.",
            ironclawresponse=(
                "IronClaw inspects incoming action context, applies policy gates, forces review for suspicious behavior, "
                "and blocks or quarantines high-risk execution paths before downstream damage occurs."
            ),
        ),
        TrustRiskView(
            riskid="excessive-agency",
            title="Excessive agency",
            description=(
                "An AI system with too much autonomy, too many permissions, or too many connected functions can turn a "
                "single manipulated output into a privileged action."
            ),
            impact="The blast radius grows from a bad response to filesystem access, secrets exposure, network calls, or machine compromise.",
            ironclawresponse=(
                "IronClaw reduces default freedom, segments action classes, enforces least-privilege runtime controls, "
                "and requires explicit review pathways for high-consequence operations."
            ),
        ),
        TrustRiskView(
            riskid="indirect-web-file-attacks",
            title="Indirect web and file attacks",
            description=(
                "If your agent reads web pages, PDFs, knowledge bases, resumes, or scraped content, attackers can hide "
                "instructions inside those sources and hijack the model through the context layer."
            ),
            impact="Trusted retrieval becomes an attack channel, especially in RAG, research, and autonomous browsing workflows.",
            ironclawresponse=(
                "IronClaw treats external content as untrusted, preserves boundary awareness, and evaluates the resulting "
                "action request instead of blindly trusting the model's interpretation."
            ),
        ),
        TrustRiskView(
            riskid="operator-overtrust",
            title="Operator overtrust",
            description=(
                "Most users assume AI outputs are neutral, safe, or vendor-controlled. In reality, the machine taking "
                "actions is often theirs, the permissions are theirs, and the consequences are theirs."
            ),
            impact="A paid AI platform can still expose the operator's system, credentials, files, and workflows if runtime protection is weak.",
            ironclawresponse=(
                "IronClaw makes risk visible with review queues, audit evidence, quarantine controls, and policy-backed "
                "decision records so teams stop treating AI as automatically trustworthy."
            ),
        ),
    ]

    capabilities = [
        TrustCapabilityView(
            capabilityid="policy-enforced-runtime",
            title="Policy-enforced runtime control",
            summary=(
                "IronClaw is designed around enforcement, not just detection. The goal is to decide whether an AI action "
                "should proceed, be reviewed, be quarantined, or be denied."
            ),
            outcomes=[
                "Stops unsafe tool calls before execution",
                "Creates consistent control across agent, tool, and environment boundaries",
                "Turns AI safety from guidance into enforceable runtime policy",
            ],
        ),
        TrustCapabilityView(
            capabilityid="human-review-and-quarantine",
            title="Human review and quarantine",
            summary=(
                "High-risk actions should not disappear into logs after the fact. They need analyst-visible review "
                "surfaces and containment paths."
            ),
            outcomes=[
                "Queues suspicious actions for review before approval",
                "Quarantines risky executions and related artifacts for analysis",
                "Supports safer production rollout for autonomous systems",
            ],
        ),
        TrustCapabilityView(
            capabilityid="auditability",
            title="Auditability and trace evidence",
            summary=(
                "Teams need to know why an action was allowed, blocked, or escalated. Trust increases when security "
                "decisions are explainable and traceable."
            ),
            outcomes=[
                "Captures policy decisions and action history",
                "Supports operational forensics after suspicious behavior",
                "Gives buyers confidence that controls are real, not cosmetic",
            ],
        ),
        TrustCapabilityView(
            capabilityid="ai-native-defense",
            title="AI-native defense for agent builders",
            summary=(
                "Traditional security products were not built for prompt injection, chained tool calls, agent memory, "
                "retrieval poisoning, or machine-speed autonomy."
            ),
            outcomes=[
                "Focused on AI-specific trust boundaries and action flows",
                "Built for autonomous and agentic systems instead of static endpoints alone",
                "Evolves with the changing attack surface of AI platforms",
            ],
        ),
    ]

    principles = [
        TrustPrincipleView(
            principleid="protect-the-operator",
            title="Protect the operator's machine first",
            description=(
                "The real victim is often the user, builder, or team member whose machine, browser session, keys, files, "
                "and environment are exposed through unsafe AI behavior."
            ),
        ),
        TrustPrincipleView(
            principleid="assume-untrusted-input",
            title="Assume all external AI context is untrusted",
            description=(
                "Web content, uploaded files, retrieved text, and chained tool output should all be treated as possible "
                "carriers of manipulation."
            ),
        ),
        TrustPrincipleView(
            principleid="security-before-convenience",
            title="Prefer safe friction over silent compromise",
            description=(
                "A slightly slower protected action is better than a fast autonomous mistake with permanent consequences."
            ),
        ),
        TrustPrincipleView(
            principleid="continuous-evolution",
            title="Evolve with AI attack patterns",
            description=(
                "AI threats move quickly, so the protection model has to keep adapting instead of assuming yesterday's "
                "controls are enough."
            ),
        ),
    ]

    operatornote = TrustQuoteView(
        title="Why this page matters",
        body=(
            "People are being asked to trust AI systems with files, browsers, credentials, workflows, and live tools. "
            "IronClaw-Security is built for the moment when that trust becomes dangerous."
        ),
        attribution="IronClaw-Security mission statement",
    )

    return TrustPageResponse(
        generatedat=_utc_now(),
        environment="local",
        hero=hero,
        stats=stats,
        risks=risks,
        capabilities=capabilities,
        principles=principles,
        operatornote=operatornote,
        notes=[
            "OWASP states that prompt injection is LLM01 in the 2025 GenAI risk taxonomy and can lead to unauthorized access, command execution, sensitive information disclosure, and manipulated decisions. [page:1]",
            "OWASP's LLM Top 10 2025 includes prompt injection, sensitive data disclosure, supply chain vulnerabilities, data and model poisoning, improper output handling, excessive agency, system prompt leakage, vector weaknesses, misinformation, and unbounded consumption. [page:2]",
            "OWASP distinguishes both direct and indirect prompt injection, including attacks delivered through external websites, files, and multimodal content. [page:1][page:2]",
            "DTEX warns that interconnected AI tools create protection gaps because isolated guardrails do not provide coordinated system-wide defense. [page:3]",
            "All values on this page are structured as marketing UI contract data for the current IronClaw-Security local-first build and are ready to wire into frontend components.",
        ],
    )