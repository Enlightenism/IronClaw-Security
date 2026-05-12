from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/marketing",
    tags=["marketing-features"],
)


class FeaturesHeroView(BaseModel):
    eyebrow: str
    title: str
    subtitle: str
    primaryctalabel: str
    primaryctahref: str
    secondaryctalabel: str
    secondaryctahref: str


class FeatureProofStatView(BaseModel):
    statid: str
    value: str
    label: str
    context: str
    source: str


class SecurityFeatureView(BaseModel):
    featureid: str
    title: str
    category: str
    summary: str
    whyitmatters: str
    bullets: list[str] = Field(default_factory=list)


class ThreatSurfaceView(BaseModel):
    surfaceid: str
    title: str
    risk: str
    ironclawadvantage: str


class FeatureComparisonRow(BaseModel):
    label: str
    legacysecurity: str
    ironclawsecurity: str


class FeaturesPageResponse(BaseModel):
    generatedat: str
    environment: str
    hero: FeaturesHeroView
    proofstats: list[FeatureProofStatView] = Field(default_factory=list)
    features: list[SecurityFeatureView] = Field(default_factory=list)
    threatsurfaces: list[ThreatSurfaceView] = Field(default_factory=list)
    comparison: list[FeatureComparisonRow] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@router.get("/features", response_model=FeaturesPageResponse)
def get_marketing_features() -> FeaturesPageResponse:
    hero = FeaturesHeroView(
        eyebrow="Security features",
        title="AI-native protection for the threats legacy security never had to stop.",
        subtitle=(
            "IronClaw-Security is built for prompt injection, indirect context attacks, excessive agent autonomy, "
            "unsafe tool execution, and the hidden trust failures that appear when AI systems are connected to real machines."
        ),
        primaryctalabel="See product tour",
        primaryctahref="/demo",
        secondaryctalabel="Read trust page",
        secondaryctahref="/ui/marketing/trust",
    )

    proofstats = [
        FeatureProofStatView(
            statid="llm01",
            value="LLM01",
            label="Prompt injection is OWASP's top 2025 LLM risk",
            context=(
                "OWASP ranks prompt injection as the number one risk for LLM applications and highlights both direct "
                "and indirect attack paths that can alter model behavior."
            ),
            source="OWASP GenAI Security Project",
        ),
        FeatureProofStatView(
            statid="llm06",
            value="LLM06",
            label="Excessive agency is a first-class AI security failure",
            context=(
                "OWASP defines excessive agency as damage caused when an LLM is allowed to take harmful actions in "
                "response to manipulated, ambiguous, or malfunctioning outputs."
            ),
            source="OWASP GenAI Security Project",
        ),
        FeatureProofStatView(
            statid="secure-resilient",
            value="Core",
            label="Secure and resilient behavior is part of trustworthy AI",
            context=(
                "NIST identifies security and resilience as core trustworthiness characteristics for AI systems."
            ),
            source="NIST AI research on security and resilience",
        ),
        FeatureProofStatView(
            statid="indirect-vector",
            value="Hidden",
            label="Prompt injection can be embedded in websites, emails, and files",
            context=(
                "OWASP warns that indirect prompt injection can be concealed in external content that the model later processes."
            ),
            source="OWASP prompt injection guidance",
        ),
    ]

    features = [
        SecurityFeatureView(
            featureid="policy-enforcement",
            title="Runtime policy enforcement",
            category="Control plane",
            summary=(
                "IronClaw does not just observe AI behavior. It decides whether high-risk actions should be allowed, "
                "reviewed, quarantined, or blocked before execution."
            ),
            whyitmatters=(
                "If the model can act before security responds, detection arrives too late."
            ),
            bullets=[
                "Applies enforceable action decisions before downstream execution",
                "Creates consistent policy handling across tools, prompts, files, and runtime requests",
                "Reduces AI trust from assumption to controlled authorization",
            ],
        ),
        SecurityFeatureView(
            featureid="prompt-injection-defense",
            title="Prompt injection defense",
            category="AI attack prevention",
            summary=(
                "IronClaw is built around the reality that prompt injection is not edge-case behavior. It is a leading "
                "attack class for AI systems with access to data, tools, or workflows."
            ),
            whyitmatters=(
                "A compromised prompt can become a compromised action when no runtime boundary exists."
            ),
            bullets=[
                "Evaluates suspicious context before actions proceed",
                "Supports review and containment for manipulated workflows",
                "Treats prompt and context abuse as security events, not UX glitches",
            ],
        ),
        SecurityFeatureView(
            featureid="indirect-content-boundary",
            title="External content boundary awareness",
            category="Input security",
            summary=(
                "Web pages, uploaded files, emails, and retrieved artifacts can all carry hidden instructions that shift "
                "the model from serving the user to serving the attacker."
            ),
            whyitmatters=(
                "The danger often enters through content the operator assumes is harmless."
            ),
            bullets=[
                "Treats external content as untrusted by default",
                "Protects retrieval, browsing, and document-based workflows",
                "Reduces invisible attacks delivered through context layers",
            ],
        ),
        SecurityFeatureView(
            featureid="least-privilege-agents",
            title="Least-privilege agent operations",
            category="Autonomy control",
            summary=(
                "IronClaw is designed for a world where agent builders give models too much power too quickly."
            ),
            whyitmatters=(
                "Excessive agency turns model mistakes and manipulations into real-world system actions."
            ),
            bullets=[
                "Supports scoped execution models for safer autonomy",
                "Adds review gates for high-consequence actions",
                "Limits blast radius across tools, filesystems, and connected services",
            ],
        ),
        SecurityFeatureView(
            featureid="review-quarantine",
            title="Review and quarantine workflow",
            category="Operational defense",
            summary=(
                "Suspicious AI actions need a place to go besides production. IronClaw gives teams review surfaces and "
                "quarantine paths that slow dangerous automation down."
            ),
            whyitmatters=(
                "Containment is what keeps one risky action from becoming an incident."
            ),
            bullets=[
                "Queues risky behavior for human review",
                "Quarantines execution artifacts and suspicious outcomes",
                "Supports safer production deployment of agentic systems",
            ],
        ),
        SecurityFeatureView(
            featureid="audit-evidence",
            title="Traceable audit evidence",
            category="Visibility",
            summary=(
                "Every serious buyer wants evidence that decisions are real. IronClaw records the why behind allow, "
                "review, quarantine, and block outcomes."
            ),
            whyitmatters=(
                "You cannot prove control without a decision trail."
            ),
            bullets=[
                "Captures decision history for operational review",
                "Supports forensic investigation after suspicious activity",
                "Improves buyer confidence during evaluation and procurement",
            ],
        ),
    ]

    threatsurfaces = [
        ThreatSurfaceView(
            surfaceid="browsing",
            title="Autonomous browsing and research",
            risk="Hidden prompts in web pages can redirect model behavior or trigger unsafe follow-up actions.",
            ironclawadvantage="IronClaw keeps browsing-heavy systems behind policy and review-aware execution controls.",
        ),
        ThreatSurfaceView(
            surfaceid="files",
            title="File and document ingestion",
            risk="External files can act as instruction carriers, not just data sources.",
            ironclawadvantage="IronClaw treats file-driven context as untrusted input before allowing sensitive actions.",
        ),
        ThreatSurfaceView(
            surfaceid="tools",
            title="Tool-connected agents",
            risk="A single manipulated model output can call tools, access systems, or move laterally across workflows.",
            ironclawadvantage="IronClaw inserts a security decision point between model output and tool execution.",
        ),
        ThreatSurfaceView(
            surfaceid="enterprise-ai",
            title="Internal AI adoption at scale",
            risk="Multiple AI apps with uneven controls create shadow risk and invisible exposure for users.",
            ironclawadvantage="IronClaw provides a trust-centered protection layer for teams expanding AI usage across the organization.",
        ),
    ]

    comparison = [
        FeatureComparisonRow(
            label="Primary security posture",
            legacysecurity="Detects known malware, endpoint events, or static indicators after traditional signals appear",
            ironclawsecurity="Controls AI behavior at runtime before model-linked actions become system events",
        ),
        FeatureComparisonRow(
            label="Prompt injection handling",
            legacysecurity="Usually outside scope or treated as generic input validation",
            ironclawsecurity="Treated as a first-order attack class with policy, review, and containment response paths",
        ),
        FeatureComparisonRow(
            label="Agent autonomy",
            legacysecurity="Not built for tool-connected AI agents with delegated action power",
            ironclawsecurity="Designed for excessive agency, least privilege, and pre-execution decision control",
        ),
        FeatureComparisonRow(
            label="External content risk",
            legacysecurity="May inspect files or URLs without understanding model-context manipulation",
            ironclawsecurity="Assumes websites, files, and retrieved context can weaponize AI workflows",
        ),
        FeatureComparisonRow(
            label="Operational trust",
            legacysecurity="Trust depends on alerts, logs, and manual interpretation after the fact",
            ironclawsecurity="Trust is backed by explicit allow, review, quarantine, and block decisions with audit evidence",
        ),
    ]

    return FeaturesPageResponse(
        generatedat=_utc_now(),
        environment="local",
        hero=hero,
        proofstats=proofstats,
        features=features,
        threatsurfaces=threatsurfaces,
        comparison=comparison,
        notes=[
            "OWASP identifies prompt injection as LLM01 in its 2025 risk list and describes both direct and indirect attacks that can alter model behavior through prompts and external content. [web:618][web:621][web:624]",
            "OWASP defines excessive agency as a vulnerability where an LLM system is allowed to perform damaging actions due to manipulated, ambiguous, or unsafe outputs. [web:615][web:616]",
            "NIST states that secure and resilient behavior is one of the primary characteristics of trustworthy AI. [web:620]",
            "This page is designed as a premium buyer-facing features surface for IronClaw-Security, emphasizing AI-native control rather than legacy after-the-fact detection.",
            "All content is structured as production-ready UI contract data for the current local-first Gen1 build.",
        ],
    )