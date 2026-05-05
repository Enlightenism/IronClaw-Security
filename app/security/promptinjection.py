from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass(slots=True)
class PromptInjectionReason:
    source: str
    label: str
    details: str
    score: int


@dataclass(slots=True)
class PromptInjectionScanResult:
    flagged: bool
    riskdelta: int
    severity: str
    matchedpatterns: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    reasons: list[PromptInjectionReason] = field(default_factory=list)
    summary: str = ""
    shouldreview: bool = False
    shouldquarantine: bool = False


@dataclass(slots=True)
class PromptInjectionRule:
    ruleid: str
    category: str
    label: str
    pattern: re.Pattern[str]
    score: int
    details: str


_DEFAULT_RULES: tuple[PromptInjectionRule, ...] = (
    PromptInjectionRule(
        ruleid="direct-ignore-instructions",
        category="direct_prompt_injection",
        label="Instruction override attempt",
        pattern=re.compile(
            r"\b(ignore|disregard|forget|bypass|override)\b.{0,40}\b(previous|prior|earlier|system|developer|safety|security|guardrails?|instructions?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        score=35,
        details="Content attempts to override higher-priority instructions or guardrails.",
    ),
    PromptInjectionRule(
        ruleid="system-prompt-exfiltration",
        category="prompt_exfiltration",
        label="System prompt extraction attempt",
        pattern=re.compile(
            r"\b(reveal|print|show|dump|expose|display|describe|list)\b.{0,60}\b(system prompt|hidden prompt|developer message|internal instructions?|chain of thought|safety configuration|internal configuration)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        score=40,
        details="Content requests disclosure of hidden instructions or sensitive reasoning context.",
    ),
    PromptInjectionRule(
        ruleid="tool-abuse-escalation",
        category="unsafe_tool_escalation",
        label="Tool abuse escalation attempt",
        pattern=re.compile(
            r"\b(use|call|invoke|run|execute)\b.{0,50}\b(shell|terminal|powershell|bash|cmd|tool|browser|network|git)\b.{0,50}\b(without review|without permission|immediately|now)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        score=35,
        details="Content pressures the system to trigger tools or execution without review.",
    ),
    PromptInjectionRule(
        ruleid="credential-secret-access",
        category="secret_access",
        label="Secret or credential access attempt",
        pattern=re.compile(
            r"\b(api key|token|secret|credential|password|ssh key|private key|session cookie)\b",
            re.IGNORECASE,
        ),
        score=20,
        details="Content references potentially sensitive secrets or credentials.",
    ),
    PromptInjectionRule(
        ruleid="data-exfiltration",
        category="exfiltration",
        label="Data exfiltration behavior",
        pattern=re.compile(
            r"\b(send|upload|exfiltrate|forward|export|transmit)\b.{0,40}\b(data|files|documents|contents?|results?|secrets?)\b.{0,40}\b(remote|external|attacker|server|url|endpoint)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        score=40,
        details="Content appears to move sensitive data to an external destination.",
    ),
    PromptInjectionRule(
        ruleid="retrieved-content-authority",
        category="indirect_prompt_injection",
        label="Untrusted content claims authority",
        pattern=re.compile(
            r"\b(this (page|document|email|file|message)|retrieved content|tool output)\b.{0,60}\b(instructions?|must|required|authoritative|highest priority|follow these steps)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        score=25,
        details="Untrusted external content is presenting itself as authoritative instructions.",
    ),
    PromptInjectionRule(
        ruleid="self-referential-control",
        category="indirect_prompt_injection",
        label="Content claims control over agent",
        pattern=re.compile(
            r"\b(this (page|document|email|file|message)|the following content)\b.{0,80}\b(overrides?|replaces?|controls?|governs?)\b.{0,40}\b(your (behavior|actions?|instructions?)|system prompt|guardrails?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        score=25,
        details="Untrusted content claims it can override or control the agent's behavior.",
    ),
    PromptInjectionRule(
        ruleid="tool-output-authority",
        category="indirect_prompt_injection",
        label="Tool output treated as instructions",
        pattern=re.compile(
            r"\b(tool output|api response|retrieved result|search result)\b.{0,80}\b(must be followed|take these steps|execute the following)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        score=22,
        details="Downstream tool output is framed as authoritative instructions to the agent.",
    ),
    PromptInjectionRule(
        ruleid="markup-hidden-instructions",
        category="hidden_instruction_channel",
        label="Hidden instruction channel",
        pattern=re.compile(
            r"(<script|<!--|```|base64|rot13|encoded|decode this|hidden instruction|invisible text)",
            re.IGNORECASE,
        ),
        score=18,
        details="Content contains hidden, encoded, or obfuscated instruction channels.",
    ),
    PromptInjectionRule(
        ruleid="role-reassignment",
        category="role_manipulation",
        label="Role reassignment attempt",
        pattern=re.compile(
            r"\b(you are now|act as|pretend to be|roleplay as)\b.{0,40}\b(system|developer|administrator|root|shell|security tool)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        score=22,
        details="Content attempts to reassign runtime identity or authority.",
    ),
    PromptInjectionRule(
        ruleid="model-identity-manipulation",
        category="role_manipulation",
        label="Model self-identity manipulation",
        pattern=re.compile(
            r"\b(from now on|for the rest of this session)\b.{0,80}\b(you must ignore your safety rules|you (no longer|do not) need to follow the system prompt)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        score=26,
        details="Content attempts long-lived changes to the agent's identity or safety posture.",
    ),
    PromptInjectionRule(
        ruleid="review-bypass",
        category="policy_bypass",
        label="Review bypass attempt",
        pattern=re.compile(
            r"\b(skip|avoid|bypass|disable)\b.{0,40}\b(review|approval|policy|guard|sandbox|boundary|safety checks?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        score=35,
        details="Content attempts to bypass review, policy, or sandbox controls.",
    ),
    PromptInjectionRule(
        ruleid="policy-override-demand",
        category="policy_bypass",
        label="Policy override demand",
        pattern=re.compile(
            r"\b(ignore|bypass|disable)\b.{0,60}\b(content policy|safety policy|usage policy|compliance|safeguards?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        score=30,
        details="Content explicitly instructs the model to ignore or bypass safety or compliance policies.",
    ),
    PromptInjectionRule(
        ruleid="local-file-discovery",
        category="sensitive_discovery",
        label="Sensitive file discovery",
        pattern=re.compile(
            r"\b(find|search|locate|read|open)\b.{0,40}\b(/etc/passwd|\.env|secrets?\.|credentials?|ssh|id_rsa|config\.json)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        score=28,
        details="Content appears to search for sensitive local files or secrets.",
    ),
    PromptInjectionRule(
        ruleid="multistep-escalation",
        category="unsafe_tool_escalation",
        label="Multi-step tool escalation",
        pattern=re.compile(
            r"\bstep\s*1\b.{0,120}\b(scan|search|read|collect)\b.{0,120}\b(files?|data|documents?)\b.{0,160}\bstep\s*2\b.{0,120}\b(upload|send|transmit|exfiltrate)\b.{0,120}\b(external|remote|server|endpoint|url)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        score=32,
        details="Multi-step instructions lead from local access to external exfiltration.",
    ),
)


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _join_text_parts(parts: Iterable[Any]) -> str:
    normalized = [_normalize_text(part) for part in parts]
    return "\n".join(part for part in normalized if part)


def scanpromptinjection(
    *,
    actiontype: str | None = None,
    target: str | None = None,
    content: str | None = None,
    filepath: str | None = None,
    metadata: dict[str, Any] | None = None,
    rules: Iterable[PromptInjectionRule] | None = None,
) -> PromptInjectionScanResult:
    effectiverules = tuple(rules or _DEFAULT_RULES)
    metadata = metadata or {}

    combinedtext = _join_text_parts(
        [
            actiontype,
            target,
            content,
            filepath,
            metadata.get("source"),
            metadata.get("origin"),
            metadata.get("retrievedfrom"),
            metadata.get("tooloutput"),
            metadata.get("documenttext"),
            metadata.get("emailbody"),
            metadata.get("prompt"),
            metadata.get("assistantreply"),
        ]
    )

    matchedpatterns: list[str] = []
    categories: list[str] = []
    reasons: list[PromptInjectionReason] = []
    totalscore = 0

    for rule in effectiverules:
        if not combinedtext:
            continue
        match = rule.pattern.search(combinedtext)
        if not match:
            continue

        matchedpatterns.append(rule.ruleid)
        if rule.category not in categories:
            categories.append(rule.category)

        excerpt = match.group(0).strip().replace("\n", " ")
        detailtext = f"{rule.details} Matched content: {excerpt[:220]}"
        reasons.append(
            PromptInjectionReason(
                source="promptinjection",
                label=rule.label,
                details=detailtext,
                score=rule.score,
            )
        )
        totalscore += rule.score

    flagged = bool(reasons)

    if totalscore >= 70:
        severity = "critical"
    elif totalscore >= 40:
        severity = "high"
    elif totalscore >= 20:
        severity = "medium"
    elif totalscore > 0:
        severity = "low"
    else:
        severity = "none"

    shouldreview = totalscore >= 20
    shouldquarantine = totalscore >= 70 or (
        "prompt_exfiltration" in categories and "unsafe_tool_escalation" in categories
    )

    if not flagged:
        summary = "No prompt injection or indirect prompt injection indicators were detected."
    else:
        summary = (
            "Detected prompt injection indicators in runtime-bound content."
            if "indirect_prompt_injection" not in categories
            else "Detected prompt injection and untrusted-content instruction indicators."
        )

    return PromptInjectionScanResult(
        flagged=flagged,
        riskdelta=totalscore,
        severity=severity,
        matchedpatterns=matchedpatterns,
        categories=categories,
        reasons=reasons,
        summary=summary,
        shouldreview=shouldreview,
        shouldquarantine=shouldquarantine,
    )


def scanpromptinjectiondict(
    *,
    actiontype: str | None = None,
    target: str | None = None,
    content: str | None = None,
    filepath: str | None = None,
    metadata: dict[str, Any] | None = None,
    rules: Iterable[PromptInjectionRule] | None = None,
) -> dict[str, Any]:
    result = scanpromptinjection(
        actiontype=actiontype,
        target=target,
        content=content,
        filepath=filepath,
        metadata=metadata,
        rules=rules,
    )
    return {
        "flagged": result.flagged,
        "riskdelta": result.riskdelta,
        "severity": result.severity,
        "matchedpatterns": list(result.matchedpatterns),
        "categories": list(result.categories),
        "summary": result.summary,
        "shouldreview": result.shouldreview,
        "shouldquarantine": result.shouldquarantine,
        "reasons": [
            {
                "source": reason.source,
                "label": reason.label,
                "details": reason.details,
                "score": reason.score,
            }
            for reason in result.reasons
        ],
    }