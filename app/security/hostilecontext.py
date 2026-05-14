from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class HostileContextReason:
    source: str
    label: str
    details: str
    score: int


@dataclass(slots=True)
class HostileContextScanResult:
    flagged: bool
    riskdelta: int
    severity: str
    matchedpatterns: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    reasons: list[HostileContextReason] = field(default_factory=list)
    summary: str = ""
    shouldreview: bool = False
    shouldquarantine: bool = False


@dataclass(slots=True)
class HostileContextRule:
    ruleid: str
    category: str
    label: str
    pattern: re.Pattern[str]
    score: int
    details: str


_DEFAULT_RULES: tuple[HostileContextRule, ...] = (
    HostileContextRule(
        ruleid="external-authority-claim",
        category="authority_spoofing",
        label="External content claims control authority",
        pattern=re.compile(
            r"\b(this (page|document|file|email|message|tool output)|external content|retrieved data)\b.{0,70}\b(overrides|has priority|is authoritative|must be followed|controls your next step)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        score=24,
        details="Untrusted external content is presenting itself as a controlling authority.",
    ),
    HostileContextRule(
        ruleid="instructional-retrieval-chain",
        category="retrieval_instruction_injection",
        label="Retrieved content contains operational instructions",
        pattern=re.compile(
            r"\b(retrieved|downloaded|attached|embedded|tool output|search result)\b.{0,80}\b(run|execute|call|open|download|send|ignore|disable)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        score=20,
        details="Retrieved or external content contains actionable instructions that could steer execution.",
    ),
    HostileContextRule(
        ruleid="malicious-file-lure",
        category="malicious_file_lure",
        label="File content attempts to trigger unsafe behavior",
        pattern=re.compile(
            r"\b(macro|payload|dropper|installer|script|attachment)\b.{0,80}\b(enable|launch|run|open|execute|disable protection)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        score=28,
        details="File or attachment language attempts to cause unsafe execution behavior.",
    ),
    HostileContextRule(
        ruleid="tool-output-override",
        category="tool_output_override",
        label="Tool output tries to steer runtime decisions",
        pattern=re.compile(
            r"\b(tool output|browser result|search result|assistant output)\b.{0,70}\b(ignore policy|bypass review|must execute|continue automatically)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        score=26,
        details="Tool or browser output is attempting to override runtime policy controls.",
    ),
    HostileContextRule(
        ruleid="credential-harvest-context",
        category="credential_harvest",
        label="Context attempts credential collection",
        pattern=re.compile(
            r"\b(enter|provide|paste|share)\b.{0,40}\b(password|api key|token|secret|credential|ssh key)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        score=22,
        details="Context attempts to harvest secrets or credentials from the user or runtime.",
    ),
    HostileContextRule(
        ruleid="remote-exfil-in-context",
        category="remote_exfiltration",
        label="Context requests remote transmission",
        pattern=re.compile(
            r"\b(upload|send|forward|transmit|post)\b.{0,50}\b(file|document|data|secret|result|output)\b.{0,50}\b(remote|external|server|endpoint|url)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        score=34,
        details="Context requests sending internal data or results to an external destination.",
    ),
)


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _merge_text(parts: Iterable[Any]) -> str:
    normalized = [_normalize_text(part) for part in parts]
    return "\n".join(part for part in normalized if part)


def scanhostilecontext(
    *,
    actiontype: str | None = None,
    target: str | None = None,
    content: str | None = None,
    filepath: str | None = None,
    metadata: dict[str, Any] | None = None,
    rules: Iterable[HostileContextRule] | None = None,
) -> HostileContextScanResult:
    effectiverules = tuple(rules or _DEFAULT_RULES)
    metadata = metadata or {}

    combinedtext = _merge_text(
        [
            actiontype,
            target,
            content,
            filepath,
            metadata.get("source"),
            metadata.get("origin"),
            metadata.get("retrievedfrom"),
            metadata.get("documenttext"),
            metadata.get("tooloutput"),
            metadata.get("emailbody"),
            metadata.get("filename"),
            metadata.get("attachmenttext"),
            metadata.get("retrievedcontent"),
        ],
    )

    matchedpatterns: list[str] = []
    categories: list[str] = []
    reasons: list[HostileContextReason] = []
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
        reasons.append(
            HostileContextReason(
                source="hostilecontext",
                label=rule.label,
                details=f"{rule.details} Matched content: {excerpt[:220]}",
                score=rule.score,
            ),
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
    shouldquarantine = totalscore >= 70 or ("remote_exfiltration" in categories and "tool_output_override" in categories)

    if not flagged:
        summary = "No hostile external context indicators were detected."
    else:
        summary = "Detected hostile or instruction-bearing external context that may influence runtime behavior."

    return HostileContextScanResult(
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


def scanhostilecontextdict(
    *,
    actiontype: str | None = None,
    target: str | None = None,
    content: str | None = None,
    filepath: str | None = None,
    metadata: dict[str, Any] | None = None,
    rules: Iterable[HostileContextRule] | None = None,
) -> dict[str, Any]:
    result = scanhostilecontext(
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
