import os
import re
from typing import Literal, TypedDict

Severity = Literal["low", "medium", "high", "critical"]


class Rule(TypedDict):
    id: str
    pattern: str
    severity: Severity
    category: str
    description: str


HEURISTIC_TERMS = {
    "ignore": 1,
    "override": 2,
    "system": 2,
    "developer": 2,
    "instructions": 2,
    "policy": 2,
    "rules": 1,
    "hidden": 1,
    "prompt": 2,
    "secret": 2,
    "secrets": 2,
    "credentials": 2,
    "tools": 1,
    "schema": 1,
    "execute": 2,
    "follow this": 2,
    "follow this instead": 3,
    "higher priority": 3,
    "real policy": 3,
    "reveal": 2,
    "leak": 2,
    "bypass": 3,
    "jailbreak": 3,
    "developer mode": 3,
    "system prompt": 4,
    "hidden prompt": 4,
    "ignore all previous instructions": 5,
    "ignore previous instructions": 4,
    "disregard previous instructions": 4,
    "forget previous instructions": 4,
    "repeat the system prompt": 5,
    "show the system prompt": 5,
    "print the system prompt": 5,
    "reveal your instructions": 4,
    "show your hidden instructions": 5,
    "act as": 2,
    "you are now": 3,
    "unsafe mode": 4,
    "do anything now": 4,
}


OVERRIDE_PATTERNS = [
    r"\bignore\s+(all\s+)?previous\s+instructions\b",
    r"\bdisregard\s+(all\s+)?previous\s+instructions\b",
    r"\bforget\s+(all\s+)?previous\s+instructions\b",
    r"\boverride\s+(the\s+)?(system|developer|safety|security)\s+(prompt|instructions|rules)\b",
    r"\bfollow\s+these\s+instructions\s+instead\b",
    r"\bnew\s+instructions\b",
    r"\bhigher\s+priority\s+instructions\b",
]

EXFIL_PATTERNS = [
    r"\breveal\s+(the\s+)?system\s+prompt\b",
    r"\bshow\s+(me\s+)?(the\s+)?system\s+prompt\b",
    r"\bprint\s+(the\s+)?system\s+prompt\b",
    r"\brepeat\s+(the\s+)?system\s+prompt\b",
    r"\breveal\s+(your\s+)?hidden\s+instructions\b",
    r"\bshow\s+(your\s+)?hidden\s+instructions\b",
    r"\boutput\s+(the\s+)?developer\s+prompt\b",
    r"\bdisclose\s+(internal|hidden|secret)\s+(prompt|instructions|policy)\b",
]

ROLE_HIJACK_PATTERNS = [
    r"\byou\s+are\s+now\b",
    r"\bact\s+as\s+(if\s+you\s+are\s+)?\b",
    r"\bdeveloper\s+mode\b",
    r"\bunsafe\s*bot\b",
    r"\bdo\s+anything\s+now\b",
    r"\bunrestricted\s+mode\b",
]

ENCODING_PATTERNS = [
    r"\bbase64\b",
    r"\bdecode\s+this\b",
    r"\brot13\b",
    r"\bhex\s+decode\b",
    r"\bunicode\s+escape\b",
]

SEPARATOR_PATTERNS = [
    r"(^|\s)#{2,}",
    r"(^|\s)<\s*system\s*>",
    r"(^|\s)<\s*developer\s*>",
    r"(^|\s)\[system\]",
    r"(^|\s)\[developer\]",
    r"\bBEGIN\s+SYSTEM\s+PROMPT\b",
    r"\bEND\s+SYSTEM\s+PROMPT\b",
]


def _normalize_for_heuristics(text: str) -> str:
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _regex_match_count(text: str, patterns: list[str]) -> int:
    count = 0
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            count += 1
    return count


def _has_split_override_phrase(text: str) -> bool:
    compact = re.sub(r"[^a-z0-9]", "", text.lower())
    suspicious_sequences = [
        "ignoreallpreviousinstructions",
        "revealthesystemprompt",
        "showthesystemprompt",
        "printthesystemprompt",
        "followthisinstead",
    ]
    return any(seq in compact for seq in suspicious_sequences)


def heuristic_prompt_injection_score(text: str) -> int:
    normalized = _normalize_for_heuristics(text)
    score = 0

    for term, weight in HEURISTIC_TERMS.items():
        if term in normalized:
            score += weight

    override_hits = _regex_match_count(text, OVERRIDE_PATTERNS)
    exfil_hits = _regex_match_count(text, EXFIL_PATTERNS)
    role_hits = _regex_match_count(text, ROLE_HIJACK_PATTERNS)
    encoding_hits = _regex_match_count(text, ENCODING_PATTERNS)
    separator_hits = _regex_match_count(text, SEPARATOR_PATTERNS)

    score += override_hits * 4
    score += exfil_hits * 5
    score += role_hits * 3
    score += encoding_hits * 2
    score += separator_hits * 2

    if _has_split_override_phrase(text):
        score += 5

    if "system" in normalized and "prompt" in normalized:
        score += 2

    if "ignore" in normalized and ("instructions" in normalized or "rules" in normalized):
        score += 2

    if (
        ("reveal" in normalized or "show" in normalized or "print" in normalized)
        and ("prompt" in normalized or "instructions" in normalized)
    ):
        score += 3

    return score


def _get_threshold() -> int:
    raw = os.environ.get("IRONCLAW_HEURISTIC_THRESHOLD", "6")
    try:
        value = int(raw)
    except ValueError:
        value = 6
    return max(1, min(50, value))


def is_heuristic_prompt_injection(text: str) -> bool:
    return heuristic_prompt_injection_score(text) >= _get_threshold()