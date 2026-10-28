from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
import re
from typing import Any, Literal

SECRET_PATTERNS: dict[str, str] = {
    "openai_api_key": r"\bsk-[A-Za-z0-9]{20,}\b",
    "aws_access_key": r"\bAKIA[0-9A-Z]{16}\b",
    "github_token": r"\bghp_[A-Za-z0-9]{20,}\b",
    "slack_token": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
    "jwt": r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\b",
    "private_key_block": r"-----BEGIN [A-Z ]+PRIVATE KEY-----",
}

DANGEROUS_OUTPUT_PATTERNS: dict[str, str] = {
    "powershell_encoded": r"powershell\s+-enc\b",
    "curl_pipe_bash": r"curl\s+[^|]+\|\s*(bash|sh)\b",
    "wget_pipe_shell": r"wget\s+[^|]+\|\s*(bash|sh)\b",
    "command_chaining_delete": r"(rm\s+-rf|del\s+/f\s+/q|format\s+c:)",
    "script_tag": r"<script\b",
    "data_exfil_url": r"https?://[^\s]+/(collect|exfil|beacon|callback)\b",
}

REDACTION_TOKEN = "[REDACTED]"


@dataclass(slots=True)
class OutputSanitizationResult:
    sanitized_text: str
    modified: bool
    risk_score: int
    verdict: Literal["allow", "block"]
    reason: str
    redacted_items: list[str] = field(default_factory=list)
    failed_checks: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _extract_text(payload: Any) -> str:
    if isinstance(payload, str):
        return payload

    if isinstance(payload, Mapping):
        for key in ("content", "text", "output", "message", "result", "summary"):
            value = payload.get(key)
            if isinstance(value, str):
                return value
        return str(payload)

    return str(payload)


def _redact_patterns(
    text: str,
    patterns: Mapping[str, str],
    failed_checks: list[str],
    redacted_items: list[str],
) -> tuple[str, int]:
    hits = 0
    sanitized = text

    for label, pattern in patterns.items():
        matches = re.findall(pattern, sanitized, flags=re.IGNORECASE)
        if matches:
            sanitized = re.sub(pattern, REDACTION_TOKEN, sanitized, flags=re.IGNORECASE)
            hits += len(matches)
            redacted_items.append(label)
            failed_checks.append(f"redacted {label}")

    return sanitized, hits


def sanitize_output(payload: Any) -> OutputSanitizationResult:
    original_text = _extract_text(payload)
    failed_checks: list[str] = []
    redacted_items: list[str] = []

    sanitized_text, secret_hits = _redact_patterns(
        original_text,
        SECRET_PATTERNS,
        failed_checks,
        redacted_items,
    )
    sanitized_text, dangerous_hits = _redact_patterns(
        sanitized_text,
        DANGEROUS_OUTPUT_PATTERNS,
        failed_checks,
        redacted_items,
    )

    modified = sanitized_text != original_text
    risk_score = min(100, secret_hits * 30 + dangerous_hits * 20)

    if secret_hits > 0:
        verdict = "block"
        reason = "sensitive secret material detected in output"
    elif dangerous_hits > 0:
        verdict = "block"
        reason = "dangerous executable or exfiltration-style output detected"
    else:
        verdict = "allow"
        reason = "output passed sanitization checks"

    return OutputSanitizationResult(
        sanitized_text=sanitized_text,
        modified=modified,
        risk_score=risk_score,
        verdict=verdict,
        reason=reason,
        redacted_items=redacted_items,
        failed_checks=failed_checks,
        metadata={"source": "output_sanitizer"},
    )


def summarize_output_sanitizer(payload: Any) -> dict[str, Any]:
    return sanitize_output(payload).to_dict()


__all__ = [
    "DANGEROUS_OUTPUT_PATTERNS",
    "REDACTION_TOKEN",
    "SECRET_PATTERNS",
    "OutputSanitizationResult",
    "sanitize_output",
    "summarize_output_sanitizer",
]
