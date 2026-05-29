from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Patterns — extend as needed
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key", re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{32,}")),
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9\-_]{32,}")),
    ("generic_api_key", re.compile(r"(?i)(api[_\-]?key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{20,}['\"]?")),
    ("bearer_token", re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}")),
    ("private_key_header", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("password_field", re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?.{6,}['\"]?")),
    ("connection_string", re.compile(r"(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s'\"]+")),
]


def scan_for_secrets(content: str) -> list[dict[str, Any]]:
    """Scan raw text for secret patterns. Returns a list of finding dicts."""
    findings: list[dict[str, Any]] = []
    for label, pattern in _SECRET_PATTERNS:
        matches = pattern.findall(content)
        if matches:
            findings.append(
                {
                    "type": label,
                    "count": len(matches),
                    "masked_samples": [_mask(str(m)) for m in matches[:3]],
                }
            )
    return findings


def evaluate_secret_scanner_request(
    *,
    content: str,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate content for secrets and return a structured result dict."""
    findings = scan_for_secrets(content)
    blocked = len(findings) > 0
    return {
        "scanned": True,
        "blocked": blocked,
        "findings": findings,
        "findings_count": len(findings),
        "source": "secret_scanner",
        "context": context or {},
    }


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "•" * len(value)
    return f"{value[:4]}…{value[-4:]}"
