"""Container entrypoint for the IronClaw sandbox scanner. Standard library only.

Reads one JSON scan request from stdin and writes one verdict JSON object to stdout.
Parse errors, oversized input, and any suspicious pattern produce a block verdict.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

# Sized for a 100,000-character return window with worst-case ASCII escaping plus a 512 KiB payload.
MAX_INPUT_BYTES = 2_097_152
SUSPICIOUS_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b",
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"\b__import__\s*\(",
        r"\bos\.(system|popen|exec\w*|spawn\w*)\b",
        r"\bsubprocess\b",
        r"\bpty\.spawn\b",
        r"\bbase64\s+(-d|--decode)\b",
        r"\b(nc|ncat|netcat)\b[^\n]*\s-[a-z]*e\b",
        r"/dev/tcp/",
        r"\brm\s+-rf\s+/",
        r"\bsocket\.socket\s*\(",
        r"\b(ba|z)?sh\s+-i\s*>&",
        r"\bmkfifo\b",
        r"\b(curl|wget)\b[^\n]*(\s-d\s*@|--data(-binary|-raw)?\s*@|\s-F\s*\S*@|--post-file\b|--upload-file\b)",
        r"\b(gopher|dict|tftp|ldap)://",
        r"file:///?(etc|root|proc|home|var|users|windows)/",
        r"169\.254\.169\.254",
        r"169\.254\.170\.2\b",
        r"100\.100\.100\.200\b",
        r"fd00:ec2::254",
        r"metadata\.google\.internal",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"\b(iex|invoke-expression)\b[^\n]*\b(downloadstring|downloadfile|iwr|irm|invoke-webrequest|invoke-restmethod)\b",
        r"\b(downloadstring|downloadfile)\s*\(",
        r"-e(nc|ncodedcommand)\s+[a-z0-9+/=]{20,}",
        r"\bcertutil\b[^\n]*-urlcache\b",
        r"\.ssh[/\\](id_[a-z0-9_]+|authorized_keys)\b",
        r"\.aws[/\\]credentials\b",
        r"\bignore (all )?(the )?(previous|prior|above) instructions",
        r"\bdisregard (all )?(the )?(previous|prior|above|earlier) (instructions|prompts|rules)",
        r"<\|im_(start|end)\|>|<\|(system|user|assistant)\|>|\[/?INST\]",
        r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]",
    )
)


def _block(reason: str) -> dict[str, str]:
    return {"verdict": "block", "reason": reason}


def _collect_strings(value: Any, out: list[str]) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            out.append(str(key))
            _collect_strings(item, out)
    elif isinstance(value, list):
        for item in value:
            _collect_strings(item, out)


def evaluate(raw: bytes) -> dict[str, str]:
    if len(raw) > MAX_INPUT_BYTES:
        return _block("input_too_large")
    try:
        text = raw.decode("utf-8")
        request = json.loads(text)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return _block("invalid_request")
    if not isinstance(request, dict):
        return _block("invalid_request")

    strings: list[str] = []
    _collect_strings(request, strings)
    haystack = "\n".join([text, *strings])
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern.search(haystack):
            return _block("suspicious_content")
    return {"verdict": "allow", "reason": "clean"}


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    sys.stdout.write(json.dumps(evaluate(raw)))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
