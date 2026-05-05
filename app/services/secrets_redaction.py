from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable


REDACTION_TOKEN = "•••"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_text(value: str | None) -> str:
    return (value or "").strip()


@dataclass(slots=True)
class RedactionRule:
    """Simple pattern-based redaction rule.

    Gen1 keeps this intentionally local-first and regex-free for determinism and
    safety: we rely on prefix/suffix markers and keyword windows instead of
    unbounded patterns.
    """

    name: str
    description: str
    enabled: bool = True
    prefixes: list[str] = field(default_factory=list)
    suffixes: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    window: int = 64  # number of characters to scan around a keyword
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "prefixes": list(self.prefixes),
            "suffixes": list(self.suffixes),
            "keywords": list(self.keywords),
            "window": self.window,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class RedactionResult:
    original: str
    redacted: str
    applied_rules: list[str] = field(default_factory=list)
    redacted_spans: list[tuple[int, int]] = field(default_factory=list)
    checked_at: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "original": self.original,
            "redacted": self.redacted,
            "applied_rules": list(self.applied_rules),
            "redacted_spans": [list(span) for span in self.redacted_spans],
            "checked_at": self.checked_at,
        }


@dataclass(slots=True)
class SecretRedactionConfig:
    """Configuration for local secret redaction in Gen1."""

    enabled: bool = True
    max_span_length: int = 256
    rules: list[RedactionRule] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "max_span_length": self.max_span_length,
            "rules": [rule.to_dict() for rule in self.rules],
            "metadata": dict(self.metadata),
        }


def _default_rules() -> list[RedactionRule]:
    # These are heuristic, local-first markers for common secret patterns.
    return [
        RedactionRule(
            name="api-key",
            description="Redact obvious API key and token markers.",
            prefixes=["api_key=", "api-key=", "apikey=", "token=", "auth_token="],
            suffixes=["\"", "'", " ", "\n"],
            keywords=["api key", "token", "secret"],
            window=96,
            metadata={"priority": 1},
        ),
        RedactionRule(
            name="password",
            description="Redact inline password markers.",
            prefixes=["password=", "passwd=", "pwd="],
            suffixes=["\"", "'", " ", "\n"],
            keywords=["password", "pwd"],
            window=96,
            metadata={"priority": 1},
        ),
        RedactionRule(
            name="ssh-key-header",
            description="Redact SSH private key blocks.",
            prefixes=["-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----"],
            suffixes=["-----END OPENSSH PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"],
            window=4096,
            metadata={"priority": 0},
        ),
    ]


def initialize_secrets_redaction_config() -> SecretRedactionConfig:
    """Initialize the default local redaction configuration for Gen1."""
    return SecretRedactionConfig(
        enabled=True,
        max_span_length=256,
        rules=_default_rules(),
        metadata={
            "strategy": "local-heuristic",
            "review_required_for_overrides": True,
        },
    )


def _find_spans_by_prefix_suffix(
    text: str,
    prefixes: Iterable[str],
    suffixes: Iterable[str],
    max_span_length: int,
) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    lower_text = text.lower()

    for prefix in prefixes:
        if not prefix:
            continue
        prefix_lower = prefix.lower()
        start = 0
        while True:
            idx = lower_text.find(prefix_lower, start)
            if idx == -1:
                break

            end_limit = min(len(text), idx + max_span_length)
            best_end = end_limit

            for suffix in suffixes:
                if not suffix:
                    continue
                suffix_lower = suffix.lower()
                s_idx = lower_text.find(suffix_lower, idx + len(prefix_lower), end_limit)
                if s_idx != -1:
                    candidate_end = s_idx + len(suffix)
                    if candidate_end <= end_limit:
                        best_end = candidate_end
                        break

            spans.append((idx, best_end))
            start = best_end

    return spans


def _merge_overlapping_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not spans:
        return []

    spans = sorted(spans, key=lambda s: (s[0], s[1]))
    merged: list[tuple[int, int]] = [spans[0]]

    for start, end in spans[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))

    return merged


def redact_secrets(
    text: str,
    config: SecretRedactionConfig | None = None,
) -> RedactionResult:
    """Redact obvious secrets from the provided text using local rules.

    This is designed for prompt/tool payload pre-processing before they leave
    the trusted boundary.
    """
    if config is None:
        config = initialize_secrets_redaction_config()

    if not config.enabled or not config.rules:
        return RedactionResult(
            original=text,
            redacted=text,
            applied_rules=[],
            redacted_spans=[],
        )

    spans: list[tuple[int, int]] = []
    applied_rules: list[str] = []

    for rule in config.rules:
        if not rule.enabled:
            continue

        rule_spans = _find_spans_by_prefix_suffix(
            text,
            prefixes=rule.prefixes,
            suffixes=rule.suffixes or [" ", "\n"],
            max_span_length=min(rule.window, config.max_span_length),
        )
        if rule_spans:
            applied_rules.append(rule.name)
            spans.extend(rule_spans)

    merged_spans = _merge_overlapping_spans(spans)
    if not merged_spans:
        return RedactionResult(
            original=text,
            redacted=text,
            applied_rules=[],
            redacted_spans=[],
        )

    redacted_parts: list[str] = []
    last_idx = 0
    for start, end in merged_spans:
        redacted_parts.append(text[last_idx:start])
        redacted_parts.append(REDACTION_TOKEN)
        last_idx = end
    redacted_parts.append(text[last_idx:])

    redacted_text = "".join(redacted_parts)

    return RedactionResult(
        original=text,
        redacted=redacted_text,
        applied_rules=applied_rules,
        redacted_spans=merged_spans,
    )


def summarize_redaction_result(result: RedactionResult) -> dict[str, Any]:
    """Compact summary for UI/telemetry views."""
    return {
        "checked_at": result.checked_at,
        "redacted": result.redacted != result.original,
        "applied_rule_count": len(result.applied_rules),
        "span_count": len(result.redacted_spans),
    }