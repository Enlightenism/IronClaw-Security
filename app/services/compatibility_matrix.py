from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal


CompatibilityState = Literal["supported", "warning", "unsupported"]
RuntimeFamily = Literal["claude-code", "openclaw", "generic-agent"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_text(value: str | None) -> str:
    return (value or "").strip()


def _parse_version(version: str) -> tuple[int, int, int]:
    normalized = _normalize_text(version)
    if not normalized:
        raise ValueError("version is required")

    parts = normalized.split(".")
    if len(parts) < 3:
        parts = parts + ["0"] * (3 - len(parts))
    if len(parts) > 3:
        parts = parts[:3]

    try:
        major, minor, patch = (int(part) for part in parts)
    except ValueError as exc:
        raise ValueError(f"invalid version: {version}") from exc

    return major, minor, patch


@dataclass(slots=True)
class CompatibilityRule:
    runtime_family: RuntimeFamily
    min_version: str
    max_version: str
    state: CompatibilityState
    reason: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "runtime_family": self.runtime_family,
            "min_version": self.min_version,
            "max_version": self.max_version,
            "state": self.state,
            "reason": self.reason,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class CompatibilityMatrix:
    rules: list[CompatibilityRule] = field(default_factory=list)
    generated_at: str = field(default_factory=_utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rules": [rule.to_dict() for rule in self.rules],
            "generated_at": self.generated_at,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class CompatibilityDecision:
    runtime_family: str
    version: str
    state: CompatibilityState
    reason: str
    checked_at: str = field(default_factory=_utc_now)
    matched_rule: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "runtime_family": self.runtime_family,
            "version": self.version,
            "state": self.state,
            "reason": self.reason,
            "checked_at": self.checked_at,
            "matched_rule": dict(self.matched_rule or {}),
            "metadata": dict(self.metadata),
        }


def default_compatibility_rules() -> list[CompatibilityRule]:
    return [
        CompatibilityRule(
            runtime_family="claude-code",
            min_version="0.1.0",
            max_version="1.9.99",
            state="supported",
            reason="Claude Code adapter contract is supported for Gen1.",
            metadata={"priority": 1},
        ),
        CompatibilityRule(
            runtime_family="openclaw",
            min_version="0.1.0",
            max_version="1.9.99",
            state="supported",
            reason="OpenClaw adapter contract is supported for Gen1.",
            metadata={"priority": 1},
        ),
        CompatibilityRule(
            runtime_family="generic-agent",
            min_version="0.1.0",
            max_version="0.9.99",
            state="warning",
            reason="Generic agent support is available but may require custom wrapper hooks.",
            metadata={"priority": 1},
        ),
    ]


def initialize_compatibility_matrix() -> CompatibilityMatrix:
    return CompatibilityMatrix(
        rules=default_compatibility_rules(),
        metadata={
            "matrix_version": "1.0.0",
            "scope": "IronClaw-Security",
        },
    )


def list_compatibility_rules(
    matrix: CompatibilityMatrix,
    *,
    runtime_family: str | None = None,
) -> list[CompatibilityRule]:
    rules = list(matrix.rules)
    if runtime_family:
        normalized = _normalize_text(runtime_family).lower()
        rules = [rule for rule in rules if rule.runtime_family == normalized]

    return sorted(
        rules,
        key=lambda item: (
            item.runtime_family,
            _parse_version(item.min_version),
            _parse_version(item.max_version),
        ),
    )


def evaluate_compatibility(
    matrix: CompatibilityMatrix,
    *,
    runtime_family: str,
    version: str,
) -> CompatibilityDecision:
    normalized_family = _normalize_text(runtime_family).lower()
    normalized_version = _normalize_text(version)

    if not normalized_family:
        raise ValueError("runtime_family is required")
    if not normalized_version:
        raise ValueError("version is required")

    parsed_version = _parse_version(normalized_version)

    candidates = list_compatibility_rules(
        matrix,
        runtime_family=normalized_family,
    )

    for rule in candidates:
        min_version = _parse_version(rule.min_version)
        max_version = _parse_version(rule.max_version)
        if min_version <= parsed_version <= max_version:
            return CompatibilityDecision(
                runtime_family=normalized_family,
                version=normalized_version,
                state=rule.state,
                reason=rule.reason,
                matched_rule=rule.to_dict(),
                metadata={"matched": True},
            )

    return CompatibilityDecision(
        runtime_family=normalized_family,
        version=normalized_version,
        state="unsupported",
        reason="No compatibility rule matched this runtime family and version.",
        matched_rule=None,
        metadata={"matched": False},
    )


def summarize_compatibility_decision(
    decision: CompatibilityDecision,
) -> dict[str, Any]:
    return {
        "runtime_family": decision.runtime_family,
        "version": decision.version,
        "state": decision.state,
        "reason": decision.reason,
        "checked_at": decision.checked_at,
        "matched": bool(decision.matched_rule),
    }