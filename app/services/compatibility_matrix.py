from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

CompatibilityState = Literal["supported", "warning", "unsupported"]
RuntimeFamily = Literal[
    "claude-code",
    "openclaw",
    "cursor",
    "goose",
    "gemini-cli",
    "copilot",
    "security-guardian",
    "generic-agent",
]

_RUNTIME_ALIASES: dict[str, tuple[str, ...]] = {
    "claude-code": ("claude-code", "claude_code", "claude"),
    "openclaw": ("openclaw", "open_claw", "open-claw", "ironclaw"),
    "cursor": ("cursor", "cursor-agent", "cursor_agent", "cursor agent", "cursor-cli", "cursor_cli", "cursor cli"),
    "goose": ("goose", "goose-agent", "goose_agent", "goose agent", "goose-cli", "goose_cli", "goose cli"),
    "gemini-cli": ("gemini-cli", "gemini_cli", "gemini cli", "gemini"),
    "copilot": ("copilot", "github-copilot", "github_copilot", "github copilot", "githubcopilot"),
    "security-guardian": (
        "security-guardian",
        "security_guardian",
        "security guardian",
        "securityguardian",
        "skill",
        "skills",
        "security_guardian_skill",
        "security_guardian_skill_",
    ),
    "generic-agent": ("generic-agent", "generic_agent", "generic agent"),
}

_RUNTIME_CONFIG: dict[str, dict[str, Any]] = {
    "claude-code": {
        "min_version": "0.1.0",
        "max_version": "1.9.99",
        "state": "supported",
        "reason": "Claude Code adapter contract is supported for Gen1.",
        "metadata": {
            "priority": 1,
            "install_key_program": "claude_code",
            "install_key_prefix": "ic_install_claude_code_",
            "compatible_runtime_aliases": _RUNTIME_ALIASES["claude-code"],
        },
    },
    "openclaw": {
        "min_version": "0.1.0",
        "max_version": "1.9.99",
        "state": "supported",
        "reason": "OpenClaw adapter contract is supported for Gen1.",
        "metadata": {
            "priority": 1,
            "install_key_program": "openclaw",
            "install_key_prefix": "ic_install_openclaw_",
            "compatible_runtime_aliases": _RUNTIME_ALIASES["openclaw"],
        },
    },
    "cursor": {
        "min_version": "0.1.0",
        "max_version": "1.9.99",
        "state": "supported",
        "reason": "Cursor runtime is supported via the Cursor install-key family and local adapter hooks.",
        "metadata": {
            "priority": 2,
            "install_key_program": "cursor",
            "install_key_prefix": "ic_install_cursor_",
            "compatible_runtime_aliases": _RUNTIME_ALIASES["cursor"],
            "compatible_platform_runtimes": ["cursor", "cursor-agent", "cursor-agent", "cursor cli"],
        },
    },
    "goose": {
        "min_version": "0.1.0",
        "max_version": "1.9.99",
        "state": "supported",
        "reason": "Goose runtime is supported through its install-key family and local security hooks.",
        "metadata": {
            "priority": 2,
            "install_key_program": "goose",
            "install_key_prefix": "ic_install_goose_",
            "compatible_runtime_aliases": _RUNTIME_ALIASES["goose"],
            "compatible_platform_runtimes": ["goose", "goose-agent", "goose cli"],
        },
    },
    "gemini-cli": {
        "min_version": "0.1.0",
        "max_version": "1.9.99",
        "state": "supported",
        "reason": "Gemini CLI is supported for direct local runtime guarding and execution review.",
        "metadata": {
            "priority": 2,
            "install_key_program": "gemini_cli",
            "install_key_prefix": "ic_install_gemini_cli_",
            "compatible_runtime_aliases": _RUNTIME_ALIASES["gemini-cli"],
            "compatible_platform_runtimes": ["gemini-cli", "gemini cli", "gemini"],
        },
    },
    "copilot": {
        "min_version": "0.1.0",
        "max_version": "1.9.99",
        "state": "supported",
        "reason": "GitHub Copilot is supported with the Copilot install-key family and local policy enforcement.",
        "metadata": {
            "priority": 2,
            "install_key_program": "copilot",
            "install_key_prefix": "ic_install_copilot_",
            "compatible_runtime_aliases": _RUNTIME_ALIASES["copilot"],
            "compatible_platform_runtimes": ["copilot", "github-copilot", "github copilot"],
        },
    },
    "security-guardian": {
        "min_version": "0.1.0",
        "max_version": "1.9.99",
        "state": "supported",
        "reason": "The shared security-guardian skills package can be attached to multiple runtime installers while preserving the same install-key family.",
        "metadata": {
            "priority": 3,
            "install_key_program": "security_guardian",
            "install_key_prefix": "ic_install_security_guardian_",
            "compatible_runtime_aliases": _RUNTIME_ALIASES["security-guardian"],
            "compatible_platform_runtimes": ["security-guardian", "security_guardian", "skill", "skills"],
            "multi_runtime_assignment": True,
            "install_key_family_shared_across_platforms": True,
        },
    },
    "generic-agent": {
        "min_version": "0.1.0",
        "max_version": "0.9.99",
        "state": "warning",
        "reason": "Generic agent support is available but may require custom wrapper hooks.",
        "metadata": {
            "priority": 4,
            "install_key_program": None,
            "install_key_prefix": None,
            "compatible_runtime_aliases": _RUNTIME_ALIASES["generic-agent"],
            "compatible_platform_runtimes": ["generic-agent", "generic agent"],
        },
    },
}


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_text(value: str | None) -> str:
    return (value or "").strip()


def _canonical_runtime_family(value: str | None) -> str:
    candidate = _normalize_text(value).lower().replace("_", "-")
    if not candidate:
        return ""

    for canonical, aliases in _RUNTIME_ALIASES.items():
        if candidate == canonical:
            return canonical
        if candidate in {alias.lower().replace("_", "-") for alias in aliases}:
            return canonical

    return candidate


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
    rules: list[CompatibilityRule] = []
    for runtime_family, config in _RUNTIME_CONFIG.items():
        rules.append(
            CompatibilityRule(
                runtime_family=runtime_family,
                min_version=config["min_version"],
                max_version=config["max_version"],
                state=config["state"],
                reason=config["reason"],
                metadata=config["metadata"],
            )
        )
    return rules


def initialize_compatibility_matrix() -> CompatibilityMatrix:
    return CompatibilityMatrix(
        rules=default_compatibility_rules(),
        metadata={
            "matrix_version": "1.1.0",
            "scope": "IronClaw-Security",
            "install_key_family_tracking": {
                "program_key": "install_key_program",
                "prefix_key": "install_key_prefix",
                "shared_runtime_assignment": "multi_runtime_assignment",
            },
        },
    )


def list_compatibility_rules(
    matrix: CompatibilityMatrix,
    *,
    runtime_family: str | None = None,
) -> list[CompatibilityRule]:
    rules = list(matrix.rules)
    if runtime_family:
        normalized = _canonical_runtime_family(runtime_family)
        rules = [rule for rule in rules if _canonical_runtime_family(rule.runtime_family) == normalized]

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
    normalized_family = _canonical_runtime_family(runtime_family)
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
                metadata={
                    "matched": True,
                    "install_key_program": rule.metadata.get("install_key_program"),
                    "install_key_prefix": rule.metadata.get("install_key_prefix"),
                    "compatible_runtime_aliases": rule.metadata.get("compatible_runtime_aliases", ()),
                },
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
