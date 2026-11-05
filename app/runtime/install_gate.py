"""Install gate: allows IronClaw-pinned installs and scans every other install source before allowing it. Fails closed."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import logging
import re
from typing import Any, Final

from app.core.install_key_formats import InstallKeyFormatRegistry
from app.runtime.return_scanner import ALLOW_VERDICT, BLOCK_VERDICT
from app.schemas.telemetry import TelemetryEventType
from app.services.audit_store import record_gate_audit_event
from app.services.block_store import GATE_INSTALL, record_block
from app.services.incident_store import record_gate_block_incident
from app.services.install_allowlist import find_pinned_install_block, fingerprint_install_block
from app.services.telemetry import append_telemetry_event
from app.services.third_party_install_scanner import download_pipe_body, scan_third_party_install

logger = logging.getLogger(__name__)

MAX_INSTALL_COMMAND_CHARS: Final[int] = 4096
SHELL_METACHARACTERS: Final[frozenset[str]] = frozenset(";&|`<>$()")
ALLOWED_CONTROL_CHARACTERS: Final[frozenset[str]] = frozenset("\t\r\n")

FAMILY_IRONCLAW: Final[str] = "ironclaw_installer"
FAMILY_CLAUDE_PLUGIN: Final[str] = "claude_plugin"
FAMILY_HERMES_SKILL: Final[str] = "hermes_skill"
FAMILY_GH_SKILL: Final[str] = "gh_skill"
FAMILY_OPENCLAW: Final[str] = "openclaw"
FAMILY_GOOSE_RECIPE: Final[str] = "goose_recipe"
FAMILY_NPM: Final[str] = "npm"
FAMILY_PIP: Final[str] = "pip"
FAMILY_GIT: Final[str] = "git"
FAMILY_DOWNLOAD_PIPE: Final[str] = "download_pipe"
FAMILY_UNRESOLVABLE: Final[str] = "unresolvable_package_manager"
FAMILY_UNKNOWN: Final[str] = "unknown"
FAMILY_MIXED: Final[str] = "mixed"
FAMILY_MALFORMED: Final[str] = "malformed"

_LINE_FAMILY_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (FAMILY_IRONCLAW, re.compile(r"\bironclaw_installer\b")),
    (FAMILY_DOWNLOAD_PIPE, re.compile(r"\b(curl|wget)\b(?=.*https://).*(\|\s*(sudo\s+)?(sh|bash|zsh|python3?)\b|(&&|;)\s*(sudo\s+)?(sh|bash|zsh)\b)")),
    (FAMILY_DOWNLOAD_PIPE, re.compile(r"\$\(\s*(curl|wget|iwr|irm)\b|<\(\s*(curl|wget)\b")),
    (FAMILY_HERMES_SKILL, re.compile(r"\bhermes\s+skills?\b")),
    (FAMILY_GH_SKILL, re.compile(r"\bgh\s+skill\b")),
    (FAMILY_CLAUDE_PLUGIN, re.compile(r"\bclaude\s+(plugins?|marketplace)\b|/plugin\s+install\b")),
    (FAMILY_OPENCLAW, re.compile(r"\bopenclaw\s+(plugins?|skills?)\b")),
    (FAMILY_GOOSE_RECIPE, re.compile(r"\bgoose\s+(recipe|run)\b|--recipe\b")),
    (FAMILY_NPM, re.compile(r"^\s*npx\b|^\s*(npm|pnpm|yarn)\s+(install|i|add|ci|exec|dlx)\b")),
    (FAMILY_PIP, re.compile(r"\bpip3?\s+install\b")),
    (FAMILY_GIT, re.compile(r"^\s*git\s+(clone|submodule|fetch|pull)\b|\bgit\+")),
    (FAMILY_UNRESOLVABLE, re.compile(r"\b(?:brew|cargo|go|gem|composer|apt-get|apt|winget|choco|conda)\s+(?:install|get|add)\b|--install-extension\b")),
)


@dataclass(frozen=True)
class InstallGateDecision:
    verdict: str
    family: str
    program: str | None
    pinned: bool
    reasons: list[str] = field(default_factory=list)
    fingerprint: str = ""
    artifacts: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.verdict == ALLOW_VERDICT


def _deny(family: str, program: str | None, reason: str, *, pinned: bool = False, fingerprint: str = "") -> InstallGateDecision:
    return InstallGateDecision(BLOCK_VERDICT, family, program, pinned, [reason], fingerprint)


def _malformed_reason(command: str, download_body: str | None) -> str | None:
    if not command.strip():
        return "empty_command"
    if len(command) > MAX_INSTALL_COMMAND_CHARS:
        return "command_too_long"
    if not command.isascii():
        return "non_ascii"
    if any((ord(char) < 32 and char not in ALLOWED_CONTROL_CHARACTERS) or ord(char) == 127 for char in command):
        return "control_characters"
    checked = command if download_body is None else download_body
    if any(char in SHELL_METACHARACTERS for char in checked):
        return "shell_metacharacters"
    return None


def _classify_line(line: str) -> str:
    for family, pattern in _LINE_FAMILY_PATTERNS:
        if pattern.search(line):
            return family
    return FAMILY_UNKNOWN


def classify_install_family(command: str) -> str:
    families = {_classify_line(line) for line in command.splitlines() if line.strip()}
    if not families:
        return FAMILY_UNKNOWN
    if len(families) == 1:
        return families.pop()
    return FAMILY_MIXED


def _evaluate(command: str, platform: str) -> InstallGateDecision:
    download_body = download_pipe_body(command)
    malformed = _malformed_reason(command, download_body)
    if malformed is not None:
        return _deny(FAMILY_MALFORMED, None, malformed)

    program = InstallKeyFormatRegistry.normalize_program(platform)
    if program is None:
        return _deny(FAMILY_UNKNOWN, None, "unsupported_platform")

    fingerprint = fingerprint_install_block(command)
    pin = find_pinned_install_block(command)
    if pin is None:
        outcome = scan_third_party_install(command if download_body is None else download_body, platform=program)
        verdict = ALLOW_VERDICT if outcome.allowed else BLOCK_VERDICT
        return InstallGateDecision(verdict, classify_install_family(command), None, False, outcome.reasons, fingerprint, outcome.artifacts)
    if pin.program != program:
        return _deny(FAMILY_IRONCLAW, pin.program, "platform_mismatch", pinned=True, fingerprint=fingerprint)

    source_tokens = {token for token in command.split() if "://" in token}
    if not source_tokens <= set(pin.source_urls):
        return _deny(FAMILY_IRONCLAW, pin.program, "source_not_allowed", pinned=True, fingerprint=fingerprint)
    return InstallGateDecision(ALLOW_VERDICT, FAMILY_IRONCLAW, pin.program, True, ["pinned_install_command"], fingerprint)


def _record_decision(
    decision: InstallGateDecision,
    *,
    platform: str,
    agent_id: str | None,
    client_id: str | None,
    owner_key: str | None,
) -> None:
    try:
        append_telemetry_event(
            TelemetryEventType.INSTALL_GATE_DECISION,
            {
                "verdict": decision.verdict,
                "family": decision.family,
                "program": decision.program,
                "pinned": decision.pinned,
                "reasons": decision.reasons,
                "fingerprint": decision.fingerprint,
                "artifacts": decision.artifacts,
                "platform": platform,
                "agent_id": agent_id,
                "client_id": client_id,
            },
        )
    except Exception:
        logger.exception("install gate telemetry write failed")
    record_gate_audit_event(
        gate=GATE_INSTALL,
        verdict=decision.verdict,
        platform=platform,
        reason_codes=decision.reasons,
        owner_key=owner_key,
        agent_id=agent_id,
        details={
            "family": decision.family,
            "program": decision.program,
            "pinned": decision.pinned,
            "fingerprint": decision.fingerprint,
            "artifacts": decision.artifacts,
        },
    )


def evaluate_install_command(
    command: str,
    *,
    platform: str,
    agent_id: str | None = None,
    client_id: str | None = None,
    owner_key: str | None = None,
) -> InstallGateDecision:
    try:
        decision = _evaluate(command, platform)
    except Exception:
        logger.exception("install gate evaluation failed; blocking")
        decision = _deny(FAMILY_UNKNOWN, None, "install_gate_error")
    _record_decision(decision, platform=platform, agent_id=agent_id, client_id=client_id, owner_key=owner_key)
    if not decision.allowed:
        record_block(gate=GATE_INSTALL, platform=platform, reason_codes=decision.reasons, owner_key=owner_key)
        record_gate_block_incident(gate=GATE_INSTALL, platform=platform, reason_codes=decision.reasons, owner_key=owner_key)
    return decision


def is_install_command(command: str) -> bool:
    return classify_install_family(command) != FAMILY_UNKNOWN


def _string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        value = list(value.values())
    if isinstance(value, list):
        return [text for child in value for text in _string_values(child)]
    return []


def install_command_from_content(content: str) -> str:
    try:
        parsed = json.loads(content)
    except ValueError:
        return content
    if isinstance(parsed, str):
        return parsed
    if not isinstance(parsed, dict | list):
        return content
    return " ".join(_string_values(parsed))


def gate_shell_payload(
    content: str,
    *,
    platform: str | None,
    agent_id: str | None = None,
    client_id: str | None = None,
    owner_key: str | None = None,
) -> InstallGateDecision | None:
    command = install_command_from_content(content)
    if not is_install_command(command):
        return None
    return evaluate_install_command(
        command,
        platform=platform or "",
        agent_id=agent_id,
        client_id=client_id,
        owner_key=owner_key,
    )
