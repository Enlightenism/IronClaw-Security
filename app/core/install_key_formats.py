from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final, Literal

IRONCLAW_GITHUB_REPOSITORY: Final[str] = "Enlightenism/IronClaw-Security"
IRONCLAW_REPOSITORY_URL: Final[str] = f"https://github.com/{IRONCLAW_GITHUB_REPOSITORY}.git"
IRONCLAW_INSTALLER_SOURCE_URL: Final[str] = f"git+{IRONCLAW_REPOSITORY_URL}"
IRONCLAW_PUBLIC_BASE_URL: Final[str] = "https://ironclaw-security.onrender.com"
SECURITY_GUARDIAN_SKILL_NAME: Final[str] = "ironclaw-security"
SECURITY_GUARDIAN_SKILL_REPOSITORY_PATH: Final[str] = f"skills/{SECURITY_GUARDIAN_SKILL_NAME}"
SECURITY_GUARDIAN_SKILL_FILE_PATH: Final[str] = f"{SECURITY_GUARDIAN_SKILL_REPOSITORY_PATH}/SKILL.md"
SECURITY_GUARDIAN_SKILL_ROUTE: Final[str] = f"/{SECURITY_GUARDIAN_SKILL_FILE_PATH}"
SECURITY_GUARDIAN_SKILL_URL: Final[str] = f"{IRONCLAW_PUBLIC_BASE_URL}{SECURITY_GUARDIAN_SKILL_ROUTE}"

_INSTALL_CLAIM_PREFIX_TEMPLATE: Final[str] = f"python -m pip install --no-deps --upgrade {IRONCLAW_INSTALLER_SOURCE_URL}\npython -m ironclaw_installer redeem --program {{program}} --claim-token {{claim_token}}"


def _generic_install_command(agent_cli_id: str | None, program: str) -> str:
    if program == "hermes":
        return f"hermes skills install {SECURITY_GUARDIAN_SKILL_URL} --name {SECURITY_GUARDIAN_SKILL_NAME}"
    if agent_cli_id is None:
        return ""
    return f"gh skill install {IRONCLAW_GITHUB_REPOSITORY} {SECURITY_GUARDIAN_SKILL_REPOSITORY_PATH} --agent {agent_cli_id} --scope user"


RuntimeInstallKeyProgram = Literal[
    "openclaw",
    "claude_code",
    "cursor",
    "goose",
    "gemini_cli",
    "copilot",
    "hermes",
]
InstallKeyProgram = RuntimeInstallKeyProgram | Literal["security_guardian"]
InstallKeyFormatFamily = InstallKeyProgram

RUNTIME_INSTALL_KEY_PROGRAMS: Final[tuple[RuntimeInstallKeyProgram, ...]] = (
    "openclaw",
    "claude_code",
    "cursor",
    "goose",
    "gemini_cli",
    "copilot",
    "hermes",
)
CONNECTOR_INSTALL_KEY_PROGRAMS: Final[tuple[str, ...]] = ("security_guardian",)
SUPPORTED_INSTALL_KEY_PROGRAMS: Final[tuple[InstallKeyProgram, ...]] = (
    *RUNTIME_INSTALL_KEY_PROGRAMS,
    *CONNECTOR_INSTALL_KEY_PROGRAMS,
)

_INSTALL_KEY_PREFIX_OPENCLAW: Final[str] = "ic_install_openclaw_"
_INSTALL_KEY_PREFIX_CLAUDE: Final[str] = "ic_install_claude_code_"
_INSTALL_KEY_PREFIX_CURSOR: Final[str] = "ic_install_cursor_"
_INSTALL_KEY_PREFIX_GOOSE: Final[str] = "ic_install_goose_"
_INSTALL_KEY_PREFIX_GEMINI: Final[str] = "ic_install_gemini_cli_"
_INSTALL_KEY_PREFIX_COPILOT: Final[str] = "ic_install_copilot_"
_INSTALL_KEY_PREFIX_HERMES: Final[str] = "ic_install_hermes_"
_INSTALL_KEY_PREFIX_SECURITY_GUARDIAN: Final[str] = "ic_install_security_guardian_"


def _normalize_platform_token(value: str | None) -> str:
    if value is None:
        return ""
    candidate = str(value).strip().lower()
    if not candidate:
        return ""
    normalized = candidate.replace(" ", "_").replace("-", "_")
    return normalized.replace("__", "_").strip("_")


@dataclass(frozen=True, slots=True)
class InstallKeyFormatSpec:
    """Canonical format metadata for install-key families.

    This registry describes the install-key trust domain rather than the generic
    platform API-key trust domain. It groups platforms by format compatibility
    while preserving the canonical install-key issuance rules enforced by
    app.core.install_keys.
    """

    family: InstallKeyFormatFamily
    program: InstallKeyProgram
    display_name: str
    prefix: str
    aliases: tuple[str, ...]
    platform_aliases: tuple[str, ...]
    agent_cli_id: str | None = None
    command_template: str = ""

    @property
    def canonical_slug(self) -> str:
        return self.program.replace("_", "-")

    @property
    def generic_command(self) -> str:
        """Per-platform skill-install command with no claim embedded."""
        return _generic_install_command(self.agent_cli_id, self.program)

    def __post_init__(self) -> None:
        if not self.prefix:
            raise ValueError("prefix is required")
        if not self.program:
            raise ValueError("program is required")
        if self.family != self.program:
            raise ValueError(f"family and program must match: {self.family!r} != {self.program!r}")
        if not self.command_template:
            object.__setattr__(self, "command_template", self._default_command_template())

    def _default_command_template(self) -> str:
        generic = self.generic_command
        if not generic:
            return _INSTALL_CLAIM_PREFIX_TEMPLATE
        return f"{_INSTALL_CLAIM_PREFIX_TEMPLATE}\n{generic}"

    def format_command(self, install_key: str | None) -> str:
        normalized_key = str(install_key).strip() if install_key is not None else ""
        if not normalized_key:
            raise ValueError("install_key is required")
        payload: dict[str, str] = {
            "claim_token": normalized_key,
            "platform": self.canonical_slug,
            "program": self.program,
        }
        return self.command_template.format(**payload)

    def matches_key(self, candidate: str | None) -> bool:
        if candidate is None:
            return False
        normalized = str(candidate).strip()
        return bool(normalized) and normalized.startswith(self.prefix)

    def parse_program(self, candidate: str | None) -> InstallKeyProgram | None:
        if candidate is None:
            return None
        normalized = _normalize_platform_token(candidate)
        if not normalized:
            return None
        if normalized in tuple(alias.lower().replace(" ", "_").replace("-", "_") for alias in self.aliases) or normalized in tuple(alias.lower().replace(" ", "_").replace("-", "_") for alias in self.platform_aliases):
            return self.program
        return None


class InstallKeyFormatRegistry:
    """Canonical registry for install-key formats and platform aliases.

    The registry models the install-key trust boundary, not generic API-key
    families. It is meant to be the single source of truth for which key family
    corresponds to a given agent platform or install path.
    """

    _SPEC_BY_PROGRAM: Final[dict[InstallKeyProgram, InstallKeyFormatSpec]] = {
        "openclaw": InstallKeyFormatSpec(
            family="openclaw",
            program="openclaw",
            display_name="OpenClaw",
            prefix=_INSTALL_KEY_PREFIX_OPENCLAW,
            aliases=(
                "openclaw",
                "open_claw",
                "open-claw",
                "openclaw_agent",
                "openclaw-agent",
                "openclaw agent",
                "openclaw_cli",
                "openclaw-cli",
                "openclaw cli",
                "ironclaw",
                "claw",
            ),
            platform_aliases=(
                "openclaw",
                "open_claw",
                "open-claw",
                "openclaw_agent",
                "openclaw-agent",
                "openclaw agent",
                "openclaw_cli",
                "openclaw-cli",
                "openclaw cli",
                "ironclaw",
                "claw",
            ),
            agent_cli_id="openclaw",
        ),
        "claude_code": InstallKeyFormatSpec(
            family="claude_code",
            program="claude_code",
            display_name="Claude Code",
            prefix=_INSTALL_KEY_PREFIX_CLAUDE,
            aliases=(
                "claude_code",
                "claude-code",
                "claude code",
                "claude",
                "claude_code_cli",
                "claude-code-cli",
                "claude code cli",
                "anthropic",
            ),
            platform_aliases=(
                "claude_code",
                "claude-code",
                "claude code",
                "claude",
                "claude_code_cli",
                "claude-code-cli",
                "claude code cli",
                "anthropic",
            ),
            agent_cli_id="claude-code",
        ),
        "cursor": InstallKeyFormatSpec(
            family="cursor",
            program="cursor",
            display_name="Cursor",
            prefix=_INSTALL_KEY_PREFIX_CURSOR,
            aliases=(
                "cursor",
                "cursor_agent",
                "cursor-agent",
                "cursor agent",
                "cursor_cli",
                "cursor-cli",
                "cursor cli",
            ),
            platform_aliases=(
                "cursor",
                "cursor_agent",
                "cursor-agent",
                "cursor agent",
                "cursor_cli",
                "cursor-cli",
                "cursor cli",
            ),
            agent_cli_id="cursor",
        ),
        "goose": InstallKeyFormatSpec(
            family="goose",
            program="goose",
            display_name="Goose",
            prefix=_INSTALL_KEY_PREFIX_GOOSE,
            aliases=(
                "goose",
                "goose_agent",
                "goose-agent",
                "goose agent",
                "goose_cli",
                "goose-cli",
                "goose cli",
            ),
            platform_aliases=(
                "goose",
                "goose_agent",
                "goose-agent",
                "goose agent",
                "goose_cli",
                "goose-cli",
                "goose cli",
            ),
            agent_cli_id="goose",
        ),
        "gemini_cli": InstallKeyFormatSpec(
            family="gemini_cli",
            program="gemini_cli",
            display_name="Gemini CLI",
            prefix=_INSTALL_KEY_PREFIX_GEMINI,
            aliases=(
                "gemini_cli",
                "gemini-cli",
                "gemini cli",
                "gemini",
                "gemini_cli_agent",
                "gemini-cli-agent",
            ),
            platform_aliases=(
                "gemini_cli",
                "gemini-cli",
                "gemini cli",
                "gemini",
                "gemini_cli_agent",
                "gemini-cli-agent",
            ),
            agent_cli_id="gemini-cli",
        ),
        "copilot": InstallKeyFormatSpec(
            family="copilot",
            program="copilot",
            display_name="GitHub Copilot",
            prefix=_INSTALL_KEY_PREFIX_COPILOT,
            aliases=(
                "copilot",
                "github_copilot",
                "github-copilot",
                "github copilot",
                "githubcopilot",
                "github_copilot_cli",
                "github-copilot-cli",
            ),
            platform_aliases=(
                "copilot",
                "github_copilot",
                "github-copilot",
                "github copilot",
                "githubcopilot",
                "github_copilot_cli",
                "github-copilot-cli",
            ),
            agent_cli_id="github-copilot",
        ),
        "hermes": InstallKeyFormatSpec(
            family="hermes",
            program="hermes",
            display_name="Hermes",
            prefix=_INSTALL_KEY_PREFIX_HERMES,
            aliases=(
                "hermes",
                "hermes_agent",
                "hermes-agent",
                "hermes agent",
                "hermes_cli",
                "hermes-cli",
                "hermes cli",
            ),
            platform_aliases=(
                "hermes",
                "hermes_agent",
                "hermes-agent",
                "hermes agent",
                "hermes_cli",
                "hermes-cli",
                "hermes cli",
            ),
        ),
        "security_guardian": InstallKeyFormatSpec(
            family="security_guardian",
            program="security_guardian",
            display_name="Security Guardian",
            prefix=_INSTALL_KEY_PREFIX_SECURITY_GUARDIAN,
            aliases=(
                "security_guardian",
                "security-guardian",
                "security guardian",
                "securityguardian",
                "security_guardian_skill",
                "security_guardian_skill_",
                "skill",
                "skills",
            ),
            platform_aliases=(),
        ),
    }

    _PLATFORM_TO_PROGRAM: Final[dict[str, InstallKeyProgram]] = {_normalize_platform_token(alias): program for program, spec in _SPEC_BY_PROGRAM.items() for alias in (*spec.aliases, *spec.platform_aliases) if _normalize_platform_token(alias)}

    @classmethod
    def normalize_program(cls, value: str | None) -> InstallKeyProgram | None:
        if value is None:
            return None
        normalized = _normalize_platform_token(value)
        if not normalized:
            return None
        return cls._PLATFORM_TO_PROGRAM.get(normalized)

    @classmethod
    def normalize_platform(cls, value: str | None) -> str:
        return _normalize_platform_token(value)

    @classmethod
    def get_spec(cls, program: str | None) -> InstallKeyFormatSpec:
        normalized = cls.normalize_program(program)
        if normalized is None:
            raise ValueError(f"Unsupported install-key program or platform: {program!r}")
        return cls._SPEC_BY_PROGRAM[normalized]

    @classmethod
    def get_format_for_platform(cls, platform_name: str | None) -> InstallKeyFormatSpec:
        if platform_name is None:
            raise ValueError("platform_name is required")
        normalized = cls.normalize_platform(platform_name)
        candidate = cls._PLATFORM_TO_PROGRAM.get(normalized)
        if candidate is None:
            raise ValueError(f"Unsupported platform for install-key format registry: {platform_name!r}")
        return cls._SPEC_BY_PROGRAM[candidate]

    @classmethod
    def list_programs(cls) -> tuple[RuntimeInstallKeyProgram, ...]:
        return RUNTIME_INSTALL_KEY_PROGRAMS

    @classmethod
    def list_specs(cls) -> tuple[InstallKeyFormatSpec, ...]:
        return tuple(cls._SPEC_BY_PROGRAM.values())

    @classmethod
    def matches_key_family(cls, candidate: str | None, program: str | None) -> bool:
        try:
            spec = cls.get_spec(program)
        except ValueError:
            return False
        return spec.matches_key(candidate)

    @classmethod
    def parse_program_from_key(cls, candidate: str | None) -> InstallKeyProgram | None:
        if candidate is None:
            return None
        normalized = str(candidate).strip()
        for spec in cls._SPEC_BY_PROGRAM.values():
            if spec.matches_key(normalized):
                return spec.program
        return None

    @classmethod
    def is_supported_platform(cls, value: str | None) -> bool:
        if value is None:
            return False
        return cls.normalize_platform(value) in cls._PLATFORM_TO_PROGRAM

    @classmethod
    def supported_platforms(cls) -> tuple[str, ...]:
        ordered: list[str] = []
        seen: set[str] = set()
        for program in cls.list_programs():
            if program == "security_guardian":
                continue
            platform_slug = _normalize_platform_token(cls._SPEC_BY_PROGRAM[program].program)
            if platform_slug and platform_slug not in seen:
                seen.add(platform_slug)
                ordered.append(platform_slug)
        return tuple(ordered)

    @classmethod
    def list_platforms(cls) -> tuple[str, ...]:
        return cls.supported_platforms()


_default_registry = InstallKeyFormatRegistry()


def get_install_key_format_registry() -> InstallKeyFormatRegistry:
    return _default_registry


def normalize_install_key_program(value: str | None) -> InstallKeyProgram | None:
    return InstallKeyFormatRegistry.normalize_program(value)


def get_install_key_format_spec(program: str | None) -> InstallKeyFormatSpec:
    return InstallKeyFormatRegistry.get_spec(program)


def is_valid_install_key_for_program(candidate: str | None, program: str | None) -> bool:
    return InstallKeyFormatRegistry.matches_key_family(candidate, program)


def iter_supported_install_key_programs() -> Iterable[InstallKeyProgram]:
    return tuple(InstallKeyFormatRegistry.list_programs())


__all__ = [
    "IRONCLAW_GITHUB_REPOSITORY",
    "IRONCLAW_REPOSITORY_URL",
    "IRONCLAW_INSTALLER_SOURCE_URL",
    "IRONCLAW_PUBLIC_BASE_URL",
    "SECURITY_GUARDIAN_SKILL_NAME",
    "SECURITY_GUARDIAN_SKILL_REPOSITORY_PATH",
    "SECURITY_GUARDIAN_SKILL_FILE_PATH",
    "SECURITY_GUARDIAN_SKILL_ROUTE",
    "SECURITY_GUARDIAN_SKILL_URL",
    "InstallKeyProgram",
    "InstallKeyFormatFamily",
    "InstallKeyFormatSpec",
    "InstallKeyFormatRegistry",
    "get_install_key_format_registry",
    "normalize_install_key_program",
    "get_install_key_format_spec",
    "is_valid_install_key_for_program",
    "iter_supported_install_key_programs",
    "_normalize_platform_token",
    "_INSTALL_KEY_PREFIX_OPENCLAW",
    "_INSTALL_KEY_PREFIX_CLAUDE",
    "_INSTALL_KEY_PREFIX_CURSOR",
    "_INSTALL_KEY_PREFIX_GOOSE",
    "_INSTALL_KEY_PREFIX_GEMINI",
    "_INSTALL_KEY_PREFIX_COPILOT",
    "_INSTALL_KEY_PREFIX_HERMES",
    "_INSTALL_KEY_PREFIX_SECURITY_GUARDIAN",
]
