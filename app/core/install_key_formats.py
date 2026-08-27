from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final, Literal

InstallKeyProgram = Literal["openclaw", "claude_code"]
InstallKeyFormatFamily = InstallKeyProgram

_INSTALL_KEY_PREFIX_OPENCLAW: Final[str] = "ic_install_openclaw_"
_INSTALL_KEY_PREFIX_CLAUDE: Final[str] = "ic_install_claude_code_"


@dataclass(frozen=True, slots=True)
class InstallKeyFormatSpec:
    """Canonical format metadata for install-key families.

    This registry is intentionally narrow: it describes the install-key trust
    domain rather than the generic platform API-key trust domain. It is used to
    group platforms by format compatibility while preserving the canonical
    install-key issuance rules enforced by app.core.install_keys.
    """

    family: InstallKeyFormatFamily
    program: InstallKeyProgram
    display_name: str
    prefix: str
    aliases: tuple[str, ...]
    platform_aliases: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.prefix:
            raise ValueError("prefix is required")
        if not self.program:
            raise ValueError("program is required")
        if self.family != self.program:
            raise ValueError(f"family and program must match: {self.family!r} != {self.program!r}")

    def matches_key(self, candidate: str | None) -> bool:
        if candidate is None:
            return False
        normalized = str(candidate).strip()
        return bool(normalized) and normalized.startswith(self.prefix)

    def parse_program(self, candidate: str | None) -> InstallKeyProgram | None:
        if candidate is None:
            return None
        normalized = str(candidate).strip().lower()
        if not normalized:
            return None
        if normalized in self.aliases or normalized in self.platform_aliases:
            return self.program
        return None


class InstallKeyFormatRegistry:
    """Central registry for install-key format families and platform aliases.

    The registry intentionally only models install-key families and their
    canonical program identifiers. It does not perform payment or billing
    validation; that remains the responsibility of app.core.install_keys and the
    installation provisioning services.
    """

    _SPEC_BY_PROGRAM: Final[dict[InstallKeyProgram, InstallKeyFormatSpec]] = {
        "openclaw": InstallKeyFormatSpec(
            family="openclaw",
            program="openclaw",
            display_name="OpenClaw",
            prefix=_INSTALL_KEY_PREFIX_OPENCLAW,
            aliases=("openclaw", "open_claw", "open-claw", "claw"),
            platform_aliases=("openclaw", "ironclaw", "open_claw", "open-claw"),
        ),
        "claude_code": InstallKeyFormatSpec(
            family="claude_code",
            program="claude_code",
            display_name="Claude Code",
            prefix=_INSTALL_KEY_PREFIX_CLAUDE,
            aliases=("claude_code", "claude-code", "claude code", "claude"),
            platform_aliases=("claude_code", "claude-code", "claude code", "anthropic"),
        ),
    }

    _PLATFORM_TO_PROGRAM: Final[dict[str, InstallKeyProgram]] = {alias: program for program, spec in _SPEC_BY_PROGRAM.items() for alias in (*spec.aliases, *spec.platform_aliases)}

    @classmethod
    def normalize_program(cls, value: str | None) -> InstallKeyProgram | None:
        if value is None:
            return None
        candidate = str(value).strip().lower()
        if not candidate:
            return None
        normalized = candidate.replace("-", "_")
        if normalized in cls._PLATFORM_TO_PROGRAM:
            return cls._PLATFORM_TO_PROGRAM[normalized]
        return None

    @classmethod
    def normalize_platform(cls, value: str | None) -> str:
        if value is None:
            return ""
        candidate = str(value).strip().lower()
        if not candidate:
            return ""
        return candidate.replace("-", "_")

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
    def list_programs(cls) -> tuple[InstallKeyProgram, ...]:
        return tuple(cls._SPEC_BY_PROGRAM.keys())

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
        seen: set[str] = set()
        ordered: list[str] = []
        for spec in cls._SPEC_BY_PROGRAM.values():
            for alias in (*spec.platform_aliases, *spec.aliases):
                key = alias.lower().replace("-", "_")
                if key not in seen:
                    seen.add(key)
                    ordered.append(key)
        return tuple(ordered)


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
    "InstallKeyProgram",
    "InstallKeyFormatFamily",
    "InstallKeyFormatSpec",
    "InstallKeyFormatRegistry",
    "get_install_key_format_registry",
    "normalize_install_key_program",
    "get_install_key_format_spec",
    "is_valid_install_key_for_program",
    "iter_supported_install_key_programs",
    "_INSTALL_KEY_PREFIX_OPENCLAW",
    "_INSTALL_KEY_PREFIX_CLAUDE",
]
