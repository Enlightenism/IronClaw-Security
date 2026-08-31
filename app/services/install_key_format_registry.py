from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from app.core.install_key_formats import (
    InstallKeyFormatRegistry,
    InstallKeyFormatSpec,
    InstallKeyProgram,
    normalize_install_key_program,
)


@dataclass(frozen=True, slots=True)
class InstallKeyPlatformFormat:
    """Service-level view of a platform's canonical install-key format family."""

    platform: str
    display_name: str
    program: InstallKeyProgram
    family: str
    prefix: str
    aliases: tuple[str, ...]
    platform_aliases: tuple[str, ...]

    @property
    def canonical_platform(self) -> str:
        return self.platform

    def matches_program(self, value: str | None) -> bool:
        if value is None:
            return False
        candidate = str(value).strip().lower().replace("-", "_")
        return candidate == self.program or candidate in self.aliases or candidate in self.platform_aliases

    def matches_key(self, candidate: str | None) -> bool:
        if candidate is None:
            return False
        normalized = str(candidate).strip()
        return bool(normalized) and normalized.startswith(self.prefix)


class InstallKeyFormatRegistryService:
    """Canonical platform-to-format resolver for install-key compatibility groups.

    This service intentionally sits on top of app.core.install_key_formats and
    provides the platform-oriented lookup surface used by higher-level routing,
    dashboard grouping, and compatibility checks. It does not redefine the
    install-key trust model or permit generic API-key families to masquerade as
    install-key families.
    """

    _DEFAULT_REGISTRY: Final[InstallKeyFormatRegistry] = InstallKeyFormatRegistry()

    @staticmethod
    def _normalized_aliases(aliases: tuple[str, ...]) -> tuple[str, ...]:
        seen: set[str] = set()
        ordered: list[str] = []
        for alias in aliases:
            key = InstallKeyFormatRegistryService.normalize_platform(alias)
            if key and key not in seen:
                seen.add(key)
                ordered.append(key)
        return tuple(ordered)

    @classmethod
    def normalize_platform(cls, value: str | None) -> str:
        normalized = cls._DEFAULT_REGISTRY.normalize_platform(value)
        return normalized or ""

    @classmethod
    def normalize_program(cls, value: str | None) -> InstallKeyProgram | None:
        return normalize_install_key_program(value)

    @classmethod
    def get_format_spec(cls, program: str | None) -> InstallKeyFormatSpec:
        return cls._DEFAULT_REGISTRY.get_spec(program)

    @classmethod
    def get_format_group(cls, program: str | None) -> InstallKeyPlatformFormat:
        spec = cls.get_format_spec(program)
        normalized_aliases = cls._normalized_aliases(spec.aliases)
        normalized_platform_aliases = cls._normalized_aliases(spec.platform_aliases)
        canonical_alias = normalized_platform_aliases[0] if normalized_platform_aliases else normalized_aliases[0] if normalized_aliases else spec.program
        canonical_platform = cls.normalize_platform(canonical_alias) or spec.program
        return InstallKeyPlatformFormat(
            platform=canonical_platform,
            display_name=spec.display_name,
            program=spec.program,
            family=spec.family,
            prefix=spec.prefix,
            aliases=normalized_aliases,
            platform_aliases=normalized_platform_aliases,
        )

    @classmethod
    def resolve_for_platform(cls, platform_name: str | None) -> InstallKeyPlatformFormat:
        if platform_name is None:
            raise ValueError("platform_name is required")
        spec = cls._DEFAULT_REGISTRY.get_format_for_platform(platform_name)
        normalized_platform = cls.normalize_platform(platform_name)
        group = cls.get_format_group(spec.program)
        canonical_platform = normalized_platform if normalized_platform in group.platform_aliases or normalized_platform in group.aliases else group.platform
        return InstallKeyPlatformFormat(
            platform=canonical_platform,
            display_name=spec.display_name,
            program=spec.program,
            family=spec.family,
            prefix=spec.prefix,
            aliases=group.aliases,
            platform_aliases=group.platform_aliases,
        )

    @classmethod
    def resolve_for_key(cls, candidate: str | None) -> InstallKeyPlatformFormat:
        program = cls._DEFAULT_REGISTRY.parse_program_from_key(candidate)
        if program is None:
            raise ValueError(f"Unsupported install-key format for key: {candidate!r}")
        return cls.get_format_group(program)

    @classmethod
    def resolve_for_program(cls, program: str | None) -> InstallKeyPlatformFormat:
        return cls.get_format_group(program)

    @classmethod
    def list_programs(cls) -> tuple[InstallKeyProgram, ...]:
        return cls._DEFAULT_REGISTRY.list_programs()

    @classmethod
    def list_format_groups(cls) -> tuple[InstallKeyPlatformFormat, ...]:
        return tuple(cls.get_format_group(program) for program in cls.list_programs())

    @classmethod
    def list_platforms_for_program(cls, program: str | None) -> tuple[str, ...]:
        spec = cls.get_format_spec(program)
        return cls._normalized_aliases((*spec.platform_aliases, *spec.aliases))

    @classmethod
    def list_platforms(cls) -> tuple[str, ...]:
        ordered: list[str] = []
        seen: set[str] = set()
        for program in cls.list_programs():
            for platform in cls.list_platforms_for_program(program):
                if platform not in seen:
                    seen.add(platform)
                    ordered.append(platform)
        return tuple(ordered)

    @classmethod
    def get_format_family(cls, program: str | None) -> str:
        return cls.get_format_spec(program).family

    @classmethod
    def is_compatible_platform(cls, platform_name: str | None, program: str | None) -> bool:
        if platform_name is None or program is None:
            return False
        try:
            return cls.resolve_for_platform(platform_name).program == cls.normalize_program(program)
        except ValueError:
            return False

    @classmethod
    def is_compatible_key(cls, candidate: str | None, program: str | None) -> bool:
        if candidate is None:
            return False
        try:
            return cls._DEFAULT_REGISTRY.matches_key_family(candidate, program)
        except ValueError:
            return False

    @classmethod
    def format_key_for_program(cls, program: str | None, secret: str | None) -> str:
        if not secret:
            raise ValueError("secret is required")
        spec = cls.get_format_spec(program)
        normalized_secret = str(secret).strip()
        if not normalized_secret:
            raise ValueError("secret cannot be blank")
        return f"{spec.prefix}{normalized_secret}"

    @staticmethod
    def _canonical_platform_name(program: InstallKeyProgram, platform_name: str | None) -> str:
        normalized = (platform_name or "").strip().lower().replace("-", "_")
        if not normalized:
            return program
        return normalized


_default_install_key_format_registry_service = InstallKeyFormatRegistryService()


def get_install_key_format_registry_service() -> InstallKeyFormatRegistryService:
    return _default_install_key_format_registry_service


def normalize_install_key_platform(value: str | None) -> str:
    return InstallKeyFormatRegistryService.normalize_platform(value)


def resolve_install_key_platform_format(platform_name: str | None) -> InstallKeyPlatformFormat:
    return InstallKeyFormatRegistryService.resolve_for_platform(platform_name)


def resolve_install_key_format_for_key(candidate: str | None) -> InstallKeyPlatformFormat:
    return InstallKeyFormatRegistryService.resolve_for_key(candidate)


def list_install_key_platforms() -> tuple[str, ...]:
    return InstallKeyFormatRegistryService.list_platforms()


def list_install_key_format_groups() -> tuple[InstallKeyPlatformFormat, ...]:
    return InstallKeyFormatRegistryService.list_format_groups()


def is_compatible_install_key_platform(platform_name: str | None, program: str | None) -> bool:
    return InstallKeyFormatRegistryService.is_compatible_platform(platform_name, program)


__all__ = [
    "InstallKeyPlatformFormat",
    "InstallKeyFormatRegistryService",
    "get_install_key_format_registry_service",
    "normalize_install_key_platform",
    "resolve_install_key_platform_format",
    "resolve_install_key_format_for_key",
    "list_install_key_platforms",
    "list_install_key_format_groups",
    "is_compatible_install_key_platform",
]
