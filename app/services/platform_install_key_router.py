from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from app.services.install_key_format_registry import (
    InstallKeyFormatRegistryService,
    InstallKeyPlatformFormat,
)
from app.services.install_key_provisioning import InstallKeyIssued, InstallKeyProvisioningService

_CONNECTOR_PLATFORM_ALIASES: Final[tuple[str, ...]] = (
    "security_guardian",
    "security-guardian",
    "securityguardian",
    "skill",
    "skills",
)


@dataclass(frozen=True, slots=True)
class PlatformInstallKeyRoute:
    """Resolved routing target for a platform-specific install-key request."""

    requested_platform: str
    canonical_platform: str
    program: str
    family: str
    display_name: str
    prefix: str
    aliases: tuple[str, ...]
    group_platforms: tuple[str, ...]
    format_group: InstallKeyPlatformFormat

    @property
    def key_format(self) -> str:
        return self.prefix

    def is_grouped_with(self, platform_name: str | None) -> bool:
        if platform_name is None:
            return False
        normalized = InstallKeyFormatRegistryService.normalize_platform(platform_name)
        return normalized in self.group_platforms

    def validate_key(self, candidate: str | None) -> PlatformInstallKeyRoute:
        if candidate is None:
            raise ValueError("candidate install key is required")
        normalized = str(candidate).strip()
        if not normalized:
            raise ValueError("candidate install key is required")
        if not normalized.startswith(self.prefix):
            raise ValueError(f"Install key {candidate!r} does not match the canonical {self.program} family prefix {self.prefix!r}.")
        try:
            parsed_format = InstallKeyFormatRegistryService.resolve_for_key(normalized)
        except ValueError as exc:
            raise ValueError(f"Install key {candidate!r} is not a supported install key for the {self.program} runtime family.") from exc
        if parsed_format.program != self.program:
            raise ValueError(f"Install key {candidate!r} belongs to the {parsed_format.program} family, not the requested {self.program} runtime family.")
        return self

    def is_valid_for_key(self, candidate: str | None) -> bool:
        try:
            self.validate_key(candidate)
            return True
        except ValueError:
            return False


@dataclass(frozen=True, slots=True)
class PlatformInstallKeyGroup:
    """Shared-format section used to group compatible platform identities."""

    family: str
    program: str
    display_name: str
    prefix: str
    canonical_platform: str
    platforms: tuple[str, ...]
    aliases: tuple[str, ...]

    @property
    def route_count(self) -> int:
        return len(self.platforms)

    def includes(self, platform_name: str | None) -> bool:
        if platform_name is None:
            return False
        normalized = InstallKeyFormatRegistryService.normalize_platform(platform_name)
        return normalized in self.platforms


class PlatformInstallKeyRouter:
    """Routes platform-specific install-key requests into the canonical flow.

    Platform identity is intentionally decoupled from the actual install-key
    issuance trust boundary. The router resolves a platform alias to the correct
    install-key family and then delegates all generation and validation to the
    canonical provisioning registry and format registry.
    """

    _DEFAULT_ROUTER: Final[PlatformInstallKeyRouter | None] = None

    def __init__(
        self,
        *,
        format_registry: InstallKeyFormatRegistryService | None = None,
        provisioning_service: InstallKeyProvisioningService | None = None,
    ) -> None:
        self._format_registry = format_registry or InstallKeyFormatRegistryService()
        self._provisioning_service = provisioning_service or InstallKeyProvisioningService()

    @staticmethod
    def normalize_platform(value: str | None) -> str:
        return InstallKeyFormatRegistryService.normalize_platform(value)

    def resolve_platform(self, platform_name: str | None) -> PlatformInstallKeyRoute:
        if platform_name is None:
            raise ValueError("platform_name is required")

        normalized_platform = self.normalize_platform(platform_name)
        if not normalized_platform:
            raise ValueError("platform_name cannot be blank")
        if normalized_platform in _CONNECTOR_PLATFORM_ALIASES:
            raise ValueError("Security Guardian is a shared install-key connector, not a runtime platform.")

        format_group = self._format_registry.resolve_for_platform(normalized_platform)
        if format_group.program == "security_guardian":
            raise ValueError("Security Guardian is a shared install-key connector, not a runtime platform.")
        group_platforms = tuple(dict.fromkeys(self._format_registry.list_platforms_for_program(format_group.program)))
        canonical_platform = group_platforms[0] if group_platforms else format_group.platform

        return PlatformInstallKeyRoute(
            requested_platform=normalized_platform,
            canonical_platform=canonical_platform,
            program=format_group.program,
            family=format_group.family,
            display_name=format_group.display_name,
            prefix=format_group.prefix,
            aliases=format_group.aliases,
            group_platforms=group_platforms,
            format_group=format_group,
        )

    def resolve_key(self, candidate: str | None) -> PlatformInstallKeyRoute:
        if candidate is None:
            raise ValueError("candidate install key is required")
        format_group = self._format_registry.resolve_for_key(candidate)
        if format_group.program == "security_guardian":
            raise ValueError("Security Guardian is a shared install-key connector, not a runtime platform.")
        return self.resolve_platform(format_group.platform)

    def resolve_group(self, platform_name: str | None) -> PlatformInstallKeyGroup:
        route = self.resolve_platform(platform_name)
        return PlatformInstallKeyGroup(
            family=route.family,
            program=route.program,
            display_name=route.display_name,
            prefix=route.prefix,
            canonical_platform=route.canonical_platform,
            platforms=route.group_platforms,
            aliases=route.aliases,
        )

    def list_groups(self) -> tuple[PlatformInstallKeyGroup, ...]:
        groups: list[PlatformInstallKeyGroup] = []
        for program in self._format_registry.list_programs():
            if program == "security_guardian":
                continue
            format_group = self._format_registry.get_format_group(program)
            platforms = tuple(platform for platform in dict.fromkeys(self._format_registry.list_platforms_for_program(program)) if platform not in _CONNECTOR_PLATFORM_ALIASES)
            groups.append(
                PlatformInstallKeyGroup(
                    family=format_group.family,
                    program=format_group.program,
                    display_name=format_group.display_name,
                    prefix=format_group.prefix,
                    canonical_platform=format_group.platform,
                    platforms=platforms,
                    aliases=format_group.aliases,
                )
            )
        return tuple(groups)

    def list_platforms(self) -> tuple[str, ...]:
        return tuple(platform for platform in self._format_registry.list_platforms() if platform not in _CONNECTOR_PLATFORM_ALIASES)

    def is_supported_platform(self, platform_name: str | None) -> bool:
        if platform_name is None:
            return False
        try:
            self.resolve_platform(platform_name)
            return True
        except ValueError:
            return False

    def validate_platform_key(self, platform_name: str | None, candidate: str | None) -> PlatformInstallKeyRoute:
        if platform_name is None:
            raise ValueError("platform_name is required")
        route = self.resolve_platform(platform_name)
        route.validate_key(candidate)
        return route

    def is_valid_platform_key(self, platform_name: str | None, candidate: str | None) -> bool:
        try:
            self.validate_platform_key(platform_name, candidate)
            return True
        except ValueError:
            return False

    def provision_for_platform(
        self,
        *,
        platform_name: str | None,
        owner_key: str,
        subscription_id: str,
        source: str = "purchase",
        label: str = "auto-provisioned",
        metadata: dict[str, Any] | None = None,
        payment_status: str | None = "paid",
        entitlements_status: str | None = "active",
        issued_after_payment: bool = True,
        checkout_session_id: str | None = None,
        purchase_reference: str | None = None,
        customer_id: str | None = None,
        org_id: str | None = None,
        payment_confirmed: bool | None = None,
    ) -> InstallKeyIssued:
        route = self.resolve_platform(platform_name)
        effective_metadata: dict[str, Any] = {
            "platform": route.requested_platform,
            "canonical_platform": route.canonical_platform,
            "program": route.program,
            "family": route.family,
            "prefix": route.prefix,
            "group_platforms": list(route.group_platforms),
        }
        if metadata:
            effective_metadata.update(metadata)

        return self._provisioning_service.provision_for_program(
            owner_key=owner_key,
            subscription_id=subscription_id,
            program=route.program,
            source=source,
            label=label,
            metadata=effective_metadata,
            payment_status=payment_status,
            entitlements_status=entitlements_status,
            issued_after_payment=issued_after_payment,
            checkout_session_id=checkout_session_id,
            purchase_reference=purchase_reference,
            customer_id=customer_id,
            org_id=org_id,
            payment_confirmed=payment_confirmed,
        )

    @classmethod
    def default(cls) -> PlatformInstallKeyRouter:
        if cls._DEFAULT_ROUTER is None:
            cls._DEFAULT_ROUTER = cls()
        return cls._DEFAULT_ROUTER


_default_platform_install_key_router = PlatformInstallKeyRouter.default()


def get_platform_install_key_router() -> PlatformInstallKeyRouter:
    return _default_platform_install_key_router


def resolve_platform_install_key_route(platform_name: str | None) -> PlatformInstallKeyRoute:
    return get_platform_install_key_router().resolve_platform(platform_name)


def resolve_platform_install_key_group(platform_name: str | None) -> PlatformInstallKeyGroup:
    return get_platform_install_key_router().resolve_group(platform_name)


def list_platform_install_key_groups() -> tuple[PlatformInstallKeyGroup, ...]:
    return get_platform_install_key_router().list_groups()


def list_platform_install_key_platforms() -> tuple[str, ...]:
    return get_platform_install_key_router().list_platforms()


__all__ = [
    "PlatformInstallKeyRoute",
    "PlatformInstallKeyGroup",
    "PlatformInstallKeyRouter",
    "get_platform_install_key_router",
    "resolve_platform_install_key_route",
    "resolve_platform_install_key_group",
    "list_platform_install_key_groups",
    "list_platform_install_key_platforms",
]
