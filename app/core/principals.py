from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field


def _clean(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


def _clean_lower(value: object) -> str:
    return _clean(value).lower()


def _normalize_values(values: Iterable[object] | None) -> tuple[str, ...]:
    if values is None:
        return ()

    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = _clean_lower(value)
        if not cleaned or cleaned in seen:
            continue
        normalized.append(cleaned)
        seen.add(cleaned)

    return tuple(normalized)


def _stringify_metadata(metadata: Mapping[str, object] | None) -> dict[str, str]:
    if metadata is None:
        return {}
    return {str(key): str(value) for key, value in metadata.items()}


@dataclass(frozen=True, slots=True)
class Principal:
    principal_id: str
    principal_type: str
    org_id: str | None = None
    email: str | None = None
    display_name: str | None = None
    roles: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()
    active: bool = True
    service_name: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def is_operator(self) -> bool:
        return self.principal_type == "operator"

    @property
    def is_customer(self) -> bool:
        return self.principal_type == "customer"

    @property
    def is_service(self) -> bool:
        return self.principal_type == "service"

    def to_dict(self) -> dict[str, object]:
        return {
            "principal_id": self.principal_id,
            "principal_type": self.principal_type,
            "org_id": self.org_id,
            "email": self.email,
            "display_name": self.display_name,
            "roles": list(self.roles),
            "permissions": list(self.permissions),
            "active": self.active,
            "service_name": self.service_name,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class PrincipalReference:
    principal_id: str
    principal_type: str
    org_id: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "principal_id": self.principal_id,
            "principal_type": self.principal_type,
            "org_id": self.org_id,
        }


def build_principal(
    *,
    principal_id: str,
    principal_type: str,
    org_id: str | None = None,
    email: str | None = None,
    display_name: str | None = None,
    roles: Iterable[object] | None = None,
    permissions: Iterable[object] | None = None,
    active: bool = True,
    service_name: str | None = None,
    metadata: Mapping[str, object] | None = None,
) -> Principal:
    normalized_type = _clean_lower(principal_type) or "unknown"
    normalized_org_id = _clean(org_id) or None
    normalized_email = _clean_lower(email) or None
    normalized_display_name = _clean(display_name) or None
    normalized_service_name = _clean(service_name) or None

    return Principal(
        principal_id=_clean(principal_id),
        principal_type=normalized_type,
        org_id=normalized_org_id,
        email=normalized_email,
        display_name=normalized_display_name,
        roles=_normalize_values(roles),
        permissions=_normalize_values(permissions),
        active=bool(active),
        service_name=normalized_service_name,
        metadata=_stringify_metadata(metadata),
    )


def principal_reference(principal: Principal) -> PrincipalReference:
    return PrincipalReference(
        principal_id=principal.principal_id,
        principal_type=principal.principal_type,
        org_id=principal.org_id,
    )


def principal_matches_org(principal: Principal, org_id: str | None) -> bool:
    normalized_org_id = _clean(org_id)
    return bool(principal.org_id and normalized_org_id and principal.org_id == normalized_org_id)


def principal_has_role(principal: Principal, role_name: str) -> bool:
    normalized_role = _clean_lower(role_name)
    return bool(normalized_role and normalized_role in principal.roles)


def principal_has_permission(principal: Principal, permission: str) -> bool:
    normalized_permission = _clean_lower(permission)
    if not normalized_permission:
        return False

    for granted in principal.permissions:
        if granted == "*" or granted == normalized_permission:
            return True
        if granted.endswith(":*"):
            prefix = granted[:-2]
            if normalized_permission == prefix or normalized_permission.startswith(f"{prefix}:"):
                return True

    return False


def is_operator_principal(principal: Principal) -> bool:
    return principal.principal_type == "operator"


def is_customer_principal(principal: Principal) -> bool:
    return principal.principal_type == "customer"


def is_service_principal(principal: Principal) -> bool:
    return principal.principal_type == "service"


def deactivate_principal(
    principal: Principal,
    *,
    metadata: Mapping[str, object] | None = None,
) -> Principal:
    merged_metadata = dict(principal.metadata)
    merged_metadata.update(_stringify_metadata(metadata))

    return Principal(
        principal_id=principal.principal_id,
        principal_type=principal.principal_type,
        org_id=principal.org_id,
        email=principal.email,
        display_name=principal.display_name,
        roles=principal.roles,
        permissions=principal.permissions,
        active=False,
        service_name=principal.service_name,
        metadata=merged_metadata,
    )


def activate_principal(
    principal: Principal,
    *,
    metadata: Mapping[str, object] | None = None,
) -> Principal:
    merged_metadata = dict(principal.metadata)
    merged_metadata.update(_stringify_metadata(metadata))

    return Principal(
        principal_id=principal.principal_id,
        principal_type=principal.principal_type,
        org_id=principal.org_id,
        email=principal.email,
        display_name=principal.display_name,
        roles=principal.roles,
        permissions=principal.permissions,
        active=True,
        service_name=principal.service_name,
        metadata=merged_metadata,
    )
