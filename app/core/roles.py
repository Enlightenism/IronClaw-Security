from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from app.core.permissions import ROLE_PERMISSIONS


@dataclass(frozen=True, slots=True)
class RoleDefinition:
    name: str
    principal_type: str
    description: str
    permissions: tuple[str, ...] = field(default_factory=tuple)
    system_role: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "principal_type": self.principal_type,
            "description": self.description,
            "permissions": list(self.permissions),
            "system_role": self.system_role,
        }


ROLE_DEFINITIONS: dict[str, RoleDefinition] = {
    "platform_admin": RoleDefinition(
        name="platform_admin",
        principal_type="operator",
        description="Full platform administration across all organizations and security surfaces.",
        permissions=ROLE_PERMISSIONS.get("platform_admin", ()),
    ),
    "system_admin": RoleDefinition(
        name="system_admin",
        principal_type="operator",
        description="System-wide administrative access for trusted internal operations.",
        permissions=ROLE_PERMISSIONS.get("system_admin", ()),
    ),
    "operator_admin": RoleDefinition(
        name="operator_admin",
        principal_type="operator",
        description="Administrative operator access for organization and security management tasks.",
        permissions=ROLE_PERMISSIONS.get("operator_admin", ()),
    ),
    "operator_analyst": RoleDefinition(
        name="operator_analyst",
        principal_type="operator",
        description="Read-focused operator role for investigations, monitoring, and analysis.",
        permissions=ROLE_PERMISSIONS.get("operator_analyst", ()),
    ),
    "customer_admin": RoleDefinition(
        name="customer_admin",
        principal_type="customer",
        description="Administrative customer access within the customer's own organization boundary.",
        permissions=ROLE_PERMISSIONS.get("customer_admin", ()),
    ),
    "customer_user": RoleDefinition(
        name="customer_user",
        principal_type="customer",
        description="Standard customer access with org-bound read capabilities.",
        permissions=ROLE_PERMISSIONS.get("customer_user", ()),
    ),
    "auditor": RoleDefinition(
        name="auditor",
        principal_type="operator",
        description="Read-only audit-focused access for compliance and review workflows.",
        permissions=ROLE_PERMISSIONS.get("auditor", ()),
    ),
    "service": RoleDefinition(
        name="service",
        principal_type="service",
        description="Internal service principal for controlled machine-to-machine operations.",
        permissions=ROLE_PERMISSIONS.get("service", ()),
    ),
}


def _clean_role(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().lower()


def list_roles(*, principal_type: str | None = None) -> list[RoleDefinition]:
    roles = list(ROLE_DEFINITIONS.values())
    if principal_type is None:
        return sorted(roles, key=lambda item: item.name)

    normalized_principal_type = _clean_role(principal_type)
    return sorted(
        (role for role in roles if _clean_role(role.principal_type) == normalized_principal_type),
        key=lambda item: item.name,
    )


def get_role_definition(role_name: str) -> RoleDefinition | None:
    return ROLE_DEFINITIONS.get(_clean_role(role_name))


def role_exists(role_name: str) -> bool:
    return get_role_definition(role_name) is not None


def get_role_permissions(role_name: str) -> tuple[str, ...]:
    definition = get_role_definition(role_name)
    if definition is None:
        return ()
    return definition.permissions


def normalize_roles(roles: Iterable[object] | None) -> tuple[str, ...]:
    if roles is None:
        return ()

    normalized: list[str] = []
    seen: set[str] = set()

    for value in roles:
        role_name = _clean_role(value)
        if not role_name or role_name in seen:
            continue
        if role_name not in ROLE_DEFINITIONS:
            continue
        normalized.append(role_name)
        seen.add(role_name)

    return tuple(normalized)


def is_operator_role(role_name: str) -> bool:
    definition = get_role_definition(role_name)
    return definition is not None and definition.principal_type == "operator"


def is_customer_role(role_name: str) -> bool:
    definition = get_role_definition(role_name)
    return definition is not None and definition.principal_type == "customer"


def is_service_role(role_name: str) -> bool:
    definition = get_role_definition(role_name)
    return definition is not None and definition.principal_type == "service"


def roles_for_principal_type(principal_type: str) -> tuple[str, ...]:
    return tuple(role.name for role in list_roles(principal_type=principal_type))


def describe_roles(roles: Iterable[object] | None) -> list[dict[str, object]]:
    return [definition.to_dict() for role_name in normalize_roles(roles) if (definition := get_role_definition(role_name)) is not None]
