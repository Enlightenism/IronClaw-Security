from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from app.core.auth import AuthContext
from app.core.errors import AppError


@dataclass(frozen=True, slots=True)
class PermissionDecision:
    allowed: bool
    permission: str
    principal_id: str | None
    principal_type: str
    org_id: str | None
    reason: str
    matched_permissions: tuple[str, ...] = ()
    matched_roles: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "permission": self.permission,
            "principal_id": self.principal_id,
            "principal_type": self.principal_type,
            "org_id": self.org_id,
            "reason": self.reason,
            "matched_permissions": list(self.matched_permissions),
            "matched_roles": list(self.matched_roles),
            "metadata": dict(self.metadata),
        }


ROLE_PERMISSIONS: dict[str, tuple[str, ...]] = {
    "platform_admin": (
        "*",
    ),
    "system_admin": (
        "*",
    ),
    "operator_admin": (
        "operator:read",
        "operator:write",
        "operator:manage",
        "customer:read",
        "org:read",
        "org:write",
        "org:isolate",
        "session:read",
        "session:write",
        "session:revoke",
        "permissions:read",
        "permissions:write",
    ),
    "operator_analyst": (
        "operator:read",
        "customer:read",
        "org:read",
        "session:read",
        "permissions:read",
    ),
    "customer_admin": (
        "customer:read",
        "customer:write",
        "org:read",
        "session:read",
        "session:write",
        "permissions:read",
    ),
    "customer_user": (
        "customer:read",
        "org:read",
        "session:read",
    ),
    "auditor": (
        "operator:read",
        "customer:read",
        "org:read",
        "session:read",
        "permissions:read",
    ),
    "service": (
        "system:read",
        "system:write",
        "session:read",
        "permissions:read",
    ),
}


def _clean_permission(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().lower()


def _normalize_permissions(values: Iterable[object] | None) -> tuple[str, ...]:
    if values is None:
        return ()
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        permission = _clean_permission(value)
        if permission and permission not in seen:
            normalized.append(permission)
            seen.add(permission)
    return tuple(normalized)


def _normalize_roles(values: Iterable[object] | None) -> tuple[str, ...]:
    if values is None:
        return ()
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        role = _clean_permission(value)
        if role and role not in seen:
            normalized.append(role)
            seen.add(role)
    return tuple(normalized)


def expand_role_permissions(roles: Iterable[object] | None) -> tuple[str, ...]:
    expanded: list[str] = []
    seen: set[str] = set()

    for role in _normalize_roles(roles):
        for permission in ROLE_PERMISSIONS.get(role, ()):
            if permission not in seen:
                expanded.append(permission)
                seen.add(permission)

    return tuple(expanded)


def resolve_effective_permissions(
    *,
    direct_permissions: Iterable[object] | None = None,
    roles: Iterable[object] | None = None,
) -> tuple[str, ...]:
    effective: list[str] = []
    seen: set[str] = set()

    for permission in _normalize_permissions(direct_permissions):
        if permission not in seen:
            effective.append(permission)
            seen.add(permission)

    for permission in expand_role_permissions(roles):
        if permission not in seen:
            effective.append(permission)
            seen.add(permission)

    return tuple(effective)


def _permission_matches(granted: str, required: str) -> bool:
    if granted == "*" or granted == required:
        return True

    if granted.endswith(":*"):
        prefix = granted[:-2]
        return required == prefix or required.startswith(f"{prefix}:")

    return False


def has_permission(
    required_permission: str,
    *,
    permissions: Iterable[object] | None = None,
    roles: Iterable[object] | None = None,
) -> bool:
    required = _clean_permission(required_permission)
    if not required:
        return False

    effective = resolve_effective_permissions(
        direct_permissions=permissions,
        roles=roles,
    )
    return any(_permission_matches(granted, required) for granted in effective)


def evaluate_permission(
    context: AuthContext,
    required_permission: str,
    *,
    resource_org_id: str | None = None,
    metadata: Mapping[str, object] | None = None,
) -> PermissionDecision:
    required = _clean_permission(required_permission)
    if not required:
        return PermissionDecision(
            allowed=False,
            permission="",
            principal_id=context.principal_id,
            principal_type=context.principal_type,
            org_id=context.org_id,
            reason="invalid_permission",
            matched_permissions=(),
            matched_roles=context.roles,
            metadata={},
        )

    if not context.authenticated:
        return PermissionDecision(
            allowed=False,
            permission=required,
            principal_id=context.principal_id,
            principal_type=context.principal_type,
            org_id=context.org_id,
            reason="authentication_required",
            matched_permissions=(),
            matched_roles=context.roles,
            metadata=_stringify_metadata(metadata),
        )

    if resource_org_id and context.org_id and resource_org_id != context.org_id:
        return PermissionDecision(
            allowed=False,
            permission=required,
            principal_id=context.principal_id,
            principal_type=context.principal_type,
            org_id=context.org_id,
            reason="org_scope_mismatch",
            matched_permissions=(),
            matched_roles=context.roles,
            metadata=_stringify_metadata(metadata),
        )

    effective = resolve_effective_permissions(
        direct_permissions=context.permissions,
        roles=context.roles,
    )
    matched = tuple(
        granted for granted in effective if _permission_matches(granted, required)
    )

    if matched:
        return PermissionDecision(
            allowed=True,
            permission=required,
            principal_id=context.principal_id,
            principal_type=context.principal_type,
            org_id=context.org_id,
            reason="allowed",
            matched_permissions=matched,
            matched_roles=context.roles,
            metadata=_stringify_metadata(metadata),
        )

    return PermissionDecision(
        allowed=False,
        permission=required,
        principal_id=context.principal_id,
        principal_type=context.principal_type,
        org_id=context.org_id,
        reason="missing_permission",
        matched_permissions=(),
        matched_roles=context.roles,
        metadata=_stringify_metadata(metadata),
    )


def require_permission(
    context: AuthContext,
    required_permission: str,
    *,
    resource_org_id: str | None = None,
    metadata: Mapping[str, object] | None = None,
) -> AuthContext:
    decision = evaluate_permission(
        context,
        required_permission,
        resource_org_id=resource_org_id,
        metadata=metadata,
    )
    if decision.allowed:
        return context

    status_code = 403
    if decision.reason == "authentication_required":
        status_code = 401

    raise AppError(
        error="permission_denied",
        message="Permission denied",
        status_code=status_code,
        details=decision.to_dict(),
    )


def _stringify_metadata(
    metadata: Mapping[str, object] | None,
) -> dict[str, str]:
    if metadata is None:
        return {}
    return {str(key): str(value) for key, value in metadata.items()}