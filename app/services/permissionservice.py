from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from app.core.access_control import AccessControlDecision, evaluate_access
from app.core.auth import AuthContext
from app.core.permissions import (
    PermissionDecision,
    evaluate_permission,
    expand_role_permissions,
    resolve_effective_permissions,
)
from app.core.roles import (
    describe_roles,
    get_role_permissions,
    normalize_roles,
)


def _stringify_metadata(metadata: Mapping[str, object] | None) -> dict[str, str]:
    if metadata is None:
        return {}
    return {str(key): str(value) for key, value in metadata.items()}


@dataclass(frozen=True, slots=True)
class PermissionServiceResult:
    allowed: bool
    scope: str
    reason: str
    principal_id: str | None
    org_id: str | None
    permissions: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "scope": self.scope,
            "reason": self.reason,
            "principal_id": self.principal_id,
            "org_id": self.org_id,
            "permissions": list(self.permissions),
            "roles": list(self.roles),
            "metadata": dict(self.metadata),
        }


class PermissionService:
    def resolve_permissions(
        self,
        *,
        direct_permissions: Iterable[object] | None = None,
        roles: Iterable[object] | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> PermissionServiceResult:
        normalized_roles = normalize_roles(roles)
        effective_permissions = resolve_effective_permissions(
            direct_permissions=direct_permissions,
            roles=normalized_roles,
        )
        return PermissionServiceResult(
            allowed=True,
            scope="resolve_permissions",
            reason="resolved",
            principal_id=None,
            org_id=None,
            permissions=effective_permissions,
            roles=normalized_roles,
            metadata=_stringify_metadata(metadata),
        )

    def expand_roles(
        self,
        *,
        roles: Iterable[object] | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> PermissionServiceResult:
        normalized_roles = normalize_roles(roles)
        expanded_permissions = expand_role_permissions(normalized_roles)
        return PermissionServiceResult(
            allowed=True,
            scope="expand_roles",
            reason="expanded",
            principal_id=None,
            org_id=None,
            permissions=expanded_permissions,
            roles=normalized_roles,
            metadata=_stringify_metadata(metadata),
        )

    def describe_role_set(
        self,
        *,
        roles: Iterable[object] | None = None,
    ) -> list[dict[str, object]]:
        return describe_roles(roles)

    def get_permissions_for_role(
        self,
        role_name: str,
        *,
        metadata: Mapping[str, object] | None = None,
    ) -> PermissionServiceResult:
        permissions = get_role_permissions(role_name)
        roles = normalize_roles([role_name])
        return PermissionServiceResult(
            allowed=bool(roles),
            scope="role_permissions",
            reason="resolved" if roles else "unknown_role",
            principal_id=None,
            org_id=None,
            permissions=permissions,
            roles=roles,
            metadata=_stringify_metadata(metadata),
        )

    def evaluate_permission(
        self,
        context: AuthContext,
        permission: str,
        *,
        resource_org_id: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> PermissionDecision:
        return evaluate_permission(
            context,
            permission,
            resource_org_id=resource_org_id,
            metadata=metadata,
        )

    def evaluate_access(
        self,
        context: AuthContext,
        *,
        action: str,
        required_permission: str | None = None,
        required_roles: Iterable[object] | None = None,
        resource_org_id: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> AccessControlDecision:
        normalized_roles = normalize_roles(required_roles)
        return evaluate_access(
            context,
            action=action,
            required_permission=required_permission,
            required_roles=normalized_roles,
            resource_org_id=resource_org_id,
            metadata=metadata,
        )

    def summarize_context_permissions(
        self,
        context: AuthContext,
        *,
        metadata: Mapping[str, object] | None = None,
    ) -> PermissionServiceResult:
        effective_permissions = resolve_effective_permissions(
            direct_permissions=context.permissions,
            roles=context.roles,
        )
        return PermissionServiceResult(
            allowed=context.authenticated,
            scope="context_permissions",
            reason="authenticated" if context.authenticated else "authentication_required",
            principal_id=context.principal_id,
            org_id=context.org_id,
            permissions=effective_permissions,
            roles=context.roles,
            metadata=_stringify_metadata(metadata),
        )


def build_permission_service() -> PermissionService:
    return PermissionService()
