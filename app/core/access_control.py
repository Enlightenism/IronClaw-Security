from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from app.core.auth import AuthContext
from app.core.errors import AppError
from app.core.permissions import PermissionDecision, evaluate_permission
from app.core.roles import get_role_definition

_PLATFORM_PRINCIPAL_TYPES = frozenset({"platform", "system", "platform_admin"})


@dataclass(frozen=True, slots=True)
class AccessControlDecision:
    allowed: bool
    action: str
    principal_id: str | None
    principal_type: str
    org_id: str | None
    reason: str
    permission: str | None = None
    required_roles: tuple[str, ...] = ()
    matched_roles: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "action": self.action,
            "principal_id": self.principal_id,
            "principal_type": self.principal_type,
            "org_id": self.org_id,
            "reason": self.reason,
            "permission": self.permission,
            "required_roles": list(self.required_roles),
            "matched_roles": list(self.matched_roles),
            "metadata": dict(self.metadata),
        }


def _clean_value(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().lower()


def _normalize_role_names(
    values: tuple[str, ...] | list[str] | set[str] | None,
) -> tuple[str, ...]:
    if values is None:
        return ()

    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        role_name = _clean_value(value)
        if not role_name or role_name in seen:
            continue
        normalized.append(role_name)
        seen.add(role_name)

    return tuple(normalized)


def _stringify_metadata(metadata: Mapping[str, object] | None) -> dict[str, str]:
    if metadata is None:
        return {}
    return {str(key): str(value) for key, value in metadata.items()}


def _role_matches(
    context: AuthContext,
    required_roles: tuple[str, ...],
) -> tuple[str, ...]:
    held_roles = {_clean_value(role) for role in context.roles}
    matched = [role for role in required_roles if role in held_roles]
    return tuple(matched)


def _validate_roles(required_roles: tuple[str, ...]) -> tuple[str, ...]:
    valid: list[str] = []
    for role_name in required_roles:
        if get_role_definition(role_name) is not None:
            valid.append(role_name)
    return tuple(valid)


def _is_platform_principal(context: AuthContext) -> bool:
    return _clean_value(context.principal_type) in _PLATFORM_PRINCIPAL_TYPES


def evaluate_access(
    context: AuthContext,
    *,
    action: str,
    required_permission: str | None = None,
    required_roles: tuple[str, ...] | list[str] | set[str] | None = None,
    resource_org_id: str | None = None,
    metadata: Mapping[str, object] | None = None,
) -> AccessControlDecision:
    normalized_action = _clean_value(action)
    normalized_roles = _validate_roles(_normalize_role_names(required_roles))
    normalized_metadata = _stringify_metadata(metadata)

    if not normalized_action:
        return AccessControlDecision(
            allowed=False,
            action="",
            principal_id=context.principal_id,
            principal_type=context.principal_type,
            org_id=context.org_id,
            reason="invalid_action",
            permission=required_permission,
            required_roles=normalized_roles,
            matched_roles=(),
            metadata=normalized_metadata,
        )

    if not context.authenticated:
        return AccessControlDecision(
            allowed=False,
            action=normalized_action,
            principal_id=context.principal_id,
            principal_type=context.principal_type,
            org_id=context.org_id,
            reason="authentication_required",
            permission=required_permission,
            required_roles=normalized_roles,
            matched_roles=(),
            metadata=normalized_metadata,
        )

    # Platform principals bypass role and permission gates entirely.
    if _is_platform_principal(context):
        return AccessControlDecision(
            allowed=True,
            action=normalized_action,
            principal_id=context.principal_id,
            principal_type=context.principal_type,
            org_id=context.org_id,
            reason="platform_bypass",
            permission=_clean_value(required_permission) or None,
            required_roles=normalized_roles,
            matched_roles=normalized_roles,
            metadata=normalized_metadata,
        )

    if resource_org_id and context.org_id and resource_org_id != context.org_id:
        return AccessControlDecision(
            allowed=False,
            action=normalized_action,
            principal_id=context.principal_id,
            principal_type=context.principal_type,
            org_id=context.org_id,
            reason="org_scope_mismatch",
            permission=required_permission,
            required_roles=normalized_roles,
            matched_roles=(),
            metadata=normalized_metadata,
        )

    matched_roles = _role_matches(context, normalized_roles)
    if normalized_roles and not matched_roles:
        return AccessControlDecision(
            allowed=False,
            action=normalized_action,
            principal_id=context.principal_id,
            principal_type=context.principal_type,
            org_id=context.org_id,
            reason="missing_role",
            permission=required_permission,
            required_roles=normalized_roles,
            matched_roles=(),
            metadata=normalized_metadata,
        )

    permission_decision: PermissionDecision | None = None
    normalized_permission = _clean_value(required_permission)
    if normalized_permission:
        permission_decision = evaluate_permission(
            context,
            normalized_permission,
            resource_org_id=resource_org_id,
            metadata=metadata,
        )
        if not permission_decision.allowed:
            return AccessControlDecision(
                allowed=False,
                action=normalized_action,
                principal_id=context.principal_id,
                principal_type=context.principal_type,
                org_id=context.org_id,
                reason=permission_decision.reason,
                permission=normalized_permission,
                required_roles=normalized_roles,
                matched_roles=matched_roles,
                metadata=normalized_metadata,
            )

    return AccessControlDecision(
        allowed=True,
        action=normalized_action,
        principal_id=context.principal_id,
        principal_type=context.principal_type,
        org_id=context.org_id,
        reason="allowed",
        permission=normalized_permission or None,
        required_roles=normalized_roles,
        matched_roles=matched_roles,
        metadata=normalized_metadata,
    )


def require_access(
    context: AuthContext,
    *,
    action: str,
    required_permission: str | None = None,
    required_roles: tuple[str, ...] | list[str] | set[str] | None = None,
    resource_org_id: str | None = None,
    metadata: Mapping[str, object] | None = None,
) -> AuthContext:
    decision = evaluate_access(
        context,
        action=action,
        required_permission=required_permission,
        required_roles=required_roles,
        resource_org_id=resource_org_id,
        metadata=metadata,
    )
    if decision.allowed:
        return context

    status_code = 403
    if decision.reason == "authentication_required":
        status_code = 401

    raise AppError(
        error="access_denied",
        message="Access denied",
        status_code=status_code,
        details=decision.to_dict(),
    )
