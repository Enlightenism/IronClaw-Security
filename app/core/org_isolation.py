from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from app.core.auth import AuthContext
from app.core.errors import AppError


@dataclass(frozen=True, slots=True)
class OrgIsolationDecision:
    allowed: bool
    principal_id: str | None
    principal_type: str
    actor_org_id: str | None
    target_org_id: str | None
    reason: str
    bypass_roles: tuple[str, ...] = ()
    matched_roles: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "principal_id": self.principal_id,
            "principal_type": self.principal_type,
            "actor_org_id": self.actor_org_id,
            "target_org_id": self.target_org_id,
            "reason": self.reason,
            "bypass_roles": list(self.bypass_roles),
            "matched_roles": list(self.matched_roles),
            "metadata": dict(self.metadata),
        }


DEFAULT_BYPASS_ROLES: tuple[str, ...] = (
    "platform_admin",
    "system_admin",
    "operator_admin",
)


def _clean(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


def _clean_lower(value: object) -> str:
    return _clean(value).lower()


def _normalize_roles(values: Iterable[object] | None) -> tuple[str, ...]:
    if values is None:
        return ()

    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        role_name = _clean_lower(value)
        if not role_name or role_name in seen:
            continue
        normalized.append(role_name)
        seen.add(role_name)

    return tuple(normalized)


def _stringify_metadata(metadata: Mapping[str, object] | None) -> dict[str, str]:
    if metadata is None:
        return {}
    return {str(key): str(value) for key, value in metadata.items()}


def _matched_bypass_roles(
    context: AuthContext,
    bypass_roles: tuple[str, ...],
) -> tuple[str, ...]:
    held_roles = set(_normalize_roles(context.roles))
    return tuple(role for role in bypass_roles if role in held_roles)


def org_ids_match(left_org_id: str | None, right_org_id: str | None) -> bool:
    left = _clean(left_org_id)
    right = _clean(right_org_id)
    return bool(left and right and left == right)


def evaluate_org_isolation(
    context: AuthContext,
    *,
    target_org_id: str | None,
    bypass_roles: Iterable[object] | None = None,
    metadata: Mapping[str, object] | None = None,
) -> OrgIsolationDecision:
    normalized_target_org_id = _clean(target_org_id) or None
    normalized_actor_org_id = _clean(context.org_id) or None
    normalized_bypass_roles = _normalize_roles(bypass_roles) or DEFAULT_BYPASS_ROLES
    normalized_metadata = _stringify_metadata(metadata)

    if not context.authenticated:
        return OrgIsolationDecision(
            allowed=False,
            principal_id=context.principal_id,
            principal_type=context.principal_type,
            actor_org_id=normalized_actor_org_id,
            target_org_id=normalized_target_org_id,
            reason="authentication_required",
            bypass_roles=normalized_bypass_roles,
            matched_roles=(),
            metadata=normalized_metadata,
        )

    matched_roles = _matched_bypass_roles(context, normalized_bypass_roles)
    if matched_roles:
        return OrgIsolationDecision(
            allowed=True,
            principal_id=context.principal_id,
            principal_type=context.principal_type,
            actor_org_id=normalized_actor_org_id,
            target_org_id=normalized_target_org_id,
            reason="bypass_role",
            bypass_roles=normalized_bypass_roles,
            matched_roles=matched_roles,
            metadata=normalized_metadata,
        )

    if normalized_target_org_id is None:
        return OrgIsolationDecision(
            allowed=False,
            principal_id=context.principal_id,
            principal_type=context.principal_type,
            actor_org_id=normalized_actor_org_id,
            target_org_id=None,
            reason="target_org_required",
            bypass_roles=normalized_bypass_roles,
            matched_roles=(),
            metadata=normalized_metadata,
        )

    if normalized_actor_org_id is None:
        return OrgIsolationDecision(
            allowed=False,
            principal_id=context.principal_id,
            principal_type=context.principal_type,
            actor_org_id=None,
            target_org_id=normalized_target_org_id,
            reason="actor_org_required",
            bypass_roles=normalized_bypass_roles,
            matched_roles=(),
            metadata=normalized_metadata,
        )

    if normalized_actor_org_id != normalized_target_org_id:
        return OrgIsolationDecision(
            allowed=False,
            principal_id=context.principal_id,
            principal_type=context.principal_type,
            actor_org_id=normalized_actor_org_id,
            target_org_id=normalized_target_org_id,
            reason="org_isolation_violation",
            bypass_roles=normalized_bypass_roles,
            matched_roles=(),
            metadata=normalized_metadata,
        )

    return OrgIsolationDecision(
        allowed=True,
        principal_id=context.principal_id,
        principal_type=context.principal_type,
        actor_org_id=normalized_actor_org_id,
        target_org_id=normalized_target_org_id,
        reason="org_match",
        bypass_roles=normalized_bypass_roles,
        matched_roles=(),
        metadata=normalized_metadata,
    )


def require_same_org(
    context: AuthContext,
    *,
    target_org_id: str | None,
    bypass_roles: Iterable[object] | None = None,
    metadata: Mapping[str, object] | None = None,
) -> AuthContext:
    decision = evaluate_org_isolation(
        context,
        target_org_id=target_org_id,
        bypass_roles=bypass_roles,
        metadata=metadata,
    )
    if decision.allowed:
        return context

    status_code = 403
    if decision.reason == "authentication_required":
        status_code = 401

    raise AppError(
        error="org_isolation_denied",
        message="Organization isolation policy denied access",
        status_code=status_code,
        details=decision.to_dict(),
    )


def require_matching_org_ids(
    actor_org_id: str | None,
    target_org_id: str | None,
    *,
    metadata: Mapping[str, object] | None = None,
) -> str:
    normalized_actor_org_id = _clean(actor_org_id) or None
    normalized_target_org_id = _clean(target_org_id) or None

    if normalized_actor_org_id is None:
        raise AppError(
            error="org_isolation_denied",
            message="Organization isolation policy denied access",
            status_code=403,
            details={
                "reason": "actor_org_required",
                "actor_org_id": None,
                "target_org_id": normalized_target_org_id,
                "metadata": _stringify_metadata(metadata),
            },
        )

    if normalized_target_org_id is None:
        raise AppError(
            error="org_isolation_denied",
            message="Organization isolation policy denied access",
            status_code=403,
            details={
                "reason": "target_org_required",
                "actor_org_id": normalized_actor_org_id,
                "target_org_id": None,
                "metadata": _stringify_metadata(metadata),
            },
        )

    if normalized_actor_org_id != normalized_target_org_id:
        raise AppError(
            error="org_isolation_denied",
            message="Organization isolation policy denied access",
            status_code=403,
            details={
                "reason": "org_isolation_violation",
                "actor_org_id": normalized_actor_org_id,
                "target_org_id": normalized_target_org_id,
                "metadata": _stringify_metadata(metadata),
            },
        )

    return normalized_target_org_id
