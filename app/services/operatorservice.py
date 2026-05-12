from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from app.core.auth import AuthContext
from app.core.org_isolation import evaluate_org_isolation
from app.core.permissions import evaluate_permission
from app.core.principals import Principal
from app.services.authservice import AuthService, build_auth_service


def _stringify_metadata(metadata: Mapping[str, object] | None) -> dict[str, str]:
    if metadata is None:
        return {}
    return {str(key): str(value) for key, value in metadata.items()}


@dataclass(frozen=True, slots=True)
class OperatorAccessResult:
    allowed: bool
    scope: str
    principal_id: str | None
    org_id: str | None
    reason: str
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "scope": self.scope,
            "principal_id": self.principal_id,
            "org_id": self.org_id,
            "reason": self.reason,
            "metadata": dict(self.metadata),
        }


class OperatorService:
    def __init__(self, *, auth_service: AuthService | None = None) -> None:
        self._auth_service = auth_service or build_auth_service()

    @property
    def auth_service(self) -> AuthService:
        return self._auth_service

    def build_operator_context(
        self,
        principal: Principal,
        *,
        session_id: str | None = None,
        auth_method: str = "operator",
        metadata: Mapping[str, object] | None = None,
    ) -> AuthContext:
        combined_metadata = dict(principal.metadata)
        combined_metadata.update(_stringify_metadata(metadata))

        return AuthContext(
            authenticated=principal.active,
            principal_id=principal.principal_id,
            principal_type=principal.principal_type,
            org_id=principal.org_id,
            roles=principal.roles,
            permissions=principal.permissions,
            session_id=session_id,
            auth_method=auth_method,
            metadata=combined_metadata,
        )

    def validate_operator(
        self,
        principal: Principal,
        *,
        session_id: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> OperatorAccessResult:
        context = self.build_operator_context(
            principal,
            session_id=session_id,
            auth_method="operator",
            metadata=metadata,
        )

        if not principal.active:
            return OperatorAccessResult(
                allowed=False,
                scope="operator_auth",
                principal_id=principal.principal_id,
                org_id=principal.org_id,
                reason="principal_inactive",
                metadata=_stringify_metadata(metadata),
            )

        if principal.principal_type != "operator":
            return OperatorAccessResult(
                allowed=False,
                scope="operator_auth",
                principal_id=principal.principal_id,
                org_id=principal.org_id,
                reason="principal_type_mismatch",
                metadata=_stringify_metadata(metadata),
            )

        if not any(role in principal.roles for role in ("platform_admin", "system_admin", "operator_admin", "operator_analyst", "auditor")):
            return OperatorAccessResult(
                allowed=False,
                scope="operator_auth",
                principal_id=principal.principal_id,
                org_id=principal.org_id,
                reason="missing_operator_role",
                metadata=_stringify_metadata(metadata),
            )

        return OperatorAccessResult(
            allowed=context.authenticated,
            scope="operator_auth",
            principal_id=context.principal_id,
            org_id=context.org_id,
            reason="allowed",
            metadata=_stringify_metadata(metadata),
        )

    def authorize_read(
        self,
        context: AuthContext,
        *,
        metadata: Mapping[str, object] | None = None,
    ) -> OperatorAccessResult:
        return self._authorize_permission(
            context,
            permission="operator:read",
            scope="operator_read",
            metadata=metadata,
        )

    def authorize_write(
        self,
        context: AuthContext,
        *,
        metadata: Mapping[str, object] | None = None,
    ) -> OperatorAccessResult:
        return self._authorize_permission(
            context,
            permission="operator:write",
            scope="operator_write",
            metadata=metadata,
        )

    def authorize_manage(
        self,
        context: AuthContext,
        *,
        metadata: Mapping[str, object] | None = None,
    ) -> OperatorAccessResult:
        return self._authorize_permission(
            context,
            permission="operator:manage",
            scope="operator_manage",
            metadata=metadata,
        )

    def authorize_org_access(
        self,
        context: AuthContext,
        *,
        target_org_id: str | None,
        metadata: Mapping[str, object] | None = None,
    ) -> OperatorAccessResult:
        decision = evaluate_org_isolation(
            context,
            target_org_id=target_org_id,
            metadata=metadata,
        )
        return OperatorAccessResult(
            allowed=decision.allowed,
            scope="operator_org",
            principal_id=context.principal_id,
            org_id=target_org_id or context.org_id,
            reason=decision.reason,
            metadata=dict(decision.metadata),
        )

    def authorize_permission(
        self,
        context: AuthContext,
        permission: str,
        *,
        metadata: Mapping[str, object] | None = None,
    ) -> OperatorAccessResult:
        return self._authorize_permission(
            context,
            permission=permission,
            scope="operator_permission",
            metadata=metadata,
        )

    def _authorize_permission(
        self,
        context: AuthContext,
        *,
        permission: str,
        scope: str,
        metadata: Mapping[str, object] | None = None,
    ) -> OperatorAccessResult:
        decision = evaluate_permission(
            context,
            permission,
            resource_org_id=context.org_id,
            metadata=metadata,
        )
        return OperatorAccessResult(
            allowed=decision.allowed,
            scope=scope,
            principal_id=context.principal_id,
            org_id=context.org_id,
            reason=decision.reason,
            metadata=dict(decision.metadata),
        )


def build_operator_service(
    *,
    auth_service: AuthService | None = None,
) -> OperatorService:
    return OperatorService(auth_service=auth_service)