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
class CustomerAuthResult:
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


class CustomerAuthService:
    def __init__(self, *, auth_service: AuthService | None = None) -> None:
        self._auth_service = auth_service or build_auth_service()

    @property
    def auth_service(self) -> AuthService:
        return self._auth_service

    def build_customer_context(
        self,
        principal: Principal,
        *,
        session_id: str | None = None,
        auth_method: str = "customer",
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

    def validate_customer(
        self,
        principal: Principal,
        *,
        session_id: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> CustomerAuthResult:
        context = self.build_customer_context(
            principal,
            session_id=session_id,
            auth_method="customer",
            metadata=metadata,
        )

        if not principal.active:
            return CustomerAuthResult(
                allowed=False,
                scope="customer_auth",
                principal_id=principal.principal_id,
                org_id=principal.org_id,
                reason="principal_inactive",
                metadata=_stringify_metadata(metadata),
            )

        if principal.principal_type != "customer":
            return CustomerAuthResult(
                allowed=False,
                scope="customer_auth",
                principal_id=principal.principal_id,
                org_id=principal.org_id,
                reason="principal_type_mismatch",
                metadata=_stringify_metadata(metadata),
            )

        if not any(role in principal.roles for role in ("customer_admin", "customer_user")):
            return CustomerAuthResult(
                allowed=False,
                scope="customer_auth",
                principal_id=principal.principal_id,
                org_id=principal.org_id,
                reason="missing_customer_role",
                metadata=_stringify_metadata(metadata),
            )

        return CustomerAuthResult(
            allowed=context.authenticated,
            scope="customer_auth",
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
    ) -> CustomerAuthResult:
        return self._authorize_permission(
            context,
            permission="customer:read",
            scope="customer_read",
            metadata=metadata,
        )

    def authorize_write(
        self,
        context: AuthContext,
        *,
        metadata: Mapping[str, object] | None = None,
    ) -> CustomerAuthResult:
        return self._authorize_permission(
            context,
            permission="customer:write",
            scope="customer_write",
            metadata=metadata,
        )

    def authorize_session_access(
        self,
        context: AuthContext,
        *,
        metadata: Mapping[str, object] | None = None,
    ) -> CustomerAuthResult:
        return self._authorize_permission(
            context,
            permission="session:read",
            scope="customer_session_access",
            metadata=metadata,
        )

    def authorize_org_access(
        self,
        context: AuthContext,
        *,
        target_org_id: str | None,
        metadata: Mapping[str, object] | None = None,
    ) -> CustomerAuthResult:
        decision = evaluate_org_isolation(
            context,
            target_org_id=target_org_id,
            metadata=metadata,
        )
        return CustomerAuthResult(
            allowed=decision.allowed,
            scope="customer_org",
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
    ) -> CustomerAuthResult:
        return self._authorize_permission(
            context,
            permission=permission,
            scope="customer_permission",
            metadata=metadata,
        )

    def _authorize_permission(
        self,
        context: AuthContext,
        *,
        permission: str,
        scope: str,
        metadata: Mapping[str, object] | None = None,
    ) -> CustomerAuthResult:
        decision = evaluate_permission(
            context,
            permission,
            resource_org_id=context.org_id,
            metadata=metadata,
        )
        return CustomerAuthResult(
            allowed=decision.allowed,
            scope=scope,
            principal_id=context.principal_id,
            org_id=context.org_id,
            reason=decision.reason,
            metadata=dict(decision.metadata),
        )


def build_customer_auth_service(
    *,
    auth_service: AuthService | None = None,
) -> CustomerAuthService:
    return CustomerAuthService(auth_service=auth_service)