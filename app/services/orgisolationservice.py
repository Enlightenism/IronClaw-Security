from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from app.core.auth import AuthContext
from app.core.org_isolation import (
    DEFAULT_BYPASS_ROLES,
    OrgIsolationDecision,
    evaluate_org_isolation,
    org_ids_match,
)


def _stringify_metadata(metadata: Mapping[str, object] | None) -> dict[str, str]:
    if metadata is None:
        return {}
    return {str(key): str(value) for key, value in metadata.items()}


@dataclass(frozen=True, slots=True)
class OrgIsolationServiceResult:
    allowed: bool
    scope: str
    reason: str
    actor_org_id: str | None
    target_org_id: str | None
    principal_id: str | None = None
    principal_type: str | None = None
    matched_roles: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "scope": self.scope,
            "reason": self.reason,
            "actor_org_id": self.actor_org_id,
            "target_org_id": self.target_org_id,
            "principal_id": self.principal_id,
            "principal_type": self.principal_type,
            "matched_roles": list(self.matched_roles),
            "metadata": dict(self.metadata),
        }


class OrgIsolationService:
    def evaluate(
        self,
        context: AuthContext,
        *,
        target_org_id: str | None,
        bypass_roles: tuple[str, ...] | list[str] | set[str] | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> OrgIsolationDecision:
        return evaluate_org_isolation(
            context,
            target_org_id=target_org_id,
            bypass_roles=bypass_roles,
            metadata=metadata,
        )

    def authorize(
        self,
        context: AuthContext,
        *,
        target_org_id: str | None,
        bypass_roles: tuple[str, ...] | list[str] | set[str] | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> OrgIsolationServiceResult:
        decision = self.evaluate(
            context,
            target_org_id=target_org_id,
            bypass_roles=bypass_roles,
            metadata=metadata,
        )
        return self._to_result(decision, scope="org_isolation")

    def compare_org_ids(
        self,
        *,
        actor_org_id: str | None,
        target_org_id: str | None,
        metadata: Mapping[str, object] | None = None,
    ) -> OrgIsolationServiceResult:
        matched = org_ids_match(actor_org_id, target_org_id)
        return OrgIsolationServiceResult(
            allowed=matched,
            scope="org_id_compare",
            reason="org_match" if matched else "org_mismatch",
            actor_org_id=actor_org_id,
            target_org_id=target_org_id,
            metadata=_stringify_metadata(metadata),
        )

    def summarize_context(
        self,
        context: AuthContext,
        *,
        metadata: Mapping[str, object] | None = None,
    ) -> OrgIsolationServiceResult:
        return OrgIsolationServiceResult(
            allowed=context.authenticated,
            scope="org_context_summary",
            reason="authenticated" if context.authenticated else "authentication_required",
            actor_org_id=context.org_id,
            target_org_id=context.org_id,
            principal_id=context.principal_id,
            principal_type=context.principal_type,
            matched_roles=context.roles,
            metadata=_stringify_metadata(metadata),
        )

    def authorize_same_org(
        self,
        context: AuthContext,
        *,
        target_org_id: str | None,
        metadata: Mapping[str, object] | None = None,
    ) -> OrgIsolationServiceResult:
        return self.authorize(
            context,
            target_org_id=target_org_id,
            bypass_roles=(),
            metadata=metadata,
        )

    def authorize_with_default_bypass(
        self,
        context: AuthContext,
        *,
        target_org_id: str | None,
        metadata: Mapping[str, object] | None = None,
    ) -> OrgIsolationServiceResult:
        return self.authorize(
            context,
            target_org_id=target_org_id,
            bypass_roles=DEFAULT_BYPASS_ROLES,
            metadata=metadata,
        )

    def _to_result(
        self,
        decision: OrgIsolationDecision,
        *,
        scope: str,
    ) -> OrgIsolationServiceResult:
        return OrgIsolationServiceResult(
            allowed=decision.allowed,
            scope=scope,
            reason=decision.reason,
            actor_org_id=decision.actor_org_id,
            target_org_id=decision.target_org_id,
            principal_id=decision.principal_id,
            principal_type=decision.principal_type,
            matched_roles=decision.matched_roles,
            metadata=dict(decision.metadata),
        )


def build_org_isolation_service() -> OrgIsolationService:
    return OrgIsolationService()