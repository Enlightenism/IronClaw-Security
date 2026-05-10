from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, Header, Query

from app.core.auth import AuthContext, get_auth_context
from app.core.org_isolation import require_matching_org_ids, require_same_org


def _clean(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


@dataclass(frozen=True, slots=True)
class OrgContext:
    actor_org_id: str | None
    target_org_id: str
    source: str

    def to_dict(self) -> dict[str, str | None]:
        return {
            "actor_org_id": self.actor_org_id,
            "target_org_id": self.target_org_id,
            "source": self.source,
        }


def resolve_target_org_id(
    *,
    auth_context: AuthContext,
    header_org_id: str | None = None,
    query_org_id: str | None = None,
    default_to_actor_org: bool = True,
) -> tuple[str | None, str]:
    normalized_header_org_id = _clean(header_org_id) or None
    normalized_query_org_id = _clean(query_org_id) or None

    if normalized_header_org_id:
        return normalized_header_org_id, "header"

    if normalized_query_org_id:
        return normalized_query_org_id, "query"

    if default_to_actor_org and auth_context.org_id:
        return auth_context.org_id, "actor"

    return None, "missing"


def build_org_context(
    auth_context: AuthContext,
    *,
    target_org_id: str,
    source: str,
) -> OrgContext:
    return OrgContext(
        actor_org_id=auth_context.org_id,
        target_org_id=target_org_id,
        source=source,
    )


async def get_org_context(
    x_org_id: str | None = Header(default=None),
    org_id: str | None = Query(default=None),
    auth_context: AuthContext = Depends(get_auth_context),
) -> OrgContext:
    target_org_id, source = resolve_target_org_id(
        auth_context=auth_context,
        header_org_id=x_org_id,
        query_org_id=org_id,
        default_to_actor_org=True,
    )
    resolved_target_org_id = require_matching_org_ids(
        auth_context.org_id,
        target_org_id,
        metadata={"dependency": "get_org_context", "source": source},
    )
    return build_org_context(
        auth_context,
        target_org_id=resolved_target_org_id,
        source=source,
    )


async def require_org_context(
    x_org_id: str | None = Header(default=None),
    org_id: str | None = Query(default=None),
    auth_context: AuthContext = Depends(get_auth_context),
) -> OrgContext:
    target_org_id, source = resolve_target_org_id(
        auth_context=auth_context,
        header_org_id=x_org_id,
        query_org_id=org_id,
        default_to_actor_org=False,
    )
    require_same_org(
        auth_context,
        target_org_id=target_org_id,
        metadata={"dependency": "require_org_context", "source": source},
    )
    return build_org_context(
        auth_context,
        target_org_id=target_org_id or "",
        source=source,
    )


def require_explicit_org_context():
    async def dependency(
        x_org_id: str | None = Header(default=None),
        org_id: str | None = Query(default=None),
        auth_context: AuthContext = Depends(get_auth_context),
    ) -> OrgContext:
        target_org_id, source = resolve_target_org_id(
            auth_context=auth_context,
            header_org_id=x_org_id,
            query_org_id=org_id,
            default_to_actor_org=False,
        )
        resolved_target_org_id = require_matching_org_ids(
            auth_context.org_id,
            target_org_id,
            metadata={
                "dependency": "require_explicit_org_context",
                "source": source,
            },
        )
        return build_org_context(
            auth_context,
            target_org_id=resolved_target_org_id,
            source=source,
        )

    return dependency