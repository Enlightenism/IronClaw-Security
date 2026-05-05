from __future__ import annotations

from typing import Any, Mapping

from fastapi import Header, Request

from app.core.access_control import require_access
from app.core.auth import AuthContext
from app.core.org_isolation import require_same_org
from app.core.permissions import require_permission


def _clean(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


def _clean_lower(value: object) -> str:
    return _clean(value).lower()


def _normalize_string_list(value: object) -> tuple[str, ...]:
    if value is None:
        return ()

    items: list[object]
    if isinstance(value, str):
        items = [part for part in value.split(",")]
    elif isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        return ()

    normalized: list[str] = []
    seen: set[str] = set()

    for item in items:
        cleaned = _clean_lower(item)
        if not cleaned or cleaned in seen:
            continue
        normalized.append(cleaned)
        seen.add(cleaned)

    return tuple(normalized)


def _normalize_metadata(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def _extract_auth_payload(request: Request) -> Mapping[str, Any]:
    payload = getattr(request.state, "auth", None)
    if isinstance(payload, Mapping):
        return payload

    payload = getattr(request.state, "auth_context", None)
    if isinstance(payload, Mapping):
        return payload

    return {}


def build_auth_context(request: Request) -> AuthContext:
    payload = _extract_auth_payload(request)

    return AuthContext(
        authenticated=bool(payload.get("authenticated", False)),
        principal_id=_clean(payload.get("principal_id")) or None,
        principal_type=_clean_lower(payload.get("principal_type")) or "anonymous",
        org_id=_clean(payload.get("org_id")) or None,
        roles=_normalize_string_list(payload.get("roles")),
        permissions=_normalize_string_list(payload.get("permissions")),
        session_id=_clean(payload.get("session_id")) or None,
        auth_method=_clean_lower(payload.get("auth_method")) or None,
        metadata=_normalize_metadata(payload.get("metadata")),
    )


async def get_auth_context(request: Request) -> AuthContext:
    return build_auth_context(request)


async def get_authenticated_auth_context(request: Request) -> AuthContext:
    context = build_auth_context(request)
    require_access(
        context,
        action="authenticated_context",
    )
    return context


async def require_authenticated(request: Request) -> AuthContext:
    context = build_auth_context(request)
    require_access(
        context,
        action="authenticated",
    )
    return context


def require_permission_dependency(permission: str):
    async def dependency(request: Request) -> AuthContext:
        context = build_auth_context(request)
        require_permission(
            context,
            permission,
            metadata={"dependency": "require_permission_dependency"},
        )
        return context

    return dependency


def require_access_dependency(
    *,
    action: str,
    permission: str | None = None,
    roles: tuple[str, ...] | list[str] | set[str] | None = None,
):
    async def dependency(request: Request) -> AuthContext:
        context = build_auth_context(request)
        require_access(
            context,
            action=action,
            required_permission=permission,
            required_roles=roles,
            metadata={"dependency": "require_access_dependency"},
        )
        return context

    return dependency


async def require_same_org_dependency(
    request: Request,
    x_org_id: str | None = Header(default=None),
) -> AuthContext:
    context = build_auth_context(request)
    target_org_id = _clean(x_org_id) or context.org_id
    require_same_org(
        context,
        target_org_id=target_org_id,
        metadata={"dependency": "require_same_org_dependency"},
    )
    return context