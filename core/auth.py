from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from core.settings import get_settings
from fastapi import Header, HTTPException, Request, status

from core.apikeys import ApiKeyRecord, registry

PrincipalType = Literal["system", "customer", "service"]


@dataclass(slots=True)
class AuthPrincipal:
    subject: str
    principal_type: PrincipalType
    key_id: str
    key_name: str
    scope: str
    is_authenticated: bool = True


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _forbidden(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=detail,
    )


def _normalize_scope(scope: str | None) -> str:
    value = (scope or "").strip().lower()
    if not value:
        return "customer"
    return value


def _principal_type_from_scope(scope: str) -> PrincipalType:
    normalized = _normalize_scope(scope)
    if normalized in {"internal", "system", "platform", "admin"}:
        return "system"
    if normalized in {"service", "integration"}:
        return "service"
    return "customer"


def parse_bearer_token(authorization: str | None) -> str | None:
    if authorization is None:
        return None

    value = authorization.strip()
    if not value:
        return None

    scheme, _, token = value.partition(" ")
    if scheme.lower() != "bearer":
        return None

    token = token.strip()
    if not token:
        return None

    return token


def _configured_platform_api_key(request: Request | None = None) -> str | None:
    try:
        settings = get_settings()
    except Exception:
        settings = None

    candidate_names = (
        "internal_api_key",
        "platform_api_key",
        "ironclaw_api_key",
        "api_key",
    )

    if settings is not None:
        for name in candidate_names:
            value = getattr(settings, name, None)
            if isinstance(value, str) and value.strip():
                return value.strip()

    if request is not None:
        app_settings = getattr(getattr(request, "app", None), "state", None)
        app_settings = getattr(app_settings, "settings", None)
        if app_settings is not None:
            for name in candidate_names:
                value = getattr(app_settings, name, None)
                if isinstance(value, str) and value.strip():
                    return value.strip()

    return None


def _match_configured_platform_key(candidate: str, request: Request | None = None) -> AuthPrincipal | None:
    configured_key = _configured_platform_api_key(request)
    if not configured_key or candidate != configured_key:
        return None

    return AuthPrincipal(
        subject="ironclaw-platform",
        principal_type="system",
        key_id="internal-platform-key",
        key_name="Internal Platform API Key",
        scope="internal",
        is_authenticated=True,
    )


def get_api_key_record(raw_api_key: str, request: Request | None = None) -> ApiKeyRecord:
    candidate = raw_api_key.strip() if raw_api_key else ""
    if not candidate:
        raise _unauthorized("Missing API key")

    record = registry.authenticate(candidate)
    if record is None:
        platform_principal = _match_configured_platform_key(candidate, request)
        if platform_principal is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Configured platform key should be resolved through principal authentication, not record lookup.",
            )
        raise _unauthorized("Invalid API key")

    return record


def authenticate_api_key(raw_api_key: str, request: Request | None = None) -> AuthPrincipal:
    candidate = raw_api_key.strip() if raw_api_key else ""
    if not candidate:
        raise _unauthorized("Missing API key")

    platform_principal = _match_configured_platform_key(candidate, request)
    if platform_principal is not None:
        return platform_principal

    record = get_api_key_record(candidate, request)

    return AuthPrincipal(
        subject=record.owner_id or record.key_id,
        principal_type=_principal_type_from_scope(record.scope),
        key_id=record.key_id,
        key_name=record.name,
        scope=_normalize_scope(record.scope),
        is_authenticated=True,
    )


def resolve_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> AuthPrincipal:
    bearer_token = parse_bearer_token(authorization)
    candidate = x_api_key or bearer_token
    return authenticate_api_key(candidate or "", request)


def require_scope(principal: AuthPrincipal, *allowed_scopes: str) -> AuthPrincipal:
    normalized_allowed = {_normalize_scope(scope) for scope in allowed_scopes if scope}
    principal_scope = _normalize_scope(principal.scope)

    if normalized_allowed and principal_scope not in normalized_allowed:
        raise _forbidden("Insufficient scope")

    return principal
