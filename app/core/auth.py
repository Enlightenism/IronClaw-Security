from __future__ import annotations

from dataclasses import dataclass, field
import hmac
import logging
from typing import Any, cast

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader
import jwt

from app.core.apikeys import (
    APIKeyRecord,
    fingerprint_api_key,
    get_api_key_registry,
    is_api_key_expired,
)
from app.core.errors import AppError
from app.core.settings import get_settings

_logger = logging.getLogger(__name__)

API_KEY_HEADER_NAME = "X-API-Key"
SESSION_ID_HEADER_NAME = "X-Session-Id"
ORG_ID_HEADER_NAME = "X-Org-Id"
AUTHORIZATION_HEADER_NAME = "Authorization"

api_key_header = APIKeyHeader(name=API_KEY_HEADER_NAME, auto_error=False)
session_id_header = APIKeyHeader(name=SESSION_ID_HEADER_NAME, auto_error=False)
org_id_header = APIKeyHeader(name=ORG_ID_HEADER_NAME, auto_error=False)
authorization_header = APIKeyHeader(name=AUTHORIZATION_HEADER_NAME, auto_error=False)


@dataclass(frozen=True, slots=True)
class AuthContext:
    api_key: str | None
    principal_type: str
    principal_id: str | None
    session_id: str | None
    org_id: str | None
    permissions: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    authenticated: bool = False
    auth_source: str = "none"
    auth_method: str | None = None
    key_type: str = "personal"
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class BearerAuthContext:
    token: str
    principal_id: str
    claims: dict[str, Any]
    auth_source: str = "supabase_jwt"
    auth_method: str = "bearer_jwt"


def _get_settings(request: Request) -> Any | None:
    try:
        state_settings = getattr(request.app.state, "settings", None)
        if state_settings is not None:
            return state_settings
    except Exception:
        pass
    try:
        return get_settings()
    except Exception:
        return None


def _clean_optional_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _coerce_optional_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off"}:
            return False
    return None


def _is_preflight_request(request: Request) -> bool:
    return request.method.upper() == "OPTIONS" and bool(request.headers.get("origin")) and bool(request.headers.get("access-control-request-method"))


def _preflight_auth_context() -> AuthContext:
    return AuthContext(
        api_key=None,
        principal_type="preflight",
        principal_id=None,
        session_id=None,
        org_id=None,
        authenticated=False,
        auth_source="preflight",
        auth_method=None,
        key_type="personal",
        metadata={"request_method": "OPTIONS"},
    )


def _extract_configured_api_key(request: Request) -> str | None:
    settings = _get_settings(request)
    if settings is None:
        return None

    for attr_name in (
        "ironclaw_api_key",
        "internal_platform_api_key",
        "platform_api_key",
        "admin_api_key",
        "api_key",
    ):
        value = _clean_optional_string(getattr(settings, attr_name, None))
        if value is not None:
            return value

    return _clean_optional_string(
        getattr(settings, "effective_platform_api_key", None),
    )


def get_secret_key(request: Request) -> str | None:
    settings = _get_settings(request)
    if settings is None:
        return None
    effective_value = _clean_optional_string(getattr(settings, "effective_secret_key", None))
    if effective_value is not None:
        return effective_value
    value = _clean_optional_string(getattr(settings, "secret_key", None))
    if value and value != "changeme-32-chars-minimum!!!!!":
        return value
    return None


_get_secret_key = get_secret_key


def get_jwt_secret(request: Request) -> str | None:
    settings = _get_settings(request)
    if settings is None:
        return None
    effective_value = _clean_optional_string(getattr(settings, "effective_jwt_secret", None))
    if effective_value is not None:
        return effective_value
    value = _clean_optional_string(getattr(settings, "jwt_secret", None))
    if value and value != "changeme-jwt-32-chars-minimum!!":
        return value
    return None


_get_jwt_secret = get_jwt_secret


def get_supabase_jwt_secret(request: Request) -> str | None:
    settings = _get_settings(request)
    if settings is None:
        return None

    for attr_name in (
        "supabase_jwt_secret",
        "SUPABASE_JWT_SECRET",
    ):
        value = _clean_optional_string(getattr(settings, attr_name, None))
        if value:
            return value

    return get_jwt_secret(request)


def _touch_record_if_possible(record: APIKeyRecord) -> APIKeyRecord:
    touch = getattr(record, "touch", None)
    if not callable(touch):
        return record

    try:
        updated = cast(APIKeyRecord | None, touch())
    except Exception:
        return record

    if updated is None:
        return record

    registry = get_api_key_registry()
    updater = getattr(registry, "upsert_record", None)
    if callable(updater):
        try:
            updater(updated)
        except Exception:
            pass
    return updated


def _record_is_usable(record: APIKeyRecord | None) -> bool:
    if record is None:
        return False
    if not getattr(record, "active", True):
        return False
    if getattr(record, "revoked_at", None) is not None:
        return False
    if is_api_key_expired(record):
        return False
    return True


def _resolve_registry_api_key(provided_api_key: str) -> APIKeyRecord | None:
    normalized_api_key = _clean_optional_string(provided_api_key)
    if normalized_api_key is None:
        return None

    registry = get_api_key_registry()
    fingerprint = fingerprint_api_key(normalized_api_key)

    resolver = getattr(registry, "get_by_fingerprint", None)
    if callable(resolver):
        try:
            record = resolver(fingerprint)
        except Exception:
            record = None
        if _record_is_usable(record):
            return _touch_record_if_possible(record)

    return None


def _has_registry_keys() -> bool:
    registry = get_api_key_registry()

    summary = getattr(registry, "summary", None)
    if callable(summary):
        try:
            data = summary()
            if isinstance(data, dict):
                return int(data.get("total", 0)) > 0
        except Exception:
            pass

    for attr_name in ("has_keys", "has_api_keys", "has_active_keys"):
        method = getattr(registry, attr_name, None)
        if callable(method):
            try:
                return bool(method())
            except TypeError:
                pass

    list_keys = getattr(registry, "list_keys", None)
    if callable(list_keys):
        try:
            return bool(list_keys())
        except TypeError:
            try:
                return bool(list_keys(active_only=False))
            except Exception:
                pass

    for attr_name in ("keys_by_id", "_keys_by_id", "_records_by_id"):
        value = getattr(registry, attr_name, None)
        if value is not None:
            try:
                return bool(value)
            except TypeError:
                return True

    return False


def _is_auth_required(request: Request) -> bool:
    if _is_preflight_request(request):
        return False

    settings = _get_settings(request)
    if settings is None:
        return _has_registry_keys()

    explicit_flag = _coerce_optional_bool(getattr(settings, "auth_required", None))
    if explicit_flag is not None:
        return explicit_flag

    if _extract_configured_api_key(request) is not None:
        return True

    return _has_registry_keys()


def _constant_time_match(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return False
    return hmac.compare_digest(left, right)


def _coerce_roles(record: APIKeyRecord | None) -> tuple[str, ...]:
    if record is None:
        return ()

    for attr_name in ("roles", "role_names", "grants"):
        value = getattr(record, attr_name, None)
        if isinstance(value, (list, tuple, set)):
            return tuple(str(item).strip() for item in value if str(item).strip())

    role = getattr(record, "role", None)
    role_text = _clean_optional_string(role)
    return (role_text,) if role_text else ()


def _coerce_permissions(record: APIKeyRecord | None) -> tuple[str, ...]:
    if record is None:
        return ()

    for attr_name in ("permissions", "scopes", "allowed_actions"):
        value = getattr(record, attr_name, None)
        if isinstance(value, (list, tuple, set)):
            return tuple(str(item).strip() for item in value if str(item).strip())

    return ()


def _coerce_principal_id(record: APIKeyRecord | None) -> str | None:
    if record is None:
        return None

    for attr_name in ("key_id", "id", "client_id", "owner_id", "principal_id"):
        value = _clean_optional_string(getattr(record, attr_name, None))
        if value is not None:
            return value

    return None


def _coerce_org_id(
    request: Request,
    provided_org_id: str | None,
    record: APIKeyRecord | None,
) -> str | None:
    header_org_id = _clean_optional_string(provided_org_id)
    if header_org_id is not None:
        return header_org_id

    if record is not None:
        for attr_name in ("org_id", "organization_id", "tenant_id"):
            value = _clean_optional_string(getattr(record, attr_name, None))
            if value is not None:
                return value

    settings = _get_settings(request)
    if settings is not None:
        for attr_name in ("org_id", "organization_id", "default_org_id"):
            value = _clean_optional_string(getattr(settings, attr_name, None))
            if value is not None:
                return value

    return None


def _coerce_key_type(record: APIKeyRecord | None) -> str:
    if record is None:
        return "personal"
    value = _clean_optional_string(getattr(record, "key_type", None))
    return value if value else "personal"


def _extract_bearer_token(raw_authorization: str | None) -> str | None:
    value = _clean_optional_string(raw_authorization)
    if value is None:
        return None
    if not value.lower().startswith("bearer "):
        return None
    token = value[7:].strip()
    return token or None


def _clean_claim_strings(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        cleaned = _clean_optional_string(value)
        return (cleaned,) if cleaned else ()
    if isinstance(value, (list, tuple, set)):
        return tuple(item for item in (_clean_optional_string(candidate) for candidate in value) if item is not None)
    return ()


def _extract_claim_values(claims: dict[str, Any], *claim_names: str) -> tuple[str, ...]:
    values: list[str] = []
    seen: set[str] = set()

    for claim_name in claim_names:
        for candidate in _clean_claim_strings(claims.get(claim_name)):
            normalized = candidate.strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                values.append(normalized)

    return tuple(values)


def _resolve_bearer_org_id(
    request: Request,
    claims: dict[str, Any],
    provided_org_id: str | None,
) -> str | None:
    for claim_name in (
        "org_id",
        "organization_id",
        "tenant_id",
        "orgId",
    ):
        claim_value = _clean_optional_string(claims.get(claim_name))
        if claim_value is not None:
            return claim_value

    user_metadata = claims.get("user_metadata")
    if isinstance(user_metadata, dict):
        for claim_name in ("org_id", "organization_id", "tenant_id", "orgId"):
            claim_value = _clean_optional_string(user_metadata.get(claim_name))
            if claim_value is not None:
                return claim_value

    app_metadata = claims.get("app_metadata")
    if isinstance(app_metadata, dict):
        for claim_name in ("org_id", "organization_id", "tenant_id", "orgId"):
            claim_value = _clean_optional_string(app_metadata.get(claim_name))
            if claim_value is not None:
                return claim_value

    return _coerce_org_id(request, provided_org_id, None)


def _resolve_bearer_roles(claims: dict[str, Any]) -> tuple[str, ...]:
    roles = _extract_claim_values(
        claims,
        "roles",
        "role",
        "permissions_role",
    )

    if roles:
        return roles

    app_metadata = claims.get("app_metadata")
    if isinstance(app_metadata, dict):
        roles = _extract_claim_values(
            app_metadata,
            "roles",
            "role",
            "permissions_role",
        )
        if roles:
            return roles

    user_metadata = claims.get("user_metadata")
    if isinstance(user_metadata, dict):
        roles = _extract_claim_values(
            user_metadata,
            "roles",
            "role",
            "permissions_role",
        )
        if roles:
            return roles

    return ("customer_user",)


def _resolve_bearer_permissions(claims: dict[str, Any]) -> tuple[str, ...]:
    permissions = _extract_claim_values(
        claims,
        "permissions",
        "scopes",
        "scope",
        "allowed_actions",
    )

    if permissions:
        return permissions

    app_metadata = claims.get("app_metadata")
    if isinstance(app_metadata, dict):
        permissions = _extract_claim_values(
            app_metadata,
            "permissions",
            "scopes",
            "scope",
            "allowed_actions",
        )
        if permissions:
            return permissions

    user_metadata = claims.get("user_metadata")
    if isinstance(user_metadata, dict):
        permissions = _extract_claim_values(
            user_metadata,
            "permissions",
            "scopes",
            "scope",
            "allowed_actions",
        )
        if permissions:
            return permissions

    return ("customer:read",)


def _resolve_bearer_principal_type(claims: dict[str, Any]) -> str:
    for claim_name in ("principal_type", "principalType"):
        claim_value = _clean_optional_string(claims.get(claim_name))
        if claim_value is not None:
            return claim_value

    app_metadata = claims.get("app_metadata")
    if isinstance(app_metadata, dict):
        for claim_name in ("principal_type", "principalType"):
            claim_value = _clean_optional_string(app_metadata.get(claim_name))
            if claim_value is not None:
                return claim_value

    user_metadata = claims.get("user_metadata")
    if isinstance(user_metadata, dict):
        for claim_name in ("principal_type", "principalType"):
            claim_value = _clean_optional_string(user_metadata.get(claim_name))
            if claim_value is not None:
                return claim_value

    return "customer"


def get_bearer_context(
    request: Request,
    raw_authorization: str | None = Depends(authorization_header),
) -> BearerAuthContext | None:
    if _is_preflight_request(request):
        return None

    token = _extract_bearer_token(raw_authorization)
    if token is None:
        return None

    secret = get_supabase_jwt_secret(request)
    if not secret:
        if not _is_auth_required(request):
            _logger.info("Ignoring Bearer token because auth is disabled and no JWT secret is configured")
            return None
        _logger.warning("Missing SUPABASE_JWT_SECRET for Bearer auth")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SUPABASE_JWT_SECRET is not configured",
        )

    try:
        claims = cast(
            dict[str, Any],
            jwt.decode(
                token,
                secret,
                algorithms=["HS256"],
                options={"verify_aud": False},
            ),
        )
    except jwt.PyJWTError as exc:
        if not _is_auth_required(request):
            _logger.info("Ignoring invalid Bearer token because auth is disabled")
            return None
        _logger.warning("Invalid Bearer token: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Bearer token",
        ) from exc

    principal_id = _clean_optional_string(claims.get("sub"))
    if principal_id is None:
        if not _is_auth_required(request):
            _logger.info("Ignoring Bearer token without sub claim because auth is disabled")
            return None
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token missing sub claim",
        )

    return BearerAuthContext(
        token=token,
        principal_id=principal_id,
        claims=claims,
    )


def get_api_key(
    request: Request,
    provided_api_key: str | None = Depends(api_key_header),
    bearer_context: BearerAuthContext | None = Depends(get_bearer_context),
) -> str | None:
    if _is_preflight_request(request):
        return None

    normalized_api_key = _clean_optional_string(provided_api_key)
    auth_required = _is_auth_required(request)

    if normalized_api_key is None:
        if isinstance(bearer_context, BearerAuthContext):
            return None
        if auth_required:
            _logger.warning("Missing API key")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing API key — provide X-API-Key or Bearer token",
            )
        return None

    configured_api_key = _extract_configured_api_key(request)

    if _constant_time_match(configured_api_key, normalized_api_key):
        return normalized_api_key

    registry_record = _resolve_registry_api_key(normalized_api_key)
    if registry_record is not None:
        return normalized_api_key

    if not auth_required:
        _logger.info("Allowing unrecognized API key passthrough because auth is disabled")
        return normalized_api_key

    if configured_api_key is None and not _has_registry_keys():
        _logger.warning(
            "auth_not_configured: auth_required=True but no API keys are configured",
        )
        raise AppError(
            "auth_not_configured",
            "Authentication is required but no API keys are configured",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    _logger.warning("Invalid API key")
    raise AppError(
        "invalid_api_key",
        "Invalid API key",
        status_code=status.HTTP_401_UNAUTHORIZED,
    )


def get_auth_context(
    request: Request,
    api_key: str | None = Depends(get_api_key),
    bearer_context: BearerAuthContext | None = Depends(get_bearer_context),
    session_id: str | None = Depends(session_id_header),
    provided_org_id: str | None = Depends(org_id_header),
) -> AuthContext:
    if _is_preflight_request(request):
        return _preflight_auth_context()

    normalized_session_id = _clean_optional_string(session_id)
    normalized_api_key = _clean_optional_string(api_key)

    if normalized_api_key:
        registry_record = _resolve_registry_api_key(normalized_api_key)
        principal_type = "platform"
        auth_source = "passthrough"
        auth_method = "api_key"

        if registry_record is not None:
            principal_type = "api_key"
            auth_source = "registry"
            auth_method = "registry_api_key"
        elif _is_auth_required(request):
            auth_source = "configured"

        resolved_key_type = _coerce_key_type(registry_record)
        resolved_org_id = _coerce_org_id(request, provided_org_id, registry_record)

        if resolved_key_type == "org" and registry_record is not None:
            principal_type = "org_key"

        return AuthContext(
            api_key=normalized_api_key,
            principal_type=principal_type,
            principal_id=_coerce_principal_id(registry_record),
            session_id=normalized_session_id,
            org_id=resolved_org_id,
            permissions=_coerce_permissions(registry_record),
            roles=_coerce_roles(registry_record),
            authenticated=True,
            auth_source=auth_source,
            auth_method=auth_method,
            key_type=resolved_key_type,
            metadata={"header": API_KEY_HEADER_NAME},
        )

    if isinstance(bearer_context, BearerAuthContext):
        metadata: dict[str, str] = {
            "header": AUTHORIZATION_HEADER_NAME,
        }

        for claim_name in ("email", "role", "aal", "iss"):
            claim_value = _clean_optional_string(bearer_context.claims.get(claim_name))
            if claim_value is not None:
                metadata[claim_name] = claim_value

        resolved_org_id = _resolve_bearer_org_id(
            request,
            bearer_context.claims,
            provided_org_id,
        )
        resolved_roles = _resolve_bearer_roles(bearer_context.claims)
        resolved_permissions = _resolve_bearer_permissions(bearer_context.claims)
        resolved_principal_type = _resolve_bearer_principal_type(bearer_context.claims)

        return AuthContext(
            api_key=None,
            principal_type=resolved_principal_type,
            principal_id=bearer_context.principal_id,
            session_id=normalized_session_id,
            org_id=resolved_org_id,
            permissions=resolved_permissions,
            roles=resolved_roles,
            authenticated=True,
            auth_source=bearer_context.auth_source,
            auth_method=bearer_context.auth_method,
            key_type="personal",
            metadata=metadata,
        )

    if _is_auth_required(request):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key — provide X-API-Key or Bearer token",
        )

    return AuthContext(
        api_key=None,
        principal_type="anonymous",
        principal_id=None,
        session_id=normalized_session_id,
        org_id=_clean_optional_string(provided_org_id),
        authenticated=False,
        auth_source="disabled",
        auth_method=None,
        key_type="personal",
    )


def require_api_key(
    request: Request,
    api_key: str | None = Depends(get_api_key),
) -> str | None:
    if _is_preflight_request(request):
        return None
    return api_key


def require_auth_context(
    context: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    if context.principal_type == "preflight":
        return context
    if not context.authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return context


def get_current_organization_id(
    context: AuthContext = Depends(get_auth_context),
) -> str:
    org_id = context.org_id
    if org_id:
        return org_id
    return "default"
