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
from app.services.supabase_auth import validate_token_via_supabase

_logger = logging.getLogger(__name__)


API_KEY_HEADER_NAME = "X-API-Key"
SESSION_ID_HEADER_NAME = "X-Session-Id"
ORG_ID_HEADER_NAME = "X-Org-Id"
ORGANIZATION_ID_HEADER_NAME = "X-Organization-Id"
TENANT_ID_HEADER_NAME = "X-Tenant-Id"
AUTHORIZATION_HEADER_NAME = "Authorization"


_RESOLVED_API_KEY_RECORD_REQUEST_STATE_KEY = "_resolved_api_key_record"


api_key_header = APIKeyHeader(name=API_KEY_HEADER_NAME, auto_error=False)
session_id_header = APIKeyHeader(name=SESSION_ID_HEADER_NAME, auto_error=False)
org_id_header = APIKeyHeader(name=ORG_ID_HEADER_NAME, auto_error=False)
organization_id_header = APIKeyHeader(
    name=ORGANIZATION_ID_HEADER_NAME,
    auto_error=False,
)
tenant_id_header = APIKeyHeader(name=TENANT_ID_HEADER_NAME, auto_error=False)
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

    effective_api_key = _clean_optional_string(
        getattr(settings, "effective_api_key", None),
    )
    if effective_api_key is not None:
        return effective_api_key

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

    effective_value = _clean_optional_string(
        getattr(settings, "effective_secret_key", None),
    )
    if effective_value is not None:
        return effective_value

    value = _clean_optional_string(getattr(settings, "secret_key", None))
    if value:
        return value

    return None


_get_secret_key = get_secret_key


def get_jwt_secret(request: Request) -> str | None:
    settings = _get_settings(request)
    if settings is None:
        return None

    effective_value = _clean_optional_string(
        getattr(settings, "effective_jwt_secret", None),
    )
    if effective_value is not None:
        return effective_value

    value = _clean_optional_string(getattr(settings, "jwt_secret", None))
    if value:
        return value

    return None


_get_jwt_secret = get_jwt_secret


def get_supabase_jwt_secret(request: Request) -> str | None:
    settings = _get_settings(request)
    if settings is None:
        return None

    effective_value = _clean_optional_string(
        getattr(settings, "effective_supabase_jwt_secret", None),
    )
    if effective_value is not None:
        return effective_value

    for attr_name in ("supabase_jwt_secret", "SUPABASE_JWT_SECRET"):
        value = _clean_optional_string(getattr(settings, attr_name, None))
        if value:
            return value

    return get_jwt_secret(request)


def _get_jwt_algorithm(request: Request) -> str:
    settings = _get_settings(request)
    if settings is None:
        return "HS256"

    effective_value = _clean_optional_string(
        getattr(settings, "effective_jwt_algorithm", None),
    )
    if effective_value is not None:
        return effective_value.upper()

    for attr_name in ("jwt_algorithm", "JWT_ALGORITHM"):
        value = _clean_optional_string(getattr(settings, attr_name, None))
        if value is not None:
            return value.upper()

    return "HS256"


def _token_algorithm(token: str) -> str | None:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        return None
    return _clean_optional_string(header.get("alg"))


def _validate_bearer_token_remotely(
    request: Request,
    token: str,
) -> dict[str, Any] | None:
    settings = _get_settings(request)
    try:
        return validate_token_via_supabase(token, settings=settings)
    except Exception as exc:
        _logger.warning("Remote Supabase bearer validation failed: %s", exc)
        return None


def _bearer_token_error(
    algorithm: str,
    token_algorithm: str | None,
) -> dict[str, str | None]:
    return {
        "error": "invalid_bearer_token",
        "detail": "Invalid Bearer token — algorithm mismatch or signature failure",
        "alg_in_token": token_algorithm,
        "expected_alg": algorithm,
    }


def _touch_record_if_possible(record: APIKeyRecord) -> APIKeyRecord:
    touch = getattr(record, "touch", None)
    if not callable(touch):
        return record

    try:
        updated = cast("APIKeyRecord | None", touch())
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


def _get_cached_registry_record(request: Request) -> APIKeyRecord | None:
    try:
        return cast(
            "APIKeyRecord | None",
            getattr(request.state, _RESOLVED_API_KEY_RECORD_REQUEST_STATE_KEY, None),
        )
    except Exception:
        return None


def _cache_registry_record(request: Request, record: APIKeyRecord | None) -> None:
    try:
        setattr(request.state, _RESOLVED_API_KEY_RECORD_REQUEST_STATE_KEY, record)
    except Exception:
        pass


def _resolve_registry_api_key_for_request(
    request: Request,
    provided_api_key: str | None,
) -> APIKeyRecord | None:
    normalized_api_key = _clean_optional_string(provided_api_key)
    if normalized_api_key is None:
        return None

    cached_record = _get_cached_registry_record(request)
    if cached_record is not None:
        return cached_record

    record = _resolve_registry_api_key(normalized_api_key)
    if record is not None:
        _cache_registry_record(request, record)

    return record


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


def _has_bearer_auth_config(request: Request) -> bool:
    settings = _get_settings(request)
    if settings is None:
        return False

    return get_supabase_jwt_secret(request) is not None or (
        _clean_optional_string(
            getattr(settings, "effective_supabase_url", None),
        )
        is not None
        and (
            _clean_optional_string(
                getattr(settings, "effective_supabase_anon_key", None),
            )
            is not None
            or _clean_optional_string(
                getattr(settings, "effective_supabase_service_role_key", None),
            )
            is not None
        )
    )


def _is_auth_required(request: Request) -> bool:
    if _is_preflight_request(request):
        return False

    settings = _get_settings(request)
    if settings is None:
        return _has_registry_keys() or _extract_configured_api_key(request) is not None or _has_bearer_auth_config(request)

    effective_flag = _coerce_optional_bool(
        getattr(settings, "effective_auth_required", None),
    )
    if effective_flag is not None:
        return effective_flag

    explicit_flag = _coerce_optional_bool(
        getattr(settings, "auth_required", None),
    )
    if explicit_flag is not None:
        return explicit_flag

    explicit_flag = _coerce_optional_bool(
        getattr(settings, "AUTH_REQUIRED", None),
    )
    if explicit_flag is not None:
        return explicit_flag

    configured_flag = _coerce_optional_bool(
        getattr(settings, "auth_configured", None),
    )
    if configured_flag is not None:
        return configured_flag

    if _extract_configured_api_key(request) is not None:
        return True

    if _has_bearer_auth_config(request):
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

    for attr_name in (
        "key_id",
        "id",
        "client_id",
        "owner_id",
        "principal_id",
    ):
        value = _clean_optional_string(getattr(record, attr_name, None))
        if value is not None:
            return value

    return None


def _extract_header_org_candidates(
    request: Request,
    provided_org_id: str | None,
    provided_organization_id: str | None,
    provided_tenant_id: str | None,
) -> tuple[str | None, str | None]:
    candidates: list[tuple[str, str | None]] = [
        (ORG_ID_HEADER_NAME, provided_org_id),
        (ORGANIZATION_ID_HEADER_NAME, provided_organization_id),
        (TENANT_ID_HEADER_NAME, provided_tenant_id),
        (ORG_ID_HEADER_NAME, request.headers.get(ORG_ID_HEADER_NAME)),
        (
            ORGANIZATION_ID_HEADER_NAME,
            request.headers.get(ORGANIZATION_ID_HEADER_NAME),
        ),
        (TENANT_ID_HEADER_NAME, request.headers.get(TENANT_ID_HEADER_NAME)),
    ]

    normalized_values: list[tuple[str, str]] = []
    seen_values: set[str] = set()

    for header_name, raw_value in candidates:
        value = _clean_optional_string(raw_value)
        if value is None:
            continue

        if value not in seen_values:
            normalized_values.append((header_name, value))
            seen_values.add(value)

    if not normalized_values:
        return None, None

    first_header_name, first_value = normalized_values[0]
    conflicting_values = {value for _, value in normalized_values}
    if len(conflicting_values) > 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=("Conflicting organization scope headers provided; send only one organization identifier value"),
        )

    return first_value, first_header_name


def _coerce_org_id_from_record(record: APIKeyRecord | None) -> str | None:
    if record is None:
        return None

    for attr_name in ("org_id", "organization_id", "tenant_id"):
        value = _clean_optional_string(getattr(record, attr_name, None))
        if value is not None:
            return value

    return None


def _coerce_org_id_from_settings(request: Request) -> str | None:
    settings = _get_settings(request)
    if settings is not None:
        for attr_name in ("org_id", "organization_id", "default_org_id"):
            value = _clean_optional_string(getattr(settings, attr_name, None))
            if value is not None:
                return value

    return None


def _coerce_org_id(
    request: Request,
    provided_org_id: str | None,
    provided_organization_id: str | None,
    provided_tenant_id: str | None,
    record: APIKeyRecord | None,
) -> tuple[str | None, str]:
    header_org_id, header_source = _extract_header_org_candidates(
        request,
        provided_org_id,
        provided_organization_id,
        provided_tenant_id,
    )
    if header_org_id is not None:
        return header_org_id, header_source or "header"

    record_org_id = _coerce_org_id_from_record(record)
    if record_org_id is not None:
        return record_org_id, "api_key_record"

    settings_org_id = _coerce_org_id_from_settings(request)
    if settings_org_id is not None:
        return settings_org_id, "settings"

    return None, "none"


def _coerce_key_type(record: APIKeyRecord | None) -> str:
    if record is None:
        return "personal"

    for attr_name in ("key_type", "kind"):
        value = _clean_optional_string(getattr(record, attr_name, None))
        if value is not None:
            normalized = value.lower()
            if normalized in {"org", "organization", "tenant"}:
                return "org"
            if normalized in {"personal", "user"}:
                return "personal"
            return normalized

    api_key_value = _clean_optional_string(getattr(record, "api_key", None))
    if api_key_value and api_key_value.startswith("ic_org_"):
        return "org"

    if _coerce_org_id_from_record(record) is not None:
        return "org"

    return "personal"


def _resolve_registry_principal_type(record: APIKeyRecord | None) -> str:
    if record is None:
        return "api_key"

    explicit_principal_type = _clean_optional_string(
        getattr(record, "principal_type", None),
    )
    if explicit_principal_type is not None:
        return explicit_principal_type

    return "org_key" if _coerce_key_type(record) == "org" else "api_key"


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


def _extract_claim_values(
    claims: dict[str, Any],
    *claim_names: str,
) -> tuple[str, ...]:
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
    provided_organization_id: str | None,
    provided_tenant_id: str | None,
) -> tuple[str | None, str]:
    for claim_name in (
        "org_id",
        "organization_id",
        "tenant_id",
        "orgId",
    ):
        claim_value = _clean_optional_string(claims.get(claim_name))
        if claim_value is not None:
            return claim_value, f"claim:{claim_name}"

    user_metadata = claims.get("user_metadata")
    if isinstance(user_metadata, dict):
        for claim_name in (
            "org_id",
            "organization_id",
            "tenant_id",
            "orgId",
        ):
            claim_value = _clean_optional_string(user_metadata.get(claim_name))
            if claim_value is not None:
                return claim_value, f"user_metadata:{claim_name}"

    app_metadata = claims.get("app_metadata")
    if isinstance(app_metadata, dict):
        for claim_name in (
            "org_id",
            "organization_id",
            "tenant_id",
            "orgId",
        ):
            claim_value = _clean_optional_string(app_metadata.get(claim_name))
            if claim_value is not None:
                return claim_value, f"app_metadata:{claim_name}"

    return _coerce_org_id(
        request,
        provided_org_id,
        provided_organization_id,
        provided_tenant_id,
        None,
    )


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

    auth_required = _is_auth_required(request)
    secret = get_supabase_jwt_secret(request)
    algorithm = _get_jwt_algorithm(request)
    token_algorithm = _token_algorithm(token)
    claims: dict[str, Any] | None = None

    if secret:
        try:
            claims = cast(
                "dict[str, Any]",
                jwt.decode(
                    token,
                    secret,
                    algorithms=[algorithm],
                    options={"verify_aud": False},
                ),
            )
        except jwt.PyJWTError as exc:
            _logger.warning(
                "Local Bearer validation failed: %s; alg_in_token=%s expected_alg=%s",
                exc,
                token_algorithm,
                algorithm,
            )
            claims = _validate_bearer_token_remotely(request, token)
    else:
        claims = _validate_bearer_token_remotely(request, token)

    if claims is None:
        if not auth_required:
            _logger.info("Ignoring invalid Bearer token because auth is disabled")
            return None

        if not secret:
            _logger.warning(
                "Bearer auth validation unavailable: SUPABASE_JWT_SECRET is not configured",
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=("SUPABASE_JWT_SECRET is not configured; configure or use remote validation via SUPABASE_URL + SUPABASE_ANON_KEY"),
            )

        _logger.warning(
            "Invalid Bearer token: alg_in_token=%s expected_alg=%s",
            token_algorithm,
            algorithm,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_bearer_token_error(algorithm, token_algorithm),
        )

    principal_id = _clean_optional_string(claims.get("sub"))
    if principal_id is None:
        if not auth_required:
            _logger.info(
                "Ignoring Bearer token without sub claim because auth is disabled",
            )
            return None

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token missing sub claim",
        )

    return BearerAuthContext(
        token=token,
        principal_id=principal_id,
        claims=claims,
        auth_source="supabase_jwt" if secret else "supabase_remote",
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
        _cache_registry_record(request, None)
        return normalized_api_key

    registry_record = _resolve_registry_api_key_for_request(
        request,
        normalized_api_key,
    )
    if registry_record is not None:
        return normalized_api_key

    if not auth_required:
        _logger.info(
            "Allowing unrecognized API key passthrough because auth is disabled",
        )
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
    provided_organization_id: str | None = Depends(organization_id_header),
    provided_tenant_id: str | None = Depends(tenant_id_header),
) -> AuthContext:
    if _is_preflight_request(request):
        return _preflight_auth_context()

    normalized_session_id = _clean_optional_string(session_id)
    normalized_api_key = _clean_optional_string(api_key)

    if normalized_api_key:
        registry_record = _resolve_registry_api_key_for_request(
            request,
            normalized_api_key,
        )
        principal_type = "platform"
        auth_source = "passthrough"
        auth_method = "api_key"

        if registry_record is not None:
            principal_type = _resolve_registry_principal_type(registry_record)
            auth_source = "registry"
            auth_method = "registry_api_key"
        else:
            configured_api_key = _extract_configured_api_key(request)
            if _constant_time_match(configured_api_key, normalized_api_key):
                auth_source = "configured"

        resolved_key_type = _coerce_key_type(registry_record)
        resolved_org_id, org_source = _coerce_org_id(
            request,
            provided_org_id,
            provided_organization_id,
            provided_tenant_id,
            registry_record,
        )
        resolved_principal_id = _coerce_principal_id(registry_record)

        if registry_record is not None and resolved_key_type == "org":
            principal_type = "org_key"

        return AuthContext(
            api_key=normalized_api_key,
            principal_type=principal_type,
            principal_id=resolved_principal_id,
            session_id=normalized_session_id,
            org_id=resolved_org_id,
            permissions=_coerce_permissions(registry_record),
            roles=_coerce_roles(registry_record),
            authenticated=True,
            auth_source=auth_source,
            auth_method=auth_method,
            key_type=resolved_key_type,
            metadata={
                "header": API_KEY_HEADER_NAME,
                "org_source": org_source,
            },
        )

    if isinstance(bearer_context, BearerAuthContext):
        metadata: dict[str, str] = {
            "header": AUTHORIZATION_HEADER_NAME,
        }

        for claim_name in ("email", "role", "aal", "iss"):
            claim_value = _clean_optional_string(
                bearer_context.claims.get(claim_name),
            )
            if claim_value is not None:
                metadata[claim_name] = claim_value

        resolved_org_id, org_source = _resolve_bearer_org_id(
            request,
            bearer_context.claims,
            provided_org_id,
            provided_organization_id,
            provided_tenant_id,
        )
        resolved_roles = _resolve_bearer_roles(bearer_context.claims)
        resolved_permissions = _resolve_bearer_permissions(bearer_context.claims)
        resolved_principal_type = _resolve_bearer_principal_type(
            bearer_context.claims,
        )
        metadata["org_source"] = org_source

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

    resolved_org_id, org_source = _coerce_org_id(
        request,
        provided_org_id,
        provided_organization_id,
        provided_tenant_id,
        None,
    )

    return AuthContext(
        api_key=None,
        principal_type="anonymous",
        principal_id=None,
        session_id=normalized_session_id,
        org_id=resolved_org_id,
        authenticated=False,
        auth_source="disabled",
        auth_method=None,
        key_type="personal",
        metadata={"org_source": org_source},
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
