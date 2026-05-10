from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from typing import Any, Optional

from fastapi import Depends, Request, status
from fastapi.security import APIKeyHeader

from app.core.apikeys import APIKeyRecord, get_api_key_registry
from app.core.errors import AppError


API_KEY_HEADER_NAME = "X-API-Key"
SESSION_ID_HEADER_NAME = "X-Session-Id"
ORG_ID_HEADER_NAME = "X-Org-Id"

api_key_header = APIKeyHeader(name=API_KEY_HEADER_NAME, auto_error=False)
session_id_header = APIKeyHeader(name=SESSION_ID_HEADER_NAME, auto_error=False)
org_id_header = APIKeyHeader(name=ORG_ID_HEADER_NAME, auto_error=False)


@dataclass(frozen=True, slots=True)
class AuthContext:
    api_key: Optional[str]
    principal_type: str
    principal_id: Optional[str]
    session_id: Optional[str]
    org_id: Optional[str]
    permissions: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    authenticated: bool = False
    auth_source: str = "none"
    auth_method: Optional[str] = None
    metadata: dict[str, str] = field(default_factory=dict)


def _get_settings(request: Request) -> Any | None:
    return getattr(request.app.state, "settings", None)


def _clean_optional_string(value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _extract_configured_api_key(request: Request) -> Optional[str]:
    settings = _get_settings(request)
    if settings is None:
        return None

    for attr_name in (
        "internal_platform_api_key",
        "platform_api_key",
        "admin_api_key",
        "api_key",
    ):
        value = _clean_optional_string(getattr(settings, attr_name, None))
        if value is not None:
            return value

    return _clean_optional_string(
        getattr(settings, "effective_platform_api_key", None)
    )


def _touch_record_if_possible(record: APIKeyRecord) -> APIKeyRecord:
    touch = getattr(record, "touch", None)
    if not callable(touch):
        return record

    try:
        updated = touch()
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


def _resolve_registry_api_key(provided_api_key: str) -> Optional[APIKeyRecord]:
    registry = get_api_key_registry()

    authenticate = getattr(registry, "authenticate", None)
    if callable(authenticate):
        try:
            record = authenticate(provided_api_key, touch=True)
            if record is not None:
                return record
        except TypeError:
            try:
                record = authenticate(provided_api_key)
                if record is not None:
                    return _touch_record_if_possible(record)
            except Exception:
                pass
        except Exception:
            pass

    for attr_name in (
        "resolve_api_key",
        "get_by_raw_key",
        "get_by_api_key",
        "find_by_api_key",
    ):
        resolver = getattr(registry, attr_name, None)
        if callable(resolver):
            try:
                record = resolver(provided_api_key)
                if record is not None:
                    return _touch_record_if_possible(record)
            except Exception:
                pass

    for attr_name in (
        "_key_id_by_secret",
        "key_id_by_secret",
    ):
        mapping = getattr(registry, attr_name, None)
        if mapping is not None:
            try:
                key_id = mapping.get(provided_api_key)
            except Exception:
                key_id = None
            if key_id:
                getter = getattr(registry, "get_by_id", None)
                if callable(getter):
                    try:
                        record = getter(key_id)
                        if record is not None:
                            return _touch_record_if_possible(record)
                    except Exception:
                        pass
                records_by_id = getattr(registry, "_records_by_id", None) or getattr(
                    registry, "keys_by_id", None
                )
                if records_by_id is not None:
                    try:
                        record = records_by_id.get(key_id)
                        if record is not None:
                            return _touch_record_if_possible(record)
                    except Exception:
                        pass

    for attr_name in (
        "_records_by_id",
        "keys_by_id",
        "_keys_by_id",
    ):
        records = getattr(registry, attr_name, None)
        if records is not None:
            try:
                iterable = records.values()
            except Exception:
                iterable = ()
            for record in iterable:
                raw_key = getattr(record, "raw_key", None)
                api_key = getattr(record, "api_key", None)
                if provided_api_key == raw_key or provided_api_key == api_key:
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

    for attr_name in (
        "has_keys",
        "has_api_keys",
        "has_active_keys",
    ):
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

    for attr_name in (
        "keys_by_id",
        "_keys_by_id",
        "_records_by_id",
    ):
        value = getattr(registry, attr_name, None)
        if value is not None:
            try:
                return bool(value)
            except TypeError:
                return True

    return False


def _is_auth_required(request: Request) -> bool:
    settings = _get_settings(request)
    if settings is None:
        return False

    explicit_flag = getattr(settings, "auth_required", None)
    if explicit_flag is not None:
        return bool(explicit_flag)

    if _extract_configured_api_key(request) is not None:
        return True

    return _has_registry_keys()


def _constant_time_match(left: Optional[str], right: Optional[str]) -> bool:
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


def _coerce_principal_id(record: APIKeyRecord | None) -> Optional[str]:
    if record is None:
        return None

    for attr_name in ("key_id", "id", "client_id", "owner_id", "principal_id"):
        value = _clean_optional_string(getattr(record, attr_name, None))
        if value is not None:
            return value

    return None


def _coerce_org_id(
    request: Request,
    provided_org_id: Optional[str],
    record: APIKeyRecord | None,
) -> Optional[str]:
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


def get_api_key(
    request: Request,
    provided_api_key: Optional[str] = Depends(api_key_header),
) -> Optional[str]:
    normalized_api_key = _clean_optional_string(provided_api_key)

    if not _is_auth_required(request):
        return normalized_api_key

    configured_api_key = _extract_configured_api_key(request)
    has_registry_keys = _has_registry_keys()

    if configured_api_key is None and not has_registry_keys:
        raise AppError(
            error="auth_not_configured",
            message="API authentication is enabled but no API key is configured",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    if normalized_api_key is None:
        raise AppError(
            error="missing_api_key",
            message="Missing API key",
            status_code=status.HTTP_401_UNAUTHORIZED,
            details={"header": API_KEY_HEADER_NAME},
        )

    if _constant_time_match(configured_api_key, normalized_api_key):
        return normalized_api_key

    registry_record = _resolve_registry_api_key(normalized_api_key)
    if registry_record is not None and getattr(registry_record, "active", True):
        return normalized_api_key

    raise AppError(
        error="invalid_api_key",
        message="Invalid API key",
        status_code=status.HTTP_401_UNAUTHORIZED,
        details={"header": API_KEY_HEADER_NAME},
    )


def get_auth_context(
    request: Request,
    api_key: Optional[str] = Depends(get_api_key),
    session_id: Optional[str] = Depends(session_id_header),
    provided_org_id: Optional[str] = Depends(org_id_header),
) -> AuthContext:
    normalized_session_id = _clean_optional_string(session_id)
    normalized_api_key = _clean_optional_string(api_key)

    # If a key is present, always authenticate regardless of enforcement mode.
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

        return AuthContext(
            api_key=normalized_api_key,
            principal_type=principal_type,
            principal_id=_coerce_principal_id(registry_record),
            session_id=normalized_session_id,
            org_id=_coerce_org_id(request, provided_org_id, registry_record),
            permissions=_coerce_permissions(registry_record),
            roles=_coerce_roles(registry_record),
            authenticated=True,
            auth_source=auth_source,
            auth_method=auth_method,
            metadata={"header": API_KEY_HEADER_NAME},
        )

    # No key present — enforce if required, otherwise anonymous.
    if _is_auth_required(request):
        raise AppError(
            error="missing_api_key",
            message="Missing API key",
            status_code=status.HTTP_401_UNAUTHORIZED,
            details={"header": API_KEY_HEADER_NAME},
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
    )


def require_api_key(
    request: Request,
    api_key: Optional[str] = Depends(get_api_key),
) -> Optional[str]:
    if not _is_auth_required(request):
        return api_key

    if not api_key:
        raise AppError(
            error="missing_api_key",
            message="Missing API key",
            status_code=status.HTTP_401_UNAUTHORIZED,
            details={"header": API_KEY_HEADER_NAME},
        )

    return api_key


def require_auth_context(
    context: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    if not context.authenticated:
        raise AppError(
            error="authentication_required",
            message="Authentication required",
            status_code=status.HTTP_401_UNAUTHORIZED,
            details={"header": API_KEY_HEADER_NAME},
        )
    return context