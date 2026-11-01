from __future__ import annotations

from typing import Any

import httpx
import jwt
from jwt import PyJWKClient

from app.core.settings import Settings, get_settings


def _clean_optional_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned or None


def _setting_value(settings: Settings, *names: str) -> str | None:
    for name in names:
        value = _clean_optional_string(getattr(settings, name, None))
        if value is not None:
            return value
    return None


def _clean_string_list(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        cleaned = _clean_optional_string(value)
        return (cleaned,) if cleaned is not None else ()

    if isinstance(value, list | tuple | set):
        normalized: list[str] = []
        seen: set[str] = set()

        for candidate in value:
            cleaned = _clean_optional_string(candidate)
            if cleaned is None or cleaned in seen:
                continue
            normalized.append(cleaned)
            seen.add(cleaned)

        return tuple(normalized)

    return ()


def _first_non_empty_claim(source: dict[str, Any], *names: str) -> Any | None:
    for name in names:
        if name not in source:
            continue
        value = source.get(name)
        if isinstance(value, str):
            cleaned = _clean_optional_string(value)
            if cleaned is not None:
                return cleaned
            continue
        if value is not None:
            return value
    return None


def _resolved_roles_from_metadata(
    app_metadata: dict[str, Any],
    user_metadata: dict[str, Any],
) -> tuple[str, ...]:
    for metadata in (app_metadata, user_metadata):
        for field_name in ("roles", "role", "permissions_role"):
            roles = _clean_string_list(metadata.get(field_name))
            if roles:
                return roles
    return ()


def _claims_from_supabase_user(user: object) -> dict[str, Any] | None:
    if not isinstance(user, dict):
        return None

    user_id = _clean_optional_string(user.get("id"))
    if user_id is None:
        return None

    user_metadata = user.get("user_metadata")
    app_metadata = user.get("app_metadata")

    normalized_user_metadata = user_metadata if isinstance(user_metadata, dict) else {}
    normalized_app_metadata = app_metadata if isinstance(app_metadata, dict) else {}

    claims: dict[str, Any] = {
        "sub": user_id,
        "user_metadata": normalized_user_metadata,
        "app_metadata": normalized_app_metadata,
    }

    for field_name in (
        "email",
        "phone",
        "role",
        "aud",
        "session_id",
        "aal",
        "amr",
        "is_anonymous",
    ):
        if field_name in user:
            claims[field_name] = user.get(field_name)

    resolved_roles = _resolved_roles_from_metadata(
        normalized_app_metadata,
        normalized_user_metadata,
    )
    if resolved_roles:
        claims["roles"] = list(resolved_roles)
        if "role" not in claims:
            claims["role"] = resolved_roles[0]

    resolved_permissions_role = _first_non_empty_claim(
        normalized_app_metadata,
        "permissions_role",
    )
    if resolved_permissions_role is None:
        resolved_permissions_role = _first_non_empty_claim(
            normalized_user_metadata,
            "permissions_role",
        )
    if resolved_permissions_role is not None:
        claims["permissions_role"] = resolved_permissions_role

    return claims


def _jwks_url(settings: Settings) -> str | None:
    supabase_url = _setting_value(
        settings,
        "effective_supabase_url",
        "supabase_url",
        "SUPABASE_URL",
    )
    if supabase_url is None:
        return None
    return f"{supabase_url.rstrip('/')}/auth/v1/.well-known/jwks.json"


def _decode_token_via_jwks(
    token: str,
    settings: Settings,
) -> dict[str, Any] | None:
    jwks_url = _jwks_url(settings)
    if jwks_url is None:
        return None

    try:
        jwk_client = PyJWKClient(jwks_url)
        signing_key = jwk_client.get_signing_key_from_jwt(token)

        key = signing_key.key
        if hasattr(key, "key"):
            key = key.key

        claims = jwt.decode(
            token,
            key,
            algorithms=["ES256"],
            options={
                "verify_aud": False,
                "verify_iss": False,
            },
        )
    except Exception:
        return None

    if not isinstance(claims, dict):
        return None

    return claims


def validate_token_via_supabase(
    token: str,
    settings: Settings | None = None,
    timeout: float = 3.0,
) -> dict[str, Any] | None:
    """Validate a bearer token through Supabase JWT verification, falling back to the authenticated-user endpoint."""
    normalized_token = _clean_optional_string(token)
    if normalized_token is None:
        return None

    resolved_settings = settings
    if resolved_settings is None:
        try:
            resolved_settings = get_settings()
        except Exception:
            return None

    claims = _decode_token_via_jwks(normalized_token, resolved_settings)
    if claims is not None:
        return claims

    supabase_url = _setting_value(
        resolved_settings,
        "effective_supabase_url",
        "supabase_url",
        "SUPABASE_URL",
    )
    api_key = _setting_value(
        resolved_settings,
        "effective_supabase_anon_key",
        "supabase_anon_key",
        "SUPABASE_ANON_KEY",
        "effective_supabase_service_role_key",
        "supabase_service_role_key",
        "SUPABASE_SERVICE_ROLE_KEY",
    )
    if supabase_url is None or api_key is None:
        return None

    try:
        timeout_value = float(timeout)
    except (TypeError, ValueError):
        timeout_value = 3.0

    if timeout_value <= 0:
        timeout_value = 3.0

    endpoint = f"{supabase_url.rstrip('/')}/auth/v1/user"
    headers = {
        "Authorization": f"Bearer {normalized_token}",
        "apikey": api_key,
    }

    try:
        response = httpx.get(
            endpoint,
            headers=headers,
            timeout=timeout_value,
        )
    except httpx.HTTPError:
        return None
    except Exception:
        return None

    if response.status_code != 200:
        return None

    try:
        payload = response.json()
    except (ValueError, TypeError):
        return None

    return _claims_from_supabase_user(payload)
