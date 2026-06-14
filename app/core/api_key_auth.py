from __future__ import annotations

from dataclasses import dataclass, field
import logging
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
import httpx

from app.core.apikeys import APIKeyRecord, get_api_key_registry
from app.core.auth import AuthContext
from app.core.logging import get_logger
from app.services.secrets_vault import vault

_logger: logging.Logger = get_logger("ironclaw.api_key_auth")


_bearer_scheme = HTTPBearer(auto_error=False)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


_DEFAULT_EDGE_PATH = "/functions/v1/ironclaw-auth"

# Static API key prefixes — keys matching these are local-registry only and
# are never forwarded to the edge auth function.
_STATIC_KEY_PREFIXES: tuple[str, ...] = ("ic_personal_", "ic_org_", "ic_svc_", "ic_")


def _looks_like_static_key(raw_key: str) -> bool:
    """Return True if the key looks like a local registry key (not a JWT/Bearer token)."""
    return any(raw_key.startswith(prefix) for prefix in _STATIC_KEY_PREFIXES)


def _edge_function_url() -> str:
    base = vault.supabase_url().rstrip("/")
    path = vault.get("IRONCLAW_AUTH_EDGE_FN_PATH", _DEFAULT_EDGE_PATH) or _DEFAULT_EDGE_PATH
    return f"{base}{path}"


def _edge_function_timeout() -> float:
    raw = vault.get("IRONCLAW_AUTH_EDGE_FN_TIMEOUT_SECONDS", "5.0")
    try:
        return float(raw or "5.0")
    except (TypeError, ValueError):
        return 5.0


@dataclass(frozen=True, slots=True)
class EdgeAuthContext:
    """Auth context resolved via the ironclaw-auth Supabase Edge Function."""

    tenant_id: str
    scopes: tuple[str, ...]
    bearer_token: str
    principal_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes or "admin" in self.scopes


async def _call_edge_auth(bearer_token: str) -> EdgeAuthContext:
    url = _edge_function_url()
    timeout = _edge_function_timeout()

    service_role_key = vault.supabase_service_role_key() or vault.supabase_key()
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "apikey": service_role_key or "",
        "Authorization": f"Bearer {service_role_key or ''}",
    }
    payload: dict[str, str] = {"token": bearer_token}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, headers=headers, json=payload)
    except httpx.TimeoutException as exc:
        _logger.warning(
            "edge_auth_timeout",
            extra={"url": url, "timeout": timeout},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication service timeout",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except httpx.RequestError as exc:
        _logger.error(
            "edge_auth_request_error",
            extra={"url": url, "error": str(exc)},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication service unreachable",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    if response.status_code != status.HTTP_200_OK:
        _logger.warning(
            "edge_auth_rejected",
            extra={"status_code": response.status_code, "url": url},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        body: dict[str, Any] = response.json()
    except Exception as exc:
        _logger.error(
            "edge_auth_invalid_json",
            extra={"url": url, "error": str(exc)},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed authentication response",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    tenant_id: str | None = body.get("tenant_id")
    if not tenant_id or not isinstance(tenant_id, str):
        _logger.error(
            "edge_auth_missing_tenant_id",
            extra={"response_keys": list(body.keys())},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication response missing tenant_id",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw_scopes = body.get("scopes", [])
    if isinstance(raw_scopes, list):
        scopes: tuple[str, ...] = tuple(str(s).strip() for s in raw_scopes if str(s).strip())
    else:
        scopes = ()

    principal_id: str | None = body.get("principal_id") or None
    metadata: dict[str, Any] = body.get("metadata", {}) or {}

    return EdgeAuthContext(
        tenant_id=tenant_id,
        scopes=scopes,
        bearer_token=bearer_token,
        principal_id=principal_id,
        metadata=metadata,
    )


def _build_auth_context_from_record(api_key: str, record: APIKeyRecord) -> AuthContext:
    """Build a full AuthContext from an authenticated APIKeyRecord."""
    principal_type = "org_key" if record.key_type == "org" else "api_key"
    return AuthContext(
        api_key=api_key,
        principal_type=principal_type,
        principal_id=record.key_id,
        session_id=None,
        org_id=record.org_id,
        permissions=tuple(record.scopes),
        roles=(),
        authenticated=True,
        auth_source="api_key_registry",
        auth_method="api_key",
        key_type=record.key_type,
        metadata=dict(record.metadata),
    )


async def require_api_key(
    x_api_key: str | None = Depends(_api_key_header),
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> AuthContext | EdgeAuthContext:
    """FastAPI dependency: authenticate via local APIKeyRegistry with edge fallback.

    Resolution order:
    1. X-API-Key header or Bearer token resolved from credentials.
    2. If the key matches a local-registry prefix → local registry only.
    3. If the key does not match a static prefix (i.e. it is a JWT/Bearer token)
       and the local registry returns None → fall back to _call_edge_auth.
    4. If no key is present → 401.
    """
    raw_key: str | None = x_api_key if isinstance(x_api_key, str) else None
    if not raw_key and isinstance(credentials, HTTPAuthorizationCredentials):
        raw_key = credentials.credentials or None

    if not raw_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key — provide X-API-Key or Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    registry = get_api_key_registry()
    record: APIKeyRecord | None = registry.authenticate(raw_key, touch=True)

    if record is not None:
        _logger.debug(
            "api_key_auth_ok",
            extra={
                "key_id": record.key_id,
                "key_type": record.key_type,
                "org_id": record.org_id,
                "owner_key": record.owner_key,
            },
        )
        return _build_auth_context_from_record(raw_key, record)

    # Local registry miss — attempt edge auth only for non-static keys (JWTs / Bearer tokens).
    if not _looks_like_static_key(raw_key):
        _logger.debug(
            "api_key_auth_edge_fallback",
            extra={"masked": raw_key[:6] + "..." if len(raw_key) > 6 else "***"},
        )
        return await _call_edge_auth(raw_key)

    # Static-prefix key that the registry doesn't recognise → 401, no edge call.
    masked = raw_key[:6] + "..." if len(raw_key) > 6 else "***"
    _logger.warning(
        "api_key_auth_failed",
        extra={"masked": masked},
    )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or revoked API key",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_scope(scope: str):
    async def _inner(
        auth: EdgeAuthContext = Depends(require_api_key),
    ) -> EdgeAuthContext:
        granted = getattr(auth, "scopes", None) or getattr(auth, "permissions", ())
        if scope not in granted and "admin" not in granted:
            _logger.warning(
                "scope_denied",
                extra={
                    "principal_id": getattr(auth, "principal_id", None),
                    "required_scope": scope,
                    "granted_scopes": list(granted),
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Scope required: {scope}",
            )
        return auth

    _inner.__name__ = f"require_scope_{scope.replace(':', '_')}"
    return _inner
