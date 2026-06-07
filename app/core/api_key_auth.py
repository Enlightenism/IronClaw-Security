from __future__ import annotations

from dataclasses import dataclass, field
import logging
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import httpx

from app.core.logging import get_logger
from app.services.secrets_vault import vault

_logger: logging.Logger = get_logger("ironclaw.api_key_auth")

_bearer_scheme = HTTPBearer(auto_error=False)

_DEFAULT_EDGE_PATH = "/functions/v1/ironclaw-auth"


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


async def require_api_key(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> EdgeAuthContext:
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization: Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return await _call_edge_auth(credentials.credentials)


def require_scope(scope: str):
    async def _inner(
        auth: EdgeAuthContext = Depends(require_api_key),
    ) -> EdgeAuthContext:
        if not auth.has_scope(scope):
            _logger.warning(
                "scope_denied",
                extra={
                    "tenant_id": auth.tenant_id,
                    "required_scope": scope,
                    "granted_scopes": list(auth.scopes),
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Scope required: {scope}",
            )
        return auth

    _inner.__name__ = f"require_scope_{scope.replace(':', '_')}"
    return _inner
