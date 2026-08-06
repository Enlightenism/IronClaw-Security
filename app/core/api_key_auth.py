from __future__ import annotations

import logging

from fastapi import Depends, HTTPException, status

from app.core.auth import AuthContext, get_auth_context
from app.core.logging import get_logger

EdgeAuthContext = AuthContext

_logger: logging.Logger = get_logger("ironclaw.api_key_auth")


def _unauthorized_headers() -> dict[str, str]:
    return {"WWW-Authenticate": "Bearer"}


async def require_api_key(
    auth: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    """Compatibility dependency that delegates authentication to app.core.auth."""
    if getattr(auth, "authenticated", False):
        return auth

    _logger.warning(
        "api_key_auth_missing",
        extra={
            "principal_type": getattr(auth, "principal_type", None),
            "auth_source": getattr(auth, "auth_source", None),
            "auth_method": getattr(auth, "auth_method", None),
        },
    )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing API key — provide X-API-Key or Bearer token",
        headers=_unauthorized_headers(),
    )


def require_scope(scope: str):
    async def _inner(auth: AuthContext = Depends(require_api_key)) -> AuthContext:
        granted = tuple(getattr(auth, "permissions", ()) or ())
        if scope not in granted and "admin" not in granted:
            _logger.warning(
                "scope_denied",
                extra={
                    "principal_id": getattr(auth, "principal_id", None),
                    "principal_type": getattr(auth, "principal_type", None),
                    "required_scope": scope,
                    "granted_scopes": list(granted),
                    "auth_source": getattr(auth, "auth_source", None),
                    "auth_method": getattr(auth, "auth_method", None),
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Scope required: {scope}",
            )
        return auth

    _inner.__name__ = f"require_scope_{scope.replace(':', '_')}"
    return _inner
