"""System control-plane API-key auth only.

Install keys are a separate, payment-bound trust domain and are validated by the
install-key registry in app.core.install_keys, not by this internal API-key auth
layer.
"""

from __future__ import annotations

import logging

from fastapi import Depends, HTTPException, status

from app.core.apikeys import classify_api_key
from app.core.auth import AuthContext, get_auth_context
from app.core.logging import get_logger

EdgeAuthContext = AuthContext

_logger: logging.Logger = get_logger("ironclaw.api_key_auth")


def _unauthorized_headers() -> dict[str, str]:
    return {"WWW-Authenticate": "Bearer"}


def _looks_like_install_key_context(auth: AuthContext) -> bool:
    api_key = getattr(auth, "api_key", None)
    if isinstance(api_key, str) and classify_api_key(api_key) == "install":
        return True

    auth_source = str(getattr(auth, "auth_source", "") or "").lower()
    auth_method = str(getattr(auth, "auth_method", "") or "").lower()
    principal_type = str(getattr(auth, "principal_type", "") or "").lower()
    key_type = str(getattr(auth, "key_type", "") or "").lower()
    metadata = getattr(auth, "metadata", {}) or {}
    metadata_key_kind = str(metadata.get("key_kind", "") or "").lower()
    return auth_source == "install_key" or auth_method == "install_key" or principal_type == "install_key" or key_type == "install_key" or metadata_key_kind == "install_key"


async def require_api_key(
    auth: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    """Compatibility wrapper for internal system auth only.

    This dependency must not re-use or validate paid customer install-key
    credentials. Install keys are issued and authenticated by the canonical
    install-key registry in app.core.install_keys and must stay outside the
    internal control-plane API-key auth path.
    """
    if not getattr(auth, "authenticated", False):
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

    if _looks_like_install_key_context(auth):
        _logger.warning(
            "api_key_auth_rejected_install_key_context",
            extra={
                "principal_type": getattr(auth, "principal_type", None),
                "auth_source": getattr(auth, "auth_source", None),
                "auth_method": getattr(auth, "auth_method", None),
                "api_key_prefix": str(getattr(auth, "api_key", "") or "")[:20],
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="System API authentication does not accept install keys; install keys are handled by the paid customer install-key registry only",
            headers=_unauthorized_headers(),
        )

    return auth


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
