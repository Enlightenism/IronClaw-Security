from __future__ import annotations

from dataclasses import dataclass
import logging

from fastapi import Depends, HTTPException, Request, status

from app.core.auth import (
    AuthContext,
    BearerAuthContext,
    get_api_key,
    get_auth_context,
    get_bearer_context,
)

_logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class HybridAuthResult:
    """Result of hybrid authentication that accepts either API keys or Bearer tokens."""

    api_key: str | None
    auth_context: AuthContext | None
    bearer_context: BearerAuthContext | None
    authenticated: bool
    auth_method: str

    @property
    def principal_id(self) -> str | None:
        if self.auth_context and self.auth_context.authenticated:
            return self.auth_context.principal_id
        if self.bearer_context:
            return self.bearer_context.principal_id
        return None

    @property
    def principal_type(self) -> str:
        if self.auth_context and self.auth_context.authenticated:
            return self.auth_context.principal_type
        if self.bearer_context:
            return "customer"
        return "anonymous"

    @property
    def org_id(self) -> str | None:
        if self.auth_context and self.auth_context.authenticated:
            return self.auth_context.org_id
        return None


async def get_hybrid_auth(
    request: Request,
    api_key: str | None = Depends(get_api_key),
    bearer_context: BearerAuthContext | None = Depends(get_bearer_context),
    auth_context: AuthContext = Depends(get_auth_context),
) -> HybridAuthResult:
    """
    Hybrid authentication dependency that accepts either API keys or Bearer tokens.

    Priority:
    1. API key authentication (if provided and valid)
    2. Bearer token authentication (if provided and valid)
    3. Falls back to unauthenticated if neither is provided

    Returns:
        HybridAuthResult with authentication details
    """
    if api_key:
        return HybridAuthResult(
            api_key=api_key,
            auth_context=auth_context,
            bearer_context=None,
            authenticated=auth_context.authenticated,
            auth_method="api_key",
        )

    if bearer_context:
        return HybridAuthResult(
            api_key=None,
            auth_context=None,
            bearer_context=bearer_context,
            authenticated=True,
            auth_method="bearer_token",
        )

    return HybridAuthResult(
        api_key=None,
        auth_context=None,
        bearer_context=None,
        authenticated=False,
        auth_method="none",
    )


def require_hybrid_auth(
    result: HybridAuthResult = Depends(get_hybrid_auth),
) -> HybridAuthResult:
    """
    Require hybrid authentication - either API key or Bearer token must be valid.

    Raises:
        HTTPException: 401 if neither API key nor Bearer token is valid
    """
    if not result.authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required — provide X-API-Key or Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return result


def require_hybrid_auth_optional(
    result: HybridAuthResult = Depends(get_hybrid_auth),
) -> HybridAuthResult:
    """
    Optional hybrid authentication - allows unauthenticated requests.

    Use this for endpoints that work with or without authentication.
    """
    return result


def get_principal_from_hybrid(
    result: HybridAuthResult = Depends(require_hybrid_auth),
) -> str:
    """Extract the principal ID from hybrid authentication result."""
    return result.principal_id or "anonymous"


def get_org_id_from_hybrid(
    result: HybridAuthResult = Depends(require_hybrid_auth),
) -> str | None:
    """Extract the organization ID from hybrid authentication result."""
    return result.org_id


__all__ = [
    "HybridAuthResult",
    "get_hybrid_auth",
    "require_hybrid_auth",
    "require_hybrid_auth_optional",
    "get_principal_from_hybrid",
    "get_org_id_from_hybrid",
]
