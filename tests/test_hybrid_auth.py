"""Tests for the hybrid authentication dependency (API key + Bearer token)."""

from unittest.mock import MagicMock

from fastapi import HTTPException, Request, status
import pytest

from app.core.auth import AuthContext, BearerAuthContext
from app.dependencies.hybrid_auth import (
    HybridAuthResult,
    get_hybrid_auth,
    get_org_id_from_hybrid,
    get_principal_from_hybrid,
    require_hybrid_auth,
    require_hybrid_auth_optional,
)


class TestHybridAuthResult:
    """Test the HybridAuthResult dataclass."""

    def test_api_key_auth_result(self):
        """Test HybridAuthResult with API key authentication."""
        auth_ctx = AuthContext(
            authenticated=True,
            principal_id="user-123",
            principal_type="operator",
            org_id="org-456",
            api_key="sk_test_123",
            session_id="session-abc",
        )
        result = HybridAuthResult(
            api_key="sk_test_123",
            auth_context=auth_ctx,
            bearer_context=None,
            authenticated=True,
            auth_method="api_key",
        )

        assert result.api_key == "sk_test_123"
        assert result.authenticated is True
        assert result.auth_method == "api_key"
        assert result.principal_id == "user-123"
        assert result.principal_type == "operator"
        assert result.org_id == "org-456"

    def test_bearer_token_auth_result(self):
        """Test HybridAuthResult with Bearer token authentication."""
        bearer_ctx = BearerAuthContext(
            principal_id="customer-789",
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
            claims={"sub": "customer-789"},
        )
        result = HybridAuthResult(
            api_key=None,
            auth_context=None,
            bearer_context=bearer_ctx,
            authenticated=True,
            auth_method="bearer_token",
        )

        assert result.api_key is None
        assert result.authenticated is True
        assert result.auth_method == "bearer_token"
        assert result.principal_id == "customer-789"
        assert result.principal_type == "customer"
        assert result.org_id is None

    def test_unauthenticated_result(self):
        """Test HybridAuthResult with no authentication."""
        result = HybridAuthResult(
            api_key=None,
            auth_context=None,
            bearer_context=None,
            authenticated=False,
            auth_method="none",
        )

        assert result.api_key is None
        assert result.authenticated is False
        assert result.auth_method == "none"
        assert result.principal_id is None
        assert result.principal_type == "anonymous"
        assert result.org_id is None


class TestGetHybridAuth:
    """Test the get_hybrid_auth dependency."""

    @pytest.mark.asyncio
    async def test_api_key_takes_precedence(self):
        """Test that API key authentication takes precedence over Bearer token."""
        mock_request = MagicMock(spec=Request)
        mock_api_key = "sk_test_123"
        mock_bearer_ctx = BearerAuthContext(
            principal_id="customer-789",
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
            claims={"sub": "customer-789"},
        )
        mock_auth_ctx = AuthContext(
            authenticated=True,
            principal_id="user-123",
            principal_type="operator",
            org_id="org-456",
            api_key="sk_test_123",
            session_id="session-abc",
        )

        result = await get_hybrid_auth(
            request=mock_request,
            api_key=mock_api_key,
            bearer_context=mock_bearer_ctx,
            auth_context=mock_auth_ctx,
        )

        assert result.authenticated is True
        assert result.auth_method == "api_key"
        assert result.api_key == "sk_test_123"
        assert result.principal_id == "user-123"
        assert result.bearer_context is None

    @pytest.mark.asyncio
    async def test_bearer_token_auth(self):
        """Test Bearer token authentication when no API key is provided."""
        mock_request = MagicMock(spec=Request)
        mock_bearer_ctx = BearerAuthContext(
            principal_id="customer-789",
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
            claims={"sub": "customer-789"},
        )

        result = await get_hybrid_auth(
            request=mock_request,
            api_key=None,
            bearer_context=mock_bearer_ctx,
            auth_context=AuthContext(
                authenticated=False,
                principal_id=None,
                principal_type="anonymous",
                org_id=None,
                api_key=None,
                session_id=None,
            ),
        )

        assert result.authenticated is True
        assert result.auth_method == "bearer_token"
        assert result.api_key is None
        assert result.principal_id == "customer-789"
        assert result.bearer_context is not None

    @pytest.mark.asyncio
    async def test_no_authentication(self):
        """Test when neither API key nor Bearer token is provided."""
        mock_request = MagicMock(spec=Request)

        result = await get_hybrid_auth(
            request=mock_request,
            api_key=None,
            bearer_context=None,
            auth_context=AuthContext(
                authenticated=False,
                principal_id=None,
                principal_type="anonymous",
                org_id=None,
                api_key=None,
                session_id=None,
            ),
        )

        assert result.authenticated is False
        assert result.auth_method == "none"
        assert result.api_key is None
        assert result.bearer_context is None


class TestRequireHybridAuth:
    """Test the require_hybrid_auth dependency."""

    @pytest.mark.asyncio
    async def test_authenticated_api_key(self):
        """Test that authenticated API key requests pass through."""
        auth_ctx = AuthContext(
            authenticated=True,
            principal_id="user-123",
            principal_type="operator",
            org_id="org-456",
            api_key="sk_test_123",
            session_id="session-abc",
        )
        result = HybridAuthResult(
            api_key="sk_test_123",
            auth_context=auth_ctx,
            bearer_context=None,
            authenticated=True,
            auth_method="api_key",
        )

        returned = require_hybrid_auth(result)
        assert returned is result
        assert returned.authenticated is True

    @pytest.mark.asyncio
    async def test_authenticated_bearer_token(self):
        """Test that authenticated Bearer token requests pass through."""
        bearer_ctx = BearerAuthContext(
            principal_id="customer-789",
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
            claims={"sub": "customer-789"},
        )
        result = HybridAuthResult(
            api_key=None,
            auth_context=None,
            bearer_context=bearer_ctx,
            authenticated=True,
            auth_method="bearer_token",
        )

        returned = require_hybrid_auth(result)
        assert returned is result
        assert returned.authenticated is True

    @pytest.mark.asyncio
    async def test_unauthenticated_raises_401(self):
        """Test that unauthenticated requests raise 401."""
        result = HybridAuthResult(
            api_key=None,
            auth_context=None,
            bearer_context=None,
            authenticated=False,
            auth_method="none",
        )

        with pytest.raises(HTTPException) as exc_info:
            require_hybrid_auth(result)

        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Authentication required" in exc_info.value.detail
        assert exc_info.value.headers["WWW-Authenticate"] == "Bearer"


class TestRequireHybridAuthOptional:
    """Test the require_hybrid_auth_optional dependency."""

    @pytest.mark.asyncio
    async def test_allows_authenticated(self):
        """Test that authenticated requests pass through."""
        auth_ctx = AuthContext(
            authenticated=True,
            principal_id="user-123",
            principal_type="operator",
            org_id="org-456",
            api_key="sk_test_123",
            session_id="session-abc",
        )
        result = HybridAuthResult(
            api_key="sk_test_123",
            auth_context=auth_ctx,
            bearer_context=None,
            authenticated=True,
            auth_method="api_key",
        )

        returned = require_hybrid_auth_optional(result)
        assert returned is result

    @pytest.mark.asyncio
    async def test_allows_unauthenticated(self):
        """Test that unauthenticated requests are allowed (optional auth)."""
        result = HybridAuthResult(
            api_key=None,
            auth_context=None,
            bearer_context=None,
            authenticated=False,
            auth_method="none",
        )

        returned = require_hybrid_auth_optional(result)
        assert returned is result
        assert returned.authenticated is False


class TestGetPrincipalFromHybrid:
    """Test the get_principal_from_hybrid helper."""

    @pytest.mark.asyncio
    async def test_extract_principal_api_key(self):
        """Test principal extraction from API key auth."""
        auth_ctx = AuthContext(
            authenticated=True,
            principal_id="user-123",
            principal_type="operator",
            org_id="org-456",
            api_key="sk_test_123",
            session_id="session-abc",
        )
        result = HybridAuthResult(
            api_key="sk_test_123",
            auth_context=auth_ctx,
            bearer_context=None,
            authenticated=True,
            auth_method="api_key",
        )

        principal = get_principal_from_hybrid(result)
        assert principal == "user-123"

    @pytest.mark.asyncio
    async def test_extract_principal_bearer(self):
        """Test principal extraction from Bearer token auth."""
        bearer_ctx = BearerAuthContext(
            principal_id="customer-789",
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
            claims={"sub": "customer-789"},
        )
        result = HybridAuthResult(
            api_key=None,
            auth_context=None,
            bearer_context=bearer_ctx,
            authenticated=True,
            auth_method="bearer_token",
        )

        principal = get_principal_from_hybrid(result)
        assert principal == "customer-789"

    @pytest.mark.asyncio
    async def test_unauthenticated_returns_anonymous(self):
        """Test that unauthenticated requests return 'anonymous'."""
        result = HybridAuthResult(
            api_key=None,
            auth_context=None,
            bearer_context=None,
            authenticated=False,
            auth_method="none",
        )

        principal = get_principal_from_hybrid(result)
        assert principal == "anonymous"


class TestGetOrgIdFromHybrid:
    """Test the get_org_id_from_hybrid helper."""

    @pytest.mark.asyncio
    async def test_extract_org_id_api_key(self):
        """Test org ID extraction from API key auth."""
        auth_ctx = AuthContext(
            authenticated=True,
            principal_id="user-123",
            principal_type="operator",
            org_id="org-456",
            api_key="sk_test_123",
            session_id="session-abc",
        )
        result = HybridAuthResult(
            api_key="sk_test_123",
            auth_context=auth_ctx,
            bearer_context=None,
            authenticated=True,
            auth_method="api_key",
        )

        org_id = get_org_id_from_hybrid(result)
        assert org_id == "org-456"

    @pytest.mark.asyncio
    async def test_extract_org_id_bearer(self):
        """Test org ID extraction from Bearer token auth."""
        bearer_ctx = BearerAuthContext(
            principal_id="customer-789",
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
            claims={"sub": "customer-789"},
        )
        result = HybridAuthResult(
            api_key=None,
            auth_context=None,
            bearer_context=bearer_ctx,
            authenticated=True,
            auth_method="bearer_token",
        )

        org_id = get_org_id_from_hybrid(result)
        assert org_id is None

    @pytest.mark.asyncio
    async def test_unauthenticated_returns_none(self):
        """Test that unauthenticated requests return None for org_id."""
        result = HybridAuthResult(
            api_key=None,
            auth_context=None,
            bearer_context=None,
            authenticated=False,
            auth_method="none",
        )

        org_id = get_org_id_from_hybrid(result)
        assert org_id is None


class TestHybridAuthIntegration:
    """Integration tests for hybrid authentication scenarios."""

    @pytest.mark.asyncio
    async def test_full_api_key_flow(self):
        """Test complete API key authentication flow."""
        mock_request = MagicMock(spec=Request)
        auth_ctx = AuthContext(
            authenticated=True,
            principal_id="operator-001",
            principal_type="operator",
            org_id="org-main",
            api_key="sk_live_abc123",
            session_id="session-xyz",
        )

        result = await get_hybrid_auth(
            request=mock_request,
            api_key="sk_live_abc123",
            bearer_context=None,
            auth_context=auth_ctx,
        )

        assert result.authenticated is True
        assert result.auth_method == "api_key"
        assert result.principal_id == "operator-001"
        assert result.org_id == "org-main"

        enforced = require_hybrid_auth(result)
        assert enforced.authenticated is True

    @pytest.mark.asyncio
    async def test_full_bearer_flow(self):
        """Test complete Bearer token authentication flow."""
        mock_request = MagicMock(spec=Request)
        bearer_ctx = BearerAuthContext(
            principal_id="customer-xyz",
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
            claims={"sub": "customer-xyz"},
        )

        result = await get_hybrid_auth(
            request=mock_request,
            api_key=None,
            bearer_context=bearer_ctx,
            auth_context=AuthContext(
                authenticated=False,
                principal_id=None,
                principal_type="anonymous",
                org_id=None,
                api_key=None,
                session_id=None,
            ),
        )

        assert result.authenticated is True
        assert result.auth_method == "bearer_token"
        assert result.principal_id == "customer-xyz"

        enforced = require_hybrid_auth(result)
        assert enforced.authenticated is True

    @pytest.mark.asyncio
    async def test_optional_auth_allows_both(self):
        """Test that optional auth allows both authenticated and unauthenticated."""
        auth_ctx = AuthContext(
            authenticated=True,
            principal_id="user-123",
            principal_type="operator",
            org_id="org-456",
            api_key="sk_test_123",
            session_id="session-abc",
        )

        authenticated_result = HybridAuthResult(
            api_key="sk_test_123",
            auth_context=auth_ctx,
            bearer_context=None,
            authenticated=True,
            auth_method="api_key",
        )

        unauthenticated_result = HybridAuthResult(
            api_key=None,
            auth_context=None,
            bearer_context=None,
            authenticated=False,
            auth_method="none",
        )

        auth_passed = require_hybrid_auth_optional(authenticated_result)
        unauth_passed = require_hybrid_auth_optional(unauthenticated_result)

        assert auth_passed.authenticated is True
        assert unauth_passed.authenticated is False
