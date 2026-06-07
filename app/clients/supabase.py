from __future__ import annotations

from app.supabaseclient import (
    SupabaseAPIError,
    SupabaseClient,
    SupabaseClientError,
    SupabaseConfig,
    SupabaseConfigurationError,
    SupabaseConnectionError,
    SupabaseRequestError,
    create_supabase_client,
    get_supabase_config,
    is_supabase_configured,
)

__all__ = [
    "SupabaseClient",
    "SupabaseClientError",
    "SupabaseConfig",
    "SupabaseConfigurationError",
    "SupabaseConnectionError",
    "SupabaseRequestError",
    "SupabaseAPIError",
    "get_supabase_client",
    "get_supabase_service_client",
    "create_supabase_client",
    "get_supabase_config",
    "is_supabase_configured",
]

_client: SupabaseClient | None = None


def get_supabase_client() -> SupabaseClient:
    global _client
    if _client is None:
        _client = create_supabase_client()
    return _client


def get_supabase_service_client() -> SupabaseClient:
    """Thin re-export so callers can import from either clients or core layer."""
    from app.core.supabase import get_supabase_service_client as _svc  # noqa: PLC0415

    return _svc()
