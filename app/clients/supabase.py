from __future__ import annotations

from app.supabaseclient import (
    SupabaseAPIError,
    SupabaseClient,
    SupabaseClientError,
    SupabaseConfig,
    SupabaseConfigurationError,
    SupabaseConnectionError,
    SupabaseRequestError,
    get_supabase_client,
    get_supabase_config,
    is_supabase_configured,
    reset_supabase_client,
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
    "get_supabase_config",
    "is_supabase_configured",
    "reset_supabase_client",
]


def get_supabase_service_client() -> SupabaseClient:
    """Thin re-export so callers can import from either clients or core layer."""
    from app.core.supabase import get_supabase_service_client as _svc  # noqa: PLC0415

    return _svc()
