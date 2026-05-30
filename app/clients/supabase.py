from __future__ import annotations

from app.supabaseclient import (
    SupabaseAPIError,
    SupabaseClient,
    SupabaseClientError,
    SupabaseConfigurationError,
    SupabaseConnectionError,
    SupabaseRequestError,
    create_supabase_client,
    get_supabase_config,
)

__all__ = [
    "SupabaseClient",
    "SupabaseClientError",
    "SupabaseConfigurationError",
    "SupabaseConnectionError",
    "SupabaseRequestError",
    "SupabaseAPIError",
    "get_supabase_client",
    "create_supabase_client",
    "get_supabase_config",
]

_client: SupabaseClient | None = None


def get_supabase_client() -> SupabaseClient:
    global _client
    if _client is None:
        _client = create_supabase_client()
    return _client
