from __future__ import annotations

from app.clients.supabase import (
    SupabaseAPIError,
    SupabaseClient,
    SupabaseClientError,
    SupabaseConfig,
    SupabaseConfigurationError,
    SupabaseConnectionError,
    SupabaseRequestError,
    get_supabase_client,
    get_supabase_config,
)
from app.clients.supabase import (
    is_supabase_configured as _client_is_supabase_configured,
)
from app.core.settings import get_settings
from app.supabaseclient import SUPABASE_TIMEOUT_SECONDS

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
    "is_supabase_configured",
    "get_supabase_config",
]


def _clean_env(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip().strip('"').strip("'")
    return cleaned or None


def is_supabase_configured() -> bool:
    """Return True when a usable Supabase URL and key can be resolved."""
    settings = get_settings()
    return _client_is_supabase_configured(settings)


def get_supabase_service_client(
    *,
    timeout: float = SUPABASE_TIMEOUT_SECONDS,
) -> SupabaseClient:
    """Return a SupabaseClient authenticated for trusted server-side use.

    Resolution order is delegated to the canonical client config resolver so
    tests and runtime behavior stay aligned across the codebase.
    """
    settings = get_settings()
    config = get_supabase_config(settings)
    return SupabaseClient(config=config, timeout=timeout, settings=settings)


create_supabase_client = get_supabase_service_client
