from __future__ import annotations

import os

from app.clients.supabase import (
    SupabaseAPIError,
    SupabaseClient,
    SupabaseClientError,
    SupabaseConfig,
    SupabaseConfigurationError,
    SupabaseConnectionError,
    SupabaseRequestError,
    create_supabase_client,
    get_supabase_client,
    get_supabase_config,
)
from app.supabaseclient import SUPABASE_TIMEOUT_SECONDS

__all__ = [
    "SupabaseClient",
    "SupabaseClientError",
    "SupabaseConfigurationError",
    "SupabaseConnectionError",
    "SupabaseRequestError",
    "SupabaseAPIError",
    "get_supabase_client",
    "get_supabase_service_client",
    "create_supabase_client",
    "get_supabase_config",
]


def _clean_env(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip().strip('"').strip("'")
    return cleaned or None


def get_supabase_service_client(
    *,
    timeout: float = SUPABASE_TIMEOUT_SECONDS,
) -> SupabaseClient:
    """Return a SupabaseClient authenticated with the service-role key.

    This client bypasses RLS and must only be used for trusted server-side
    operations (webhook dispatch, audit writes, policy enforcement, etc.).
    Never expose this client to untrusted caller paths.

    Raises SupabaseConfigurationError if SUPABASE_SERVICE_ROLE_KEY or
    SUPABASE_URL are not set.
    """
    url = _clean_env(
        os.getenv("SUPABASE_URL") or os.getenv("IRONCLAW_SUPABASE_URL") or os.getenv("NEXT_PUBLIC_SUPABASE_URL"),
    )
    key = _clean_env(os.getenv("SUPABASE_SERVICE_ROLE_KEY"))

    if not url:
        raise SupabaseConfigurationError("missing SUPABASE_URL for service client")
    if not key:
        raise SupabaseConfigurationError("missing SUPABASE_SERVICE_ROLE_KEY — service client requires the " "service-role key; anon keys are not accepted")
    if not url.startswith(("http://", "https://")):
        raise SupabaseConfigurationError("SUPABASE_URL must start with http:// or https://")

    config = SupabaseConfig(url=url.rstrip("/"), key=key)
    return SupabaseClient(config=config, timeout=timeout)
