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
    get_supabase_client,
    get_supabase_config,
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
    "is_supabase_configured",
    "get_supabase_config",
]


def _clean_env(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip().strip('"').strip("'")
    return cleaned or None


def is_supabase_configured() -> bool:
    """Return True if both SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are present."""
    settings = get_settings()
    raw_url: str | None = settings.supabase_url or os.getenv("IRONCLAW_SUPABASE_URL") or os.getenv("NEXT_PUBLIC_SUPABASE_URL") or None
    url = _clean_env(raw_url)
    key = _clean_env(os.getenv("SUPABASE_SERVICE_ROLE_KEY"))
    return bool(url and key and url.startswith(("http://", "https://")))


def get_supabase_service_client(
    *,
    timeout: float = SUPABASE_TIMEOUT_SECONDS,
) -> SupabaseClient:
    """Return a SupabaseClient authenticated with the service-role key.

    This client bypasses RLS and must only be used for trusted server-side
    operations (webhook dispatch, audit writes, policy enforcement, etc.).
    Never expose this client to untrusted caller paths.

    URL resolution order:
      1. Settings object (SUPABASE_URL / IRONCLAW_SUPABASE_URL /
         NEXT_PUBLIC_SUPABASE_URL via pydantic-settings env resolution)
      2. Direct os.getenv fallback for edge deployments where Settings
         may not be initialised (e.g. Lambda cold-start before app init).

    Key resolution: SUPABASE_SERVICE_ROLE_KEY only — anon keys are rejected.

    Raises SupabaseConfigurationError if either credential is absent or
    if the URL scheme is invalid.
    """
    settings = get_settings()

    raw_url: str | None = settings.supabase_url or os.getenv("IRONCLAW_SUPABASE_URL") or os.getenv("NEXT_PUBLIC_SUPABASE_URL") or None
    url = _clean_env(raw_url)

    raw_key: str | None = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    key = _clean_env(raw_key)

    if not url:
        raise SupabaseConfigurationError("missing SUPABASE_URL for service client")
    if not key:
        raise SupabaseConfigurationError("missing SUPABASE_SERVICE_ROLE_KEY — service client requires the service-role key; anon keys are not accepted")
    if not url.startswith(("http://", "https://")):
        raise SupabaseConfigurationError("SUPABASE_URL must start with http:// or https://")

    config = SupabaseConfig(url=url.rstrip("/"), key=key)
    return SupabaseClient(config=config, timeout=timeout)
