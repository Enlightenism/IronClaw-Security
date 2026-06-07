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
    "get_supabase_config",
]


def _clean_env(value: str | None) -> str | None:
    """Strip whitespace and surrounding quotes from an env string.

    Returns None if the cleaned value is empty so callers can use a
    simple truthiness check without worrying about blank-string env vars.
    """
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

    # Prefer settings-resolved value; fall back to raw env for edge cases.
    raw_url: str | None = settings.supabase_url or os.getenv("IRONCLAW_SUPABASE_URL") or os.getenv("NEXT_PUBLIC_SUPABASE_URL") or None
    url = _clean_env(raw_url)

    # Service-role key is not surfaced through Settings (intentional —
    # Settings.supabase_service_role_key exists but may be empty in
    # environments that inject it only at runtime). Always read from env
    # so the key is never accidentally logged via Settings.__repr__.
    raw_key: str | None = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    key = _clean_env(raw_key)

    if not url:
        raise SupabaseConfigurationError("missing SUPABASE_URL for service client")
    if not key:
        raise SupabaseConfigurationError("missing SUPABASE_SERVICE_ROLE_KEY — service client requires the " "service-role key; anon keys are not accepted")
    if not url.startswith(("http://", "https://")):
        raise SupabaseConfigurationError("SUPABASE_URL must start with http:// or https://")

    config = SupabaseConfig(url=url.rstrip("/"), key=key)
    return SupabaseClient(config=config, timeout=timeout)
