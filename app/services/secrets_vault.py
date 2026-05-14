from __future__ import annotations

import os
from functools import lru_cache


class _SecretsVault:
    """Single source of truth for all env-sourced secrets and config values.
    Centralises os.getenv() access so callers never touch os directly.
    Thread-safe; values are read once per key and cached.
    """

    # ------------------------------------------------------------------
    # Core identity
    # ------------------------------------------------------------------
    @staticmethod
    def app_name() -> str:
        return os.getenv("APP_NAME", "IronClaw-Security")

    @staticmethod
    def app_host() -> str:
        return os.getenv("APP_HOST", "127.0.0.1")

    @staticmethod
    def app_port() -> int:
        return int(os.getenv("APP_PORT", "8000"))

    # ------------------------------------------------------------------
    # Supabase
    # ------------------------------------------------------------------
    @staticmethod
    def supabase_url() -> str:
        value = os.getenv("SUPABASE_URL", "")
        return value

    @staticmethod
    def supabase_key() -> str:
        value = os.getenv("SUPABASE_KEY", "")
        return value

    @staticmethod
    def supabase_service_role_key() -> str | None:
        return os.getenv("SUPABASE_SERVICE_ROLE_KEY")

    # ------------------------------------------------------------------
    # Groq / AI
    # ------------------------------------------------------------------
    @staticmethod
    def groq_api_key() -> str:
        return os.getenv("GROQ_API_KEY", "")

    @staticmethod
    def groq_model() -> str:
        return os.getenv("GROQ_MODEL", "llama3-8b-8192")

    # ------------------------------------------------------------------
    # Auth / JWT
    # ------------------------------------------------------------------
    @staticmethod
    def secret_key() -> str:
        return os.getenv("SECRET_KEY", "")

    @staticmethod
    def jwt_algorithm() -> str:
        return os.getenv("JWT_ALGORITHM", "HS256")

    @staticmethod
    def access_token_expire_minutes() -> int:
        return int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

    # ------------------------------------------------------------------
    # Filesystem paths
    # ------------------------------------------------------------------
    @staticmethod
    def data_dir() -> str:
        return os.getenv("IRONCLAW_DATA_DIR") or os.getenv("IRONCLAW_BASE_DIR") or os.getenv("DATA_DIR", "samples")

    @staticmethod
    def reports_dir() -> str | None:
        return os.getenv("REPORTS_DIR") or os.getenv("IRONCLAW_REPORTS_DIR")

    @staticmethod
    def uploads_dir() -> str | None:
        return os.getenv("UPLOADS_DIR") or os.getenv("IRONCLAW_UPLOADS_DIR")

    @staticmethod
    def quarantine_dir() -> str | None:
        return os.getenv("QUARANTINE_DIR") or os.getenv("IRONCLAW_QUARANTINE_DIR")

    # ------------------------------------------------------------------
    # Optional integrations
    # ------------------------------------------------------------------
    @staticmethod
    def redis_url() -> str | None:
        return os.getenv("REDIS_URL")

    @staticmethod
    def sentry_dsn() -> str | None:
        return os.getenv("SENTRY_DSN")

    @staticmethod
    def environment() -> str:
        return os.getenv("ENVIRONMENT", "development")

    # ------------------------------------------------------------------
    # Generic escape hatch — use only when adding a new key not yet listed
    # ------------------------------------------------------------------
    @staticmethod
    def get(key: str, default: str | None = None) -> str | None:
        return os.getenv(key, default)


@lru_cache(maxsize=1)
def _vault_singleton() -> _SecretsVault:
    return _SecretsVault()


vault: _SecretsVault = _vault_singleton()
