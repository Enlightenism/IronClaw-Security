from __future__ import annotations

from functools import lru_cache
import os


class _SecretsVault:
    """Single source of truth for all env-sourced secrets and config values.
    Centralises os.getenv() access so callers never touch os directly.
    Thread-safe; values are read once at call time — no instance state.
    """

    @staticmethod
    def _first_non_empty(*keys: str) -> str:
        for key in keys:
            value = os.getenv(key)
            if value is not None and value != "":
                return value
        return ""

    # ------------------------------------------------------------------
    # Core identity
    # ------------------------------------------------------------------
    @staticmethod
    def app_name() -> str:
        return os.getenv("APP_NAME", "IronClaw-Security")

    @staticmethod
    def app_version() -> str:
        return os.getenv("APP_VERSION", "0.1.0")

    @staticmethod
    def app_host() -> str:
        return os.getenv("APP_HOST", "127.0.0.1")

    @staticmethod
    def app_port() -> int:
        return int(os.getenv("APP_PORT", "8000"))

    @staticmethod
    def app_base_url() -> str:
        return os.getenv(
            "APP_BASE_URL",
            f"http://{os.getenv('APP_HOST', '127.0.0.1')}:{os.getenv('APP_PORT', '8000')}",
        )

    @staticmethod
    def api_prefix() -> str:
        return os.getenv("API_PREFIX", "")

    @staticmethod
    def debug() -> bool:
        return os.getenv("DEBUG", "false").lower() in ("1", "true", "yes")

    @staticmethod
    def reload() -> bool:
        return os.getenv("RELOAD", "false").lower() in ("1", "true", "yes")

    # ------------------------------------------------------------------
    # Engine (IronClawClient target — single source of truth)
    # ------------------------------------------------------------------
    @staticmethod
    def engine_base_url() -> str:
        return os.getenv("ENGINE_BASE_URL", "http://127.0.0.1:8010")

    # ------------------------------------------------------------------
    # Environment / logging
    # ------------------------------------------------------------------
    @staticmethod
    def environment() -> str:
        return os.getenv("ENVIRONMENT", "development")

    @staticmethod
    def log_level() -> str:
        return os.getenv("LOG_LEVEL", "INFO").upper()

    @staticmethod
    def structured_logging_enabled() -> bool:
        return os.getenv("STRUCTURED_LOGGING_ENABLED", "true").lower() in (
            "1",
            "true",
            "yes",
        )

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    @staticmethod
    def auth_required() -> bool:
        return os.getenv("AUTH_REQUIRED", "false").lower() in ("1", "true", "yes")

    @staticmethod
    def api_key() -> str:
        return _SecretsVault._first_non_empty("API_KEY", "IRONCLAW_API_KEY")

    @staticmethod
    def admin_api_key() -> str:
        return os.getenv("ADMIN_API_KEY", "")

    @staticmethod
    def platform_api_key() -> str:
        return os.getenv("PLATFORM_API_KEY", "")

    @staticmethod
    def internal_platform_api_key() -> str:
        return os.getenv("INTERNAL_PLATFORM_API_KEY", "")

    @staticmethod
    def ironclaw_api_key() -> str:
        return os.getenv("IRONCLAW_API_KEY", "")

    # ------------------------------------------------------------------
    # Auth / JWT
    # ------------------------------------------------------------------
    @staticmethod
    def secret_key() -> str:
        return _SecretsVault._first_non_empty(
            "SECRET_KEY",
            "IRONCLAW_SECRET_KEY",
            "APP_SECRET_KEY",
        )

    @staticmethod
    def jwt_secret() -> str:
        return _SecretsVault._first_non_empty(
            "JWT_SECRET",
            "SUPABASE_JWT_SECRET",
            "SECRET_KEY",
            "IRONCLAW_SECRET_KEY",
            "APP_SECRET_KEY",
        )

    @staticmethod
    def supabase_jwt_secret() -> str:
        return _SecretsVault._first_non_empty("SUPABASE_JWT_SECRET", "JWT_SECRET")

    @staticmethod
    def jwt_algorithm() -> str:
        return os.getenv("JWT_ALGORITHM", "HS256")

    @staticmethod
    def access_token_expire_minutes() -> int:
        return int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

    # ------------------------------------------------------------------
    # IronClaw Auth Edge Function
    # ------------------------------------------------------------------
    @staticmethod
    def ironclaw_auth_edge_fn_path() -> str:
        """URL path or full URL to the IronClaw auth edge function endpoint.
        Defaults to empty string — callers must guard against empty value.
        """
        return os.getenv("IRONCLAW_AUTH_EDGE_FN_PATH", "")

    @staticmethod
    def ironclaw_auth_edge_fn_timeout_seconds() -> float:
        """HTTP timeout in seconds for calls to the auth edge function."""
        return float(os.getenv("IRONCLAW_AUTH_EDGE_FN_TIMEOUT_SECONDS", "10.0"))

    # ------------------------------------------------------------------
    # Supabase
    # ------------------------------------------------------------------
    @staticmethod
    def supabase_url() -> str:
        return os.getenv("SUPABASE_URL", "")

    @staticmethod
    def supabase_key() -> str:
        return _SecretsVault._first_non_empty("SUPABASE_KEY", "SUPABASE_ANON_KEY")

    @staticmethod
    def supabase_anon_key() -> str:
        return _SecretsVault._first_non_empty("SUPABASE_ANON_KEY", "SUPABASE_KEY")

    @staticmethod
    def supabase_service_role_key() -> str | None:
        return os.getenv("SUPABASE_SERVICE_ROLE_KEY")

    # ------------------------------------------------------------------
    # Stripe
    # ------------------------------------------------------------------
    @staticmethod
    def stripe_secret_key() -> str:
        """Stripe secret key (sk_test_... or sk_live_...).
        Env var: STRIPE_SECRET_KEY — must match .env exactly.
        Used by stripe_service.py for all Stripe API calls.
        """
        return os.getenv("STRIPE_SECRET_KEY", "")

    @staticmethod
    def stripe_publishable_key() -> str:
        """Stripe publishable key (pk_test_... or pk_live_...).
        Env var: STRIPE_PUBLISHABLE_KEY — must match .env exactly.
        Returned to frontend for Stripe.js initialisation.
        """
        return os.getenv("STRIPE_PUBLISHABLE_KEY", "")

    @staticmethod
    def stripe_webhook_secret() -> str:
        """Stripe webhook signing secret (whsec_...).
        Env var: STRIPE_WEBHOOK_SECRET — must match .env exactly.
        Used by stripe_service.py for HMAC webhook signature verification.
        """
        return os.getenv("STRIPE_WEBHOOK_SECRET", "")

    # ------------------------------------------------------------------
    # Groq / AI
    # ------------------------------------------------------------------
    @staticmethod
    def groq_enabled() -> bool:
        return os.getenv("GROQ_ENABLED", "false").lower() in ("1", "true", "yes")

    @staticmethod
    def groq_api_key() -> str:
        return os.getenv("GROQ_API_KEY", "")

    @staticmethod
    def groq_model() -> str:
        return os.getenv("GROQ_MODEL", "llama3-8b-8192")

    @staticmethod
    def groq_timeout_seconds() -> float:
        return float(os.getenv("GROQ_TIMEOUT_SECONDS", "60.0"))

    # ------------------------------------------------------------------
    # OpenAI
    # ------------------------------------------------------------------
    @staticmethod
    def openai_api_key() -> str:
        return os.getenv("OPENAI_API_KEY", "")

    # ------------------------------------------------------------------
    # Policy / verdict defaults
    # ------------------------------------------------------------------
    @staticmethod
    def default_scan_verdict() -> str:
        return os.getenv("DEFAULT_SCAN_VERDICT", "allow")

    @staticmethod
    def default_review_status() -> str:
        return os.getenv("DEFAULT_REVIEW_STATUS", "not_required")

    # ------------------------------------------------------------------
    # Risk thresholds
    # ------------------------------------------------------------------
    @staticmethod
    def risk_threshold_allow_max() -> int:
        return int(os.getenv("RISK_THRESHOLD_ALLOW_MAX", "29"))

    @staticmethod
    def risk_threshold_quarantine_min() -> int:
        return int(os.getenv("RISK_THRESHOLD_QUARANTINE_MIN", "30"))

    @staticmethod
    def risk_threshold_block_min() -> int:
        return int(os.getenv("RISK_THRESHOLD_BLOCK_MIN", "70"))

    # ------------------------------------------------------------------
    # Input size limits
    # ------------------------------------------------------------------
    @staticmethod
    def max_text_chars() -> int:
        return int(os.getenv("MAX_TEXT_CHARS", "100000"))

    @staticmethod
    def max_url_length() -> int:
        return int(os.getenv("MAX_URL_LENGTH", "2048"))

    @staticmethod
    def max_archive_name_length() -> int:
        return int(os.getenv("MAX_ARCHIVE_NAME_LENGTH", "512"))

    @staticmethod
    def max_repo_url_length() -> int:
        return int(os.getenv("MAX_REPO_URL_LENGTH", "2048"))

    # ------------------------------------------------------------------
    # Filesystem paths
    # ------------------------------------------------------------------
    @staticmethod
    def data_dir() -> str:
        return os.getenv("IRONCLAW_DATA_DIR") or os.getenv("IRONCLAW_BASE_DIR") or os.getenv("DATA_DIR", "samples")

    @staticmethod
    def reports_dir() -> str | None:
        return os.getenv("REPORTS_DIR") or os.getenv("IRONCLAW_REPORTS_DIR") or None

    @staticmethod
    def uploads_dir() -> str | None:
        return os.getenv("UPLOADS_DIR") or os.getenv("IRONCLAW_UPLOADS_DIR") or None

    @staticmethod
    def quarantine_dir() -> str | None:
        return os.getenv("QUARANTINE_DIR") or os.getenv("IRONCLAW_QUARANTINE_DIR") or None

    @staticmethod
    def backup_dir() -> str:
        return os.getenv("BACKUP_DIR", "./data/backups")

    # ------------------------------------------------------------------
    # Optional integrations
    # ------------------------------------------------------------------
    @staticmethod
    def redis_url() -> str | None:
        return os.getenv("REDIS_URL")

    @staticmethod
    def sentry_dsn() -> str | None:
        return os.getenv("SENTRY_DSN")

    # ------------------------------------------------------------------
    # Generic escape hatch — use only for a new key not yet listed above
    # ------------------------------------------------------------------
    @staticmethod
    def get(key: str, default: str | None = None) -> str | None:
        return os.getenv(key, default)


@lru_cache(maxsize=1)
def _vault_singleton() -> _SecretsVault:
    return _SecretsVault()


vault: _SecretsVault = _vault_singleton()
