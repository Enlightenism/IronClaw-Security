from __future__ import annotations

import functools

from pydantic import Field
from pydantic_settings import BaseSettings

SECRET_KEY_SENTINEL = "changeme-32-chars-minimum!!!!!"
JWT_SECRET_SENTINEL = "changeme-jwt-32-chars-minimum!!"


def _normalize_string(value: str | None) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


class Settings(BaseSettings):
    # ------------------------------------------------------------------
    # Core identity
    # ------------------------------------------------------------------
    app_name: str = Field(default="IronClaw-Security", alias="APP_NAME")
    app_version: str = Field(default="0.1.0", alias="APP_VERSION")
    app_host: str = Field(default="127.0.0.1", alias="APP_HOST")
    app_port: int = Field(default=8000, alias="APP_PORT")
    app_base_url: str = Field(default="", alias="APP_BASE_URL")
    api_prefix: str = Field(default="", alias="API_PREFIX")
    debug: bool = Field(default=False, alias="DEBUG")
    reload: bool = Field(default=False, alias="RELOAD")

    # ------------------------------------------------------------------
    # Environment / logging
    # ------------------------------------------------------------------
    environment: str = Field(default="development", alias="ENVIRONMENT")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    structured_logging_enabled: bool = Field(
        default=True,
        alias="STRUCTURED_LOGGING_ENABLED",
    )

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    auth_required: bool = Field(default=False, alias="AUTH_REQUIRED")
    api_key: str = Field(default="", alias="API_KEY")
    admin_api_key: str = Field(default="", alias="ADMIN_API_KEY")
    platform_api_key: str = Field(default="", alias="PLATFORM_API_KEY")
    internal_platform_api_key: str = Field(
        default="",
        alias="INTERNAL_PLATFORM_API_KEY",
    )
    ironclaw_api_key: str = Field(default="", alias="IRONCLAW_API_KEY")

    # ------------------------------------------------------------------
    # Auth / JWT
    # ------------------------------------------------------------------
    secret_key: str = Field(
        default=SECRET_KEY_SENTINEL,
        alias="IRONCLAW_SECRET_KEY",
    )
    jwt_secret: str = Field(default=JWT_SECRET_SENTINEL, alias="JWT_SECRET")
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(
        default=30,
        alias="ACCESS_TOKEN_EXPIRE_MINUTES",
    )

    # ------------------------------------------------------------------
    # IronClaw Auth Edge Function
    # ------------------------------------------------------------------
    ironclaw_auth_edge_fn_path: str = Field(
        default="",
        alias="IRONCLAW_AUTH_EDGE_FN_PATH",
    )
    ironclaw_auth_edge_fn_timeout_seconds: float = Field(
        default=10.0,
        alias="IRONCLAW_AUTH_EDGE_FN_TIMEOUT_SECONDS",
    )

    # ------------------------------------------------------------------
    # Supabase
    # ------------------------------------------------------------------
    supabase_url: str = Field(default="", alias="SUPABASE_URL")
    supabase_key: str = Field(default="", alias="SUPABASE_KEY")
    supabase_anon_key: str = Field(default="", alias="SUPABASE_ANON_KEY")
    supabase_service_role_key: str = Field(
        default="",
        alias="SUPABASE_SERVICE_ROLE_KEY",
    )
    persistence_mode: str = Field(
        default="memory",
        alias="IRONCLAW_PERSISTENCE_MODE",
    )

    # ------------------------------------------------------------------
    # Groq / AI
    # ------------------------------------------------------------------
    groq_enabled: bool = Field(default=False, alias="GROQ_ENABLED")
    groq_api_key: str = Field(default="", alias="GROQ_API_KEY")
    groq_model: str = Field(default="llama3-8b-8192", alias="GROQ_MODEL")
    groq_timeout_seconds: float = Field(
        default=60.0,
        alias="GROQ_TIMEOUT_SECONDS",
    )

    # ------------------------------------------------------------------
    # OpenAI
    # ------------------------------------------------------------------
    openai_api_key: str = Field(default="", alias="OPENAI_API_KEY")

    # ------------------------------------------------------------------
    # Stripe
    # ------------------------------------------------------------------
    stripe_secret_key: str = Field(default="", alias="STRIPE_SECRET_KEY")
    stripe_publishable_key: str = Field(
        default="",
        alias="STRIPE_PUBLISHABLE_KEY",
    )
    stripe_webhook_secret: str = Field(default="", alias="STRIPE_WEBHOOK_SECRET")

    # ------------------------------------------------------------------
    # Policy / verdict defaults
    # ------------------------------------------------------------------
    default_scan_verdict: str = Field(default="allow", alias="DEFAULT_SCAN_VERDICT")
    default_review_status: str = Field(
        default="not_required",
        alias="DEFAULT_REVIEW_STATUS",
    )

    # ------------------------------------------------------------------
    # Risk thresholds
    # ------------------------------------------------------------------
    risk_threshold_allow_max: int = Field(
        default=29,
        alias="RISK_THRESHOLD_ALLOW_MAX",
    )
    risk_threshold_quarantine_min: int = Field(
        default=30,
        alias="RISK_THRESHOLD_QUARANTINE_MIN",
    )
    risk_threshold_block_min: int = Field(
        default=70,
        alias="RISK_THRESHOLD_BLOCK_MIN",
    )

    # ------------------------------------------------------------------
    # Input size limits
    # ------------------------------------------------------------------
    max_text_chars: int = Field(default=100_000, alias="MAX_TEXT_CHARS")
    max_url_length: int = Field(default=2048, alias="MAX_URL_LENGTH")
    max_archive_name_length: int = Field(
        default=512,
        alias="MAX_ARCHIVE_NAME_LENGTH",
    )
    max_repo_url_length: int = Field(default=2048, alias="MAX_REPO_URL_LENGTH")

    # ------------------------------------------------------------------
    # Filesystem paths
    # ------------------------------------------------------------------
    data_dir: str = Field(default="samples", alias="DATA_DIR")
    backup_dir: str = Field(default="./data/backups", alias="BACKUP_DIR")
    reports_dir: str | None = Field(default=None, alias="REPORTS_DIR")
    uploads_dir: str | None = Field(default=None, alias="UPLOADS_DIR")
    quarantine_dir: str | None = Field(default=None, alias="QUARANTINE_DIR")

    # ------------------------------------------------------------------
    # CORS
    # ------------------------------------------------------------------
    allowed_origins: str = Field(default="http://localhost", alias="ALLOWED_ORIGINS")

    # ------------------------------------------------------------------
    # Optional integrations
    # ------------------------------------------------------------------
    redis_url: str | None = Field(default=None, alias="REDIS_URL")
    sentry_dsn: str | None = Field(default=None, alias="SENTRY_DSN")

    # ------------------------------------------------------------------
    # Engine
    # ------------------------------------------------------------------
    engine_base_url: str = Field(
        default="http://127.0.0.1:8010",
        alias="ENGINE_BASE_URL",
    )

    model_config = {"populate_by_name": True, "extra": "ignore"}

    @property
    def effective_api_key(self) -> str:
        for value in (
            self.ironclaw_api_key,
            self.internal_platform_api_key,
            self.platform_api_key,
            self.admin_api_key,
            self.api_key,
        ):
            normalized = _normalize_string(value)
            if normalized:
                return normalized
        return ""

    @property
    def effective_platform_api_key(self) -> str:
        return self.effective_api_key

    @property
    def effective_secret_key(self) -> str:
        value = _normalize_string(self.secret_key)
        if not value or value == SECRET_KEY_SENTINEL:
            return ""
        return value

    @property
    def effective_jwt_secret(self) -> str:
        value = _normalize_string(self.jwt_secret)
        if not value or value == JWT_SECRET_SENTINEL:
            return ""
        return value


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings(debug=False, reload=False)
