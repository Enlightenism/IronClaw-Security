from __future__ import annotations

import functools
import os
from urllib.parse import urlparse

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

SECRET_KEY_SENTINEL = "changeme-32-chars-minimum!!!!!"
JWT_SECRET_SENTINEL = "changeme-jwt-32-chars-minimum!!"


def _normalize_string(value: str | None) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


def _csv_to_list(value: str | None) -> list[str]:
    normalized = _normalize_string(value)
    if not normalized:
        return []
    return [item.strip() for item in normalized.split(",") if item.strip()]


def _normalize_unique(values: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = _normalize_string(value)
        if not item:
            continue
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(item)
    return normalized


def _normalize_origin(origin: str) -> str:
    value = _normalize_string(origin)
    if not value:
        return ""

    if value.startswith("[") and "](" in value and value.endswith(")"):
        value = value[value.index("](") + 2 : -1].strip()

    if value == "*":
        return "*"

    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return value.rstrip("/")

    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _normalize_host(value: str) -> str:
    host = _normalize_string(value)
    if not host:
        return ""

    if host == "*":
        return "*"

    if "://" in host:
        parsed = urlparse(host)
        host = parsed.netloc or parsed.path

    if host.startswith("[") and "](" in host and host.endswith(")"):
        _, _, maybe_url = host.partition("](")
        parsed = urlparse(maybe_url[:-1])
        host = parsed.netloc or host

    host = host.strip().strip("/").lower()

    if host.startswith("*."):
        return host

    if ":" in host and not host.startswith("["):
        hostname, _, port = host.partition(":")
        if port.isdigit():
            return hostname

    return host


def _host_from_url(value: str) -> str:
    normalized = _normalize_origin(value)
    if not normalized or normalized == "*":
        return ""
    parsed = urlparse(normalized)
    return _normalize_host(parsed.netloc)


def _is_local_development_host(host: str) -> bool:
    normalized = _normalize_host(host)
    return normalized in {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "testserver",
    }


def _optional_env_file() -> str | None:
    value = _normalize_string(os.getenv("IRONCLAW_ENV_FILE"))
    return value or None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        populate_by_name=True,
        extra="ignore",
        env_file=_optional_env_file(),
        env_file_encoding="utf-8",
    )

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
    # CORS — primary env var: ALLOWED_ORIGINS
    # Legacy fallback env var: CORS_ORIGINS.
    # Keep both fields so env injection and compatibility logic remain intact.
    # ------------------------------------------------------------------
    allowed_origins: str = Field(default="http://localhost", alias="ALLOWED_ORIGINS")
    cors_origins: str = Field(default="", alias="CORS_ORIGINS")
    cors_allowed_methods: str = Field(default="", alias="CORS_ALLOWED_METHODS")
    cors_allowed_headers: str = Field(default="", alias="CORS_ALLOWED_HEADERS")
    cors_expose_headers: str = Field(default="", alias="CORS_EXPOSE_HEADERS")
    cors_allow_credentials: bool | None = Field(
        default=None,
        alias="CORS_ALLOW_CREDENTIALS",
    )

    # ------------------------------------------------------------------
    # Trusted hosts / response hardening
    # ------------------------------------------------------------------
    trusted_hosts: str = Field(default="*", alias="TRUSTED_HOSTS")
    enable_hsts: bool = Field(default=True, alias="ENABLE_HSTS")
    content_security_policy: str = Field(default="", alias="CONTENT_SECURITY_POLICY")

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

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------
    @property
    def is_production(self) -> bool:
        return _normalize_string(self.environment).lower() == "production"

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

    @property
    def normalized_app_base_url(self) -> str:
        return _normalize_origin(self.app_base_url)

    @property
    def normalized_engine_base_url(self) -> str:
        return _normalize_origin(self.engine_base_url)

    @property
    def effective_allowed_origins(self) -> list[str]:
        primary = _normalize_unique(
            [_normalize_origin(item) for item in _csv_to_list(self.allowed_origins) if item.strip()],
        )
        if primary:
            return primary

        legacy = _normalize_unique(
            [_normalize_origin(item) for item in _csv_to_list(self.cors_origins) if item.strip()],
        )
        if legacy:
            return legacy

        if self.is_production:
            return []

        return [
            "http://localhost",
            "http://localhost:3000",
            "http://localhost:5173",
            "http://127.0.0.1",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5173",
        ]

    @property
    def effective_trusted_hosts(self) -> list[str]:
        configured_hosts = _csv_to_list(self.trusted_hosts)
        if configured_hosts:
            normalized_hosts = _normalize_unique(
                [normalized for item in configured_hosts if (normalized := _normalize_host(item))],
            )
            return normalized_hosts or ["*"]

        derived_hosts: list[str] = []

        for origin in self.effective_allowed_origins:
            if origin == "*":
                return ["*"]
            host = _host_from_url(origin)
            if host:
                derived_hosts.append(host)

        for base_url in (self.normalized_app_base_url, self.normalized_engine_base_url):
            host = _host_from_url(base_url)
            if not host:
                continue
            if self.is_production and _is_local_development_host(host):
                continue
            derived_hosts.append(host)

        normalized_derived = _normalize_unique(derived_hosts)
        return normalized_derived or ["*"]


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings(debug=False, reload=False)
