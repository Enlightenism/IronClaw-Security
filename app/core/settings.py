from __future__ import annotations

from enum import Enum, StrEnum
from functools import lru_cache
import os
from typing import Literal, get_args, get_origin

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict

    _HAS_PYDANTIC_SETTINGS = True
except ModuleNotFoundError:  # pragma: no cover
    _HAS_PYDANTIC_SETTINGS = False

    class BaseSettings(BaseModel):
        model_config = ConfigDict(extra="ignore")

        def __init__(self, **data):
            merged = {}
            for field_name, model_field in self.__class__.model_fields.items():
                alias = model_field.alias or field_name
                env_value = os.getenv(alias) or os.getenv(alias.upper()) or os.getenv(alias.lower())
                if env_value is not None and field_name not in data:
                    merged[field_name] = _coerce_env_value(env_value, model_field.annotation)
            merged.update(data)
            super().__init__(**merged)

    def SettingsConfigDict(**kwargs):
        return ConfigDict(**kwargs)


def _unwrap_optional(annotation):
    origin = get_origin(annotation)
    if origin is None:
        return annotation
    args = [arg for arg in get_args(annotation) if arg is not type(None)]
    if len(args) == 1:
        return args[0]
    return annotation


def _coerce_env_value(value: str, annotation):
    target = _unwrap_optional(annotation)
    origin = get_origin(target)

    if target is bool:
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if target is int:
        return int(value)
    if target is float:
        return float(value)
    if target is str:
        return value
    if isinstance(target, type) and issubclass(target, Enum):
        return target(value)

    if origin is Literal:
        literal_values = get_args(target)
        if bool in {type(item) for item in literal_values}:
            return value.strip().lower() in {"1", "true", "yes", "on"}
        for item in literal_values:
            if str(item) == value:
                return item
        return value

    return value


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        env_file_override=True,
    )

    # -------------------------------------------------------------------------
    # Application identity
    # -------------------------------------------------------------------------
    app_name: str = Field(default="IronClaw-Security", alias="APP_NAME")
    app_version: str = Field(default="0.1.0", alias="APP_VERSION")
    environment: Environment = Field(default=Environment.DEVELOPMENT, alias="ENVIRONMENT")
    debug: bool = Field(default=False, alias="DEBUG")
    reload: bool = Field(default=False, alias="RELOAD")
    api_prefix: str = Field(default="", alias="API_PREFIX")

    # -------------------------------------------------------------------------
    # Server binding — consumed by startup scripts and service.py
    # -------------------------------------------------------------------------
    app_host: str = Field(default="127.0.0.1", alias="APP_HOST")
    app_port: int = Field(default=8000, alias="APP_PORT")
    app_base_url: str = Field(default="http://127.0.0.1:8000", alias="APP_BASE_URL")

    # Legacy aliases — kept for backward compatibility with older startup paths
    ironclaw_env: str | None = Field(default=None, alias="IRONCLAW_ENV")
    ironclaw_base_url: str | None = Field(default=None, alias="IRONCLAW_BASE_URL")

    # -------------------------------------------------------------------------
    # Policy and verdict defaults
    # -------------------------------------------------------------------------
    default_scan_verdict: Literal["allow", "block", "quarantine"] = Field(
        default="allow",
        alias="DEFAULT_SCAN_VERDICT",
    )
    default_review_status: Literal["not_required", "pending", "approved", "rejected"] = Field(
        default="not_required",
        alias="DEFAULT_REVIEW_STATUS",
    )

    # -------------------------------------------------------------------------
    # Risk thresholds
    # -------------------------------------------------------------------------
    risk_threshold_allow_max: int = Field(default=29, alias="RISK_THRESHOLD_ALLOW_MAX")
    risk_threshold_quarantine_min: int = Field(default=30, alias="RISK_THRESHOLD_QUARANTINE_MIN")
    risk_threshold_block_min: int = Field(default=70, alias="RISK_THRESHOLD_BLOCK_MIN")

    # -------------------------------------------------------------------------
    # Scan feature flags
    # -------------------------------------------------------------------------
    enable_text_scanning: bool = Field(default=True, alias="ENABLE_TEXT_SCANNING")
    enable_url_scanning: bool = Field(default=True, alias="ENABLE_URL_SCANNING")
    enable_github_repo_scanning: bool = Field(default=True, alias="ENABLE_GITHUB_REPO_SCANNING")
    enable_archive_scanning: bool = Field(default=True, alias="ENABLE_ARCHIVE_SCANNING")

    # -------------------------------------------------------------------------
    # Guard and execution control flags
    # -------------------------------------------------------------------------
    enable_guard_actions: bool = Field(default=True, alias="ENABLE_GUARD_ACTIONS")
    enable_guard_action_policy: bool = Field(default=True, alias="ENABLE_GUARD_ACTION_POLICY")
    enable_guard_action_decision: bool = Field(default=True, alias="ENABLE_GUARD_ACTION_DECISION")
    enable_quarantine_review: bool = Field(default=True, alias="ENABLE_QUARANTINE_REVIEW")

    # -------------------------------------------------------------------------
    # Groq — LLM-assisted analysis
    # Conditional: GROQ_API_KEY is REQUIRED when GROQ_ENABLED=true
    # -------------------------------------------------------------------------
    groq_enabled: bool = Field(default=False, alias="GROQ_ENABLED")
    groq_api_key: str | None = Field(default=None, alias="GROQ_API_KEY")
    groq_model: str = Field(default="llama-3.3-70b-versatile", alias="GROQ_MODEL")
    groq_timeout_seconds: float = Field(default=60.0, alias="GROQ_TIMEOUT_SECONDS")

    # -------------------------------------------------------------------------
    # OpenAI — optional / future use
    # -------------------------------------------------------------------------
    openai_api_key: str | None = Field(default=None, alias="OPENAI_API_KEY")

    # -------------------------------------------------------------------------
    # Authentication
    # Conditional: at least one key REQUIRED when AUTH_REQUIRED=true
    # -------------------------------------------------------------------------
    auth_required: bool = Field(default=False, alias="AUTH_REQUIRED")
    api_key: str | None = Field(default=None, alias="API_KEY")
    admin_api_key: str | None = Field(default=None, alias="ADMIN_API_KEY")
    platform_api_key: str | None = Field(default=None, alias="PLATFORM_API_KEY")
    internal_platform_api_key: str | None = Field(
        default=None,
        alias="INTERNAL_PLATFORM_API_KEY",
    )
    ironclaw_api_key: str | None = Field(default=None, alias="IRONCLAW_API_KEY")

    # -------------------------------------------------------------------------
    # Supabase — persistence layer
    # All three keys REQUIRED for full operation
    # -------------------------------------------------------------------------
    supabase_url: str | None = Field(default=None, alias="SUPABASE_URL")
    supabase_service_role_key: str | None = Field(default=None, alias="SUPABASE_SERVICE_ROLE_KEY")
    supabase_anon_key: str | None = Field(default=None, alias="SUPABASE_ANON_KEY")

    # -------------------------------------------------------------------------
    # Input size limits
    # -------------------------------------------------------------------------
    max_text_chars: int = Field(default=100_000, alias="MAX_TEXT_CHARS")
    max_url_length: int = Field(default=2_048, alias="MAX_URL_LENGTH")
    max_archive_name_length: int = Field(default=512, alias="MAX_ARCHIVE_NAME_LENGTH")
    max_repo_url_length: int = Field(default=2_048, alias="MAX_REPO_URL_LENGTH")

    # -------------------------------------------------------------------------
    # Logging
    # -------------------------------------------------------------------------
    structured_logging_enabled: bool = Field(default=True, alias="STRUCTURED_LOGGING_ENABLED")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    # -------------------------------------------------------------------------
    # File storage paths
    # -------------------------------------------------------------------------
    reports_dir: str = Field(default="./data/reports", alias="REPORTS_DIR")
    uploads_dir: str = Field(default="./data/uploads", alias="UPLOADS_DIR")
    quarantine_dir: str = Field(default="./data/quarantine", alias="QUARANTINE_DIR")
    backup_dir: str = Field(default="./data/backups", alias="BACKUP_DIR")

    # -------------------------------------------------------------------------
    # Multi-region / High-Availability
    # region.py reads MultiRegionSettings independently for per-region Supabase
    # credentials.  These fields ensure the single .env file drives all HA
    # behaviour coherently and that validate_runtime() can enforce HA guards
    # at boot alongside the rest of the system checks.
    # -------------------------------------------------------------------------
    ha_enabled: bool = Field(default=False, alias="HA_ENABLED")
    primary_region: str = Field(default="us-east-1", alias="PRIMARY_REGION")
    replica_regions: str = Field(default="", alias="REPLICA_REGIONS")
    region_failover_enabled: bool = Field(default=False, alias="REGION_FAILOVER_ENABLED")
    region_health_check_interval_seconds: int = Field(
        default=30,
        alias="REGION_HEALTH_CHECK_INTERVAL_SECONDS",
    )

    # -------------------------------------------------------------------------
    # Field validators
    # -------------------------------------------------------------------------

    @field_validator("api_prefix")
    @classmethod
    def validate_api_prefix(cls, value: str) -> str:
        if not value:
            return ""
        value = value.strip()
        if not value.startswith("/"):
            value = f"/{value}"
        return value.rstrip("/")

    @field_validator("log_level")
    @classmethod
    def normalize_log_level(cls, value: str) -> str:
        return value.strip().upper()

    @field_validator("app_host")
    @classmethod
    def normalize_app_host(cls, value: str) -> str:
        return value.strip()

    @field_validator("app_base_url")
    @classmethod
    def normalize_app_base_url(cls, value: str) -> str:
        return value.strip().rstrip("/")

    @field_validator("ironclaw_base_url")
    @classmethod
    def normalize_ironclaw_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip().rstrip("/") or None

    @field_validator("ironclaw_env")
    @classmethod
    def normalize_ironclaw_env(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None

    @field_validator(
        "groq_api_key",
        "openai_api_key",
        "api_key",
        "admin_api_key",
        "platform_api_key",
        "internal_platform_api_key",
        "ironclaw_api_key",
        "supabase_url",
        "supabase_service_role_key",
        "supabase_anon_key",
    )
    @classmethod
    def empty_secret_to_none(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None

    @field_validator(
        "risk_threshold_allow_max",
        "risk_threshold_quarantine_min",
        "risk_threshold_block_min",
        "max_text_chars",
        "max_url_length",
        "max_archive_name_length",
        "max_repo_url_length",
        "app_port",
    )
    @classmethod
    def non_negative_ints(cls, value: int) -> int:
        if value < 0:
            raise ValueError("value must be non-negative")
        return value

    @field_validator("groq_timeout_seconds")
    @classmethod
    def positive_timeout(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("GROQ_TIMEOUT_SECONDS must be greater than 0")
        return value

    @field_validator("primary_region")
    @classmethod
    def normalize_primary_region(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("replica_regions")
    @classmethod
    def normalize_replica_regions(cls, value: str) -> str:
        return value.strip()

    @field_validator("region_health_check_interval_seconds")
    @classmethod
    def positive_health_check_interval(cls, value: int) -> int:
        if value < 1:
            raise ValueError("REGION_HEALTH_CHECK_INTERVAL_SECONDS must be >= 1")
        return value

    # -------------------------------------------------------------------------
    # Cross-field model validator — port coherence
    # -------------------------------------------------------------------------

    @model_validator(mode="after")
    def sync_base_url_port(self) -> Settings:
        """Keep app_base_url coherent with app_port when using the default."""
        if self.app_base_url == "http://127.0.0.1:8000" and self.app_port != 8000:
            self.app_base_url = f"http://{self.app_host}:{self.app_port}"
        return self

    # -------------------------------------------------------------------------
    # Properties
    # -------------------------------------------------------------------------

    @property
    def is_production(self) -> bool:
        return self.environment == Environment.PRODUCTION

    @property
    def is_test(self) -> bool:
        return self.environment == Environment.TEST

    @property
    def supported_target_types(self) -> tuple[str, ...]:
        supported: list[str] = []
        if self.enable_text_scanning:
            supported.append("text")
        if self.enable_url_scanning:
            supported.append("url")
        if self.enable_github_repo_scanning:
            supported.extend(["github_repo", "githubrepo"])
        if self.enable_archive_scanning:
            supported.append("archive")
        return tuple(supported)

    @property
    def effective_platform_api_key(self) -> str | None:
        return self.internal_platform_api_key or self.platform_api_key or self.admin_api_key or self.api_key or self.ironclaw_api_key

    @property
    def effective_base_url(self) -> str:
        """Resolve final base URL: ironclaw_base_url > app_base_url."""
        return self.ironclaw_base_url or self.app_base_url

    @property
    def parsed_replica_regions(self) -> list[str]:
        """Return REPLICA_REGIONS as a stripped, non-empty list of region codes."""
        if not self.replica_regions.strip():
            return []
        return [c.strip().lower() for c in self.replica_regions.split(",") if c.strip()]

    # -------------------------------------------------------------------------
    # Runtime validation — called once at boot by get_settings()
    # -------------------------------------------------------------------------

    def validate_runtime(self) -> None:
        if self.risk_threshold_allow_max >= self.risk_threshold_quarantine_min:
            raise ValueError("RISK_THRESHOLD_ALLOW_MAX must be less than " "RISK_THRESHOLD_QUARANTINE_MIN")
        if self.risk_threshold_quarantine_min > self.risk_threshold_block_min:
            raise ValueError("RISK_THRESHOLD_QUARANTINE_MIN must be less than or equal to " "RISK_THRESHOLD_BLOCK_MIN")
        if self.groq_enabled and not self.groq_api_key:
            raise ValueError("GROQ_ENABLED is true but GROQ_API_KEY is not set")
        if self.default_scan_verdict not in {"allow", "block", "quarantine"}:
            raise ValueError("DEFAULT_SCAN_VERDICT is invalid")
        if self.default_review_status not in {
            "not_required",
            "pending",
            "approved",
            "rejected",
        }:
            raise ValueError("DEFAULT_REVIEW_STATUS is invalid")
        if self.auth_required and not (self.api_key or self.admin_api_key or self.platform_api_key or self.internal_platform_api_key or self.ironclaw_api_key):
            raise ValueError("AUTH_REQUIRED is true but no API key is configured " "(API_KEY, ADMIN_API_KEY, PLATFORM_API_KEY, " "INTERNAL_PLATFORM_API_KEY, or IRONCLAW_API_KEY)")
        if not (1 <= self.app_port <= 65535):
            raise ValueError(f"APP_PORT {self.app_port} is out of valid range 1–65535")
        if self.ha_enabled and not self.replica_regions.strip():
            raise ValueError("HA_ENABLED requires at least one REPLICA_REGIONS entry")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.validate_runtime()
    return settings
