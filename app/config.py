from __future__ import annotations

from pathlib import Path
from typing import Final

from app.core.settings import get_settings

_settings = get_settings()


def _clean_optional_string(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or None
    cleaned = str(value).strip()
    return cleaned or None


def _get_str(*names: str, default: str = "") -> str:
    for name in names:
        value = _clean_optional_string(getattr(_settings, name, None))
        if value is not None:
            return value
    return default


def _get_optional_str(*names: str) -> str | None:
    for name in names:
        value = _clean_optional_string(getattr(_settings, name, None))
        if value is not None:
            return value
    return None


def _get_bool(*names: str, default: bool = False) -> bool:
    for name in names:
        value = getattr(_settings, name, None)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"1", "true", "yes", "on"}:
                return True
            if normalized in {"0", "false", "no", "off"}:
                return False
    return default


def _get_int(*names: str, default: int) -> int:
    for name in names:
        value = getattr(_settings, name, None)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return default


def _get_float(*names: str, default: float) -> float:
    for name in names:
        value = getattr(_settings, name, None)
        if value is None:
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return default


def _resolve_path(value: str | None, fallback: Path) -> str:
    raw = _clean_optional_string(value)
    target = Path(raw).expanduser() if raw is not None else fallback
    return str(target.resolve())


def _effective_str(name: str) -> str | None:
    return _clean_optional_string(getattr(_settings, name, None))


# ---------------------------------------------------------------------------
# Core identity
# ---------------------------------------------------------------------------
APP_NAME: Final[str] = _get_str("app_name", "APP_NAME", default="IronClaw-Security")
APP_VERSION: Final[str] = _get_str("app_version", "APP_VERSION", default="0.1.0")
ENVIRONMENT: Final[str] = _get_str("environment", "ENVIRONMENT", default="development")
DEBUG: Final[bool] = _get_bool("debug", "DEBUG", default=False)


# ---------------------------------------------------------------------------
# Server binding
# ---------------------------------------------------------------------------
APP_HOST: Final[str] = _get_str("app_host", "APP_HOST", default="127.0.0.1")
APP_PORT: Final[int] = _get_int("app_port", "APP_PORT", default=8000)
APP_BASE_URL: Final[str] = _get_str(
    "app_base_url",
    "APP_BASE_URL",
    "ironclaw_base_url",
    "IRONCLAW_BASE_URL",
    "engine_base_url",
    "ENGINE_BASE_URL",
    default=f"http://{APP_HOST}:{APP_PORT}",
)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_LEVEL: Final[str] = _get_str("log_level", "LOG_LEVEL", default="INFO")
STRUCTURED_LOGGING_ENABLED: Final[bool] = _get_bool(
    "structured_logging_enabled",
    "STRUCTURED_LOGGING_ENABLED",
    default=True,
)


# ---------------------------------------------------------------------------
# Authentication - canonical settings-backed compatibility exports
# ---------------------------------------------------------------------------
AUTH_REQUIRED: Final[bool] = bool(
    getattr(_settings, "effective_auth_required", False),
)

IRONCLAW_API_KEY: Final[str | None] = _get_optional_str("ironclaw_api_key", "IRONCLAW_API_KEY")
INTERNAL_PLATFORM_API_KEY: Final[str | None] = _get_optional_str(
    "internal_platform_api_key",
    "INTERNAL_PLATFORM_API_KEY",
)
PLATFORM_API_KEY: Final[str | None] = _get_optional_str("platform_api_key", "PLATFORM_API_KEY")
ADMIN_API_KEY: Final[str | None] = _get_optional_str("admin_api_key", "ADMIN_API_KEY")
API_KEY: Final[str | None] = _effective_str("effective_api_key") or _get_optional_str(
    "api_key",
    "API_KEY",
)

SECRET_KEY: Final[str | None] = _effective_str("effective_secret_key") or _get_optional_str(
    "secret_key",
    "SECRET_KEY",
)
JWT_SECRET: Final[str | None] = _effective_str("effective_jwt_secret") or _get_optional_str(
    "jwt_secret",
    "JWT_SECRET",
)
SUPABASE_JWT_SECRET: Final[str | None] = _effective_str(
    "effective_supabase_jwt_secret",
) or _get_optional_str(
    "supabase_jwt_secret",
    "SUPABASE_JWT_SECRET",
)
JWT_ALGORITHM: Final[str | None] = _effective_str("effective_jwt_algorithm") or _get_optional_str(
    "jwt_algorithm",
    "JWT_ALGORITHM",
)

SUPABASE_URL: Final[str] = _effective_str("effective_supabase_url") or _get_str(
    "supabase_url",
    "SUPABASE_URL",
    default="",
)
SUPABASE_ANON_KEY: Final[str | None] = _effective_str(
    "effective_supabase_anon_key",
) or _get_optional_str(
    "supabase_anon_key",
    "SUPABASE_ANON_KEY",
)
SUPABASE_SERVICE_ROLE_KEY: Final[str | None] = _effective_str(
    "effective_supabase_service_role_key",
) or _get_optional_str(
    "supabase_service_role_key",
    "SUPABASE_SERVICE_ROLE_KEY",
)
SUPABASE_KEY: Final[str | None] = SUPABASE_ANON_KEY

API_KEY_AUTH_CONFIGURED: Final[bool] = bool(
    getattr(_settings, "api_key_auth_configured", False),
)
BEARER_AUTH_CONFIGURED: Final[bool] = bool(
    getattr(_settings, "bearer_auth_configured", False),
)
AUTH_CONFIGURED: Final[bool] = bool(getattr(_settings, "auth_configured", False))

EFFECTIVE_API_KEY: Final[str | None] = _effective_str("effective_api_key")
EFFECTIVE_SECRET_KEY: Final[str | None] = _effective_str("effective_secret_key")
EFFECTIVE_JWT_SECRET: Final[str | None] = _effective_str("effective_jwt_secret")
EFFECTIVE_SUPABASE_JWT_SECRET: Final[str | None] = _effective_str("effective_supabase_jwt_secret")
EFFECTIVE_JWT_ALGORITHM: Final[str | None] = _effective_str("effective_jwt_algorithm")
EFFECTIVE_SUPABASE_URL: Final[str | None] = _effective_str("effective_supabase_url")
EFFECTIVE_SUPABASE_ANON_KEY: Final[str | None] = _effective_str("effective_supabase_anon_key")
EFFECTIVE_SUPABASE_SERVICE_ROLE_KEY: Final[str | None] = _effective_str(
    "effective_supabase_service_role_key",
)
EFFECTIVE_AUTH_REQUIRED: Final[bool] = bool(
    getattr(_settings, "effective_auth_required", False),
)


# ---------------------------------------------------------------------------
# Groq — LLM-assisted analysis
# ---------------------------------------------------------------------------
GROQ_ENABLED: Final[bool] = _get_bool("groq_enabled", "GROQ_ENABLED", default=False)
GROQ_API_KEY: Final[str] = _get_str("groq_api_key", "GROQ_API_KEY", default="")
GROQ_MODEL: Final[str] = _get_str("groq_model", "GROQ_MODEL", default="")
GROQ_TIMEOUT_SECONDS: Final[float] = _get_float(
    "groq_timeout_seconds",
    "GROQ_TIMEOUT_SECONDS",
    default=60.0,
)


# ---------------------------------------------------------------------------
# Policy and verdict defaults
# ---------------------------------------------------------------------------
DEFAULT_SCAN_VERDICT: Final[str] = _get_str(
    "default_scan_verdict",
    "DEFAULT_SCAN_VERDICT",
    default="allow",
)
DEFAULT_REVIEW_STATUS: Final[str] = _get_str(
    "default_review_status",
    "DEFAULT_REVIEW_STATUS",
    default="not_required",
)


# ---------------------------------------------------------------------------
# Risk thresholds  (constraint: ALLOW_MAX < QUARANTINE_MIN <= BLOCK_MIN)
# ---------------------------------------------------------------------------
RISK_THRESHOLD_ALLOW_MAX: Final[int] = _get_int(
    "risk_threshold_allow_max",
    "RISK_THRESHOLD_ALLOW_MAX",
    default=29,
)
RISK_THRESHOLD_QUARANTINE_MIN: Final[int] = _get_int(
    "risk_threshold_quarantine_min",
    "RISK_THRESHOLD_QUARANTINE_MIN",
    default=30,
)
RISK_THRESHOLD_BLOCK_MIN: Final[int] = _get_int(
    "risk_threshold_block_min",
    "RISK_THRESHOLD_BLOCK_MIN",
    default=70,
)


# ---------------------------------------------------------------------------
# Scan feature flags
# ---------------------------------------------------------------------------
ENABLE_TEXT_SCANNING: Final[bool] = _get_bool(
    "enable_text_scanning",
    "ENABLE_TEXT_SCANNING",
    default=True,
)
ENABLE_URL_SCANNING: Final[bool] = _get_bool(
    "enable_url_scanning",
    "ENABLE_URL_SCANNING",
    default=True,
)
ENABLE_GITHUB_REPO_SCANNING: Final[bool] = _get_bool(
    "enable_github_repo_scanning",
    "ENABLE_GITHUB_REPO_SCANNING",
    default=True,
)
ENABLE_ARCHIVE_SCANNING: Final[bool] = _get_bool(
    "enable_archive_scanning",
    "ENABLE_ARCHIVE_SCANNING",
    default=True,
)


# ---------------------------------------------------------------------------
# Guard and execution control flags
# ---------------------------------------------------------------------------
ENABLE_GUARD_ACTIONS: Final[bool] = _get_bool(
    "enable_guard_actions",
    "ENABLE_GUARD_ACTIONS",
    default=True,
)
ENABLE_GUARD_ACTION_POLICY: Final[bool] = _get_bool(
    "enable_guard_action_policy",
    "ENABLE_GUARD_ACTION_POLICY",
    default=True,
)
ENABLE_GUARD_ACTION_DECISION: Final[bool] = _get_bool(
    "enable_guard_action_decision",
    "ENABLE_GUARD_ACTION_DECISION",
    default=True,
)
ENABLE_QUARANTINE_REVIEW: Final[bool] = _get_bool(
    "enable_quarantine_review",
    "ENABLE_QUARANTINE_REVIEW",
    default=True,
)


# ---------------------------------------------------------------------------
# Input size limits
# ---------------------------------------------------------------------------
MAX_TEXT_CHARS: Final[int] = _get_int("max_text_chars", "MAX_TEXT_CHARS", default=100000)
MAX_URL_LENGTH: Final[int] = _get_int("max_url_length", "MAX_URL_LENGTH", default=2048)
MAX_ARCHIVE_NAME_LENGTH: Final[int] = _get_int(
    "max_archive_name_length",
    "MAX_ARCHIVE_NAME_LENGTH",
    default=512,
)
MAX_REPO_URL_LENGTH: Final[int] = _get_int(
    "max_repo_url_length",
    "MAX_REPO_URL_LENGTH",
    default=2048,
)


# ---------------------------------------------------------------------------
# Filesystem paths
# ---------------------------------------------------------------------------
_DATA_DIR = _get_optional_str("data_dir", "DATA_DIR", "APP_DATA_DIR")
_BASE_DIR = Path(_DATA_DIR).expanduser().resolve() if _DATA_DIR else Path("./data").expanduser().resolve()

REPORTS_DIR: Final[str] = _resolve_path(
    _get_optional_str("reports_dir", "REPORTS_DIR"),
    _BASE_DIR / "reports",
)
UPLOADS_DIR: Final[str] = _resolve_path(
    _get_optional_str("uploads_dir", "UPLOADS_DIR"),
    _BASE_DIR / "uploads",
)
QUARANTINE_DIR: Final[str] = _resolve_path(
    _get_optional_str("quarantine_dir", "QUARANTINE_DIR"),
    _BASE_DIR / "quarantine",
)
BACKUP_DIR: Final[str] = _resolve_path(
    _get_optional_str("backup_dir", "BACKUP_DIR"),
    _BASE_DIR / "backups",
)


__all__ = [
    "ADMIN_API_KEY",
    "API_KEY",
    "API_KEY_AUTH_CONFIGURED",
    "APP_BASE_URL",
    "APP_HOST",
    "APP_NAME",
    "APP_PORT",
    "APP_VERSION",
    "AUTH_CONFIGURED",
    "AUTH_REQUIRED",
    "BACKUP_DIR",
    "BEARER_AUTH_CONFIGURED",
    "DEBUG",
    "DEFAULT_REVIEW_STATUS",
    "DEFAULT_SCAN_VERDICT",
    "EFFECTIVE_API_KEY",
    "EFFECTIVE_AUTH_REQUIRED",
    "EFFECTIVE_JWT_ALGORITHM",
    "EFFECTIVE_JWT_SECRET",
    "EFFECTIVE_SECRET_KEY",
    "EFFECTIVE_SUPABASE_ANON_KEY",
    "EFFECTIVE_SUPABASE_JWT_SECRET",
    "EFFECTIVE_SUPABASE_SERVICE_ROLE_KEY",
    "EFFECTIVE_SUPABASE_URL",
    "ENABLE_ARCHIVE_SCANNING",
    "ENABLE_GITHUB_REPO_SCANNING",
    "ENABLE_GUARD_ACTION_DECISION",
    "ENABLE_GUARD_ACTION_POLICY",
    "ENABLE_GUARD_ACTIONS",
    "ENABLE_QUARANTINE_REVIEW",
    "ENABLE_TEXT_SCANNING",
    "ENABLE_URL_SCANNING",
    "ENVIRONMENT",
    "GROQ_API_KEY",
    "GROQ_ENABLED",
    "GROQ_MODEL",
    "GROQ_TIMEOUT_SECONDS",
    "INTERNAL_PLATFORM_API_KEY",
    "IRONCLAW_API_KEY",
    "JWT_ALGORITHM",
    "JWT_SECRET",
    "LOG_LEVEL",
    "MAX_ARCHIVE_NAME_LENGTH",
    "MAX_REPO_URL_LENGTH",
    "MAX_TEXT_CHARS",
    "MAX_URL_LENGTH",
    "PLATFORM_API_KEY",
    "QUARANTINE_DIR",
    "REPORTS_DIR",
    "RISK_THRESHOLD_ALLOW_MAX",
    "RISK_THRESHOLD_BLOCK_MIN",
    "RISK_THRESHOLD_QUARANTINE_MIN",
    "SECRET_KEY",
    "STRUCTURED_LOGGING_ENABLED",
    "SUPABASE_ANON_KEY",
    "SUPABASE_JWT_SECRET",
    "SUPABASE_KEY",
    "SUPABASE_SERVICE_ROLE_KEY",
    "SUPABASE_URL",
    "UPLOADS_DIR",
]
