from __future__ import annotations

from pathlib import Path

from app.services.secrets_vault import vault

# ---------------------------------------------------------------------------
# Core identity
# ---------------------------------------------------------------------------
APP_NAME: str = vault.app_name()
APP_VERSION: str = vault.get("APP_VERSION", "0.1.0") or "0.1.0"
ENVIRONMENT: str = vault.environment()
DEBUG: bool = (vault.get("DEBUG", "false") or "false").lower() == "true"

# ---------------------------------------------------------------------------
# Server binding
# ---------------------------------------------------------------------------
APP_HOST: str = vault.app_host()
APP_PORT: int = vault.app_port()
APP_BASE_URL: str = vault.get("APP_BASE_URL") or vault.get("IRONCLAW_BASE_URL") or f"http://{APP_HOST}:{APP_PORT}"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_LEVEL: str = vault.get("LOG_LEVEL", "INFO") or "INFO"
STRUCTURED_LOGGING_ENABLED: bool = (vault.get("STRUCTURED_LOGGING_ENABLED", "true") or "true").lower() == "true"

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
AUTH_REQUIRED: bool = (vault.get("AUTH_REQUIRED", "false") or "false").lower() == "true"
API_KEY: str | None = vault.get("API_KEY") or vault.get("IRONCLAW_API_KEY")
ADMIN_API_KEY: str | None = vault.get("ADMIN_API_KEY")
PLATFORM_API_KEY: str | None = vault.get("PLATFORM_API_KEY")
INTERNAL_PLATFORM_API_KEY: str | None = vault.get("INTERNAL_PLATFORM_API_KEY")

# ---------------------------------------------------------------------------
# Groq — LLM-assisted analysis
# ---------------------------------------------------------------------------
GROQ_ENABLED: bool = (vault.get("GROQ_ENABLED", "false") or "false").lower() == "true"
GROQ_API_KEY: str = vault.groq_api_key()
GROQ_MODEL: str = vault.groq_model()
GROQ_TIMEOUT_SECONDS: float = float(vault.get("GROQ_TIMEOUT_SECONDS", "60.0") or "60.0")

# ---------------------------------------------------------------------------
# Supabase — persistence layer
# ---------------------------------------------------------------------------
SUPABASE_URL: str = vault.supabase_url()
SUPABASE_KEY: str = vault.supabase_key()
SUPABASE_SERVICE_ROLE_KEY: str | None = vault.supabase_service_role_key()
SUPABASE_ANON_KEY: str | None = vault.get("SUPABASE_ANON_KEY") or vault.supabase_key() or None

# ---------------------------------------------------------------------------
# Policy and verdict defaults
# ---------------------------------------------------------------------------
DEFAULT_SCAN_VERDICT: str = vault.get("DEFAULT_SCAN_VERDICT", "allow") or "allow"
DEFAULT_REVIEW_STATUS: str = vault.get("DEFAULT_REVIEW_STATUS", "not_required") or "not_required"

# ---------------------------------------------------------------------------
# Risk thresholds  (constraint: ALLOW_MAX < QUARANTINE_MIN <= BLOCK_MIN)
# ---------------------------------------------------------------------------
RISK_THRESHOLD_ALLOW_MAX: int = int(vault.get("RISK_THRESHOLD_ALLOW_MAX", "29") or "29")
RISK_THRESHOLD_QUARANTINE_MIN: int = int(vault.get("RISK_THRESHOLD_QUARANTINE_MIN", "30") or "30")
RISK_THRESHOLD_BLOCK_MIN: int = int(vault.get("RISK_THRESHOLD_BLOCK_MIN", "70") or "70")

# ---------------------------------------------------------------------------
# Scan feature flags
# ---------------------------------------------------------------------------
ENABLE_TEXT_SCANNING: bool = (vault.get("ENABLE_TEXT_SCANNING", "true") or "true").lower() == "true"
ENABLE_URL_SCANNING: bool = (vault.get("ENABLE_URL_SCANNING", "true") or "true").lower() == "true"
ENABLE_GITHUB_REPO_SCANNING: bool = (vault.get("ENABLE_GITHUB_REPO_SCANNING", "true") or "true").lower() == "true"
ENABLE_ARCHIVE_SCANNING: bool = (vault.get("ENABLE_ARCHIVE_SCANNING", "true") or "true").lower() == "true"

# ---------------------------------------------------------------------------
# Guard and execution control flags
# ---------------------------------------------------------------------------
ENABLE_GUARD_ACTIONS: bool = (vault.get("ENABLE_GUARD_ACTIONS", "true") or "true").lower() == "true"
ENABLE_GUARD_ACTION_POLICY: bool = (vault.get("ENABLE_GUARD_ACTION_POLICY", "true") or "true").lower() == "true"
ENABLE_GUARD_ACTION_DECISION: bool = (vault.get("ENABLE_GUARD_ACTION_DECISION", "true") or "true").lower() == "true"
ENABLE_QUARANTINE_REVIEW: bool = (vault.get("ENABLE_QUARANTINE_REVIEW", "true") or "true").lower() == "true"

# ---------------------------------------------------------------------------
# Input size limits
# ---------------------------------------------------------------------------
MAX_TEXT_CHARS: int = int(vault.get("MAX_TEXT_CHARS", "100000") or "100000")
MAX_URL_LENGTH: int = int(vault.get("MAX_URL_LENGTH", "2048") or "2048")
MAX_ARCHIVE_NAME_LENGTH: int = int(vault.get("MAX_ARCHIVE_NAME_LENGTH", "512") or "512")
MAX_REPO_URL_LENGTH: int = int(vault.get("MAX_REPO_URL_LENGTH", "2048") or "2048")

# ---------------------------------------------------------------------------
# Filesystem paths
# ---------------------------------------------------------------------------
_BASE_DIR = Path(vault.data_dir()).expanduser().resolve()

_REPORTS_DIR_ENV: str = vault.reports_dir() or str(_BASE_DIR / "reports")
_UPLOADS_DIR_ENV: str = vault.uploads_dir() or str(_BASE_DIR / "uploads")
_QUARANTINE_DIR_ENV: str = vault.quarantine_dir() or str(_BASE_DIR / "quarantine")
_BACKUP_DIR_ENV: str = vault.get("BACKUP_DIR") or str(_BASE_DIR / "backups")

REPORTS_DIR: str = str(Path(_REPORTS_DIR_ENV).expanduser().resolve())
UPLOADS_DIR: str = str(Path(_UPLOADS_DIR_ENV).expanduser().resolve())
QUARANTINE_DIR: str = str(Path(_QUARANTINE_DIR_ENV).expanduser().resolve())
BACKUP_DIR: str = str(Path(_BACKUP_DIR_ENV).expanduser().resolve())
