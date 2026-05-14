from __future__ import annotations

from pathlib import Path

from app.services.secrets_vault import vault

# Core app identity and bind address
APP_NAME: str = vault.app_name()
APP_HOST: str = vault.app_host()
APP_PORT: int = vault.app_port()

# Base directory for local filesystem artifacts
_BASE_DIR = Path(vault.data_dir()).expanduser().resolve()

# Directories for reports, uploads, and quarantine
_REPORTS_DIR_ENV: str = vault.reports_dir() or str(_BASE_DIR / "reports")
_UPLOADS_DIR_ENV: str = vault.uploads_dir() or str(_BASE_DIR / "uploads")
_QUARANTINE_DIR_ENV: str = vault.quarantine_dir() or str(_BASE_DIR / "quarantine")

REPORTS_DIR: str = str(Path(_REPORTS_DIR_ENV).expanduser().resolve())
UPLOADS_DIR: str = str(Path(_UPLOADS_DIR_ENV).expanduser().resolve())
QUARANTINE_DIR: str = str(Path(_QUARANTINE_DIR_ENV).expanduser().resolve())
