from __future__ import annotations

import os
from pathlib import Path

# Core app identity and bind address
APP_NAME = os.getenv("APP_NAME", "IronClaw-Security")
APP_HOST = os.getenv("APP_HOST", "127.0.0.1")
APP_PORT = int(os.getenv("APP_PORT", "8000"))

# Base directory for local filesystem artifacts
_BASE_DIR = Path(
    os.getenv("IRONCLAW_DATA_DIR")
    or os.getenv("IRONCLAW_BASE_DIR")
    or os.getenv("DATA_DIR", "samples")
).expanduser().resolve()

# Directories for reports, uploads, and quarantine
_REPORTS_DIR_ENV = os.getenv("REPORTS_DIR") or os.getenv(
    "IRONCLAW_REPORTS_DIR", str(_BASE_DIR / "reports")
)
_UPLOADS_DIR_ENV = os.getenv("UPLOADS_DIR") or os.getenv(
    "IRONCLAW_UPLOADS_DIR", str(_BASE_DIR / "uploads")
)
_QUARANTINE_DIR_ENV = os.getenv("QUARANTINE_DIR") or os.getenv(
    "IRONCLAW_QUARANTINE_DIR", str(_BASE_DIR / "quarantine")
)

REPORTS_DIR = str(Path(_REPORTS_DIR_ENV).expanduser().resolve())
UPLOADS_DIR = str(Path(_UPLOADS_DIR_ENV).expanduser().resolve())
QUARANTINE_DIR = str(Path(_QUARANTINE_DIR_ENV).expanduser().resolve())