from __future__ import annotations

import os

# MUST be set before any app module is imported
os.environ["IRONCLAW_PERSISTENCE_MODE"] = "memory"
os.environ["ENVIRONMENT"] = "test"
os.environ["IRONCLAW_API_KEY"] = "test-api-key"
os.environ["AUTH_REQUIRED"] = "true"
os.environ["SUPABASE_URL"] = ""
os.environ["SUPABASE_SERVICE_ROLE_KEY"] = ""
os.environ["SUPABASE_KEY"] = ""
os.environ["SUPABASE_ANON_KEY"] = ""

import pytest

from app.core.settings import get_settings
from app.main import app as _app
from app.services.audit_log_service import reset_audit_log


@pytest.fixture(scope="session", autouse=True)
def _configure_settings() -> None:
    get_settings.cache_clear()
    settings = get_settings()
    _app.state.settings = settings


@pytest.fixture(scope="function", autouse=True)
def _refresh_app_settings() -> None:
    get_settings.cache_clear()
    settings = get_settings()
    _app.state.settings = settings


@pytest.fixture(autouse=True)
def reset_audit_state() -> None:
    reset_audit_log()
    yield
    reset_audit_log()
