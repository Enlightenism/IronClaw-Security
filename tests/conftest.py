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

# Clear cached settings so ENVIRONMENT=test and IRONCLAW_API_KEY are picked up fresh
get_settings.cache_clear()

# Re-apply fresh settings onto app.state so auth sees the correct api key
_app.state.settings = get_settings()


@pytest.fixture(autouse=True)
def reset_audit_state() -> None:
    reset_audit_log()
    yield
    reset_audit_log()
