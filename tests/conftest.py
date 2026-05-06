from __future__ import annotations

import os

# MUST be set before any app module is imported
os.environ["IRONCLAW_PERSISTENCE_MODE"] = "memory"
os.environ["SUPABASE_URL"] = ""
os.environ["SUPABASE_SERVICE_ROLE_KEY"] = ""
os.environ["SUPABASE_KEY"] = ""
os.environ["SUPABASE_ANON_KEY"] = ""

import pytest
from app.services.audit_log_service import reset_audit_log


@pytest.fixture(autouse=True)
def reset_audit_state():
    reset_audit_log()
    yield
    reset_audit_log()