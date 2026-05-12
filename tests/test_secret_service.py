from __future__ import annotations

import os
from unittest.mock import patch

from app.services.secrets_vault import _SecretsVault

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fresh_vault() -> _SecretsVault:
    """Return a new unseeded vault instance (bypasses lru_cache)."""
    return _SecretsVault()


# ---------------------------------------------------------------------------
# Core identity
# ---------------------------------------------------------------------------

def test_app_name_default():
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("APP_NAME", None)
        assert fresh_vault().app_name() == "IronClaw-Security"


def test_app_name_override():
    with patch.dict(os.environ, {"APP_NAME": "TestApp"}):
        assert fresh_vault().app_name() == "TestApp"


def test_app_host_default():
    os.environ.pop("APP_HOST", None)
    assert fresh_vault().app_host() == "127.0.0.1"


def test_app_port_default():
    os.environ.pop("APP_PORT", None)
    assert fresh_vault().app_port() == 8000


def test_app_port_override():
    with patch.dict(os.environ, {"APP_PORT": "9090"}):
        assert fresh_vault().app_port() == 9090


def test_app_port_is_int():
    with patch.dict(os.environ, {"APP_PORT": "5000"}):
        assert isinstance(fresh_vault().app_port(), int)


# ---------------------------------------------------------------------------
# Supabase
# ---------------------------------------------------------------------------

def test_supabase_url_empty_default():
    os.environ.pop("SUPABASE_URL", None)
    assert fresh_vault().supabase_url() == ""


def test_supabase_url_override():
    with patch.dict(os.environ, {"SUPABASE_URL": "https://abc.supabase.co"}):
        assert fresh_vault().supabase_url() == "https://abc.supabase.co"


def test_supabase_key_empty_default():
    os.environ.pop("SUPABASE_KEY", None)
    assert fresh_vault().supabase_key() == ""


def test_supabase_service_role_key_none_when_absent():
    os.environ.pop("SUPABASE_SERVICE_ROLE_KEY", None)
    assert fresh_vault().supabase_service_role_key() is None


def test_supabase_service_role_key_returns_value():
    with patch.dict(os.environ, {"SUPABASE_SERVICE_ROLE_KEY": "srk-xyz"}):
        assert fresh_vault().supabase_service_role_key() == "srk-xyz"


# ---------------------------------------------------------------------------
# Groq / AI
# ---------------------------------------------------------------------------

def test_groq_api_key_empty_default():
    os.environ.pop("GROQ_API_KEY", None)
    assert fresh_vault().groq_api_key() == ""


def test_groq_model_default():
    os.environ.pop("GROQ_MODEL", None)
    assert fresh_vault().groq_model() == "llama3-8b-8192"


def test_groq_model_override():
    with patch.dict(os.environ, {"GROQ_MODEL": "mixtral-8x7b-32768"}):
        assert fresh_vault().groq_model() == "mixtral-8x7b-32768"


# ---------------------------------------------------------------------------
# Auth / JWT
# ---------------------------------------------------------------------------

def test_secret_key_empty_default():
    os.environ.pop("SECRET_KEY", None)
    assert fresh_vault().secret_key() == ""


def test_jwt_algorithm_default():
    os.environ.pop("JWT_ALGORITHM", None)
    assert fresh_vault().jwt_algorithm() == "HS256"


def test_access_token_expire_minutes_default():
    os.environ.pop("ACCESS_TOKEN_EXPIRE_MINUTES", None)
    assert fresh_vault().access_token_expire_minutes() == 30


def test_access_token_expire_minutes_is_int():
    with patch.dict(os.environ, {"ACCESS_TOKEN_EXPIRE_MINUTES": "60"}):
        assert isinstance(fresh_vault().access_token_expire_minutes(), int)


# ---------------------------------------------------------------------------
# Filesystem paths
# ---------------------------------------------------------------------------

def test_data_dir_falls_back_to_samples():
    for key in ("IRONCLAW_DATA_DIR", "IRONCLAW_BASE_DIR", "DATA_DIR"):
        os.environ.pop(key, None)
    assert fresh_vault().data_dir() == "samples"


def test_data_dir_prefers_ironclaw_data_dir():
    with patch.dict(
        os.environ,
        {"IRONCLAW_DATA_DIR": "/data/ic", "DATA_DIR": "/data/other"},
    ):
        assert fresh_vault().data_dir() == "/data/ic"


def test_reports_dir_none_when_absent():
    os.environ.pop("REPORTS_DIR", None)
    os.environ.pop("IRONCLAW_REPORTS_DIR", None)
    assert fresh_vault().reports_dir() is None


def test_reports_dir_returns_value():
    with patch.dict(os.environ, {"REPORTS_DIR": "/tmp/reports"}):
        assert fresh_vault().reports_dir() == "/tmp/reports"


def test_uploads_dir_none_when_absent():
    os.environ.pop("UPLOADS_DIR", None)
    os.environ.pop("IRONCLAW_UPLOADS_DIR", None)
    assert fresh_vault().uploads_dir() is None


def test_quarantine_dir_none_when_absent():
    os.environ.pop("QUARANTINE_DIR", None)
    os.environ.pop("IRONCLAW_QUARANTINE_DIR", None)
    assert fresh_vault().quarantine_dir() is None


# ---------------------------------------------------------------------------
# Optional integrations
# ---------------------------------------------------------------------------

def test_redis_url_none_when_absent():
    os.environ.pop("REDIS_URL", None)
    assert fresh_vault().redis_url() is None


def test_sentry_dsn_none_when_absent():
    os.environ.pop("SENTRY_DSN", None)
    assert fresh_vault().sentry_dsn() is None


def test_environment_default():
    os.environ.pop("ENVIRONMENT", None)
    assert fresh_vault().environment() == "development"


def test_environment_override():
    with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
        assert fresh_vault().environment() == "production"


# ---------------------------------------------------------------------------
# Generic escape hatch
# ---------------------------------------------------------------------------

def test_get_returns_default_when_absent():
    os.environ.pop("IRONCLAW_NONEXISTENT_KEY", None)
    assert fresh_vault().get("IRONCLAW_NONEXISTENT_KEY", "fallback") == "fallback"


def test_get_returns_value_when_present():
    with patch.dict(os.environ, {"IRONCLAW_NONEXISTENT_KEY": "found"}):
        assert fresh_vault().get("IRONCLAW_NONEXISTENT_KEY") == "found"


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

def test_vault_singleton_is_same_object():
    from app.services.secrets_vault import _vault_singleton
    from app.services.secrets_vault import vault as v1
    v2 = _vault_singleton()
    assert v1 is v2