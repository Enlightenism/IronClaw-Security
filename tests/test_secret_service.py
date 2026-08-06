from __future__ import annotations

import os
from unittest.mock import patch

import pytest

import app.services.secrets_vault as _vault_module
from app.services.secrets_vault import _SecretsVault

_ALL_VAULT_ENV_KEYS = (
    "APP_NAME",
    "APP_VERSION",
    "APP_HOST",
    "APP_PORT",
    "APP_BASE_URL",
    "API_PREFIX",
    "DEBUG",
    "RELOAD",
    "ENGINE_BASE_URL",
    "ENVIRONMENT",
    "LOG_LEVEL",
    "STRUCTURED_LOGGING_ENABLED",
    "AUTH_REQUIRED",
    "API_KEY",
    "ADMIN_API_KEY",
    "PLATFORM_API_KEY",
    "INTERNAL_PLATFORM_API_KEY",
    "IRONCLAW_API_KEY",
    "SECRET_KEY",
    "IRONCLAW_SECRET_KEY",
    "APP_SECRET_KEY",
    "JWT_SECRET",
    "SUPABASE_JWT_SECRET",
    "JWT_ALGORITHM",
    "ACCESS_TOKEN_EXPIRE_MINUTES",
    "IRONCLAW_AUTH_EDGE_FN_PATH",
    "IRONCLAW_AUTH_EDGE_FN_TIMEOUT_SECONDS",
    "SUPABASE_URL",
    "SUPABASE_KEY",
    "SUPABASE_ANON_KEY",
    "SUPABASE_SERVICE_ROLE_KEY",
    "STRIPE_SECRET_KEY",
    "STRIPE_PUBLISHABLE_KEY",
    "STRIPE_WEBHOOK_SECRET",
    "GROQ_ENABLED",
    "GROQ_API_KEY",
    "GROQ_MODEL",
    "GROQ_TIMEOUT_SECONDS",
    "OPENAI_API_KEY",
    "DEFAULT_SCAN_VERDICT",
    "DEFAULT_REVIEW_STATUS",
    "RISK_THRESHOLD_ALLOW_MAX",
    "RISK_THRESHOLD_QUARANTINE_MIN",
    "RISK_THRESHOLD_BLOCK_MIN",
    "MAX_TEXT_CHARS",
    "MAX_URL_LENGTH",
    "MAX_ARCHIVE_NAME_LENGTH",
    "MAX_REPO_URL_LENGTH",
    "IRONCLAW_DATA_DIR",
    "IRONCLAW_BASE_DIR",
    "DATA_DIR",
    "REPORTS_DIR",
    "IRONCLAW_REPORTS_DIR",
    "UPLOADS_DIR",
    "IRONCLAW_UPLOADS_DIR",
    "QUARANTINE_DIR",
    "IRONCLAW_QUARANTINE_DIR",
    "BACKUP_DIR",
    "REDIS_URL",
    "SENTRY_DSN",
)


@pytest.fixture(autouse=True)
def clean_vault_env():
    with patch.dict(os.environ, {}, clear=False):
        for key in _ALL_VAULT_ENV_KEYS:
            os.environ.pop(key, None)
        _vault_module._vault_singleton.cache_clear()
        yield
        _vault_module._vault_singleton.cache_clear()


def fresh_vault() -> _SecretsVault:
    return _SecretsVault()


def test_app_name_default():
    assert fresh_vault().app_name() == "IronClaw-Security"


def test_app_name_override():
    with patch.dict(os.environ, {"APP_NAME": "TestApp"}, clear=False):
        assert fresh_vault().app_name() == "TestApp"


def test_app_host_default():
    assert fresh_vault().app_host() == "127.0.0.1"


def test_app_host_override():
    with patch.dict(os.environ, {"APP_HOST": "0.0.0.0"}, clear=False):
        assert fresh_vault().app_host() == "0.0.0.0"


def test_app_port_default():
    assert fresh_vault().app_port() == 8000


def test_app_port_override():
    with patch.dict(os.environ, {"APP_PORT": "9090"}, clear=False):
        assert fresh_vault().app_port() == 9090


def test_app_port_is_int():
    with patch.dict(os.environ, {"APP_PORT": "5000"}, clear=False):
        assert isinstance(fresh_vault().app_port(), int)


def test_supabase_url_empty_default():
    assert fresh_vault().supabase_url() == ""


def test_supabase_url_override():
    with patch.dict(os.environ, {"SUPABASE_URL": "https://abc.supabase.co"}, clear=False):
        assert fresh_vault().supabase_url() == "https://abc.supabase.co"


def test_supabase_key_empty_default():
    assert fresh_vault().supabase_key() == ""


def test_supabase_key_override():
    with patch.dict(os.environ, {"SUPABASE_KEY": "sk-test-key"}, clear=False):
        assert fresh_vault().supabase_key() == "sk-test-key"


def test_supabase_service_role_key_none_when_absent():
    assert fresh_vault().supabase_service_role_key() is None


def test_supabase_service_role_key_returns_value():
    with patch.dict(os.environ, {"SUPABASE_SERVICE_ROLE_KEY": "srk-xyz"}, clear=False):
        assert fresh_vault().supabase_service_role_key() == "srk-xyz"


def test_groq_api_key_empty_default():
    assert fresh_vault().groq_api_key() == ""


def test_groq_api_key_override():
    with patch.dict(os.environ, {"GROQ_API_KEY": "gsk-test-key"}, clear=False):
        assert fresh_vault().groq_api_key() == "gsk-test-key"


def test_groq_model_default():
    assert fresh_vault().groq_model() == "llama3-8b-8192"


def test_groq_model_override():
    with patch.dict(os.environ, {"GROQ_MODEL": "mixtral-8x7b-32768"}, clear=False):
        assert fresh_vault().groq_model() == "mixtral-8x7b-32768"


def test_secret_key_empty_default():
    assert fresh_vault().secret_key() == ""


def test_secret_key_override():
    with patch.dict(os.environ, {"SECRET_KEY": "supersecret"}, clear=False):
        assert fresh_vault().secret_key() == "supersecret"


def test_secret_key_falls_back_to_ironclaw_secret_key():
    with patch.dict(os.environ, {"IRONCLAW_SECRET_KEY": "ironclaw-secret"}, clear=False):
        assert fresh_vault().secret_key() == "ironclaw-secret"


def test_secret_key_falls_back_to_app_secret_key():
    with patch.dict(os.environ, {"APP_SECRET_KEY": "app-secret"}, clear=False):
        assert fresh_vault().secret_key() == "app-secret"


def test_jwt_algorithm_default():
    assert fresh_vault().jwt_algorithm() == "HS256"


def test_jwt_algorithm_override():
    with patch.dict(os.environ, {"JWT_ALGORITHM": "RS256"}, clear=False):
        assert fresh_vault().jwt_algorithm() == "RS256"


def test_access_token_expire_minutes_default():
    assert fresh_vault().access_token_expire_minutes() == 30


def test_access_token_expire_minutes_override():
    with patch.dict(os.environ, {"ACCESS_TOKEN_EXPIRE_MINUTES": "60"}, clear=False):
        assert fresh_vault().access_token_expire_minutes() == 60


def test_access_token_expire_minutes_is_int():
    with patch.dict(os.environ, {"ACCESS_TOKEN_EXPIRE_MINUTES": "60"}, clear=False):
        assert isinstance(fresh_vault().access_token_expire_minutes(), int)


def test_data_dir_falls_back_to_samples():
    assert fresh_vault().data_dir() == "samples"


def test_data_dir_prefers_ironclaw_data_dir():
    with patch.dict(
        os.environ,
        {"IRONCLAW_DATA_DIR": "/data/ic", "DATA_DIR": "/data/other"},
        clear=False,
    ):
        assert fresh_vault().data_dir() == "/data/ic"


def test_data_dir_falls_back_to_ironclaw_base_dir():
    with patch.dict(
        os.environ,
        {"IRONCLAW_BASE_DIR": "/data/base"},
        clear=False,
    ):
        assert fresh_vault().data_dir() == "/data/base"


def test_data_dir_falls_back_to_data_dir_env():
    with patch.dict(os.environ, {"DATA_DIR": "/data/generic"}, clear=False):
        assert fresh_vault().data_dir() == "/data/generic"


def test_reports_dir_none_when_absent():
    assert fresh_vault().reports_dir() is None


def test_reports_dir_returns_value():
    with patch.dict(os.environ, {"REPORTS_DIR": "/tmp/reports"}, clear=False):
        assert fresh_vault().reports_dir() == "/tmp/reports"


def test_reports_dir_falls_back_to_ironclaw_reports_dir():
    with patch.dict(os.environ, {"IRONCLAW_REPORTS_DIR": "/tmp/ic_reports"}, clear=False):
        assert fresh_vault().reports_dir() == "/tmp/ic_reports"


def test_uploads_dir_none_when_absent():
    assert fresh_vault().uploads_dir() is None


def test_uploads_dir_returns_value():
    with patch.dict(os.environ, {"UPLOADS_DIR": "/tmp/uploads"}, clear=False):
        assert fresh_vault().uploads_dir() == "/tmp/uploads"


def test_uploads_dir_falls_back_to_ironclaw_uploads_dir():
    with patch.dict(os.environ, {"IRONCLAW_UPLOADS_DIR": "/tmp/ic_uploads"}, clear=False):
        assert fresh_vault().uploads_dir() == "/tmp/ic_uploads"


def test_quarantine_dir_none_when_absent():
    assert fresh_vault().quarantine_dir() is None


def test_quarantine_dir_returns_value():
    with patch.dict(os.environ, {"QUARANTINE_DIR": "/tmp/quarantine"}, clear=False):
        assert fresh_vault().quarantine_dir() == "/tmp/quarantine"


def test_quarantine_dir_falls_back_to_ironclaw_quarantine_dir():
    with patch.dict(os.environ, {"IRONCLAW_QUARANTINE_DIR": "/tmp/ic_quarantine"}, clear=False):
        assert fresh_vault().quarantine_dir() == "/tmp/ic_quarantine"


def test_redis_url_none_when_absent():
    assert fresh_vault().redis_url() is None


def test_redis_url_returns_value():
    with patch.dict(os.environ, {"REDIS_URL": "redis://localhost:6379/0"}, clear=False):
        assert fresh_vault().redis_url() == "redis://localhost:6379/0"


def test_sentry_dsn_none_when_absent():
    assert fresh_vault().sentry_dsn() is None


def test_sentry_dsn_returns_value():
    with patch.dict(os.environ, {"SENTRY_DSN": "https://sentry.io/123"}, clear=False):
        assert fresh_vault().sentry_dsn() == "https://sentry.io/123"


def test_environment_default():
    assert fresh_vault().environment() == "development"


def test_environment_override():
    with patch.dict(os.environ, {"ENVIRONMENT": "production"}, clear=False):
        assert fresh_vault().environment() == "production"


def test_get_returns_default_when_absent():
    assert fresh_vault().get("IRONCLAW_NONEXISTENT_KEY", "fallback") == "fallback"


def test_get_returns_value_when_present():
    with patch.dict(os.environ, {"IRONCLAW_NONEXISTENT_KEY": "found"}, clear=False):
        assert fresh_vault().get("IRONCLAW_NONEXISTENT_KEY") == "found"


def test_get_returns_none_when_absent_no_default():
    assert fresh_vault().get("IRONCLAW_NONEXISTENT_KEY") is None


def test_vault_singleton_is_same_object():
    _vault_module._vault_singleton.cache_clear()
    v1 = _vault_module._vault_singleton()
    v2 = _vault_module._vault_singleton()
    assert v1 is v2


def test_vault_singleton_is_secrets_vault_instance():
    vault = _vault_module.vault
    assert isinstance(vault, _vault_module._SecretsVault)


def test_vault_module_level_export_functional():
    vault = _vault_module.vault
    assert vault.app_name() in (
        "IronClaw-Security",
        os.getenv("APP_NAME", "IronClaw-Security"),
    )
    assert isinstance(vault.app_port(), int)
    assert vault.environment() in (
        "development",
        "staging",
        "production",
        os.getenv("ENVIRONMENT", "development"),
    )
