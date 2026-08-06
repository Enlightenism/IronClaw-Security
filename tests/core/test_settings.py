from __future__ import annotations

import pytest

from app.core.settings import (
    JWT_SECRET_SENTINEL,
    SECRET_KEY_SENTINEL,
    Settings,
    get_settings,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fresh(monkeypatch, **env_overrides) -> Settings:
    """Clear lru_cache, apply env overrides, return a new Settings instance."""
    get_settings.cache_clear()
    for key, value in env_overrides.items():
        monkeypatch.setenv(key, str(value))
    return get_settings()


# ---------------------------------------------------------------------------
# Core identity defaults
# ---------------------------------------------------------------------------


class TestCoreIdentityDefaults:
    def test_app_name_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("APP_NAME", raising=False)
        s = get_settings()
        assert s.app_name == "IronClaw-Security"
        assert isinstance(s.app_name, str)

    def test_app_version_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("APP_VERSION", raising=False)
        s = get_settings()
        assert s.app_version == "0.1.0"
        assert isinstance(s.app_version, str)

    def test_app_host_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("APP_HOST", raising=False)
        s = get_settings()
        assert s.app_host == "127.0.0.1"
        assert isinstance(s.app_host, str)

    def test_app_port_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("APP_PORT", raising=False)
        s = get_settings()
        assert s.app_port == 8000
        assert isinstance(s.app_port, int)

    def test_app_base_url_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("APP_BASE_URL", raising=False)
        s = get_settings()
        assert s.app_base_url == ""
        assert isinstance(s.app_base_url, str)

    def test_api_prefix_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("API_PREFIX", raising=False)
        s = get_settings()
        assert s.api_prefix == ""
        assert isinstance(s.api_prefix, str)

    def test_debug_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("DEBUG", raising=False)
        s = get_settings()
        assert s.debug is False
        assert isinstance(s.debug, bool)

    def test_reload_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("RELOAD", raising=False)
        s = get_settings()
        assert s.reload is False
        assert isinstance(s.reload, bool)


# ---------------------------------------------------------------------------
# Core identity overrides
# ---------------------------------------------------------------------------


class TestCoreIdentityOverrides:
    def test_app_name_override(self, monkeypatch):
        s = _fresh(monkeypatch, APP_NAME="TestClaw")
        assert s.app_name == "TestClaw"

    def test_app_version_override(self, monkeypatch):
        s = _fresh(monkeypatch, APP_VERSION="9.9.9")
        assert s.app_version == "9.9.9"

    def test_app_host_override(self, monkeypatch):
        s = _fresh(monkeypatch, APP_HOST="0.0.0.0")
        assert s.app_host == "0.0.0.0"

    def test_app_port_override(self, monkeypatch):
        s = _fresh(monkeypatch, APP_PORT="9090")
        assert s.app_port == 9090
        assert isinstance(s.app_port, int)

    def test_debug_override_true(self, monkeypatch):
        s = _fresh(monkeypatch, DEBUG="true")
        assert s.debug is False
        assert isinstance(s.debug, bool)

    def test_reload_override_true(self, monkeypatch):
        s = _fresh(monkeypatch, RELOAD="1")
        assert s.reload is False
        assert isinstance(s.reload, bool)


# ---------------------------------------------------------------------------
# Environment / logging defaults
# ---------------------------------------------------------------------------


class TestEnvironmentLoggingDefaults:
    def test_environment_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        s = get_settings()
        assert s.environment == "development"
        assert isinstance(s.environment, str)

    def test_log_level_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("LOG_LEVEL", raising=False)
        s = get_settings()
        assert s.log_level == "INFO"
        assert isinstance(s.log_level, str)

    def test_structured_logging_enabled_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("STRUCTURED_LOGGING_ENABLED", raising=False)
        s = get_settings()
        assert s.structured_logging_enabled is True
        assert isinstance(s.structured_logging_enabled, bool)

    def test_environment_override(self, monkeypatch):
        s = _fresh(monkeypatch, ENVIRONMENT="production")
        assert s.environment == "production"

    def test_log_level_override(self, monkeypatch):
        s = _fresh(monkeypatch, LOG_LEVEL="DEBUG")
        assert s.log_level == "DEBUG"

    def test_structured_logging_override_false(self, monkeypatch):
        s = _fresh(monkeypatch, STRUCTURED_LOGGING_ENABLED="false")
        assert s.structured_logging_enabled is False


# ---------------------------------------------------------------------------
# Authentication defaults
# ---------------------------------------------------------------------------


class TestAuthenticationDefaults:
    def test_auth_required_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("AUTH_REQUIRED", raising=False)
        s = get_settings()
        assert s.auth_required is False
        assert isinstance(s.auth_required, bool)

    def test_api_key_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("API_KEY", raising=False)
        s = get_settings()
        assert s.api_key == ""
        assert isinstance(s.api_key, str)

    def test_admin_api_key_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("ADMIN_API_KEY", raising=False)
        s = get_settings()
        assert s.admin_api_key == ""
        assert isinstance(s.admin_api_key, str)

    def test_platform_api_key_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("PLATFORM_API_KEY", raising=False)
        s = get_settings()
        assert s.platform_api_key == ""
        assert isinstance(s.platform_api_key, str)

    def test_internal_platform_api_key_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("INTERNAL_PLATFORM_API_KEY", raising=False)
        s = get_settings()
        assert s.internal_platform_api_key == ""
        assert isinstance(s.internal_platform_api_key, str)

    def test_ironclaw_api_key_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("IRONCLAW_API_KEY", raising=False)
        s = get_settings()
        assert s.ironclaw_api_key == ""
        assert isinstance(s.ironclaw_api_key, str)

    def test_auth_required_override_true(self, monkeypatch):
        s = _fresh(monkeypatch, AUTH_REQUIRED="true")
        assert s.auth_required is True

    def test_api_key_override(self, monkeypatch):
        s = _fresh(monkeypatch, API_KEY="sk-test-abc123")
        assert s.api_key == "sk-test-abc123"

    def test_admin_api_key_override(self, monkeypatch):
        s = _fresh(monkeypatch, ADMIN_API_KEY="admin-secret-xyz")
        assert s.admin_api_key == "admin-secret-xyz"


# ---------------------------------------------------------------------------
# Auth / JWT defaults
# ---------------------------------------------------------------------------


class TestJWTDefaults:
    def test_secret_key_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("IRONCLAW_SECRET_KEY", raising=False)
        monkeypatch.delenv("SECRET_KEY", raising=False)
        s = get_settings()
        assert s.secret_key == SECRET_KEY_SENTINEL
        assert isinstance(s.secret_key, str)

    def test_jwt_secret_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("JWT_SECRET", raising=False)
        monkeypatch.delenv("SUPABASE_JWT_SECRET", raising=False)
        s = get_settings()
        assert s.jwt_secret == JWT_SECRET_SENTINEL
        assert isinstance(s.jwt_secret, str)

    def test_jwt_algorithm_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("JWT_ALGORITHM", raising=False)
        s = get_settings()
        assert s.jwt_algorithm == ""
        assert isinstance(s.jwt_algorithm, str)

    def test_access_token_expire_minutes_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("ACCESS_TOKEN_EXPIRE_MINUTES", raising=False)
        s = get_settings()
        assert s.access_token_expire_minutes == 30
        assert isinstance(s.access_token_expire_minutes, int)

    def test_jwt_algorithm_override(self, monkeypatch):
        s = _fresh(monkeypatch, JWT_ALGORITHM="RS256")
        assert s.jwt_algorithm == "RS256"

    def test_access_token_expire_minutes_override(self, monkeypatch):
        s = _fresh(monkeypatch, ACCESS_TOKEN_EXPIRE_MINUTES="60")
        assert s.access_token_expire_minutes == 60
        assert isinstance(s.access_token_expire_minutes, int)

    def test_effective_secret_key_returns_empty_for_sentinel(self, monkeypatch):
        monkeypatch.delenv("IRONCLAW_SECRET_KEY", raising=False)
        monkeypatch.delenv("SECRET_KEY", raising=False)
        s = Settings(IRONCLAW_SECRET_KEY=SECRET_KEY_SENTINEL)
        assert s.effective_secret_key == ""

    def test_effective_secret_key_returns_trimmed_value_from_settings(self, monkeypatch):
        monkeypatch.delenv("IRONCLAW_SECRET_KEY", raising=False)
        monkeypatch.delenv("SECRET_KEY", raising=False)
        s = Settings(IRONCLAW_SECRET_KEY="  real-secret-key  ")
        assert s.effective_secret_key == "real-secret-key"

    def test_effective_secret_key_prefers_vault_env(self, monkeypatch):
        monkeypatch.setenv("IRONCLAW_SECRET_KEY", "vault-secret")
        s = Settings(IRONCLAW_SECRET_KEY="settings-secret")
        assert s.effective_secret_key == "vault-secret"

    def test_effective_secret_key_uses_legacy_secret_key_fallback(self, monkeypatch):
        monkeypatch.delenv("IRONCLAW_SECRET_KEY", raising=False)
        monkeypatch.setenv("SECRET_KEY", "legacy-secret")
        s = Settings()
        assert s.effective_secret_key == "legacy-secret"

    def test_effective_jwt_secret_returns_empty_for_sentinel(self, monkeypatch):
        monkeypatch.delenv("JWT_SECRET", raising=False)
        monkeypatch.delenv("SUPABASE_JWT_SECRET", raising=False)
        monkeypatch.delenv("IRONCLAW_SECRET_KEY", raising=False)
        monkeypatch.delenv("SECRET_KEY", raising=False)
        s = Settings(JWT_SECRET=JWT_SECRET_SENTINEL)
        assert s.effective_jwt_secret == ""

    def test_effective_jwt_secret_returns_trimmed_value_from_settings(self, monkeypatch):
        monkeypatch.delenv("JWT_SECRET", raising=False)
        monkeypatch.delenv("SUPABASE_JWT_SECRET", raising=False)
        monkeypatch.delenv("IRONCLAW_SECRET_KEY", raising=False)
        monkeypatch.delenv("SECRET_KEY", raising=False)
        s = Settings(JWT_SECRET="  real-jwt-secret  ")
        assert s.effective_jwt_secret == "real-jwt-secret"

    def test_effective_jwt_secret_prefers_vault_jwt_secret(self, monkeypatch):
        monkeypatch.setenv("JWT_SECRET", "vault-jwt-secret")
        monkeypatch.setenv("SUPABASE_JWT_SECRET", "vault-supabase-jwt-secret")
        s = Settings(JWT_SECRET="settings-jwt-secret")
        assert s.effective_jwt_secret == "vault-jwt-secret"

    def test_effective_jwt_secret_uses_supabase_jwt_secret_fallback(self, monkeypatch):
        monkeypatch.delenv("JWT_SECRET", raising=False)
        monkeypatch.setenv("SUPABASE_JWT_SECRET", "vault-supabase-jwt-secret")
        s = Settings()
        assert s.effective_jwt_secret == "vault-supabase-jwt-secret"

    def test_effective_supabase_jwt_secret_returns_empty_when_unset(self, monkeypatch):
        monkeypatch.delenv("SUPABASE_JWT_SECRET", raising=False)
        monkeypatch.delenv("JWT_SECRET", raising=False)
        s = Settings()
        assert s.effective_supabase_jwt_secret == ""

    def test_effective_supabase_jwt_secret_prefers_supabase_env(self, monkeypatch):
        monkeypatch.setenv("SUPABASE_JWT_SECRET", "supabase-secret")
        monkeypatch.setenv("JWT_SECRET", "jwt-secret")
        s = Settings()
        assert s.effective_supabase_jwt_secret == "supabase-secret"

    def test_effective_supabase_jwt_secret_falls_back_to_jwt_secret(self, monkeypatch):
        monkeypatch.delenv("SUPABASE_JWT_SECRET", raising=False)
        monkeypatch.setenv("JWT_SECRET", "jwt-secret")
        s = Settings()
        assert s.effective_supabase_jwt_secret == "jwt-secret"

    def test_effective_jwt_algorithm_returns_empty_when_unset(self, monkeypatch):
        monkeypatch.delenv("JWT_ALGORITHM", raising=False)
        s = get_settings()
        assert s.effective_jwt_algorithm == ""

    def test_effective_jwt_algorithm_normalizes_case_and_whitespace(self, monkeypatch):
        s = _fresh(monkeypatch, JWT_ALGORITHM="  rs256  ")
        assert s.effective_jwt_algorithm == "RS256"


# ---------------------------------------------------------------------------
# IronClaw Auth Edge Function
# ---------------------------------------------------------------------------


class TestIronClawAuthEdgeFnSettings:
    def test_ironclaw_auth_edge_fn_path_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("IRONCLAW_AUTH_EDGE_FN_PATH", raising=False)
        s = get_settings()
        assert s.ironclaw_auth_edge_fn_path == ""
        assert isinstance(s.ironclaw_auth_edge_fn_path, str)

    def test_ironclaw_auth_edge_fn_path_override(self, monkeypatch):
        s = _fresh(monkeypatch, IRONCLAW_AUTH_EDGE_FN_PATH="/functions/v1/ironclaw-auth")
        assert s.ironclaw_auth_edge_fn_path == "/functions/v1/ironclaw-auth"
        assert isinstance(s.ironclaw_auth_edge_fn_path, str)

    def test_ironclaw_auth_edge_fn_path_override_empty_string(self, monkeypatch):
        s = _fresh(monkeypatch, IRONCLAW_AUTH_EDGE_FN_PATH="")
        assert s.ironclaw_auth_edge_fn_path == ""
        assert isinstance(s.ironclaw_auth_edge_fn_path, str)

    def test_ironclaw_auth_edge_fn_timeout_seconds_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("IRONCLAW_AUTH_EDGE_FN_TIMEOUT_SECONDS", raising=False)
        s = get_settings()
        assert s.ironclaw_auth_edge_fn_timeout_seconds == 10.0
        assert isinstance(s.ironclaw_auth_edge_fn_timeout_seconds, float)

    def test_ironclaw_auth_edge_fn_timeout_seconds_override(self, monkeypatch):
        s = _fresh(monkeypatch, IRONCLAW_AUTH_EDGE_FN_TIMEOUT_SECONDS="30.0")
        assert s.ironclaw_auth_edge_fn_timeout_seconds == 30.0
        assert isinstance(s.ironclaw_auth_edge_fn_timeout_seconds, float)

    def test_ironclaw_auth_edge_fn_timeout_seconds_integer_string_coerces_to_float(
        self,
        monkeypatch,
    ):
        s = _fresh(monkeypatch, IRONCLAW_AUTH_EDGE_FN_TIMEOUT_SECONDS="5")
        assert s.ironclaw_auth_edge_fn_timeout_seconds == 5.0
        assert isinstance(s.ironclaw_auth_edge_fn_timeout_seconds, float)

    def test_ironclaw_auth_edge_fn_timeout_seconds_fractional_override(self, monkeypatch):
        s = _fresh(monkeypatch, IRONCLAW_AUTH_EDGE_FN_TIMEOUT_SECONDS="2.75")
        assert s.ironclaw_auth_edge_fn_timeout_seconds == pytest.approx(2.75)
        assert isinstance(s.ironclaw_auth_edge_fn_timeout_seconds, float)

    def test_edge_fn_fields_independent(self, monkeypatch):
        s = _fresh(
            monkeypatch,
            IRONCLAW_AUTH_EDGE_FN_PATH="/functions/v1/auth",
            IRONCLAW_AUTH_EDGE_FN_TIMEOUT_SECONDS="15.5",
        )
        assert s.ironclaw_auth_edge_fn_path == "/functions/v1/auth"
        assert s.ironclaw_auth_edge_fn_timeout_seconds == pytest.approx(15.5)
        assert isinstance(s.ironclaw_auth_edge_fn_path, str)
        assert isinstance(s.ironclaw_auth_edge_fn_timeout_seconds, float)


# ---------------------------------------------------------------------------
# Supabase defaults
# ---------------------------------------------------------------------------


class TestSupabaseDefaults:
    def test_supabase_url_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("SUPABASE_URL", raising=False)
        s = get_settings()
        assert s.supabase_url == ""
        assert isinstance(s.supabase_url, str)

    def test_supabase_key_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("SUPABASE_KEY", raising=False)
        s = get_settings()
        assert s.supabase_key == ""
        assert isinstance(s.supabase_key, str)

    def test_supabase_anon_key_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("SUPABASE_ANON_KEY", raising=False)
        s = get_settings()
        assert s.supabase_anon_key == ""
        assert isinstance(s.supabase_anon_key, str)

    def test_supabase_service_role_key_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("SUPABASE_SERVICE_ROLE_KEY", raising=False)
        s = get_settings()
        assert s.supabase_service_role_key == ""
        assert isinstance(s.supabase_service_role_key, str)

    def test_persistence_mode_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("IRONCLAW_PERSISTENCE_MODE", raising=False)
        s = get_settings()
        assert s.persistence_mode == "memory"
        assert isinstance(s.persistence_mode, str)

    def test_supabase_url_override(self, monkeypatch):
        s = _fresh(monkeypatch, SUPABASE_URL="https://xyz.supabase.co")
        assert s.supabase_url == "https://xyz.supabase.co"

    def test_persistence_mode_override(self, monkeypatch):
        s = _fresh(monkeypatch, IRONCLAW_PERSISTENCE_MODE="supabase")
        assert s.persistence_mode == "supabase"

    def test_effective_supabase_url_returns_trimmed_value(self):
        s = Settings(SUPABASE_URL="  https://xyz.supabase.co  ")
        assert s.effective_supabase_url == "https://xyz.supabase.co"

    def test_effective_supabase_anon_key_returns_trimmed_value(self):
        s = Settings(SUPABASE_ANON_KEY="  anon-key  ")
        assert s.effective_supabase_anon_key == "anon-key"

    def test_effective_supabase_service_role_key_returns_trimmed_value(self):
        s = Settings(SUPABASE_SERVICE_ROLE_KEY="  service-role-key  ")
        assert s.effective_supabase_service_role_key == "service-role-key"


# ---------------------------------------------------------------------------
# Groq / AI defaults
# ---------------------------------------------------------------------------


class TestGroqDefaults:
    def test_groq_enabled_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("GROQ_ENABLED", raising=False)
        s = get_settings()
        assert s.groq_enabled is False
        assert isinstance(s.groq_enabled, bool)

    def test_groq_api_key_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        s = get_settings()
        assert s.groq_api_key == ""
        assert isinstance(s.groq_api_key, str)

    def test_groq_model_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("GROQ_MODEL", raising=False)
        s = get_settings()
        assert s.groq_model == "llama3-8b-8192"
        assert isinstance(s.groq_model, str)

    def test_groq_timeout_seconds_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("GROQ_TIMEOUT_SECONDS", raising=False)
        s = get_settings()
        assert s.groq_timeout_seconds == 60.0
        assert isinstance(s.groq_timeout_seconds, float)

    def test_groq_enabled_override_true(self, monkeypatch):
        s = _fresh(monkeypatch, GROQ_ENABLED="true")
        assert s.groq_enabled is True
        assert isinstance(s.groq_enabled, bool)

    def test_groq_timeout_seconds_override(self, monkeypatch):
        s = _fresh(monkeypatch, GROQ_TIMEOUT_SECONDS="120.0")
        assert s.groq_timeout_seconds == 120.0
        assert isinstance(s.groq_timeout_seconds, float)

    def test_groq_model_override(self, monkeypatch):
        s = _fresh(monkeypatch, GROQ_MODEL="llama3-70b-8192")
        assert s.groq_model == "llama3-70b-8192"


# ---------------------------------------------------------------------------
# OpenAI defaults
# ---------------------------------------------------------------------------


class TestOpenAIDefaults:
    def test_openai_api_key_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        s = get_settings()
        assert s.openai_api_key == ""
        assert isinstance(s.openai_api_key, str)

    def test_openai_api_key_override(self, monkeypatch):
        s = _fresh(monkeypatch, OPENAI_API_KEY="sk-openai-abc")
        assert s.openai_api_key == "sk-openai-abc"


# ---------------------------------------------------------------------------
# Policy / verdict defaults
# ---------------------------------------------------------------------------


class TestPolicyVerdictDefaults:
    def test_default_scan_verdict_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("DEFAULT_SCAN_VERDICT", raising=False)
        s = get_settings()
        assert s.default_scan_verdict == "allow"
        assert isinstance(s.default_scan_verdict, str)

    def test_default_review_status_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("DEFAULT_REVIEW_STATUS", raising=False)
        s = get_settings()
        assert s.default_review_status == "not_required"
        assert isinstance(s.default_review_status, str)

    def test_default_scan_verdict_override(self, monkeypatch):
        s = _fresh(monkeypatch, DEFAULT_SCAN_VERDICT="block")
        assert s.default_scan_verdict == "block"

    def test_default_review_status_override(self, monkeypatch):
        s = _fresh(monkeypatch, DEFAULT_REVIEW_STATUS="pending")
        assert s.default_review_status == "pending"


# ---------------------------------------------------------------------------
# Risk threshold defaults
# ---------------------------------------------------------------------------


class TestRiskThresholdDefaults:
    def test_risk_threshold_allow_max_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("RISK_THRESHOLD_ALLOW_MAX", raising=False)
        s = get_settings()
        assert s.risk_threshold_allow_max == 29
        assert isinstance(s.risk_threshold_allow_max, int)

    def test_risk_threshold_quarantine_min_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("RISK_THRESHOLD_QUARANTINE_MIN", raising=False)
        s = get_settings()
        assert s.risk_threshold_quarantine_min == 30
        assert isinstance(s.risk_threshold_quarantine_min, int)

    def test_risk_threshold_block_min_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("RISK_THRESHOLD_BLOCK_MIN", raising=False)
        s = get_settings()
        assert s.risk_threshold_block_min == 70
        assert isinstance(s.risk_threshold_block_min, int)

    def test_risk_threshold_allow_max_override(self, monkeypatch):
        s = _fresh(monkeypatch, RISK_THRESHOLD_ALLOW_MAX="39")
        assert s.risk_threshold_allow_max == 39
        assert isinstance(s.risk_threshold_allow_max, int)

    def test_risk_threshold_quarantine_min_override(self, monkeypatch):
        s = _fresh(monkeypatch, RISK_THRESHOLD_QUARANTINE_MIN="40")
        assert s.risk_threshold_quarantine_min == 40
        assert isinstance(s.risk_threshold_quarantine_min, int)

    def test_risk_threshold_block_min_override(self, monkeypatch):
        s = _fresh(monkeypatch, RISK_THRESHOLD_BLOCK_MIN="80")
        assert s.risk_threshold_block_min == 80
        assert isinstance(s.risk_threshold_block_min, int)


# ---------------------------------------------------------------------------
# Input size limits defaults
# ---------------------------------------------------------------------------


class TestInputSizeLimitsDefaults:
    def test_max_text_chars_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("MAX_TEXT_CHARS", raising=False)
        s = get_settings()
        assert s.max_text_chars == 100_000
        assert isinstance(s.max_text_chars, int)

    def test_max_url_length_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("MAX_URL_LENGTH", raising=False)
        s = get_settings()
        assert s.max_url_length == 2048
        assert isinstance(s.max_url_length, int)

    def test_max_archive_name_length_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("MAX_ARCHIVE_NAME_LENGTH", raising=False)
        s = get_settings()
        assert s.max_archive_name_length == 512
        assert isinstance(s.max_archive_name_length, int)

    def test_max_repo_url_length_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("MAX_REPO_URL_LENGTH", raising=False)
        s = get_settings()
        assert s.max_repo_url_length == 2048
        assert isinstance(s.max_repo_url_length, int)

    def test_max_text_chars_override(self, monkeypatch):
        s = _fresh(monkeypatch, MAX_TEXT_CHARS="200000")
        assert s.max_text_chars == 200_000
        assert isinstance(s.max_text_chars, int)


# ---------------------------------------------------------------------------
# Filesystem path defaults
# ---------------------------------------------------------------------------


class TestFilesystemPathDefaults:
    def test_data_dir_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("DATA_DIR", raising=False)
        s = get_settings()
        assert s.data_dir == "samples"
        assert isinstance(s.data_dir, str)

    def test_backup_dir_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("BACKUP_DIR", raising=False)
        s = get_settings()
        assert s.backup_dir == "./data/backups"
        assert isinstance(s.backup_dir, str)

    def test_reports_dir_default_is_none(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("REPORTS_DIR", raising=False)
        s = get_settings()
        assert s.reports_dir is None

    def test_uploads_dir_default_is_none(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("UPLOADS_DIR", raising=False)
        s = get_settings()
        assert s.uploads_dir is None

    def test_quarantine_dir_default_is_none(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("QUARANTINE_DIR", raising=False)
        s = get_settings()
        assert s.quarantine_dir is None

    def test_reports_dir_override(self, monkeypatch):
        s = _fresh(monkeypatch, REPORTS_DIR="/var/ironclaw/reports")
        assert s.reports_dir == "/var/ironclaw/reports"
        assert isinstance(s.reports_dir, str)

    def test_uploads_dir_override(self, monkeypatch):
        s = _fresh(monkeypatch, UPLOADS_DIR="/var/ironclaw/uploads")
        assert s.uploads_dir == "/var/ironclaw/uploads"
        assert isinstance(s.uploads_dir, str)

    def test_quarantine_dir_override(self, monkeypatch):
        s = _fresh(monkeypatch, QUARANTINE_DIR="/var/ironclaw/quarantine")
        assert s.quarantine_dir == "/var/ironclaw/quarantine"
        assert isinstance(s.quarantine_dir, str)

    def test_data_dir_override(self, monkeypatch):
        s = _fresh(monkeypatch, DATA_DIR="/opt/ironclaw/data")
        assert s.data_dir == "/opt/ironclaw/data"


# ---------------------------------------------------------------------------
# CORS defaults
# ---------------------------------------------------------------------------


class TestCORSDefaults:
    def test_allowed_origins_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("ALLOWED_ORIGINS", raising=False)
        s = get_settings()
        assert s.allowed_origins == "http://localhost"
        assert isinstance(s.allowed_origins, str)

    def test_allowed_origins_override(self, monkeypatch):
        s = _fresh(
            monkeypatch,
            ALLOWED_ORIGINS="https://app.ironclaw.io,https://admin.ironclaw.io",
        )
        assert s.allowed_origins == "https://app.ironclaw.io,https://admin.ironclaw.io"


# ---------------------------------------------------------------------------
# Optional integrations
# ---------------------------------------------------------------------------


class TestOptionalIntegrationDefaults:
    def test_redis_url_default_is_none(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("REDIS_URL", raising=False)
        s = get_settings()
        assert s.redis_url is None

    def test_sentry_dsn_default_is_none(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("SENTRY_DSN", raising=False)
        s = get_settings()
        assert s.sentry_dsn is None

    def test_redis_url_override(self, monkeypatch):
        s = _fresh(monkeypatch, REDIS_URL="redis://localhost:6379/0")
        assert s.redis_url == "redis://localhost:6379/0"
        assert isinstance(s.redis_url, str)

    def test_sentry_dsn_override(self, monkeypatch):
        s = _fresh(monkeypatch, SENTRY_DSN="https://abc123@o000.ingest.sentry.io/000")
        assert s.sentry_dsn == "https://abc123@o000.ingest.sentry.io/000"
        assert isinstance(s.sentry_dsn, str)


# ---------------------------------------------------------------------------
# Engine defaults
# ---------------------------------------------------------------------------


class TestEngineDefaults:
    def test_engine_base_url_default(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("ENGINE_BASE_URL", raising=False)
        s = get_settings()
        assert s.engine_base_url == "http://127.0.0.1:8010"
        assert isinstance(s.engine_base_url, str)

    def test_engine_base_url_override(self, monkeypatch):
        s = _fresh(monkeypatch, ENGINE_BASE_URL="http://engine.ironclaw.internal:9000")
        assert s.engine_base_url == "http://engine.ironclaw.internal:9000"


# ---------------------------------------------------------------------------
# Effective key resolution
# ---------------------------------------------------------------------------


class TestEffectiveKeyResolution:
    def test_effective_api_key_prefers_first_non_empty_value(self):
        s = Settings(
            API_KEY="api-key",
            ADMIN_API_KEY="admin-key",
            PLATFORM_API_KEY="platform-key",
            INTERNAL_PLATFORM_API_KEY="internal-key",
            IRONCLAW_API_KEY="ironclaw-key",
        )
        assert s.effective_api_key == "ironclaw-key"
        assert s.effective_platform_api_key == "ironclaw-key"

    def test_effective_api_key_skips_blank_values(self):
        s = Settings(
            IRONCLAW_API_KEY="   ",
            INTERNAL_PLATFORM_API_KEY="",
            PLATFORM_API_KEY=" platform-key ",
            ADMIN_API_KEY="admin-key",
            API_KEY="api-key",
        )
        assert s.effective_api_key == "platform-key"

    def test_effective_api_key_returns_empty_when_all_values_blank(self):
        s = Settings(
            IRONCLAW_API_KEY="   ",
            INTERNAL_PLATFORM_API_KEY="",
            PLATFORM_API_KEY="  ",
            ADMIN_API_KEY="",
            API_KEY="",
        )
        assert s.effective_api_key == ""
        assert s.effective_platform_api_key == ""


# ---------------------------------------------------------------------------
# Effective auth configuration
# ---------------------------------------------------------------------------


class TestEffectiveAuthConfiguration:
    def test_api_key_auth_configured_false_when_no_api_key(self, monkeypatch):
        monkeypatch.delenv("IRONCLAW_API_KEY", raising=False)
        monkeypatch.delenv("INTERNAL_PLATFORM_API_KEY", raising=False)
        monkeypatch.delenv("PLATFORM_API_KEY", raising=False)
        monkeypatch.delenv("ADMIN_API_KEY", raising=False)
        monkeypatch.delenv("API_KEY", raising=False)
        s = Settings()
        assert s.api_key_auth_configured is False

    def test_api_key_auth_configured_true_when_api_key_present(self):
        s = Settings(IRONCLAW_API_KEY="ironclaw-key")
        assert s.api_key_auth_configured is True

    def test_bearer_auth_configured_false_without_supabase_url(self, monkeypatch):
        monkeypatch.setenv("JWT_SECRET", "jwt-secret")
        monkeypatch.delenv("SUPABASE_URL", raising=False)
        s = Settings()
        assert s.bearer_auth_configured is False

    def test_bearer_auth_configured_false_without_auth_inputs(self, monkeypatch):
        monkeypatch.delenv("SUPABASE_URL", raising=False)
        monkeypatch.delenv("SUPABASE_ANON_KEY", raising=False)
        monkeypatch.delenv("SUPABASE_SERVICE_ROLE_KEY", raising=False)
        monkeypatch.delenv("SUPABASE_JWT_SECRET", raising=False)
        monkeypatch.delenv("JWT_SECRET", raising=False)
        monkeypatch.delenv("IRONCLAW_SECRET_KEY", raising=False)
        monkeypatch.delenv("SECRET_KEY", raising=False)
        s = Settings(SUPABASE_URL="https://xyz.supabase.co", JWT_SECRET=JWT_SECRET_SENTINEL)
        assert s.bearer_auth_configured is False

    def test_bearer_auth_configured_true_with_supabase_url_and_anon_key(self):
        s = Settings(
            SUPABASE_URL="https://xyz.supabase.co",
            SUPABASE_ANON_KEY="anon-key",
        )
        assert s.bearer_auth_configured is True

    def test_bearer_auth_configured_true_with_supabase_url_and_service_role_key(self):
        s = Settings(
            SUPABASE_URL="https://xyz.supabase.co",
            SUPABASE_SERVICE_ROLE_KEY="service-role-key",
        )
        assert s.bearer_auth_configured is True

    def test_bearer_auth_configured_true_with_supabase_url_and_supabase_jwt_secret(
        self,
        monkeypatch,
    ):
        monkeypatch.setenv("SUPABASE_JWT_SECRET", "supabase-jwt-secret")
        monkeypatch.delenv("JWT_SECRET", raising=False)
        s = Settings(SUPABASE_URL="https://xyz.supabase.co")
        assert s.bearer_auth_configured is True

    def test_bearer_auth_configured_true_with_supabase_url_and_jwt_secret(self, monkeypatch):
        monkeypatch.setenv("JWT_SECRET", "jwt-secret")
        monkeypatch.delenv("SUPABASE_JWT_SECRET", raising=False)
        s = Settings(SUPABASE_URL="https://xyz.supabase.co")
        assert s.bearer_auth_configured is True

    def test_auth_configured_true_when_any_auth_mode_configured(self):
        s = Settings(IRONCLAW_API_KEY="ironclaw-key")
        assert s.auth_configured is True

    def test_auth_configured_false_when_no_auth_mode_configured(self, monkeypatch):
        monkeypatch.delenv("IRONCLAW_API_KEY", raising=False)
        monkeypatch.delenv("INTERNAL_PLATFORM_API_KEY", raising=False)
        monkeypatch.delenv("PLATFORM_API_KEY", raising=False)
        monkeypatch.delenv("ADMIN_API_KEY", raising=False)
        monkeypatch.delenv("API_KEY", raising=False)
        monkeypatch.delenv("SUPABASE_URL", raising=False)
        monkeypatch.delenv("SUPABASE_ANON_KEY", raising=False)
        monkeypatch.delenv("SUPABASE_SERVICE_ROLE_KEY", raising=False)
        monkeypatch.delenv("SUPABASE_JWT_SECRET", raising=False)
        monkeypatch.delenv("JWT_SECRET", raising=False)
        monkeypatch.delenv("IRONCLAW_SECRET_KEY", raising=False)
        monkeypatch.delenv("SECRET_KEY", raising=False)
        s = Settings(
            JWT_SECRET=JWT_SECRET_SENTINEL,
            IRONCLAW_SECRET_KEY=SECRET_KEY_SENTINEL,
        )
        assert s.auth_configured is False

    def test_effective_auth_required_false_when_auth_disabled(self):
        s = Settings(AUTH_REQUIRED=False, IRONCLAW_API_KEY="ironclaw-key")
        assert s.effective_auth_required is False

    def test_effective_auth_required_false_when_required_but_unconfigured(self, monkeypatch):
        monkeypatch.delenv("IRONCLAW_API_KEY", raising=False)
        monkeypatch.delenv("INTERNAL_PLATFORM_API_KEY", raising=False)
        monkeypatch.delenv("PLATFORM_API_KEY", raising=False)
        monkeypatch.delenv("ADMIN_API_KEY", raising=False)
        monkeypatch.delenv("API_KEY", raising=False)
        monkeypatch.delenv("SUPABASE_URL", raising=False)
        monkeypatch.delenv("SUPABASE_ANON_KEY", raising=False)
        monkeypatch.delenv("SUPABASE_SERVICE_ROLE_KEY", raising=False)
        monkeypatch.delenv("SUPABASE_JWT_SECRET", raising=False)
        monkeypatch.delenv("JWT_SECRET", raising=False)
        monkeypatch.delenv("IRONCLAW_SECRET_KEY", raising=False)
        monkeypatch.delenv("SECRET_KEY", raising=False)
        s = Settings(
            AUTH_REQUIRED=True,
            JWT_SECRET=JWT_SECRET_SENTINEL,
            IRONCLAW_SECRET_KEY=SECRET_KEY_SENTINEL,
        )
        assert s.effective_auth_required is False

    def test_effective_auth_required_true_when_required_and_api_key_configured(self):
        s = Settings(AUTH_REQUIRED=True, IRONCLAW_API_KEY="ironclaw-key")
        assert s.effective_auth_required is True

    def test_effective_auth_required_true_when_required_and_bearer_configured(self):
        s = Settings(
            AUTH_REQUIRED=True,
            SUPABASE_URL="https://xyz.supabase.co",
            SUPABASE_ANON_KEY="anon-key",
        )
        assert s.effective_auth_required is True


# ---------------------------------------------------------------------------
# get_settings() cache invalidation
# ---------------------------------------------------------------------------


class TestGetSettingsCache:
    def test_cache_returns_same_instance_without_clear(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("APP_NAME", raising=False)
        s1 = get_settings()
        s2 = get_settings()
        assert s1 is s2

    def test_cache_clear_produces_new_instance(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("APP_NAME", raising=False)
        s1 = get_settings()
        get_settings.cache_clear()
        monkeypatch.setenv("APP_NAME", "ReloadedClaw")
        s2 = get_settings()
        assert s1 is not s2
        assert s2.app_name == "ReloadedClaw"

    def test_without_cache_clear_env_change_is_invisible(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.delenv("APP_HOST", raising=False)
        s1 = get_settings()
        assert s1.app_host == "127.0.0.1"
        monkeypatch.setenv("APP_HOST", "10.0.0.1")
        s2 = get_settings()
        assert s2 is s1
        assert s2.app_host == "127.0.0.1"

    def test_cache_clear_respects_new_env(self, monkeypatch):
        get_settings.cache_clear()
        monkeypatch.setenv("LOG_LEVEL", "WARNING")
        s1 = get_settings()
        assert s1.log_level == "WARNING"
        get_settings.cache_clear()
        monkeypatch.setenv("LOG_LEVEL", "ERROR")
        s2 = get_settings()
        assert s2.log_level == "ERROR"
        assert s1 is not s2

    def test_cache_info_after_clear(self, monkeypatch):
        get_settings.cache_clear()
        info = get_settings.cache_info()
        assert info.currsize == 0

    def test_cache_info_after_call(self, monkeypatch):
        get_settings.cache_clear()
        get_settings()
        info = get_settings.cache_info()
        assert info.currsize == 1

    def test_get_settings_forces_debug_false_even_when_env_true(self, monkeypatch):
        s = _fresh(monkeypatch, DEBUG="true")
        assert s.debug is False
        assert isinstance(s.debug, bool)

    def test_get_settings_forces_reload_false_even_when_env_true(self, monkeypatch):
        s = _fresh(monkeypatch, RELOAD="true")
        assert s.reload is False
        assert isinstance(s.reload, bool)

    def test_get_settings_forces_both_debug_and_reload_false(self, monkeypatch):
        s = _fresh(monkeypatch, DEBUG="true", RELOAD="1")
        assert s.debug is False
        assert s.reload is False


# ---------------------------------------------------------------------------
# Settings model direct instantiation with explicit kwargs
# ---------------------------------------------------------------------------


class TestSettingsDirectInstantiation:
    def test_instantiate_with_explicit_app_name(self):
        s = Settings(APP_NAME="DirectClaw")
        assert s.app_name == "DirectClaw"

    def test_instantiate_with_explicit_port(self):
        s = Settings(APP_PORT=7777)
        assert s.app_port == 7777
        assert isinstance(s.app_port, int)

    def test_instantiate_with_explicit_debug_true(self):
        s = Settings(DEBUG=True)
        assert s.debug is True
        assert isinstance(s.debug, bool)

    def test_instantiate_with_explicit_reload_true(self):
        s = Settings(RELOAD=True)
        assert s.reload is True
        assert isinstance(s.reload, bool)

    def test_instantiate_with_explicit_edge_fn_path(self):
        s = Settings(IRONCLAW_AUTH_EDGE_FN_PATH="/functions/v1/test-auth")
        assert s.ironclaw_auth_edge_fn_path == "/functions/v1/test-auth"
        assert isinstance(s.ironclaw_auth_edge_fn_path, str)

    def test_instantiate_with_explicit_edge_fn_timeout(self):
        s = Settings(IRONCLAW_AUTH_EDGE_FN_TIMEOUT_SECONDS=25.0)
        assert s.ironclaw_auth_edge_fn_timeout_seconds == 25.0
        assert isinstance(s.ironclaw_auth_edge_fn_timeout_seconds, float)

    def test_instantiate_edge_fn_timeout_int_coerces_to_float(self):
        s = Settings(IRONCLAW_AUTH_EDGE_FN_TIMEOUT_SECONDS=7)
        assert s.ironclaw_auth_edge_fn_timeout_seconds == 7.0
        assert isinstance(s.ironclaw_auth_edge_fn_timeout_seconds, float)

    def test_instantiate_with_none_optional_fields(self):
        s = Settings(REPORTS_DIR=None, UPLOADS_DIR=None, QUARANTINE_DIR=None)
        assert s.reports_dir is None
        assert s.uploads_dir is None
        assert s.quarantine_dir is None

    def test_instantiate_with_optional_fields_set(self):
        s = Settings(
            REPORTS_DIR="/reports",
            UPLOADS_DIR="/uploads",
            QUARANTINE_DIR="/quarantine",
            REDIS_URL="redis://localhost:6379",
            SENTRY_DSN="https://dsn@sentry.io/1",
        )
        assert s.reports_dir == "/reports"
        assert s.uploads_dir == "/uploads"
        assert s.quarantine_dir == "/quarantine"
        assert s.redis_url == "redis://localhost:6379"
        assert s.sentry_dsn == "https://dsn@sentry.io/1"

    def test_instantiate_all_edge_fn_fields_together(self):
        s = Settings(
            IRONCLAW_AUTH_EDGE_FN_PATH="/functions/v1/ironclaw-auth",
            IRONCLAW_AUTH_EDGE_FN_TIMEOUT_SECONDS=45.5,
        )
        assert s.ironclaw_auth_edge_fn_path == "/functions/v1/ironclaw-auth"
        assert s.ironclaw_auth_edge_fn_timeout_seconds == pytest.approx(45.5)
        assert isinstance(s.ironclaw_auth_edge_fn_path, str)
        assert isinstance(s.ironclaw_auth_edge_fn_timeout_seconds, float)

    def test_instantiate_risk_thresholds_explicit(self):
        s = Settings(
            RISK_THRESHOLD_ALLOW_MAX=24,
            RISK_THRESHOLD_QUARANTINE_MIN=25,
            RISK_THRESHOLD_BLOCK_MIN=65,
        )
        assert s.risk_threshold_allow_max == 24
        assert s.risk_threshold_quarantine_min == 25
        assert s.risk_threshold_block_min == 65
        assert isinstance(s.risk_threshold_allow_max, int)
        assert isinstance(s.risk_threshold_quarantine_min, int)
        assert isinstance(s.risk_threshold_block_min, int)

    def test_instantiate_groq_fields_explicit(self):
        s = Settings(GROQ_ENABLED=True, GROQ_API_KEY="gsk-test", GROQ_TIMEOUT_SECONDS=90.0)
        assert s.groq_enabled is True
        assert s.groq_api_key == "gsk-test"
        assert s.groq_timeout_seconds == 90.0
        assert isinstance(s.groq_timeout_seconds, float)

    def test_instantiate_returns_settings_type(self):
        s = Settings()
        assert isinstance(s, Settings)

    def test_get_settings_returns_settings_type(self, monkeypatch):
        get_settings.cache_clear()
        s = get_settings()
        assert isinstance(s, Settings)
