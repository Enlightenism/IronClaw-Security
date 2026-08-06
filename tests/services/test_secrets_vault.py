from __future__ import annotations

import sys

import pytest

# ---------------------------------------------------------------------------
# All env keys the vault reads — stripped before every default test
# ---------------------------------------------------------------------------

_ALL_VAULT_KEYS = (
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
    "IRONCLAW_SECRET_KEY",
    "SECRET_KEY",
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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _clear_vault_modules() -> None:
    for mod in list(sys.modules.keys()):
        if "secrets_vault" in mod:
            del sys.modules[mod]


def _reload_vault() -> object:
    _clear_vault_modules()
    import app.services.secrets_vault as _sv_module

    _sv_module._vault_singleton.cache_clear()
    return _sv_module.vault


@pytest.fixture(autouse=True)
def fresh_vault(monkeypatch):
    """
    Strip ALL vault env keys from os.environ before each test so that
    default-value tests always see the true coded defaults, regardless of
    what a .env file may have pre-loaded into the process environment.
    Cache is also cleared to defeat the lru_cache singleton.
    """
    for key in _ALL_VAULT_KEYS:
        monkeypatch.delenv(key, raising=False)

    _clear_vault_modules()
    import app.services.secrets_vault as _sv_module

    _sv_module._vault_singleton.cache_clear()
    yield _sv_module.vault


# ===========================================================================
# Core identity
# ===========================================================================


class TestCoreIdentity:
    def test_app_name_default(self, fresh_vault):
        assert fresh_vault.app_name() == "IronClaw-Security"
        assert isinstance(fresh_vault.app_name(), str)

    def test_app_name_override(self, monkeypatch):
        monkeypatch.setenv("APP_NAME", "TestClaw")
        v = _reload_vault()
        assert v.app_name() == "TestClaw"

    def test_app_version_default(self, fresh_vault):
        assert fresh_vault.app_version() == "0.1.0"
        assert isinstance(fresh_vault.app_version(), str)

    def test_app_version_override(self, monkeypatch):
        monkeypatch.setenv("APP_VERSION", "9.9.9")
        v = _reload_vault()
        assert v.app_version() == "9.9.9"

    def test_app_host_default(self, fresh_vault):
        assert fresh_vault.app_host() == "127.0.0.1"
        assert isinstance(fresh_vault.app_host(), str)

    def test_app_host_override(self, monkeypatch):
        monkeypatch.setenv("APP_HOST", "0.0.0.0")
        v = _reload_vault()
        assert v.app_host() == "0.0.0.0"

    def test_app_port_default(self, fresh_vault):
        assert fresh_vault.app_port() == 8000
        assert isinstance(fresh_vault.app_port(), int)

    def test_app_port_override(self, monkeypatch):
        monkeypatch.setenv("APP_PORT", "9090")
        v = _reload_vault()
        assert v.app_port() == 9090

    def test_app_base_url_default(self, fresh_vault):
        url = fresh_vault.app_base_url()
        assert isinstance(url, str)
        assert "127.0.0.1" in url
        assert "8000" in url

    def test_app_base_url_override(self, monkeypatch):
        monkeypatch.setenv("APP_BASE_URL", "https://ironclaw.example.com")
        v = _reload_vault()
        assert v.app_base_url() == "https://ironclaw.example.com"

    def test_api_prefix_default(self, fresh_vault):
        assert fresh_vault.api_prefix() == ""
        assert isinstance(fresh_vault.api_prefix(), str)

    def test_api_prefix_override(self, monkeypatch):
        monkeypatch.setenv("API_PREFIX", "/api/v1")
        v = _reload_vault()
        assert v.api_prefix() == "/api/v1"

    def test_debug_default_false(self, fresh_vault):
        assert fresh_vault.debug() is False
        assert isinstance(fresh_vault.debug(), bool)

    @pytest.mark.parametrize("val", ["true", "1", "yes", "True", "YES"])
    def test_debug_truthy_values(self, monkeypatch, val):
        monkeypatch.setenv("DEBUG", val)
        v = _reload_vault()
        assert v.debug() is True

    def test_reload_default_false(self, fresh_vault):
        assert fresh_vault.reload() is False
        assert isinstance(fresh_vault.reload(), bool)

    def test_reload_override(self, monkeypatch):
        monkeypatch.setenv("RELOAD", "true")
        v = _reload_vault()
        assert v.reload() is True


# ===========================================================================
# Engine
# ===========================================================================


class TestEngine:
    def test_engine_base_url_default(self, fresh_vault):
        assert fresh_vault.engine_base_url() == "http://127.0.0.1:8010"
        assert isinstance(fresh_vault.engine_base_url(), str)

    def test_engine_base_url_override(self, monkeypatch):
        monkeypatch.setenv("ENGINE_BASE_URL", "http://engine.internal:8010")
        v = _reload_vault()
        assert v.engine_base_url() == "http://engine.internal:8010"


# ===========================================================================
# Environment / logging
# ===========================================================================


class TestEnvironmentLogging:
    def test_environment_default(self, fresh_vault):
        assert fresh_vault.environment() == "development"
        assert isinstance(fresh_vault.environment(), str)

    def test_environment_override(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")
        v = _reload_vault()
        assert v.environment() == "production"

    def test_log_level_default(self, fresh_vault):
        assert fresh_vault.log_level() == "INFO"
        assert isinstance(fresh_vault.log_level(), str)

    def test_log_level_is_uppercased(self, monkeypatch):
        monkeypatch.setenv("LOG_LEVEL", "debug")
        v = _reload_vault()
        assert v.log_level() == "DEBUG"

    def test_structured_logging_enabled_default(self, fresh_vault):
        assert fresh_vault.structured_logging_enabled() is True
        assert isinstance(fresh_vault.structured_logging_enabled(), bool)

    def test_structured_logging_enabled_override_false(self, monkeypatch):
        monkeypatch.setenv("STRUCTURED_LOGGING_ENABLED", "false")
        v = _reload_vault()
        assert v.structured_logging_enabled() is False


# ===========================================================================
# Authentication
# ===========================================================================


class TestAuthentication:
    def test_auth_required_default_false(self, fresh_vault):
        assert fresh_vault.auth_required() is False
        assert isinstance(fresh_vault.auth_required(), bool)

    def test_auth_required_override(self, monkeypatch):
        monkeypatch.setenv("AUTH_REQUIRED", "true")
        v = _reload_vault()
        assert v.auth_required() is True

    def test_api_key_default_empty(self, fresh_vault):
        assert fresh_vault.api_key() == ""
        assert isinstance(fresh_vault.api_key(), str)

    def test_api_key_override(self, monkeypatch):
        monkeypatch.setenv("API_KEY", "secret-key-xyz")
        v = _reload_vault()
        assert v.api_key() == "secret-key-xyz"

    def test_api_key_falls_back_to_ironclaw_api_key(self, monkeypatch):
        monkeypatch.setenv("IRONCLAW_API_KEY", "ic-secret")
        v = _reload_vault()
        assert v.api_key() == "ic-secret"

    def test_api_key_prefers_api_key_over_ironclaw_api_key(self, monkeypatch):
        monkeypatch.setenv("API_KEY", "primary-key")
        monkeypatch.setenv("IRONCLAW_API_KEY", "secondary-key")
        v = _reload_vault()
        assert v.api_key() == "primary-key"

    def test_admin_api_key_default_empty(self, fresh_vault):
        assert fresh_vault.admin_api_key() == ""

    def test_admin_api_key_override(self, monkeypatch):
        monkeypatch.setenv("ADMIN_API_KEY", "admin-secret")
        v = _reload_vault()
        assert v.admin_api_key() == "admin-secret"

    def test_platform_api_key_default_empty(self, fresh_vault):
        assert fresh_vault.platform_api_key() == ""

    def test_platform_api_key_override(self, monkeypatch):
        monkeypatch.setenv("PLATFORM_API_KEY", "platform-secret")
        v = _reload_vault()
        assert v.platform_api_key() == "platform-secret"

    def test_internal_platform_api_key_default_empty(self, fresh_vault):
        assert fresh_vault.internal_platform_api_key() == ""

    def test_internal_platform_api_key_override(self, monkeypatch):
        monkeypatch.setenv("INTERNAL_PLATFORM_API_KEY", "internal-secret")
        v = _reload_vault()
        assert v.internal_platform_api_key() == "internal-secret"

    def test_ironclaw_api_key_default_empty(self, fresh_vault):
        assert fresh_vault.ironclaw_api_key() == ""

    def test_ironclaw_api_key_override(self, monkeypatch):
        monkeypatch.setenv("IRONCLAW_API_KEY", "ic-secret")
        v = _reload_vault()
        assert v.ironclaw_api_key() == "ic-secret"


# ===========================================================================
# Auth / JWT
# ===========================================================================


class TestAuthJWT:
    def test_secret_key_default_empty(self, fresh_vault):
        assert fresh_vault.secret_key() == ""
        assert isinstance(fresh_vault.secret_key(), str)

    def test_secret_key_uses_legacy_secret_key(self, monkeypatch):
        monkeypatch.setenv("SECRET_KEY", "legacy-secret")
        v = _reload_vault()
        assert v.secret_key() == "legacy-secret"

    def test_secret_key_falls_back_to_ironclaw_secret_key(self, monkeypatch):
        monkeypatch.setenv("IRONCLAW_SECRET_KEY", "ironclaw-secret")
        v = _reload_vault()
        assert v.secret_key() == "ironclaw-secret"

    def test_secret_key_falls_back_to_app_secret_key(self, monkeypatch):
        monkeypatch.setenv("APP_SECRET_KEY", "app-secret")
        v = _reload_vault()
        assert v.secret_key() == "app-secret"

    def test_secret_key_prefers_legacy_over_ironclaw_and_app(self, monkeypatch):
        monkeypatch.setenv("SECRET_KEY", "legacy-secret")
        monkeypatch.setenv("IRONCLAW_SECRET_KEY", "ironclaw-secret")
        monkeypatch.setenv("APP_SECRET_KEY", "app-secret")
        v = _reload_vault()
        assert v.secret_key() == "legacy-secret"

    def test_secret_key_prefers_ironclaw_over_app_when_legacy_missing(self, monkeypatch):
        monkeypatch.setenv("IRONCLAW_SECRET_KEY", "ironclaw-secret")
        monkeypatch.setenv("APP_SECRET_KEY", "app-secret")
        v = _reload_vault()
        assert v.secret_key() == "ironclaw-secret"

    def test_jwt_secret_default_empty(self, fresh_vault):
        assert fresh_vault.jwt_secret() == ""
        assert isinstance(fresh_vault.jwt_secret(), str)

    def test_jwt_secret_prefers_jwt_secret(self, monkeypatch):
        monkeypatch.setenv("JWT_SECRET", "jwt-secret")
        monkeypatch.setenv("SUPABASE_JWT_SECRET", "supabase-secret")
        monkeypatch.setenv("SECRET_KEY", "legacy-secret")
        monkeypatch.setenv("IRONCLAW_SECRET_KEY", "ironclaw-secret")
        monkeypatch.setenv("APP_SECRET_KEY", "app-secret")
        v = _reload_vault()
        assert v.jwt_secret() == "jwt-secret"

    def test_jwt_secret_falls_back_to_supabase_jwt_secret(self, monkeypatch):
        monkeypatch.setenv("SUPABASE_JWT_SECRET", "supabase-secret")
        v = _reload_vault()
        assert v.jwt_secret() == "supabase-secret"

    def test_jwt_secret_falls_back_to_legacy_secret_key(self, monkeypatch):
        monkeypatch.setenv("SECRET_KEY", "legacy-secret")
        v = _reload_vault()
        assert v.jwt_secret() == "legacy-secret"

    def test_jwt_secret_falls_back_to_ironclaw_secret_key(self, monkeypatch):
        monkeypatch.setenv("IRONCLAW_SECRET_KEY", "ironclaw-secret")
        v = _reload_vault()
        assert v.jwt_secret() == "ironclaw-secret"

    def test_jwt_secret_falls_back_to_app_secret_key(self, monkeypatch):
        monkeypatch.setenv("APP_SECRET_KEY", "app-secret")
        v = _reload_vault()
        assert v.jwt_secret() == "app-secret"

    def test_supabase_jwt_secret_default_empty(self, fresh_vault):
        assert fresh_vault.supabase_jwt_secret() == ""
        assert isinstance(fresh_vault.supabase_jwt_secret(), str)

    def test_supabase_jwt_secret_prefers_supabase_jwt_secret(self, monkeypatch):
        monkeypatch.setenv("SUPABASE_JWT_SECRET", "supabase-secret")
        monkeypatch.setenv("JWT_SECRET", "jwt-secret")
        v = _reload_vault()
        assert v.supabase_jwt_secret() == "supabase-secret"

    def test_supabase_jwt_secret_falls_back_to_jwt_secret(self, monkeypatch):
        monkeypatch.setenv("JWT_SECRET", "jwt-secret")
        v = _reload_vault()
        assert v.supabase_jwt_secret() == "jwt-secret"

    def test_jwt_algorithm_default(self, fresh_vault):
        assert fresh_vault.jwt_algorithm() == "HS256"
        assert isinstance(fresh_vault.jwt_algorithm(), str)

    def test_jwt_algorithm_override(self, monkeypatch):
        monkeypatch.setenv("JWT_ALGORITHM", "RS256")
        v = _reload_vault()
        assert v.jwt_algorithm() == "RS256"

    def test_access_token_expire_minutes_default(self, fresh_vault):
        assert fresh_vault.access_token_expire_minutes() == 30
        assert isinstance(fresh_vault.access_token_expire_minutes(), int)

    def test_access_token_expire_minutes_override(self, monkeypatch):
        monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60")
        v = _reload_vault()
        assert v.access_token_expire_minutes() == 60


# ===========================================================================
# IronClaw Auth Edge Function
# ===========================================================================


class TestIronClawAuthEdgeFn:
    def test_edge_fn_path_default_is_empty_string(self, fresh_vault):
        result = fresh_vault.ironclaw_auth_edge_fn_path()
        assert result == ""
        assert isinstance(result, str)

    def test_edge_fn_path_default_when_env_absent(self, monkeypatch):
        monkeypatch.delenv("IRONCLAW_AUTH_EDGE_FN_PATH", raising=False)
        v = _reload_vault()
        assert v.ironclaw_auth_edge_fn_path() == ""

    def test_edge_fn_path_override_relative(self, monkeypatch):
        monkeypatch.setenv("IRONCLAW_AUTH_EDGE_FN_PATH", "/auth/edge")
        v = _reload_vault()
        assert v.ironclaw_auth_edge_fn_path() == "/auth/edge"
        assert isinstance(v.ironclaw_auth_edge_fn_path(), str)

    def test_edge_fn_path_override_full_url(self, monkeypatch):
        monkeypatch.setenv(
            "IRONCLAW_AUTH_EDGE_FN_PATH",
            "https://edge.supabase.co/functions/v1/ironclaw-auth",
        )
        v = _reload_vault()
        assert v.ironclaw_auth_edge_fn_path() == "https://edge.supabase.co/functions/v1/ironclaw-auth"

    def test_edge_fn_timeout_default_is_10_float(self, fresh_vault):
        result = fresh_vault.ironclaw_auth_edge_fn_timeout_seconds()
        assert result == 10.0
        assert isinstance(result, float)

    def test_edge_fn_timeout_default_when_env_absent(self, monkeypatch):
        monkeypatch.delenv("IRONCLAW_AUTH_EDGE_FN_TIMEOUT_SECONDS", raising=False)
        v = _reload_vault()
        assert v.ironclaw_auth_edge_fn_timeout_seconds() == 10.0

    def test_edge_fn_timeout_override_integer_string_coerces_to_float(self, monkeypatch):
        monkeypatch.setenv("IRONCLAW_AUTH_EDGE_FN_TIMEOUT_SECONDS", "30")
        v = _reload_vault()
        result = v.ironclaw_auth_edge_fn_timeout_seconds()
        assert result == 30.0
        assert isinstance(result, float)

    def test_edge_fn_timeout_override_float_string(self, monkeypatch):
        monkeypatch.setenv("IRONCLAW_AUTH_EDGE_FN_TIMEOUT_SECONDS", "5.5")
        v = _reload_vault()
        result = v.ironclaw_auth_edge_fn_timeout_seconds()
        assert result == 5.5
        assert isinstance(result, float)

    def test_edge_fn_timeout_override_zero(self, monkeypatch):
        monkeypatch.setenv("IRONCLAW_AUTH_EDGE_FN_TIMEOUT_SECONDS", "0.0")
        v = _reload_vault()
        assert v.ironclaw_auth_edge_fn_timeout_seconds() == 0.0

    def test_edge_fn_timeout_invalid_raises_value_error(self, monkeypatch):
        monkeypatch.setenv("IRONCLAW_AUTH_EDGE_FN_TIMEOUT_SECONDS", "not-a-float")
        v = _reload_vault()
        with pytest.raises(ValueError):
            v.ironclaw_auth_edge_fn_timeout_seconds()


# ===========================================================================
# Supabase
# ===========================================================================


class TestSupabase:
    def test_supabase_url_default_empty(self, fresh_vault):
        assert fresh_vault.supabase_url() == ""
        assert isinstance(fresh_vault.supabase_url(), str)

    def test_supabase_url_override(self, monkeypatch):
        monkeypatch.setenv("SUPABASE_URL", "https://xyz.supabase.co")
        v = _reload_vault()
        assert v.supabase_url() == "https://xyz.supabase.co"

    def test_supabase_key_default_empty(self, fresh_vault):
        assert fresh_vault.supabase_key() == ""

    def test_supabase_key_override(self, monkeypatch):
        monkeypatch.setenv("SUPABASE_KEY", "supabase-key-abc")
        v = _reload_vault()
        assert v.supabase_key() == "supabase-key-abc"

    def test_supabase_key_falls_back_to_anon_key(self, monkeypatch):
        monkeypatch.setenv("SUPABASE_ANON_KEY", "anon-key")
        v = _reload_vault()
        assert v.supabase_key() == "anon-key"

    def test_supabase_key_prefers_supabase_key_over_anon_key(self, monkeypatch):
        monkeypatch.setenv("SUPABASE_KEY", "supabase-key-abc")
        monkeypatch.setenv("SUPABASE_ANON_KEY", "anon-key")
        v = _reload_vault()
        assert v.supabase_key() == "supabase-key-abc"

    def test_supabase_anon_key_default_empty(self, fresh_vault):
        assert fresh_vault.supabase_anon_key() == ""

    def test_supabase_anon_key_override(self, monkeypatch):
        monkeypatch.setenv("SUPABASE_ANON_KEY", "anon-key")
        v = _reload_vault()
        assert v.supabase_anon_key() == "anon-key"

    def test_supabase_anon_key_falls_back_to_supabase_key(self, monkeypatch):
        monkeypatch.setenv("SUPABASE_KEY", "supabase-key-abc")
        v = _reload_vault()
        assert v.supabase_anon_key() == "supabase-key-abc"

    def test_supabase_anon_key_prefers_anon_key_over_supabase_key(self, monkeypatch):
        monkeypatch.setenv("SUPABASE_ANON_KEY", "anon-key")
        monkeypatch.setenv("SUPABASE_KEY", "supabase-key-abc")
        v = _reload_vault()
        assert v.supabase_anon_key() == "anon-key"

    def test_supabase_service_role_key_default_none(self, fresh_vault):
        result = fresh_vault.supabase_service_role_key()
        assert result is None

    def test_supabase_service_role_key_override(self, monkeypatch):
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "service-role-key")
        v = _reload_vault()
        result = v.supabase_service_role_key()
        assert result == "service-role-key"
        assert isinstance(result, str)


# ===========================================================================
# Stripe
# ===========================================================================


class TestStripe:
    def test_stripe_secret_key_default_empty(self, fresh_vault):
        assert fresh_vault.stripe_secret_key() == ""
        assert isinstance(fresh_vault.stripe_secret_key(), str)

    def test_stripe_secret_key_override(self, monkeypatch):
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_123")
        v = _reload_vault()
        assert v.stripe_secret_key() == "sk_test_123"

    def test_stripe_publishable_key_default_empty(self, fresh_vault):
        assert fresh_vault.stripe_publishable_key() == ""
        assert isinstance(fresh_vault.stripe_publishable_key(), str)

    def test_stripe_publishable_key_override(self, monkeypatch):
        monkeypatch.setenv("STRIPE_PUBLISHABLE_KEY", "pk_test_123")
        v = _reload_vault()
        assert v.stripe_publishable_key() == "pk_test_123"

    def test_stripe_webhook_secret_default_empty(self, fresh_vault):
        assert fresh_vault.stripe_webhook_secret() == ""
        assert isinstance(fresh_vault.stripe_webhook_secret(), str)

    def test_stripe_webhook_secret_override(self, monkeypatch):
        monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_123")
        v = _reload_vault()
        assert v.stripe_webhook_secret() == "whsec_123"


# ===========================================================================
# Groq / AI
# ===========================================================================


class TestGroq:
    def test_groq_enabled_default_false(self, fresh_vault):
        assert fresh_vault.groq_enabled() is False
        assert isinstance(fresh_vault.groq_enabled(), bool)

    def test_groq_enabled_override(self, monkeypatch):
        monkeypatch.setenv("GROQ_ENABLED", "true")
        v = _reload_vault()
        assert v.groq_enabled() is True

    def test_groq_api_key_default_empty(self, fresh_vault):
        assert fresh_vault.groq_api_key() == ""

    def test_groq_api_key_override(self, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "groq-key-xyz")
        v = _reload_vault()
        assert v.groq_api_key() == "groq-key-xyz"

    def test_groq_model_default(self, fresh_vault):
        assert fresh_vault.groq_model() == "llama3-8b-8192"
        assert isinstance(fresh_vault.groq_model(), str)

    def test_groq_model_override(self, monkeypatch):
        monkeypatch.setenv("GROQ_MODEL", "mixtral-8x7b-32768")
        v = _reload_vault()
        assert v.groq_model() == "mixtral-8x7b-32768"

    def test_groq_timeout_default(self, fresh_vault):
        assert fresh_vault.groq_timeout_seconds() == 60.0
        assert isinstance(fresh_vault.groq_timeout_seconds(), float)

    def test_groq_timeout_override(self, monkeypatch):
        monkeypatch.setenv("GROQ_TIMEOUT_SECONDS", "30.0")
        v = _reload_vault()
        assert v.groq_timeout_seconds() == 30.0


# ===========================================================================
# OpenAI
# ===========================================================================


class TestOpenAI:
    def test_openai_api_key_default_empty(self, fresh_vault):
        assert fresh_vault.openai_api_key() == ""
        assert isinstance(fresh_vault.openai_api_key(), str)

    def test_openai_api_key_override(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-test")
        v = _reload_vault()
        assert v.openai_api_key() == "sk-openai-test"


# ===========================================================================
# Policy / verdict defaults
# ===========================================================================


class TestPolicyDefaults:
    def test_default_scan_verdict_default(self, fresh_vault):
        assert fresh_vault.default_scan_verdict() == "allow"
        assert isinstance(fresh_vault.default_scan_verdict(), str)

    def test_default_scan_verdict_override(self, monkeypatch):
        monkeypatch.setenv("DEFAULT_SCAN_VERDICT", "block")
        v = _reload_vault()
        assert v.default_scan_verdict() == "block"

    def test_default_review_status_default(self, fresh_vault):
        assert fresh_vault.default_review_status() == "not_required"
        assert isinstance(fresh_vault.default_review_status(), str)

    def test_default_review_status_override(self, monkeypatch):
        monkeypatch.setenv("DEFAULT_REVIEW_STATUS", "pending")
        v = _reload_vault()
        assert v.default_review_status() == "pending"


# ===========================================================================
# Risk thresholds
# ===========================================================================


class TestRiskThresholds:
    def test_risk_threshold_allow_max_default(self, fresh_vault):
        assert fresh_vault.risk_threshold_allow_max() == 29
        assert isinstance(fresh_vault.risk_threshold_allow_max(), int)

    def test_risk_threshold_allow_max_override(self, monkeypatch):
        monkeypatch.setenv("RISK_THRESHOLD_ALLOW_MAX", "39")
        v = _reload_vault()
        assert v.risk_threshold_allow_max() == 39

    def test_risk_threshold_quarantine_min_default(self, fresh_vault):
        assert fresh_vault.risk_threshold_quarantine_min() == 30
        assert isinstance(fresh_vault.risk_threshold_quarantine_min(), int)

    def test_risk_threshold_quarantine_min_override(self, monkeypatch):
        monkeypatch.setenv("RISK_THRESHOLD_QUARANTINE_MIN", "40")
        v = _reload_vault()
        assert v.risk_threshold_quarantine_min() == 40

    def test_risk_threshold_block_min_default(self, fresh_vault):
        assert fresh_vault.risk_threshold_block_min() == 70
        assert isinstance(fresh_vault.risk_threshold_block_min(), int)

    def test_risk_threshold_block_min_override(self, monkeypatch):
        monkeypatch.setenv("RISK_THRESHOLD_BLOCK_MIN", "80")
        v = _reload_vault()
        assert v.risk_threshold_block_min() == 80


# ===========================================================================
# Input size limits
# ===========================================================================


class TestInputLimits:
    def test_max_text_chars_default(self, fresh_vault):
        assert fresh_vault.max_text_chars() == 100000
        assert isinstance(fresh_vault.max_text_chars(), int)

    def test_max_text_chars_override(self, monkeypatch):
        monkeypatch.setenv("MAX_TEXT_CHARS", "50000")
        v = _reload_vault()
        assert v.max_text_chars() == 50000

    def test_max_url_length_default(self, fresh_vault):
        assert fresh_vault.max_url_length() == 2048
        assert isinstance(fresh_vault.max_url_length(), int)

    def test_max_url_length_override(self, monkeypatch):
        monkeypatch.setenv("MAX_URL_LENGTH", "4096")
        v = _reload_vault()
        assert v.max_url_length() == 4096

    def test_max_archive_name_length_default(self, fresh_vault):
        assert fresh_vault.max_archive_name_length() == 512
        assert isinstance(fresh_vault.max_archive_name_length(), int)

    def test_max_archive_name_length_override(self, monkeypatch):
        monkeypatch.setenv("MAX_ARCHIVE_NAME_LENGTH", "256")
        v = _reload_vault()
        assert v.max_archive_name_length() == 256

    def test_max_repo_url_length_default(self, fresh_vault):
        assert fresh_vault.max_repo_url_length() == 2048
        assert isinstance(fresh_vault.max_repo_url_length(), int)

    def test_max_repo_url_length_override(self, monkeypatch):
        monkeypatch.setenv("MAX_REPO_URL_LENGTH", "1024")
        v = _reload_vault()
        assert v.max_repo_url_length() == 1024


# ===========================================================================
# Filesystem paths
# ===========================================================================


class TestFilesystemPaths:
    def test_data_dir_default(self, fresh_vault):
        assert fresh_vault.data_dir() == "samples"
        assert isinstance(fresh_vault.data_dir(), str)

    def test_data_dir_override_via_ironclaw_data_dir(self, monkeypatch):
        monkeypatch.setenv("IRONCLAW_DATA_DIR", "/var/ironclaw/data")
        v = _reload_vault()
        assert v.data_dir() == "/var/ironclaw/data"

    def test_data_dir_override_via_ironclaw_base_dir(self, monkeypatch):
        monkeypatch.setenv("IRONCLAW_BASE_DIR", "/var/ironclaw/base")
        v = _reload_vault()
        assert v.data_dir() == "/var/ironclaw/base"

    def test_data_dir_override_via_data_dir(self, monkeypatch):
        monkeypatch.setenv("DATA_DIR", "/custom/data")
        v = _reload_vault()
        assert v.data_dir() == "/custom/data"

    def test_data_dir_prefers_ironclaw_data_dir_over_base_dir_and_data_dir(self, monkeypatch):
        monkeypatch.setenv("IRONCLAW_DATA_DIR", "/var/ironclaw/data")
        monkeypatch.setenv("IRONCLAW_BASE_DIR", "/var/ironclaw/base")
        monkeypatch.setenv("DATA_DIR", "/custom/data")
        v = _reload_vault()
        assert v.data_dir() == "/var/ironclaw/data"

    def test_data_dir_prefers_ironclaw_base_dir_over_data_dir_when_data_dir_missing(self, monkeypatch):
        monkeypatch.setenv("IRONCLAW_BASE_DIR", "/var/ironclaw/base")
        monkeypatch.setenv("DATA_DIR", "/custom/data")
        v = _reload_vault()
        assert v.data_dir() == "/var/ironclaw/base"

    def test_reports_dir_default_none(self, fresh_vault):
        assert fresh_vault.reports_dir() is None

    def test_reports_dir_override_via_reports_dir(self, monkeypatch):
        monkeypatch.setenv("REPORTS_DIR", "/var/reports")
        v = _reload_vault()
        assert v.reports_dir() == "/var/reports"

    def test_reports_dir_override_via_ironclaw_reports_dir(self, monkeypatch):
        monkeypatch.setenv("IRONCLAW_REPORTS_DIR", "/var/ironclaw/reports")
        v = _reload_vault()
        assert v.reports_dir() == "/var/ironclaw/reports"

    def test_reports_dir_prefers_reports_dir_over_ironclaw_reports_dir(self, monkeypatch):
        monkeypatch.setenv("REPORTS_DIR", "/var/reports")
        monkeypatch.setenv("IRONCLAW_REPORTS_DIR", "/var/ironclaw/reports")
        v = _reload_vault()
        assert v.reports_dir() == "/var/reports"

    def test_uploads_dir_default_none(self, fresh_vault):
        assert fresh_vault.uploads_dir() is None

    def test_uploads_dir_override_via_uploads_dir(self, monkeypatch):
        monkeypatch.setenv("UPLOADS_DIR", "/var/uploads")
        v = _reload_vault()
        assert v.uploads_dir() == "/var/uploads"

    def test_uploads_dir_override_via_ironclaw_uploads_dir(self, monkeypatch):
        monkeypatch.setenv("IRONCLAW_UPLOADS_DIR", "/var/ironclaw/uploads")
        v = _reload_vault()
        assert v.uploads_dir() == "/var/ironclaw/uploads"

    def test_uploads_dir_prefers_uploads_dir_over_ironclaw_uploads_dir(self, monkeypatch):
        monkeypatch.setenv("UPLOADS_DIR", "/var/uploads")
        monkeypatch.setenv("IRONCLAW_UPLOADS_DIR", "/var/ironclaw/uploads")
        v = _reload_vault()
        assert v.uploads_dir() == "/var/uploads"

    def test_quarantine_dir_default_none(self, fresh_vault):
        assert fresh_vault.quarantine_dir() is None

    def test_quarantine_dir_override_via_quarantine_dir(self, monkeypatch):
        monkeypatch.setenv("QUARANTINE_DIR", "/var/quarantine")
        v = _reload_vault()
        assert v.quarantine_dir() == "/var/quarantine"

    def test_quarantine_dir_override_via_ironclaw_quarantine_dir(self, monkeypatch):
        monkeypatch.setenv("IRONCLAW_QUARANTINE_DIR", "/var/ironclaw/quarantine")
        v = _reload_vault()
        assert v.quarantine_dir() == "/var/ironclaw/quarantine"

    def test_quarantine_dir_prefers_quarantine_dir_over_ironclaw_quarantine_dir(self, monkeypatch):
        monkeypatch.setenv("QUARANTINE_DIR", "/var/quarantine")
        monkeypatch.setenv("IRONCLAW_QUARANTINE_DIR", "/var/ironclaw/quarantine")
        v = _reload_vault()
        assert v.quarantine_dir() == "/var/quarantine"

    def test_backup_dir_default(self, fresh_vault):
        assert fresh_vault.backup_dir() == "./data/backups"
        assert isinstance(fresh_vault.backup_dir(), str)

    def test_backup_dir_override(self, monkeypatch):
        monkeypatch.setenv("BACKUP_DIR", "/mnt/backups")
        v = _reload_vault()
        assert v.backup_dir() == "/mnt/backups"


# ===========================================================================
# Optional integrations
# ===========================================================================


class TestOptionalIntegrations:
    def test_redis_url_default_none(self, fresh_vault):
        assert fresh_vault.redis_url() is None

    def test_redis_url_override(self, monkeypatch):
        monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
        v = _reload_vault()
        assert v.redis_url() == "redis://localhost:6379/0"

    def test_sentry_dsn_default_none(self, fresh_vault):
        assert fresh_vault.sentry_dsn() is None

    def test_sentry_dsn_override(self, monkeypatch):
        monkeypatch.setenv("SENTRY_DSN", "https://key@sentry.io/1234")
        v = _reload_vault()
        assert v.sentry_dsn() == "https://key@sentry.io/1234"


# ===========================================================================
# Generic escape hatch
# ===========================================================================


class TestGenericGet:
    def test_get_unknown_key_default_none(self, fresh_vault, monkeypatch):
        monkeypatch.delenv("_IRONCLAW_TEST_KEY_", raising=False)
        result = fresh_vault.get("_IRONCLAW_TEST_KEY_")
        assert result is None

    def test_get_unknown_key_with_explicit_default(self, fresh_vault, monkeypatch):
        monkeypatch.delenv("_IRONCLAW_TEST_KEY_", raising=False)
        result = fresh_vault.get("_IRONCLAW_TEST_KEY_", "fallback")
        assert result == "fallback"

    def test_get_existing_key(self, monkeypatch):
        monkeypatch.setenv("_IRONCLAW_TEST_KEY_", "found-it")
        v = _reload_vault()
        assert v.get("_IRONCLAW_TEST_KEY_") == "found-it"


# ===========================================================================
# Return-type contract assertions
# ===========================================================================


class TestReturnTypeContracts:
    """One consolidated test asserting every accessor returns the declared type."""

    def test_all_str_accessors_return_str(self, fresh_vault):
        str_accessors = [
            fresh_vault.app_name,
            fresh_vault.app_version,
            fresh_vault.app_host,
            fresh_vault.app_base_url,
            fresh_vault.api_prefix,
            fresh_vault.engine_base_url,
            fresh_vault.environment,
            fresh_vault.log_level,
            fresh_vault.api_key,
            fresh_vault.admin_api_key,
            fresh_vault.platform_api_key,
            fresh_vault.internal_platform_api_key,
            fresh_vault.ironclaw_api_key,
            fresh_vault.secret_key,
            fresh_vault.jwt_secret,
            fresh_vault.supabase_jwt_secret,
            fresh_vault.jwt_algorithm,
            fresh_vault.ironclaw_auth_edge_fn_path,
            fresh_vault.supabase_url,
            fresh_vault.supabase_key,
            fresh_vault.supabase_anon_key,
            fresh_vault.stripe_secret_key,
            fresh_vault.stripe_publishable_key,
            fresh_vault.stripe_webhook_secret,
            fresh_vault.groq_api_key,
            fresh_vault.groq_model,
            fresh_vault.openai_api_key,
            fresh_vault.default_scan_verdict,
            fresh_vault.default_review_status,
            fresh_vault.data_dir,
            fresh_vault.backup_dir,
        ]
        for accessor in str_accessors:
            result = accessor()
            assert isinstance(result, str), f"{accessor.__name__} returned {type(result).__name__}, expected str"

    def test_all_int_accessors_return_int(self, fresh_vault):
        int_accessors = [
            fresh_vault.app_port,
            fresh_vault.access_token_expire_minutes,
            fresh_vault.risk_threshold_allow_max,
            fresh_vault.risk_threshold_quarantine_min,
            fresh_vault.risk_threshold_block_min,
            fresh_vault.max_text_chars,
            fresh_vault.max_url_length,
            fresh_vault.max_archive_name_length,
            fresh_vault.max_repo_url_length,
        ]
        for accessor in int_accessors:
            result = accessor()
            assert isinstance(result, int), f"{accessor.__name__} returned {type(result).__name__}, expected int"

    def test_all_float_accessors_return_float(self, fresh_vault):
        float_accessors = [
            fresh_vault.groq_timeout_seconds,
            fresh_vault.ironclaw_auth_edge_fn_timeout_seconds,
        ]
        for accessor in float_accessors:
            result = accessor()
            assert isinstance(result, float), f"{accessor.__name__} returned {type(result).__name__}, expected float"

    def test_all_bool_accessors_return_bool(self, fresh_vault):
        bool_accessors = [
            fresh_vault.debug,
            fresh_vault.reload,
            fresh_vault.structured_logging_enabled,
            fresh_vault.auth_required,
            fresh_vault.groq_enabled,
        ]
        for accessor in bool_accessors:
            result = accessor()
            assert isinstance(result, bool), f"{accessor.__name__} returned {type(result).__name__}, expected bool"

    def test_optional_str_accessors_return_str_or_none(self, fresh_vault):
        optional_accessors = [
            fresh_vault.supabase_service_role_key,
            fresh_vault.reports_dir,
            fresh_vault.uploads_dir,
            fresh_vault.quarantine_dir,
            fresh_vault.redis_url,
            fresh_vault.sentry_dsn,
        ]
        for accessor in optional_accessors:
            result = accessor()
            assert result is None or isinstance(result, str), f"{accessor.__name__} returned unexpected type {type(result).__name__}"
