from __future__ import annotations

import importlib
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

MODULE_NAME = "app.config"
SETTINGS_MODULE_NAME = "app.core.settings"


def _settings_module(settings: Any) -> ModuleType:
    module = ModuleType(SETTINGS_MODULE_NAME)
    module.get_settings = lambda: settings
    return module


def _build_settings(**overrides: Any) -> SimpleNamespace:
    defaults = {
        "app_name": "IronClaw-Security",
        "APP_NAME": None,
        "app_version": "0.1.0",
        "APP_VERSION": None,
        "environment": "development",
        "ENVIRONMENT": None,
        "debug": False,
        "DEBUG": None,
        "app_host": "127.0.0.1",
        "APP_HOST": None,
        "app_port": 8000,
        "APP_PORT": None,
        "app_base_url": "http://127.0.0.1:8000",
        "APP_BASE_URL": None,
        "ironclaw_base_url": None,
        "IRONCLAW_BASE_URL": None,
        "engine_base_url": None,
        "ENGINE_BASE_URL": None,
        "log_level": "INFO",
        "LOG_LEVEL": None,
        "structured_logging_enabled": True,
        "STRUCTURED_LOGGING_ENABLED": None,
        "effective_auth_required": True,
        "ironclaw_api_key": "ironclaw-key",
        "IRONCLAW_API_KEY": None,
        "internal_platform_api_key": "internal-key",
        "INTERNAL_PLATFORM_API_KEY": None,
        "platform_api_key": "platform-key",
        "PLATFORM_API_KEY": None,
        "admin_api_key": "admin-key",
        "ADMIN_API_KEY": None,
        "api_key": "general-key",
        "API_KEY": None,
        "effective_api_key": "ironclaw-key",
        "secret_key": "raw-secret",
        "SECRET_KEY": None,
        "effective_secret_key": "effective-secret",
        "jwt_secret": "raw-jwt-secret",
        "JWT_SECRET": None,
        "effective_jwt_secret": "effective-jwt-secret",
        "supabase_jwt_secret": "raw-supabase-jwt-secret",
        "SUPABASE_JWT_SECRET": None,
        "effective_supabase_jwt_secret": "effective-supabase-jwt-secret",
        "jwt_algorithm": "hs256",
        "JWT_ALGORITHM": None,
        "effective_jwt_algorithm": "HS512",
        "supabase_url": "https://raw.supabase.test",
        "SUPABASE_URL": None,
        "effective_supabase_url": "https://effective.supabase.test",
        "supabase_anon_key": "raw-anon-key",
        "SUPABASE_ANON_KEY": None,
        "effective_supabase_anon_key": "effective-anon-key",
        "supabase_service_role_key": "raw-service-role-key",
        "SUPABASE_SERVICE_ROLE_KEY": None,
        "effective_supabase_service_role_key": "effective-service-role-key",
        "api_key_auth_configured": True,
        "bearer_auth_configured": True,
        "auth_configured": True,
        "guard_enabled": False,
        "GUARD_ENABLED": None,
        "guard_model_path": "models/prompt-guard-86m",
        "GUARD_MODEL_PATH": None,
        "guard_threshold": 0.5,
        "GUARD_THRESHOLD": None,
        "default_scan_verdict": "allow",
        "DEFAULT_SCAN_VERDICT": None,
        "default_review_status": "not_required",
        "DEFAULT_REVIEW_STATUS": None,
        "risk_threshold_allow_max": 29,
        "RISK_THRESHOLD_ALLOW_MAX": None,
        "risk_threshold_quarantine_min": 30,
        "RISK_THRESHOLD_QUARANTINE_MIN": None,
        "risk_threshold_block_min": 70,
        "RISK_THRESHOLD_BLOCK_MIN": None,
        "enable_text_scanning": True,
        "ENABLE_TEXT_SCANNING": None,
        "enable_url_scanning": True,
        "ENABLE_URL_SCANNING": None,
        "enable_github_repo_scanning": True,
        "ENABLE_GITHUB_REPO_SCANNING": None,
        "enable_archive_scanning": True,
        "ENABLE_ARCHIVE_SCANNING": None,
        "enable_guard_actions": True,
        "ENABLE_GUARD_ACTIONS": None,
        "enable_guard_action_policy": True,
        "ENABLE_GUARD_ACTION_POLICY": None,
        "enable_guard_action_decision": True,
        "ENABLE_GUARD_ACTION_DECISION": None,
        "enable_quarantine_review": True,
        "ENABLE_QUARANTINE_REVIEW": None,
        "max_text_chars": 100000,
        "MAX_TEXT_CHARS": None,
        "max_url_length": 2048,
        "MAX_URL_LENGTH": None,
        "max_archive_name_length": 512,
        "MAX_ARCHIVE_NAME_LENGTH": None,
        "max_repo_url_length": 2048,
        "MAX_REPO_URL_LENGTH": None,
        "data_dir": "./data",
        "DATA_DIR": None,
        "APP_DATA_DIR": None,
        "reports_dir": None,
        "REPORTS_DIR": None,
        "uploads_dir": None,
        "UPLOADS_DIR": None,
        "quarantine_dir": None,
        "QUARANTINE_DIR": None,
        "backup_dir": None,
        "BACKUP_DIR": None,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


@pytest.fixture()
def load_config(monkeypatch: pytest.MonkeyPatch):
    def _loader(settings: Any):
        fake_settings_module = _settings_module(settings)
        monkeypatch.setitem(sys.modules, SETTINGS_MODULE_NAME, fake_settings_module)
        sys.modules.pop(MODULE_NAME, None)
        return importlib.import_module(MODULE_NAME)

    return _loader


def test_core_identity_exports_from_settings(load_config: Any) -> None:
    config = load_config(
        _build_settings(
            app_name="IronClaw-Test",
            app_version="1.2.3",
            environment="production",
            debug=True,
        )
    )

    assert config.APP_NAME == "IronClaw-Test"
    assert config.APP_VERSION == "1.2.3"
    assert config.ENVIRONMENT == "production"
    assert config.DEBUG is True


def test_server_binding_prefers_app_base_url(load_config: Any) -> None:
    config = load_config(
        _build_settings(
            app_host="0.0.0.0",
            app_port=9001,
            app_base_url="https://api.example.test",
            ironclaw_base_url="https://legacy.example.test",
            engine_base_url="https://engine.example.test",
        )
    )

    assert config.APP_HOST == "0.0.0.0"
    assert config.APP_PORT == 9001
    assert config.APP_BASE_URL == "https://api.example.test"


def test_server_binding_falls_back_to_legacy_base_urls(load_config: Any) -> None:
    config = load_config(
        _build_settings(
            app_base_url=None,
            ironclaw_base_url="https://legacy.example.test",
            engine_base_url="https://engine.example.test",
        )
    )
    assert config.APP_BASE_URL == "https://legacy.example.test"

    config = load_config(
        _build_settings(
            app_base_url=None,
            ironclaw_base_url=None,
            engine_base_url="https://engine.example.test",
        )
    )
    assert config.APP_BASE_URL == "https://engine.example.test"


def test_server_binding_defaults_to_host_and_port_when_base_url_missing(load_config: Any) -> None:
    config = load_config(
        _build_settings(
            app_host="10.0.0.7",
            app_port=8443,
            app_base_url=None,
            ironclaw_base_url=None,
            engine_base_url=None,
        )
    )

    assert config.APP_BASE_URL == "http://10.0.0.7:8443"


def test_auth_required_uses_effective_auth_required(load_config: Any) -> None:
    config = load_config(
        _build_settings(
            effective_auth_required=False,
        )
    )

    assert config.AUTH_REQUIRED is False
    assert config.EFFECTIVE_AUTH_REQUIRED is False


def test_api_key_uses_effective_api_key_surface(load_config: Any) -> None:
    config = load_config(
        _build_settings(
            ironclaw_api_key="ironclaw-key",
            internal_platform_api_key="internal-key",
            platform_api_key="platform-key",
            admin_api_key="admin-key",
            api_key="general-key",
            effective_api_key="ironclaw-key",
        )
    )

    assert config.API_KEY == "ironclaw-key"
    assert config.EFFECTIVE_API_KEY == "ironclaw-key"
    assert config.IRONCLAW_API_KEY == "ironclaw-key"
    assert config.INTERNAL_PLATFORM_API_KEY == "internal-key"
    assert config.PLATFORM_API_KEY == "platform-key"
    assert config.ADMIN_API_KEY == "admin-key"


def test_auth_secret_exports_prefer_effective_values(load_config: Any) -> None:
    config = load_config(
        _build_settings(
            secret_key="raw-secret",
            effective_secret_key="effective-secret",
            jwt_secret="raw-jwt",
            effective_jwt_secret="effective-jwt",
            supabase_jwt_secret="raw-supabase-jwt",
            effective_supabase_jwt_secret="effective-supabase-jwt",
            jwt_algorithm="hs256",
            effective_jwt_algorithm="HS512",
        )
    )

    assert config.SECRET_KEY == "effective-secret"
    assert config.JWT_SECRET == "effective-jwt"
    assert config.SUPABASE_JWT_SECRET == "effective-supabase-jwt"
    assert config.JWT_ALGORITHM == "HS512"
    assert config.EFFECTIVE_SECRET_KEY == "effective-secret"
    assert config.EFFECTIVE_JWT_SECRET == "effective-jwt"
    assert config.EFFECTIVE_SUPABASE_JWT_SECRET == "effective-supabase-jwt"
    assert config.EFFECTIVE_JWT_ALGORITHM == "HS512"


def test_supabase_exports_use_effective_values(load_config: Any) -> None:
    config = load_config(
        _build_settings(
            supabase_url="https://raw.supabase.test",
            effective_supabase_url="https://effective.supabase.test",
            supabase_anon_key=None,
            effective_supabase_anon_key=None,
            supabase_service_role_key="raw-service-role",
            effective_supabase_service_role_key="effective-service-role",
        )
    )

    assert config.SUPABASE_URL == "https://effective.supabase.test"
    assert config.EFFECTIVE_SUPABASE_URL == "https://effective.supabase.test"
    assert config.SUPABASE_ANON_KEY is None
    assert config.EFFECTIVE_SUPABASE_ANON_KEY is None
    assert config.SUPABASE_SERVICE_ROLE_KEY == "effective-service-role"
    assert config.EFFECTIVE_SUPABASE_SERVICE_ROLE_KEY == "effective-service-role"
    assert config.SUPABASE_KEY is None


def test_supabase_key_alias_tracks_anon_key_only(load_config: Any) -> None:
    config = load_config(
        _build_settings(
            effective_supabase_anon_key="effective-anon",
            effective_supabase_service_role_key="effective-service-role",
        )
    )

    assert config.SUPABASE_ANON_KEY == "effective-anon"
    assert config.SUPABASE_KEY == "effective-anon"
    assert config.SUPABASE_SERVICE_ROLE_KEY == "effective-service-role"


def test_auth_configuration_flags_export_from_settings(load_config: Any) -> None:
    config = load_config(
        _build_settings(
            api_key_auth_configured=False,
            bearer_auth_configured=True,
            auth_configured=True,
            effective_auth_required=False,
        )
    )

    assert config.API_KEY_AUTH_CONFIGURED is False
    assert config.BEARER_AUTH_CONFIGURED is True
    assert config.AUTH_CONFIGURED is True
    assert config.EFFECTIVE_AUTH_REQUIRED is False
    assert config.AUTH_REQUIRED is False


def test_logging_and_guard_exports_round_trip(load_config: Any) -> None:
    config = load_config(
        _build_settings(
            log_level="DEBUG",
            structured_logging_enabled=False,
            guard_enabled=True,
            guard_model_path="models/custom-prompt-guard",
            guard_threshold=0.75,
        )
    )

    assert config.LOG_LEVEL == "DEBUG"
    assert config.STRUCTURED_LOGGING_ENABLED is False
    assert config.GUARD_ENABLED is True
    assert config.GUARD_MODEL_PATH == "models/custom-prompt-guard"
    assert config.GUARD_THRESHOLD == pytest.approx(0.75)


def test_policy_thresholds_flags_and_limits_round_trip(load_config: Any) -> None:
    config = load_config(
        _build_settings(
            default_scan_verdict="quarantine",
            default_review_status="pending",
            risk_threshold_allow_max=10,
            risk_threshold_quarantine_min=11,
            risk_threshold_block_min=90,
            enable_text_scanning=False,
            enable_url_scanning=False,
            enable_github_repo_scanning=False,
            enable_archive_scanning=False,
            enable_guard_actions=False,
            enable_guard_action_policy=False,
            enable_guard_action_decision=False,
            enable_quarantine_review=False,
            max_text_chars=123,
            max_url_length=456,
            max_archive_name_length=789,
            max_repo_url_length=321,
        )
    )

    assert config.DEFAULT_SCAN_VERDICT == "quarantine"
    assert config.DEFAULT_REVIEW_STATUS == "pending"
    assert config.RISK_THRESHOLD_ALLOW_MAX == 10
    assert config.RISK_THRESHOLD_QUARANTINE_MIN == 11
    assert config.RISK_THRESHOLD_BLOCK_MIN == 90
    assert config.ENABLE_TEXT_SCANNING is False
    assert config.ENABLE_URL_SCANNING is False
    assert config.ENABLE_GITHUB_REPO_SCANNING is False
    assert config.ENABLE_ARCHIVE_SCANNING is False
    assert config.ENABLE_GUARD_ACTIONS is False
    assert config.ENABLE_GUARD_ACTION_POLICY is False
    assert config.ENABLE_GUARD_ACTION_DECISION is False
    assert config.ENABLE_QUARANTINE_REVIEW is False
    assert config.MAX_TEXT_CHARS == 123
    assert config.MAX_URL_LENGTH == 456
    assert config.MAX_ARCHIVE_NAME_LENGTH == 789
    assert config.MAX_REPO_URL_LENGTH == 321


def test_directory_exports_default_from_data_dir(load_config: Any) -> None:
    config = load_config(
        _build_settings(
            data_dir="./runtime-data",
            reports_dir=None,
            uploads_dir=None,
            quarantine_dir=None,
            backup_dir=None,
        )
    )

    base_dir = Path("./runtime-data").expanduser().resolve()

    assert config.REPORTS_DIR == str((base_dir / "reports").resolve())
    assert config.UPLOADS_DIR == str((base_dir / "uploads").resolve())
    assert config.QUARANTINE_DIR == str((base_dir / "quarantine").resolve())
    assert config.BACKUP_DIR == str((base_dir / "backups").resolve())


def test_directory_exports_prefer_explicit_paths(load_config: Any) -> None:
    config = load_config(
        _build_settings(
            data_dir="./runtime-data",
            reports_dir="~/reports-out",
            uploads_dir="./custom-uploads",
            quarantine_dir="./custom-quarantine",
            backup_dir="./custom-backups",
        )
    )

    assert config.REPORTS_DIR == str(Path("~/reports-out").expanduser().resolve())
    assert config.UPLOADS_DIR == str(Path("./custom-uploads").expanduser().resolve())
    assert config.QUARANTINE_DIR == str(Path("./custom-quarantine").expanduser().resolve())
    assert config.BACKUP_DIR == str(Path("./custom-backups").expanduser().resolve())


def test_all_contains_compatibility_exports(load_config: Any) -> None:
    config = load_config(_build_settings())

    expected = {
        "ADMIN_API_KEY",
        "API_KEY",
        "API_KEY_AUTH_CONFIGURED",
        "APP_BASE_URL",
        "APP_HOST",
        "APP_NAME",
        "APP_PORT",
        "APP_VERSION",
        "AUTH_CONFIGURED",
        "AUTH_REQUIRED",
        "BACKUP_DIR",
        "BEARER_AUTH_CONFIGURED",
        "DEBUG",
        "DEFAULT_REVIEW_STATUS",
        "DEFAULT_SCAN_VERDICT",
        "EFFECTIVE_API_KEY",
        "EFFECTIVE_AUTH_REQUIRED",
        "EFFECTIVE_JWT_ALGORITHM",
        "EFFECTIVE_JWT_SECRET",
        "EFFECTIVE_SECRET_KEY",
        "EFFECTIVE_SUPABASE_ANON_KEY",
        "EFFECTIVE_SUPABASE_JWT_SECRET",
        "EFFECTIVE_SUPABASE_SERVICE_ROLE_KEY",
        "EFFECTIVE_SUPABASE_URL",
        "ENABLE_ARCHIVE_SCANNING",
        "ENABLE_GITHUB_REPO_SCANNING",
        "ENABLE_GUARD_ACTION_DECISION",
        "ENABLE_GUARD_ACTION_POLICY",
        "ENABLE_GUARD_ACTIONS",
        "ENABLE_QUARANTINE_REVIEW",
        "ENABLE_TEXT_SCANNING",
        "ENABLE_URL_SCANNING",
        "ENVIRONMENT",
        "GUARD_ENABLED",
        "GUARD_MODEL_PATH",
        "GUARD_THRESHOLD",
        "INTERNAL_PLATFORM_API_KEY",
        "IRONCLAW_API_KEY",
        "JWT_ALGORITHM",
        "JWT_SECRET",
        "LOG_LEVEL",
        "MAX_ARCHIVE_NAME_LENGTH",
        "MAX_REPO_URL_LENGTH",
        "MAX_TEXT_CHARS",
        "MAX_URL_LENGTH",
        "PLATFORM_API_KEY",
        "QUARANTINE_DIR",
        "REPORTS_DIR",
        "RISK_THRESHOLD_ALLOW_MAX",
        "RISK_THRESHOLD_BLOCK_MIN",
        "RISK_THRESHOLD_QUARANTINE_MIN",
        "SECRET_KEY",
        "STRUCTURED_LOGGING_ENABLED",
        "SUPABASE_ANON_KEY",
        "SUPABASE_JWT_SECRET",
        "SUPABASE_KEY",
        "SUPABASE_SERVICE_ROLE_KEY",
        "SUPABASE_URL",
        "UPLOADS_DIR",
    }

    assert expected.issubset(set(config.__all__))
