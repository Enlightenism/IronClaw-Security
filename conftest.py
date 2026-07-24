from __future__ import annotations

from collections.abc import Generator
import os
from typing import Any

# Patch env BEFORE any app import so get_settings() cache warms with test-safe values.
_TEST_ENV_DEFAULTS: dict[str, str] = {
    "IRONCLAW_PERSISTENCE_MODE": "memory",
    "ENVIRONMENT": "test",
    "AUTH_REQUIRED": "true",
    "IRONCLAW_API_KEY": "test-api-key",
    "API_KEY": "test-api-key",
    "ALLOWED_ORIGINS": "http://testserver",
    "CORS_ORIGINS": "http://testserver",
    "TRUSTED_HOSTS": "testserver,localhost,127.0.0.1",
    "SUPABASE_URL": "",
    "SUPABASE_SERVICE_ROLE_KEY": "",
    "SUPABASE_KEY": "",
    "SUPABASE_ANON_KEY": "",
}

_SECRET_DEFAULTS: dict[str, str] = {
    "IRONCLAW_SECRET_KEY": "test-secret-key-32-chars-minimum!!",
    "JWT_SECRET": "test-jwt-secret-key-32-chars-min!",
}


def _seed_test_environment() -> None:
    for key, value in _TEST_ENV_DEFAULTS.items():
        os.environ[key] = os.environ.get(key) or value
    for key, value in _SECRET_DEFAULTS.items():
        os.environ[key] = os.environ.get(key) or value


_seed_test_environment()

from app.core.settings import get_settings  # noqa: E402

get_settings.cache_clear()
_settings = get_settings()

from fastapi.testclient import TestClient  # noqa: E402
import pytest  # noqa: E402

from app.main import app  # noqa: E402


def _patch_app_state(application: Any) -> None:
    if not hasattr(application, "state"):
        return
    application.state.settings = _settings


def _build_client() -> TestClient:
    _patch_app_state(app)
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(scope="session")
def client() -> Generator[TestClient, None, None]:
    with _build_client() as c:
        yield c


@pytest.fixture(scope="function")
def fresh_client() -> Generator[TestClient, None, None]:
    with _build_client() as c:
        yield c


@pytest.fixture(scope="function")
def test_client() -> Generator[TestClient, None, None]:
    with _build_client() as c:
        yield c
