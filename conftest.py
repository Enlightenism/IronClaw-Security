from __future__ import annotations

from collections.abc import Callable, Generator, Iterator
import os
from typing import Any

from fastapi.testclient import TestClient
import pytest

# Patch env BEFORE any app import so get_settings() cache warms with test-safe values.
# Keep the suite in fail-closed memory mode so tests cannot accidentally reach
# a real Supabase deployment or retain stale singleton state between cases.
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
    "IRONCLAW_SUPABASE_URL": "",
    "IRONCLAW_SUPABASE_KEY": "",
    "NEXT_PUBLIC_SUPABASE_URL": "",
    "NEXT_PUBLIC_SUPABASE_ANON_KEY": "",
}

_SECRET_DEFAULTS: dict[str, str] = {
    "IRONCLAW_SECRET_KEY": "test-secret-key-32-chars-minimum!!",
    "JWT_SECRET": "test-jwt-secret-key",
}

_SANITIZED_ENV_KEYS: frozenset[str] = frozenset(set(_TEST_ENV_DEFAULTS) | set(_SECRET_DEFAULTS))


def _seed_test_environment() -> None:
    for key, value in _TEST_ENV_DEFAULTS.items():
        os.environ[key] = value
    for key, value in _SECRET_DEFAULTS.items():
        os.environ[key] = value


_seed_test_environment()

import app.api.stripe_webhooks as stripe_webhooks  # noqa: E402
import app.core.install_keys as install_keys_module  # noqa: E402
from app.core.settings import get_settings  # noqa: E402
import app.core.unit_wallet as unit_wallet_module  # noqa: E402
from app.supabaseclient import reset_supabase_client  # noqa: E402

get_settings.cache_clear()
_settings = get_settings()

from app.main import app  # noqa: E402


def _reset_runtime_singletons() -> None:
    reset_supabase_client()
    stripe_webhooks.reset_processed_events()
    install_keys_module._reset_install_key_registry_for_testing()

    wallet = unit_wallet_module.UnitWalletRegistry()
    unit_wallet_module._unit_wallet_registry = wallet

    app.dependency_overrides.clear()
    get_settings.cache_clear()
    app.state.settings = get_settings()


def _patch_app_state(application: Any) -> None:
    if not hasattr(application, "state"):
        return
    application.state.settings = _settings


def _refresh_settings() -> Any:
    global _settings
    get_settings.cache_clear()
    _settings = get_settings()
    _patch_app_state(app)
    return _settings


def _restore_environment(snapshot: dict[str, str | None]) -> None:
    for key, prior in snapshot.items():
        if prior is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = prior


def _build_client() -> TestClient:
    _patch_app_state(app)
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(scope="session", autouse=True)
def sanitize_test_environment_session() -> Iterator[None]:
    original = {key: os.environ.get(key) for key in _SANITIZED_ENV_KEYS}
    try:
        _seed_test_environment()
        _refresh_settings()
        yield
    finally:
        _restore_environment(original)
        _refresh_settings()


@pytest.fixture(scope="function", autouse=True)
def sanitize_test_environment(request: pytest.FixtureRequest) -> Iterator[None]:
    if request.node.get_closest_marker("allow_real_env") is not None:
        _refresh_settings()
        yield
        _refresh_settings()
        return

    original = {key: os.environ.get(key) for key in _SANITIZED_ENV_KEYS}
    try:
        _seed_test_environment()
        _refresh_settings()
        yield
    finally:
        _restore_environment(original)
        _refresh_settings()


@pytest.fixture(scope="function", autouse=True)
def isolate_in_memory_runtime_state() -> Iterator[None]:
    """Ensure payment/install-key/wallet in-memory state is reset between tests."""
    _reset_runtime_singletons()
    yield
    _reset_runtime_singletons()


@pytest.fixture(scope="function")
def env_override(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[..., None]]:
    def _apply(**values: str | None) -> None:
        for key, value in values.items():
            if value is None:
                monkeypatch.delenv(key, raising=False)
            else:
                monkeypatch.setenv(key, value)
        _refresh_settings()

    yield _apply
    _refresh_settings()


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
