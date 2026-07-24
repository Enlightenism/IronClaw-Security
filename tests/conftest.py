from __future__ import annotations

from collections.abc import Generator
import os
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
import pytest

from app.core.auth import AuthContext, require_auth_context
from app.core.billing import _reset_billing_registry_for_testing
import app.core.install_keys as _install_keys_module
from app.core.install_keys import InstallKeyRegistry
from app.core.settings import get_settings
import app.core.unit_wallet as _unit_wallet_module
from app.core.unit_wallet import UnitWalletRegistry
from app.main import app as _app
from app.services.audit_log_service import reset_audit_log
from app.supabaseclient import reset_supabase_client
from ironclaw_sdk.client import IronclawClient
from ironclaw_sdk.exceptions import IronclawAPIError, IronclawAuthError
from ironclaw_sdk.models import ScanRequest as SDKScanRequest
from ironclaw_sdk.models import ScanResponse as SDKScanResponse

# ---------------------------------------------------------------------------
# Test environment baseline
# ---------------------------------------------------------------------------

_TEST_ENV_DEFAULTS: dict[str, str] = {
    "IRONCLAW_PERSISTENCE_MODE": "memory",
    "ENVIRONMENT": "test",
    "IRONCLAW_API_KEY": "test-api-key",
    "API_KEY": "test-api-key",
    "AUTH_REQUIRED": "true",
    "IRONCLAW_RATE_LIMIT_ENABLED": "false",
    "ALLOWED_ORIGINS": "http://testserver",
    "CORS_ORIGINS": "http://testserver",
    "TRUSTED_HOSTS": "testserver,localhost,127.0.0.1",
    "SUPABASE_URL": "",
    "SUPABASE_SERVICE_ROLE_KEY": "",
    "SUPABASE_KEY": "",
    "SUPABASE_ANON_KEY": "",
}

_TEST_SECRET_DEFAULTS: dict[str, str] = {
    "IRONCLAW_SECRET_KEY": "test-secret-key-32-chars-minimum!!",
    "JWT_SECRET": "test-jwt-secret-key-32-chars-min!",
}


def _seed_test_environment() -> None:
    for key, value in _TEST_ENV_DEFAULTS.items():
        os.environ[key] = os.environ.get(key) or value
    for key, value in _TEST_SECRET_DEFAULTS.items():
        os.environ[key] = os.environ.get(key) or value


_seed_test_environment()

# ---------------------------------------------------------------------------
# Shared auth context used by all override fixtures
# ---------------------------------------------------------------------------

_TEST_AUTH_CONTEXT = AuthContext(
    api_key="test-api-key",
    principal_type="api_key",
    principal_id="test-principal",
    session_id=None,
    org_id="test-org",
    permissions=(),
    roles=(),
    authenticated=True,
    auth_source="test",
    auth_method="api_key",
)


def _override_require_auth_context() -> AuthContext:
    return _TEST_AUTH_CONTEXT


def _clear_auth_override() -> None:
    _app.dependency_overrides.pop(require_auth_context, None)


# ---------------------------------------------------------------------------
# Autouse fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function", autouse=True)
def _reset_supabase_singleton() -> Generator[None, None, None]:
    reset_supabase_client()
    yield
    reset_supabase_client()


@pytest.fixture(scope="function", autouse=True)
def _refresh_app_settings() -> Generator[None, None, None]:
    get_settings.cache_clear()
    settings = get_settings()
    _app.state.settings = settings
    yield
    get_settings.cache_clear()
    _app.state.settings = get_settings()


@pytest.fixture(scope="function", autouse=True)
def _reset_unit_wallet_registry() -> Generator[None, None, None]:
    fresh = UnitWalletRegistry()
    _unit_wallet_module._unit_wallet_registry = fresh
    yield
    _unit_wallet_module._unit_wallet_registry = UnitWalletRegistry()


@pytest.fixture(scope="function", autouse=True)
def _reset_install_key_registry() -> Generator[None, None, None]:
    fresh = InstallKeyRegistry()
    fresh._loaded = True
    _install_keys_module._install_key_registry = fresh
    yield
    fresh2 = InstallKeyRegistry()
    fresh2._loaded = True
    _install_keys_module._install_key_registry = fresh2


@pytest.fixture(scope="function", autouse=True)
def _reset_billing_registry() -> Generator[None, None, None]:
    _reset_billing_registry_for_testing()
    yield
    _reset_billing_registry_for_testing()


@pytest.fixture(scope="function", autouse=True)
def _reset_dependency_overrides() -> Generator[None, None, None]:
    original = dict(_app.dependency_overrides)
    yield
    _app.dependency_overrides.clear()
    _app.dependency_overrides.update(original)


@pytest.fixture(scope="function", autouse=True)
def reset_audit_state() -> Generator[None, None, None]:
    reset_audit_log()
    yield
    reset_audit_log()


# ---------------------------------------------------------------------------
# HTTP client fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def test_client(_refresh_app_settings: None) -> Generator[TestClient, None, None]:
    _app.dependency_overrides[require_auth_context] = _override_require_auth_context
    with TestClient(_app, raise_server_exceptions=True) as client:
        client.headers.update({"X-API-Key": os.environ["IRONCLAW_API_KEY"]})
        yield client
    _clear_auth_override()


# ---------------------------------------------------------------------------
# SDK client fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def sdk_client(_refresh_app_settings: None) -> Generator[IronclawClient, None, None]:
    _app.dependency_overrides[require_auth_context] = _override_require_auth_context
    with TestClient(_app, raise_server_exceptions=False) as tc:
        client = IronclawClient(
            api_key=os.environ["IRONCLAW_API_KEY"],
            base_url="http://testserver",
            connect_timeout=5.0,
            read_timeout=10.0,
        )

        def _patched_scan(request: SDKScanRequest) -> SDKScanResponse:
            resp = tc.post(
                "/scan/",
                content=request.model_dump_json(),
                headers={
                    "X-API-Key": os.environ["IRONCLAW_API_KEY"],
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
            if resp.status_code in (401, 403):
                raise IronclawAuthError(status_code=resp.status_code, message=resp.text)
            if resp.status_code >= 400:
                raise IronclawAPIError(status_code=resp.status_code, body=resp.text)
            try:
                return SDKScanResponse.model_validate(resp.json())
            except Exception as exc:
                raise IronclawAPIError(status_code=resp.status_code, body=resp.text) from exc

        client.scan = _patched_scan
        yield client
    _clear_auth_override()


# ---------------------------------------------------------------------------
# Mock Supabase / hunt client fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def mock_hunt_client() -> MagicMock:
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.data = []

    query_builder = MagicMock()
    for method in (
        "select",
        "eq",
        "neq",
        "gte",
        "lte",
        "gt",
        "lt",
        "in_",
        "contains",
        "order",
        "range",
        "limit",
        "insert",
        "update",
        "upsert",
        "delete",
        "filter",
        "match",
        "not_",
        "or_",
    ):
        getattr(query_builder, method).return_value = query_builder
    query_builder.execute.return_value = mock_response
    mock_client.table.return_value = query_builder
    return mock_client
