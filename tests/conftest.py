from __future__ import annotations

from collections.abc import Generator
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

from unittest.mock import MagicMock

from fastapi.testclient import TestClient
import pytest

from app.core.settings import get_settings
from app.main import app as _app
from app.services.audit_log_service import reset_audit_log
from ironclaw_sdk.client import IronclawClient
from ironclaw_sdk.exceptions import IronclawAPIError, IronclawAuthError
from ironclaw_sdk.models import ScanRequest as SDKScanRequest
from ironclaw_sdk.models import ScanResponse as SDKScanResponse


@pytest.fixture(scope="function", autouse=True)
def _refresh_app_settings() -> None:
    get_settings.cache_clear()
    settings = get_settings()
    _app.state.settings = settings


@pytest.fixture(autouse=True)
def reset_audit_state() -> Generator[None, None, None]:
    reset_audit_log()
    yield
    reset_audit_log()


@pytest.fixture(scope="function")
def test_client() -> TestClient:
    with TestClient(_app, raise_server_exceptions=True) as client:
        yield client


@pytest.fixture(scope="function")
def sdk_client() -> Generator[IronclawClient, None, None]:
    tc = TestClient(_app, raise_server_exceptions=False)
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


@pytest.fixture(scope="function")
def mock_hunt_client() -> MagicMock:
    """
    Reusable Supabase client mock for ThreatHuntService tests.
    Returns a MagicMock pre-configured with a chainable query builder
    that yields an empty result by default. Tests override .execute.return_value
    to inject specific row payloads.
    """
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.data = []

    query_builder = MagicMock()
    query_builder.select.return_value = query_builder
    query_builder.eq.return_value = query_builder
    query_builder.gte.return_value = query_builder
    query_builder.lte.return_value = query_builder
    query_builder.order.return_value = query_builder
    query_builder.range.return_value = query_builder
    query_builder.execute.return_value = mock_response

    mock_client.table.return_value = query_builder

    return mock_client
