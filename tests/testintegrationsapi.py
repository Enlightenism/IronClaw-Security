from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.api.integrations import router as api_integrations_router
from app.api.routes.integrations import router as integrations_router
from app.core.auth import get_auth_context
from app.routes.integrations.installer import router as installer_router


@pytest.fixture
def client() -> Iterator[TestClient]:
    app = FastAPI()
    app.include_router(integrations_router)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def installer_client() -> Iterator[TestClient]:
    app = FastAPI()
    app.include_router(installer_router)
    with TestClient(app) as test_client:
        yield test_client


def test_integrations_router_registers_expected_paths(client: TestClient) -> None:
    route_paths = {route.path for route in client.app.routes}
    expected_paths = {
        "/integrations/installers",
        "/integrations/installers/{integration_id}",
        "/integrations/verifiers",
        "/integrations/verifiers/{integration_id}",
    }

    missing_paths = expected_paths - route_paths
    assert not missing_paths, f"missing integration routes: {sorted(missing_paths)}"


def test_integrations_router_exposes_expected_http_methods(client: TestClient) -> None:
    route_methods = {
        (
            route.path,
            tuple(
                sorted(method for method in route.methods if method not in {"HEAD", "OPTIONS"}),
            ),
        )
        for route in client.app.routes
        if route.path.startswith("/integrations")
    }

    expected_methods = {
        ("/integrations/installers", ("GET",)),
        ("/integrations/installers/{integration_id}", ("GET",)),
        ("/integrations/verifiers", ("GET",)),
        ("/integrations/verifiers/{integration_id}", ("GET",)),
    }

    missing_methods = expected_methods - route_methods
    assert not missing_methods, f"missing integration route methods: {sorted(missing_methods)}"


def test_integrations_route_responds_for_supported_list_and_detail_endpoints(
    client: TestClient,
) -> None:
    for path in ("/integrations/installers", "/integrations/verifiers"):
        response = client.get(path)
        assert response.status_code == 200, response.text
        payload = response.json()
        assert isinstance(payload, dict)
        assert "items" in payload

    for path in ("/integrations/installers/openai", "/integrations/verifiers/openai"):
        response = client.get(path)
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["integration_id"] == "openai"


def test_installer_detail_endpoint_returns_requested_integration_id(
    client: TestClient,
) -> None:
    integration_id = "openai"

    response = client.get(f"/integrations/installers/{integration_id}")
    assert response.status_code == 200, response.text

    payload = response.json()
    assert payload.get("integration_id") == integration_id


def test_verifier_detail_endpoint_returns_requested_integration_id(
    client: TestClient,
) -> None:
    integration_id = "openai"

    response = client.get(f"/integrations/verifiers/{integration_id}")
    assert response.status_code == 200, response.text

    payload = response.json()
    assert payload.get("integration_id") == integration_id


def test_integration_install_route_requires_paid_install_key(installer_client: TestClient) -> None:
    response = installer_client.post(
        "/integrations/integration-openclaw/install",
        json={
            "initiated_by": "tester",
            "platform": "openclaw",
        },
    )

    assert response.status_code == 403, response.text
    assert "paid install key" in response.json()["detail"].lower()


def test_integration_install_route_rejects_missing_or_inactive_owner_install_key_context(installer_client: TestClient) -> None:
    class _InactiveRecord:
        key_id = "ik_paid_123"
        owner_key = "owner-456"
        program = "openclaw"
        payment_status = "paid"
        entitlements_status = "active"
        issued_after_payment = True
        active = False

    with patch("app.routes.integrations.installer.get_install_key_registry") as mock_registry:
        mock_registry.return_value.authenticate_install_key.return_value = _InactiveRecord()
        response = installer_client.post(
            "/integrations/integration-openclaw/install",
            json={
                "initiated_by": "tester",
                "platform": "openclaw",
                "install_key": "ic_install_openclaw_validkey",
                "owner_key": "owner-456",
            },
        )
        assert response.status_code == 403, response.text
        assert "paid install key" in response.json()["detail"].lower()

    response = installer_client.post(
        "/integrations/integration-openclaw/install",
        json={
            "initiated_by": "tester",
            "platform": "openclaw",
            "install_key": "ic_install_openclaw_validkey",
        },
    )
    assert response.status_code == 403, response.text
    assert "paid install key" in response.json()["detail"].lower()


def test_integration_install_route_rejects_generic_and_mismatched_keys(installer_client: TestClient) -> None:
    class _Record:
        key_id = "ik_paid_123"
        owner_key = "owner-456"
        program = "openclaw"
        payment_status = "paid"
        entitlements_status = "active"
        issued_after_payment = True

    with patch("app.routes.integrations.installer.get_install_key_registry") as mock_registry:
        mock_registry.return_value.authenticate_install_key.return_value = _Record()

        for bad_key in ("sk_live_abc123", "token-123", "ic_org_1234", "ic_install_claude_code_validkey"):
            response = installer_client.post(
                "/integrations/integration-openclaw/install",
                json={
                    "initiated_by": "tester",
                    "platform": "openclaw",
                    "install_key": bad_key,
                    "owner_key": "owner-456",
                },
            )
            assert response.status_code == 403, response.text
            assert "paid install key" in response.json()["detail"].lower()

        response = installer_client.post(
            "/integrations/integration-openclaw/install",
            json={
                "initiated_by": "tester",
                "platform": "openclaw",
                "install_key": "ic_install_openclaw_validkey",
                "owner_key": "owner-999",
            },
        )
        assert response.status_code == 403, response.text
        assert "paid install key" in response.json()["detail"].lower()

        response = installer_client.post(
            "/integrations/integration-openclaw/install",
            json={
                "initiated_by": "tester",
                "platform": "claude-code",
                "install_key": "ic_install_openclaw_validkey",
                "owner_key": "owner-456",
            },
        )
        assert response.status_code == 403, response.text
        assert "paid install key" in response.json()["detail"].lower()


def test_integration_install_route_accepts_valid_paid_install_key(installer_client: TestClient) -> None:
    class _Record:
        key_id = "ik_paid_123"
        owner_key = "owner-456"
        program = "openclaw"
        active = True
        payment_status = "paid"
        entitlements_status = "active"
        issued_after_payment = True

    with patch("app.routes.integrations.installer.get_install_key_registry") as mock_registry:
        mock_registry.return_value.authenticate_install_key.return_value = _Record()
        with patch("app.routes.integrations.installer.get_integration_installer") as mock_installer:
            mock_installer.return_value.install_integration.return_value = {
                "installed": True,
                "success": True,
                "status": "active",
                "steps": [{"step_id": "step-install", "status": "completed", "detail": "installed"}],
            }
            response = installer_client.post(
                "/integrations/integration-openclaw/install",
                json={
                    "initiated_by": "tester",
                    "platform": "openclaw",
                    "install_key": "ic_install_openclaw_validkey",
                    "owner_key": "owner-456",
                },
            )

    assert response.status_code == 200, response.text
    assert response.json()["installation"]["installed"] is True
    assert response.json()["installation"]["state"] == "active"


def test_integration_token_uses_paid_install_keys_not_platform_api_key(client: TestClient) -> None:
    class _Record:
        def __init__(self, program: str, masked_key: str) -> None:
            self.program = program
            self.masked_key = masked_key
            self.key_id = f"ik_{program}_123"
            self.owner_key = "owner-456"
            self.payment_status = "paid"
            self.entitlements_status = "active"
            self.issued_after_payment = True
            self.active = True

    auth_context = SimpleNamespace(
        api_key="system-platform-api-key",
        principal_id="owner-456",
        org_id=None,
        key_type="personal",
    )
    registry = SimpleNamespace(
        get_keys_for_owner=lambda owner_key: [
            _Record("openclaw", "ic_install_openclaw_...abcd"),
            _Record("claude_code", "ic_install_claude_code_...efgh"),
        ]
    )

    app = client.app
    app.dependency_overrides[get_auth_context] = lambda: auth_context
    try:
        with patch("app.api.routes.integrations.get_install_key_registry", return_value=registry):
            response = client.get("/integrations/token")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["user_token"] in {None, ""}
    assert "system-platform-api-key" not in str(payload)
    assert "ic_install_openclaw_...abcd" in payload["openclaw_command"]
    assert "ic_install_claude_code_...efgh" in payload["claude_code_command"]
    assert "--platform openclaw" in payload["openclaw_command"]
    assert "--platform claude-code" in payload["claude_code_command"]


def test_api_integrations_token_ignores_generic_platform_auth_even_with_registry_data() -> None:
    api_app = FastAPI()
    api_app.include_router(api_integrations_router)
    with TestClient(api_app) as api_client:
        auth_context = SimpleNamespace(
            api_key="system-platform-api-key",
            principal_id="system-platform-api-key",
            org_id=None,
            key_type="personal",
        )
        registry = SimpleNamespace(
            get_keys_for_owner=lambda owner_key: [
                SimpleNamespace(
                    owner_key="owner-789",
                    program="openclaw",
                    active=True,
                    payment_status="paid",
                    entitlements_status="active",
                    issued_after_payment=True,
                    masked_key="ic_install_openclaw_...wxyz",
                ),
                SimpleNamespace(
                    owner_key="owner-789",
                    program="claude_code",
                    active=True,
                    payment_status="paid",
                    entitlements_status="active",
                    issued_after_payment=True,
                    masked_key="ic_install_claude_code_...qrst",
                ),
            ]
        )

        api_app.dependency_overrides[get_auth_context] = lambda: auth_context
        try:
            with patch("app.api.integrations.get_install_key_registry", return_value=registry):
                response = api_client.get("/integrations/token")
        finally:
            api_app.dependency_overrides.clear()

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["user_token"] == ""
    assert payload["openclaw_command"] == ""
    assert payload["claude_code_command"] == ""
    assert "system-platform-api-key" not in str(payload)


def test_integration_token_rejects_generic_platform_api_key_owner_fallback(client: TestClient) -> None:
    auth_context = SimpleNamespace(
        api_key="system-platform-api-key",
        principal_id="ic_legacy_system_key",
        org_id=None,
        key_type="personal",
    )
    registry = SimpleNamespace(get_keys_for_owner=lambda owner_key: [])

    app = client.app
    app.dependency_overrides[get_auth_context] = lambda: auth_context
    try:
        with patch("app.api.routes.integrations.get_install_key_registry", return_value=registry):
            response = client.get("/integrations/token")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["status"] == "locked"
    assert payload["user_token"] in {None, ""}
    assert payload["openclaw_command"] == ""
    assert payload["claude_code_command"] == ""
    assert "system-platform-api-key" not in str(payload)


def test_integration_token_returns_locked_state_when_no_paid_keys_exist(client: TestClient) -> None:
    auth_context = SimpleNamespace(
        api_key="system-platform-api-key",
        principal_id="owner-789",
        org_id=None,
        key_type="personal",
    )
    registry = SimpleNamespace(get_keys_for_owner=lambda owner_key: [])

    app = client.app
    app.dependency_overrides[get_auth_context] = lambda: auth_context
    try:
        with patch("app.api.routes.integrations.get_install_key_registry", return_value=registry):
            response = client.get("/integrations/token")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["status"] == "locked"
    assert payload["user_token"] in {None, ""}
    assert payload["openclaw_command"] == ""
    assert payload["claude_code_command"] == ""
