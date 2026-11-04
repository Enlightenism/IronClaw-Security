from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.api.integrations import router as api_integrations_router
from app.api.routes.integrations import router as integrations_router
from app.api.skill_package import router as skill_package_router
from app.core.auth import get_auth_context
from app.core.install_key_formats import (
    SECURITY_GUARDIAN_SKILL_FILE_PATH,
    SECURITY_GUARDIAN_SKILL_ROUTE,
)
from app.routes.integrations.installer import router as installer_router
from app.services.install_key_handoff import InstallKeySecretUnavailableError


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
    app.dependency_overrides[get_auth_context] = lambda: SimpleNamespace(
        authenticated=True,
        metadata={"owner_key": "owner-456"},
        org_id=None,
        principal_type="user",
    )
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


def test_package_integrations_router_registers_hermes_endpoints() -> None:
    from app.routes.integrations import router as package_router

    app = FastAPI()
    app.include_router(package_router)

    route_paths = {route.path for route in app.routes}
    assert "/integrations/hermes/health" in route_paths
    assert "/integrations/hermes/manifest" in route_paths


def test_public_security_skill_route_serves_the_canonical_skill_file() -> None:
    app = FastAPI()
    app.include_router(skill_package_router)

    source_file = (
        Path(__file__)
        .resolve()
        .parents[1]
        .joinpath(
            *SECURITY_GUARDIAN_SKILL_FILE_PATH.split("/"),
        )
    )
    with TestClient(app) as test_client:
        response = test_client.get(SECURITY_GUARDIAN_SKILL_ROUTE)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert response.text == source_file.read_text(encoding="utf-8")


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


def test_compatibility_install_route_delegates_to_canonical_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.api.integrations as compatibility_api
    from app.routes.integrations.installer import InstallationSummaryView

    token = "ic_claim_single_use_0123456789"
    auth_context = SimpleNamespace(
        authenticated=True,
        metadata={"owner_key": "owner-456"},
        org_id=None,
        principal_type="user",
    )
    expected_response = compatibility_api.IntegrationInstallResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp="2030-01-01T00:00:00Z",
        integration_id="openclaw",
        installation=InstallationSummaryView(
            state="installed",
            installed=True,
            steps_total=0,
            steps_completed=0,
            steps_failed=0,
        ),
    )
    canonical_handler = MagicMock(return_value=expected_response)
    monkeypatch.setattr(
        compatibility_api,
        "_install_canonical_integration",
        canonical_handler,
    )
    app = FastAPI()
    app.include_router(api_integrations_router)
    app.dependency_overrides[get_auth_context] = lambda: auth_context

    with TestClient(app) as compatibility_client:
        response = compatibility_client.post(
            "/integrations/openclaw/install",
            json={"claim_token": token},
        )

    assert response.status_code == 200, response.text
    assert response.json()["integration_id"] == "openclaw"
    canonical_handler.assert_called_once()
    assert canonical_handler.call_args.kwargs["integration_id"] == "openclaw"
    assert canonical_handler.call_args.kwargs["request"].claim_token == token
    assert canonical_handler.call_args.kwargs["auth"] == auth_context


def test_verifier_detail_endpoint_returns_requested_integration_id(
    client: TestClient,
) -> None:
    integration_id = "openai"

    response = client.get(f"/integrations/verifiers/{integration_id}")
    assert response.status_code == 200, response.text

    payload = response.json()
    assert payload.get("integration_id") == integration_id


def test_integration_install_route_requires_one_time_install_claim(installer_client: TestClient) -> None:
    response = installer_client.post(
        "/integrations/integration-openclaw/install",
        json={
            "initiated_by": "tester",
            "platform": "openclaw",
        },
    )

    assert response.status_code == 403, response.text
    assert "one-time install claim" in response.json()["detail"].lower()


def test_integration_install_route_rejects_legacy_raw_key_payload_without_claim(installer_client: TestClient) -> None:
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
        assert "one-time install claim" in response.json()["detail"].lower()

    response = installer_client.post(
        "/integrations/integration-openclaw/install",
        json={
            "initiated_by": "tester",
            "platform": "openclaw",
            "install_key": "ic_install_openclaw_validkey",
        },
    )
    assert response.status_code == 403, response.text
    assert "one-time install claim" in response.json()["detail"].lower()


def test_integration_install_route_rejects_generic_and_mismatched_raw_keys_without_claim(installer_client: TestClient) -> None:
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
            assert "one-time install claim" in response.json()["detail"].lower()

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
        assert "one-time install claim" in response.json()["detail"].lower()

        response = installer_client.post(
            "/integrations/integration-openclaw/install",
            json={
                "initiated_by": "tester",
                "platform": "claude-code",
                "install_key": "ic_install_openclaw_validkey",
                "owner_key": "owner-456",
            },
        )
        assert response.status_code == 400, response.text
        assert "does not match" in response.json()["detail"].lower()


def test_integration_install_route_rejects_masked_and_placeholder_raw_keys_without_claim(installer_client: TestClient) -> None:
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

        for bad_key in (
            "ic_install_openclaw_...abcd",
            "ic_install_openclaw_placeholder",
            "ic_install_openclaw_demo",
            "ic_install_openclaw_replaceme",
            "ic_install_openclaw_test_key",
            "ic_install_openclaw_redacted",
            "ic_install_openclaw_fake",
        ):
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
            assert "one-time install claim" in response.json()["detail"].lower()

        response = installer_client.post(
            "/integrations/integration-openclaw/install",
            json={
                "initiated_by": "tester",
                "platform": "openclaw",
                "install_key": "ic_install_openclaw_validkey",
                "owner_key": "placeholder-owner",
            },
        )
        assert response.status_code == 403, response.text
        assert "one-time install claim" in response.json()["detail"].lower()


def test_integration_install_route_rejects_long_lived_raw_key(installer_client: TestClient) -> None:
    class _Record:
        key_id = "ik_paid_cursor_123"
        owner_key = "owner-456"
        program = "cursor"
        active = True
        payment_status = "paid"
        entitlements_status = "active"
        issued_after_payment = True

    with patch("app.routes.integrations.installer.get_install_key_registry") as mock_registry:
        mock_registry.return_value.authenticate_install_key.return_value = _Record()
        response = installer_client.post(
            "/integrations/integration-cursor/install",
            json={
                "initiated_by": "tester",
                "platform": "cursor",
                "install_key": "ic_install_claude_code_validkey",
                "owner_key": "owner-456",
            },
        )

    assert response.status_code == 403, response.text
    assert "one-time install claim" in response.json()["detail"].lower()


def test_integration_install_route_accepts_valid_single_use_claim(installer_client: TestClient) -> None:
    claim_token = "ic_claim_0123456789abcdefghij"
    install_key = "ic_install_openclaw_validkey"
    redemption = SimpleNamespace(
        key_id="ik_paid_123",
        owner_key="owner-456",
        program="openclaw",
        install_key=install_key,
    )
    with (
        patch(
            "app.routes.integrations.installer.get_install_key_handoff_service",
            return_value=SimpleNamespace(redeem_claim=MagicMock(return_value=redemption)),
        ) as mock_handoff,
        patch("app.routes.integrations.installer._require_paid_install_key") as mock_validate_key,
        patch("app.routes.integrations.installer.get_integration_installer") as mock_installer,
    ):
        mock_installer.return_value.install_integration.return_value = {
            "installed": True,
            "success": True,
            "status": "active",
            "steps": [{"step_id": "step-install", "status": "completed", "detail": "installed"}],
        }
        response = installer_client.post(
            "/integrations/integration-openclaw/install",
            json={
                "platform": "openclaw",
                "claim_token": claim_token,
                "owner_key": "attacker-selected-owner",
            },
        )

    assert response.status_code == 200, response.text
    assert response.json()["installation"]["installed"] is True
    assert response.json()["installation"]["state"] == "active"
    assert install_key not in response.text
    mock_handoff.return_value.redeem_claim.assert_called_once_with(claim_token)
    mock_validate_key.assert_called_once_with(
        install_key,
        "owner-456",
        integration_id="integration-openclaw",
        platform="openclaw",
    )


def test_integration_install_route_normalizes_supported_platform_names(installer_client: TestClient) -> None:
    from app.core.install_key_formats import InstallKeyFormatRegistry

    claim_token = "ic_claim_0123456789abcdefghij"
    for platform, integration_id, program in (
        ("cursor", "integration-cursor", "cursor"),
        ("goose-agent", "integration-goose", "goose"),
        ("gemini-cli", "integration-gemini-cli", "gemini_cli"),
        ("github-copilot", "integration-copilot", "copilot"),
    ):
        install_key = f"{InstallKeyFormatRegistry.get_spec(program).prefix}validkey"
        redemption = SimpleNamespace(
            key_id=f"ik_paid_{program}",
            owner_key="owner-456",
            program=program,
            install_key=install_key,
        )
        with (
            patch(
                "app.routes.integrations.installer.get_install_key_handoff_service",
                return_value=SimpleNamespace(
                    redeem_claim=lambda token, redemption=redemption: redemption,
                ),
            ),
            patch("app.routes.integrations.installer._require_paid_install_key") as mock_validate_key,
            patch("app.routes.integrations.installer.get_integration_installer") as mock_installer,
        ):
            mock_installer.return_value.install_integration.return_value = {
                "installed": True,
                "success": True,
                "status": "active",
                "steps": [{"step_id": "step-install", "status": "completed", "detail": "installed"}],
            }
            response = installer_client.post(
                f"/integrations/{integration_id}/install",
                json={
                    "platform": platform,
                    "claim_token": claim_token,
                },
            )

        assert response.status_code == 200, (platform, response.text)
        assert response.json()["installation"]["installed"] is True
        assert response.json()["installation"]["state"] == "active"
        assert install_key not in response.text
        mock_validate_key.assert_called_once_with(
            install_key,
            "owner-456",
            integration_id=integration_id,
            platform=program,
        )


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
            _Record("cursor", "ic_install_cursor_...ijkl"),
            _Record("goose", "ic_install_goose_...mnop"),
            _Record("gemini_cli", "ic_install_gemini_cli_...qrst"),
            _Record("copilot", "ic_install_copilot_...uvwx"),
            _Record("hermes", "ic_install_hermes_...abcd"),
            _Record("security_guardian", "ic_install_security_guardian_...yzab"),
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
    assert payload["supported_platforms"] == [
        "openclaw",
        "claude-code",
        "cursor",
        "goose",
        "gemini-cli",
        "copilot",
        "hermes",
    ]
    assert "security-guardian" not in payload["supported_platforms"]
    assert "security-guardian" not in payload["install_metadata"]
    assert payload["status"] == "ok"
    assert all(
        not payload[field]
        for field in (
            "claude_code_command",
            "openclaw_command",
            "cursor_command",
            "goose_command",
            "gemini_cli_command",
            "copilot_command",
            "hermes_command",
        )
    )
    assert payload["install_metadata"]["openclaw"]["available"] is True
    assert payload["install_metadata"]["openclaw"]["key_id"] == "ik_openclaw_123"
    assert "install_key" not in payload["install_metadata"]["openclaw"]
    assert payload["install_metadata"]["cursor"]["program"] == "cursor"
    assert payload["install_metadata"]["hermes"]["program"] == "hermes"
    assert payload["security_guardian_command"] == ""
    assert all(not command for command in payload["command_metadata"].values())
    assert "ic_install_" not in str(payload)


def test_integration_list_endpoints_expose_canonical_platform_metadata(client: TestClient) -> None:
    for path in ("/integrations/installers", "/integrations/verifiers"):
        response = client.get(path)
        assert response.status_code == 200, response.text
        payload = response.json()
        platform_ids = [item["integration_id"] for item in payload["items"]]
        assert platform_ids == [
            "claude-code",
            "openclaw",
            "cursor",
            "goose",
            "gemini-cli",
            "copilot",
            "hermes",
        ]
        assert all(item["integration_id"] != "security-guardian" for item in payload["items"])


def test_api_integrations_token_matches_canonical_route_output() -> None:
    auth_context = SimpleNamespace(
        api_key="",
        principal_id="owner-456",
        org_id=None,
        key_type="personal",
        metadata={"owner_key": "owner-456"},
    )
    registry = SimpleNamespace(
        get_keys_for_owner=lambda owner_key: [
            SimpleNamespace(
                key_id="ik_openclaw_123",
                owner_key="owner-456",
                program="openclaw",
                active=True,
                payment_status="paid",
                entitlements_status="active",
                issued_after_payment=True,
                masked_key="ic_install_openclaw_...abcd",
            ),
            SimpleNamespace(
                key_id="ik_claude_123",
                owner_key="owner-456",
                program="claude_code",
                active=True,
                payment_status="paid",
                entitlements_status="active",
                issued_after_payment=True,
                masked_key="ic_install_claude_code_...efgh",
            ),
        ]
    )

    api_app = FastAPI()
    api_app.include_router(api_integrations_router)
    canonical_app = FastAPI()
    canonical_app.include_router(integrations_router)

    api_app.dependency_overrides[get_auth_context] = lambda: auth_context
    canonical_app.dependency_overrides[get_auth_context] = lambda: auth_context
    try:
        with patch("app.api.routes.integrations.get_install_key_registry", return_value=registry):
            with TestClient(api_app) as api_client, TestClient(canonical_app) as canonical_client:
                response = api_client.get("/integrations/token")
                canonical_response = canonical_client.get("/integrations/token")
    finally:
        api_app.dependency_overrides.clear()
        canonical_app.dependency_overrides.clear()

    assert response.status_code == 200, response.text
    assert canonical_response.status_code == 200, canonical_response.text
    assert response.json() == canonical_response.json()


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
                    key_id="ik_openclaw_789",
                ),
                SimpleNamespace(
                    owner_key="owner-789",
                    program="claude_code",
                    active=True,
                    payment_status="paid",
                    entitlements_status="active",
                    issued_after_payment=True,
                    masked_key="ic_install_claude_code_...qrst",
                    key_id="ik_claude_789",
                ),
            ]
        )

        api_app.dependency_overrides[get_auth_context] = lambda: auth_context
        try:
            with patch("app.api.routes.integrations.get_install_key_registry", return_value=registry):
                response = api_client.get("/integrations/token")
        finally:
            api_app.dependency_overrides.clear()

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["user_token"] == ""
    assert payload["openclaw_command"] == ""
    assert payload["claude_code_command"] == ""
    assert payload["supported_platforms"] == [
        "openclaw",
        "claude-code",
        "cursor",
        "goose",
        "gemini-cli",
        "copilot",
        "hermes",
    ]
    assert "security-guardian" not in payload["supported_platforms"]
    assert "security-guardian" not in payload["install_metadata"]
    assert payload["install_metadata"]["hermes"]["program"] == "hermes"
    assert "system-platform-api-key" not in str(payload)


def test_integration_token_exposes_registry_normalized_platform_aliases(client: TestClient) -> None:
    auth_context = SimpleNamespace(
        api_key="api-key",
        principal_id="owner-456",
        org_id=None,
        key_type="personal",
        metadata={"owner_key": "owner-456"},
    )
    registry = SimpleNamespace(
        get_keys_for_owner=lambda owner_key: [
            SimpleNamespace(
                owner_key="owner-456",
                program="claude_code",
                active=True,
                payment_status="paid",
                entitlements_status="active",
                issued_after_payment=True,
                masked_key="ic_install_claude_code_...abc",
                key_id="ik_claude_123",
            ),
            SimpleNamespace(
                owner_key="owner-456",
                program="gemini_cli",
                active=True,
                payment_status="paid",
                entitlements_status="active",
                issued_after_payment=True,
                masked_key="ic_install_gemini_cli_...xyz",
                key_id="ik_gemini_123",
            ),
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
    assert payload["install_metadata"]["claude-code"]["program"] == "claude_code"
    assert payload["install_metadata"]["claude-code"]["platform"] == "claude-code"
    assert payload["install_metadata"]["claude-code"]["slug"] == "claude-code"
    assert payload["install_metadata"]["claude-code"]["available"] is True
    assert payload["install_metadata"]["gemini-cli"]["available"] is True
    assert payload["command_metadata"]["claude-code"] == ""
    assert payload["command_metadata"]["gemini-cli"] == ""
    assert "claude_code" not in payload["command_metadata"]


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


def test_integration_token_filters_out_non_runtime_and_shared_family_records(client: TestClient) -> None:
    auth_context = SimpleNamespace(
        api_key="",
        principal_id="owner-456",
        org_id=None,
        key_type="personal",
        metadata={"owner_key": "owner-456"},
    )

    class _Record:
        def __init__(self, program: str, masked_key: str) -> None:
            self.owner_key = "owner-456"
            self.program = program
            self.masked_key = masked_key
            self.key_id = f"ik_{program}_123"
            self.active = True
            self.payment_status = "paid"
            self.entitlements_status = "active"
            self.issued_after_payment = True

    registry = SimpleNamespace(
        get_keys_for_owner=lambda owner_key: [
            _Record("openclaw", "ic_install_openclaw_...abcd"),
            _Record("security_guardian", "ic_install_security_guardian_...zzzz"),
            _Record("claude_code", "ic_install_claude_code_...efgh"),
            _Record("not_a_runtime", "ic_install_unknown_...wxyz"),
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
    assert payload["status"] == "ok"
    assert payload["openclaw_command"] == ""
    assert payload["claude_code_command"] == ""
    assert payload["install_metadata"]["openclaw"]["available"] is True
    assert payload["install_metadata"]["claude-code"]["available"] is True
    assert all(not command for command in payload["command_metadata"].values())
    assert payload["security_guardian_command"] == ""
    assert all(platform not in payload["install_metadata"] for platform in ("security-guardian",))
    assert set(payload["command_metadata"]) == {
        "openclaw",
        "claude-code",
        "cursor",
        "goose",
        "gemini-cli",
        "copilot",
        "hermes",
    }
    assert set(payload["install_metadata"]) == set(payload["command_metadata"])


def test_install_claim_is_owner_bound_short_lived_and_not_a_raw_key(client: TestClient) -> None:
    owner_key = "buyer@ironclaw.test"
    auth_context = SimpleNamespace(
        authenticated=True,
        api_key=None,
        principal_id="user-id",
        org_id=None,
        key_type="personal",
        metadata={"email": owner_key},
    )
    record = SimpleNamespace(
        key_id="ik_openclaw_claim_001",
        owner_key=owner_key,
        program="openclaw",
        active=True,
        payment_status="paid",
        entitlements_status="active",
        issued_after_payment=True,
        masked_key="ic_install_openclaw_...6789",
    )
    registry = SimpleNamespace(get_keys_for_owner=lambda _owner: [record])
    claim = SimpleNamespace(
        claim_token="ic_claim_single_use_0123456789",
    )
    handoff_service = SimpleNamespace(issue_claim=MagicMock(return_value=claim), save_command=MagicMock())

    client.app.dependency_overrides[get_auth_context] = lambda: auth_context
    try:
        with (
            patch("app.api.routes.integrations.get_install_key_registry", return_value=registry),
            patch("app.api.routes.integrations.get_install_key_handoff_service", return_value=handoff_service),
        ):
            response = client.post(
                "/integrations/installers/openclaw/claim",
                json={"owner_key": "attacker@ironclaw.test"},
            )
    finally:
        client.app.dependency_overrides.clear()

    assert response.status_code == 201, response.text
    payload = response.json()
    assert payload["key_id"] == record.key_id
    assert payload["claim_token"] == claim.claim_token
    assert payload["command"] == (
        "python -m pip install --no-deps --upgrade git+https://github.com/Enlightenism/IronClaw-Security.git\n"
        f"python -m ironclaw_installer redeem --program openclaw --claim-token {claim.claim_token}\n"
        "gh skill install Enlightenism/IronClaw-Security skills/ironclaw-security --agent openclaw --scope user"
    )
    assert "expires_at" not in payload
    assert "install_key" not in payload
    assert response.headers["cache-control"] == "no-store, private"
    handoff_service.issue_claim.assert_called_once_with(
        key_id=record.key_id,
        owner_key=owner_key,
        program="openclaw",
    )
    handoff_service.save_command.assert_called_once_with(
        key_id=record.key_id,
        owner_key=owner_key,
        program="openclaw",
        command=payload["command"],
    )


def test_install_claim_requires_recoverable_secret(client: TestClient) -> None:
    auth_context = SimpleNamespace(
        authenticated=True,
        principal_id="user-id",
        org_id=None,
        key_type="personal",
        metadata={"owner_key": "buyer@ironclaw.test"},
    )
    record = SimpleNamespace(
        key_id="ik_openclaw_claim_002",
        owner_key="buyer@ironclaw.test",
        program="openclaw",
        active=True,
        payment_status="paid",
        entitlements_status="active",
        issued_after_payment=True,
        masked_key="ic_install_openclaw_...6789",
    )
    registry = SimpleNamespace(get_keys_for_owner=lambda _owner: [record])
    handoff_service = SimpleNamespace(issue_claim=MagicMock(side_effect=InstallKeySecretUnavailableError("Install-key secret unavailable.")))

    client.app.dependency_overrides[get_auth_context] = lambda: auth_context
    try:
        with (
            patch("app.api.routes.integrations.get_install_key_registry", return_value=registry),
            patch("app.api.routes.integrations.get_install_key_handoff_service", return_value=handoff_service),
        ):
            response = client.post("/integrations/installers/openclaw/claim")
    finally:
        client.app.dependency_overrides.clear()

    assert response.status_code == 409
    assert "Install-key secret unavailable." in response.json()["detail"]


def test_install_claim_redemption_returns_key_once_without_caching(client: TestClient) -> None:
    redemption = SimpleNamespace(
        key_id="ik_openclaw_claim_003",
        program="openclaw",
        install_key="ic_install_openclaw_one_time_secret_123456",
    )
    handoff_service = SimpleNamespace(redeem_claim=MagicMock(return_value=redemption))

    with patch("app.api.routes.integrations.get_install_key_handoff_service", return_value=handoff_service):
        response = client.post(
            "/integrations/install-claims/redeem",
            json={"claim_token": "ic_claim_single_use_0123456789"},
        )

    assert response.status_code == 200, response.text
    assert response.json() == {
        "key_id": redemption.key_id,
        "program": redemption.program,
        "install_key": redemption.install_key,
    }
    assert response.headers["cache-control"] == "no-store, private"
    handoff_service.redeem_claim.assert_called_once_with("ic_claim_single_use_0123456789")
