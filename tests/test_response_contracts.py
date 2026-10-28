from __future__ import annotations

import os
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
import pytest

os.environ["IRONCLAW_PERSISTENCE_MODE"] = "memory"
os.environ["ENVIRONMENT"] = "test"
os.environ["IRONCLAW_API_KEY"] = "test-api-key"
os.environ["AUTH_REQUIRED"] = "true"
os.environ["SUPABASE_URL"] = ""
os.environ["SUPABASE_SERVICE_ROLE_KEY"] = ""
os.environ["SUPABASE_KEY"] = ""
os.environ["SUPABASE_ANON_KEY"] = ""

from app.core.billing import get_billing_registry
from app.core.install_keys import InstallKeyNotFoundError, get_install_key_registry
from app.core.settings import get_settings
from app.core.unit_wallet import get_unit_wallet_registry
from app.main import app
from app.services.audit_log_service import reset_audit_log

_VALID_API_KEY = os.environ["IRONCLAW_API_KEY"]
_AUTH_HEADERS = {"X-API-Key": _VALID_API_KEY}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _refresh_settings():
    get_settings.cache_clear()
    app.state.settings = get_settings()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _reset_audit():
    reset_audit_log()
    yield
    reset_audit_log()


@pytest.fixture()
def client() -> TestClient:
    c = TestClient(app, raise_server_exceptions=True)
    c.headers.update(_AUTH_HEADERS)
    return c


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _assert_has_keys(payload: dict, required_keys: set[str]) -> None:
    missing = required_keys - set(payload.keys())
    assert not missing, f"Missing keys: {sorted(missing)} in payload: {payload}"


def _make_mock_key_entry(
    key_id: str = "key-abc-123",
    program: str = "ironclaw-core",
    masked_key: str = "ic-****-xyz",
    label: str = "primary",
    active: bool = True,
    units_consumed: int = 42,
    last_used_at=None,
) -> MagicMock:
    entry = MagicMock()
    entry.key_id = key_id
    entry.program = program
    entry.masked_key = masked_key
    entry.label = label
    entry.active = active
    entry.units_consumed = units_consumed
    entry.last_used_at = last_used_at
    return entry


def _make_mock_updated_key(
    key_id: str = "key-abc-123",
    units_consumed: int = 52,
    last_used_at=None,
) -> MagicMock:
    updated = MagicMock()
    updated.key_id = key_id
    updated.units_consumed = units_consumed
    updated.last_used_at = last_used_at
    return updated


def _make_mock_wallet_registry() -> MagicMock:
    mock_wallet = MagicMock()
    mock_wallet.owner_key = "demo@ironclaw.local"
    mock_wallet.balance_units = 1000
    mock_wallet.total_purchased_units = 1000
    mock_wallet.total_consumed_units = 0
    from datetime import UTC, datetime

    mock_wallet.updated_at = datetime.now(UTC)

    registry = MagicMock()
    registry.get_wallet.return_value = mock_wallet
    registry.get_or_create_wallet.return_value = mock_wallet
    return registry


def _make_mock_billing_registry() -> MagicMock:
    registry = MagicMock()
    registry.get_active_subscription_for_customer.return_value = None
    return registry


# ===========================================================================
# Public routes — no auth required
# ===========================================================================


def test_root_contract(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    assert body, "Root response should not be empty"
    _assert_has_keys(body, {"status"})
    assert body["status"] == "ok"


def test_health_contract(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    _assert_has_keys(body, {"status"})
    assert body["status"] == "ok"


def test_health_liveness_contract(client: TestClient) -> None:
    response = client.get("/health/liveness")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    _assert_has_keys(body, {"status"})


def test_health_readiness_contract(client: TestClient) -> None:
    response = client.get("/health/readiness")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    _assert_has_keys(body, {"status"})


def test_system_status_contract(client: TestClient) -> None:
    response = client.get("/system/status")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    assert body, "System status response should not be empty"


# ===========================================================================
# /policy — protected routes
# ===========================================================================


def test_policy_status_contract(client: TestClient) -> None:
    response = client.get("/policy/status")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    assert body, "Policy status response should not be empty"


def test_policy_status_contract_unauthenticated_rejected() -> None:
    bare = TestClient(app, raise_server_exceptions=True)
    response = bare.get("/policy/status")
    assert response.status_code in (401, 403)


def test_policy_system_status_contract(client: TestClient) -> None:
    response = client.get("/policy/system-status")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    _assert_has_keys(body, {"policy", "review_summary"})
    assert isinstance(body["review_summary"], dict)


def test_policy_system_status_unauthenticated_rejected() -> None:
    bare = TestClient(app, raise_server_exceptions=True)
    response = bare.get("/policy/system-status")
    assert response.status_code in (401, 403)


# ===========================================================================
# /guard — protected routes
# ===========================================================================


def test_guard_reviews_summary_contract(client: TestClient) -> None:
    response = client.get("/guard/reviews/summary")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    assert body, "Summary response should not be empty"


def test_guard_reviews_summary_unauthenticated_rejected() -> None:
    bare = TestClient(app, raise_server_exceptions=True)
    response = bare.get("/guard/reviews/summary")
    assert response.status_code in (401, 403)


def test_pending_reviews_contract(client: TestClient) -> None:
    response = client.get("/guard/reviews/pending")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)


def test_guard_audit_events_contract(client: TestClient) -> None:
    response = client.get("/guard/audit/events")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)


def test_guard_audit_events_unauthenticated_rejected() -> None:
    bare = TestClient(app, raise_server_exceptions=True)
    response = bare.get("/guard/audit/events")
    assert response.status_code in (401, 403)


# ===========================================================================
# /history — protected routes
# ===========================================================================


def test_history_events_contract(client: TestClient) -> None:
    response = client.get("/history/events")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)


def test_history_events_unauthenticated_rejected_contracts() -> None:
    bare = TestClient(app, raise_server_exceptions=True)
    response = bare.get("/history/events")
    assert response.status_code in (401, 403)


# ===========================================================================
# /policy/guard-bundle — shape assertions
# ===========================================================================


def test_guard_bundle_contract(client: TestClient) -> None:
    response = client.post(
        "/policy/guard-bundle",
        json={"user_prompt": "safe content for contract test"},
    )
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    _assert_has_keys(body, {"highest_verdict", "should_halt", "should_warn"})
    assert body["highest_verdict"] in {"allow", "block"}
    assert body["should_halt"] is (body["highest_verdict"] == "block")
    assert body["should_warn"] is False


# ===========================================================================
# /dashboard/overview — DI-isolated contract tests
# ===========================================================================


def test_dashboard_overview_response_contract(client: TestClient) -> None:
    app.dependency_overrides[get_unit_wallet_registry] = _make_mock_wallet_registry
    app.dependency_overrides[get_billing_registry] = _make_mock_billing_registry
    try:
        response = client.get("/dashboard/overview")
    finally:
        app.dependency_overrides.pop(get_unit_wallet_registry, None)
        app.dependency_overrides.pop(get_billing_registry, None)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    data = response.json()
    assert isinstance(data, dict)
    _assert_has_keys(
        data,
        {
            "status",
            "service",
            "timestamp",
            "environment",
            "kpis",
            "alerts",
            "activity",
            "metadata",
        },
    )


def test_dashboard_overview_wallet_registry_overridable(client: TestClient) -> None:
    mock_wallet_registry = _make_mock_wallet_registry()
    app.dependency_overrides[get_unit_wallet_registry] = lambda: mock_wallet_registry
    app.dependency_overrides[get_billing_registry] = _make_mock_billing_registry
    try:
        response = client.get("/dashboard/overview")
    finally:
        app.dependency_overrides.pop(get_unit_wallet_registry, None)
        app.dependency_overrides.pop(get_billing_registry, None)

    assert response.status_code == 200
    data = response.json()
    _assert_has_keys(
        data,
        {
            "status",
            "service",
            "timestamp",
            "environment",
            "kpis",
            "alerts",
            "activity",
            "metadata",
        },
    )
    assert data["status"] == "ok"
    assert "wallet" in data["metadata"]
    assert data["metadata"]["wallet"]["owner_key"] == "demo@ironclaw.local"
    mock_wallet_registry.get_wallet.assert_called_once_with("demo@ironclaw.local")


def test_dashboard_overview_billing_registry_overridable(client: TestClient) -> None:
    mock_subscription = MagicMock()
    mock_subscription.plan = "pro"
    mock_subscription.status = "active"
    mock_subscription.units_consumed = 100
    mock_subscription.unit_limit = 5000
    mock_subscription.remaining_units = 4900

    mock_billing_registry = MagicMock()
    mock_billing_registry.get_active_subscription_for_customer.return_value = mock_subscription

    app.dependency_overrides[get_unit_wallet_registry] = _make_mock_wallet_registry
    app.dependency_overrides[get_billing_registry] = lambda: mock_billing_registry
    try:
        response = client.get("/dashboard/overview")
    finally:
        app.dependency_overrides.pop(get_unit_wallet_registry, None)
        app.dependency_overrides.pop(get_billing_registry, None)

    assert response.status_code == 200
    data = response.json()
    _assert_has_keys(
        data,
        {
            "status",
            "service",
            "timestamp",
            "environment",
            "kpis",
            "alerts",
            "activity",
            "metadata",
        },
    )
    assert data["status"] == "ok"
    assert "subscription" in data["metadata"]
    sub = data["metadata"]["subscription"]
    assert sub["plan"] == "pro"
    assert sub["status"] == "active"
    assert sub["units_consumed"] == 100
    assert sub["unit_limit"] == 5000
    assert sub["remaining_units"] == 4900
    mock_billing_registry.get_active_subscription_for_customer.assert_called_once_with("demo@ironclaw.local")


def test_dashboard_overview_filters_current_owner_paid_install_keys(client: TestClient) -> None:
    owner_key = "owner@example.com"

    current_key = MagicMock()
    current_key.key_id = "ik_current_001"
    current_key.owner_key = owner_key
    current_key.program = "openclaw"
    current_key.masked_key = "ic_install_openclaw_...abcd"
    current_key.label = "OpenClaw"
    current_key.active = True
    current_key.status = "active"
    current_key.payment_status = "paid"
    current_key.entitlements_status = "active"
    current_key.issued_after_payment = True
    current_key.units_consumed = 7
    current_key.created_at = None
    current_key.activated_at = None
    current_key.revoked_at = None
    current_key.last_used_at = None

    other_owner_key = MagicMock()
    other_owner_key.key_id = "ik_other_001"
    other_owner_key.owner_key = "other@example.com"
    other_owner_key.program = "claude_code"
    other_owner_key.masked_key = "ic_install_claude_code_...efgh"
    other_owner_key.label = "Claude Code"
    other_owner_key.active = True
    other_owner_key.status = "active"
    other_owner_key.payment_status = "paid"
    other_owner_key.entitlements_status = "active"
    other_owner_key.issued_after_payment = True
    other_owner_key.units_consumed = 9
    other_owner_key.created_at = None
    other_owner_key.activated_at = None
    other_owner_key.revoked_at = None
    other_owner_key.last_used_at = None

    system_api_key = MagicMock()
    system_api_key.key_id = "key-system-001"
    system_api_key.owner_key = owner_key
    system_api_key.program = "system"
    system_api_key.masked_key = "ic_abc1234567890"
    system_api_key.label = "System API"
    system_api_key.active = True
    system_api_key.status = "active"
    system_api_key.payment_status = "paid"
    system_api_key.entitlements_status = "active"
    system_api_key.issued_after_payment = True
    system_api_key.units_consumed = 0
    system_api_key.created_at = None
    system_api_key.activated_at = None
    system_api_key.revoked_at = None
    system_api_key.last_used_at = None

    mock_registry = MagicMock()
    mock_registry.get_keys_for_owner.return_value = [current_key, other_owner_key, system_api_key]

    app.dependency_overrides[get_unit_wallet_registry] = _make_mock_wallet_registry
    app.dependency_overrides[get_billing_registry] = _make_mock_billing_registry
    app.dependency_overrides[get_install_key_registry] = lambda: mock_registry
    try:
        response = client.get(f"/dashboard/overview?owner_key={owner_key}")
    finally:
        app.dependency_overrides.pop(get_unit_wallet_registry, None)
        app.dependency_overrides.pop(get_billing_registry, None)
        app.dependency_overrides.pop(get_install_key_registry, None)

    assert response.status_code == 200
    body = response.json()
    keys = body.get("install_keys", [])
    expected_platforms = {
        "openclaw",
        "claude_code",
        "cursor",
        "goose",
        "gemini_cli",
        "copilot",
        "hermes",
    }
    assert len(keys) == len(expected_platforms)
    by_program = {item["program"]: item for item in keys}
    assert expected_platforms.issubset(by_program.keys())
    assert "security_guardian" not in by_program
    assert by_program["openclaw"]["key_id"] == "ik_current_001"
    assert by_program["openclaw"]["status"] == "active"
    assert by_program["claude_code"]["status"] == "locked"
    assert by_program["claude_code"]["payment_status"] == "unpaid"
    assert by_program["claude_code"]["entitlements_status"] == "not_active"
    assert by_program["claude_code"]["metadata"]["placeholder"] == "Keys will be generated after purchase"
    assert by_program["claude_code"]["label"] == "Claude Code"
    assert body["metadata"]["owner_key"] == owner_key
    assert all((item["masked_key"] is None and not item["key_id"]) or item["masked_key"].startswith("ic_install_") for item in keys)
    assert all((not item["key_id"]) or "payment_status" in item for item in keys)
    assert all((not item["key_id"]) or "entitlements_status" in item for item in keys)
    assert all("metadata" in item for item in keys)


# ===========================================================================
# /dashboard/organizations — public shape contracts
# ===========================================================================


def test_organizations_response_contract(client: TestClient) -> None:
    response = client.get("/organizations")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    data = response.json()
    assert isinstance(data, dict)
    _assert_has_keys(data, {"status", "service", "timestamp", "total", "items"})


def test_ui_routes_response_contract(client: TestClient) -> None:
    response = client.get("/ui/routes")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    data = response.json()
    assert isinstance(data, dict)
    _assert_has_keys(
        data,
        {"status", "service", "timestamp", "totalroutes", "routes", "metadata"},
    )


def test_ui_pages_response_contract(client: TestClient) -> None:
    response = client.get("/ui/pages")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    data = response.json()
    assert isinstance(data, dict)
    _assert_has_keys(
        data,
        {"generatedat", "summary", "sections", "items", "metadata"},
    )


def test_ui_manifest_response_contract(client: TestClient) -> None:
    response = client.get("/ui/manifest")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    data = response.json()
    assert isinstance(data, dict)
    _assert_has_keys(
        data,
        {"status", "service", "timestamp", "totalroutes", "routes", "metadata"},
    )


# ===========================================================================
# GET /dashboard/units — DashboardUnitsResponse contract
# ===========================================================================


def test_dashboard_units_response_contract_valid_owner_key(client: TestClient) -> None:
    mock_registry = MagicMock()
    mock_registry.get_keys_for_owner.return_value = [_make_mock_key_entry()]
    app.dependency_overrides[get_install_key_registry] = lambda: mock_registry
    try:
        response = client.get("/dashboard/units", params={"owner_key": "owner-test-001"})
    finally:
        app.dependency_overrides.pop(get_install_key_registry, None)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    data = response.json()
    assert isinstance(data, dict)
    _assert_has_keys(
        data,
        {"owner_key", "total_keys", "total_units_consumed", "keys", "timestamp"},
    )
    assert data["owner_key"] == "owner-test-001"
    assert isinstance(data["total_keys"], int)
    assert isinstance(data["total_units_consumed"], int)
    assert isinstance(data["keys"], list)
    assert isinstance(data["timestamp"], str)
    assert len(data["timestamp"]) > 0


def test_dashboard_units_keys_entry_shape(client: TestClient) -> None:
    mock_registry = MagicMock()
    mock_registry.get_keys_for_owner.return_value = [_make_mock_key_entry()]
    app.dependency_overrides[get_install_key_registry] = lambda: mock_registry
    try:
        response = client.get("/dashboard/units", params={"owner_key": "owner-test-001"})
    finally:
        app.dependency_overrides.pop(get_install_key_registry, None)

    assert response.status_code == 200
    data = response.json()
    assert len(data["keys"]) == 1
    entry = data["keys"][0]
    _assert_has_keys(
        entry,
        {"key_id", "program", "masked_key", "label", "active", "units_consumed", "last_used_at"},
    )
    assert entry["key_id"] == "key-abc-123"
    assert entry["units_consumed"] == 42
    assert isinstance(entry["active"], bool)


def test_dashboard_units_empty_owner_returns_zero_totals(client: TestClient) -> None:
    mock_registry = MagicMock()
    mock_registry.get_keys_for_owner.return_value = []
    app.dependency_overrides[get_install_key_registry] = lambda: mock_registry
    try:
        response = client.get("/dashboard/units", params={"owner_key": "owner-nobody"})
    finally:
        app.dependency_overrides.pop(get_install_key_registry, None)

    assert response.status_code == 200
    data = response.json()
    assert data["total_keys"] == 0
    assert data["total_units_consumed"] == 0
    assert data["keys"] == []


# ===========================================================================
# POST /dashboard/units/record — RecordKeyUsageResponse contract
# ===========================================================================


def test_record_key_usage_response_contract_valid_body(client: TestClient) -> None:
    mock_registry = MagicMock()
    mock_registry.record_key_usage.return_value = _make_mock_updated_key()
    app.dependency_overrides[get_install_key_registry] = lambda: mock_registry
    try:
        response = client.post(
            "/dashboard/units/record",
            json={"key_id": "key-abc-123", "units": 10},
        )
    finally:
        app.dependency_overrides.pop(get_install_key_registry, None)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    data = response.json()
    assert isinstance(data, dict)
    _assert_has_keys(data, {"key_id", "units_consumed", "last_used_at", "timestamp"})
    assert data["key_id"] == "key-abc-123"
    assert isinstance(data["units_consumed"], int)
    assert isinstance(data["timestamp"], str)
    assert len(data["timestamp"]) > 0


def test_record_key_usage_unknown_key_id_returns_404(client: TestClient) -> None:
    mock_registry = MagicMock()
    mock_registry.record_key_usage.side_effect = InstallKeyNotFoundError("key-unknown not found")
    app.dependency_overrides[get_install_key_registry] = lambda: mock_registry
    try:
        response = client.post(
            "/dashboard/units/record",
            json={"key_id": "key-unknown", "units": 5},
        )
    finally:
        app.dependency_overrides.pop(get_install_key_registry, None)

    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/json")
    data = response.json()
    assert "detail" in data


def test_record_key_usage_units_zero_rejected_by_schema(client: TestClient) -> None:
    response = client.post(
        "/dashboard/units/record",
        json={"key_id": "key-abc-123", "units": 0},
    )
    assert response.status_code == 422


def test_record_key_usage_units_negative_rejected_by_schema(client: TestClient) -> None:
    response = client.post(
        "/dashboard/units/record",
        json={"key_id": "key-abc-123", "units": -10},
    )
    assert response.status_code == 422


def test_record_key_usage_missing_key_id_rejected_by_schema(client: TestClient) -> None:
    response = client.post(
        "/dashboard/units/record",
        json={"units": 5},
    )
    assert response.status_code == 422


def test_record_key_usage_missing_units_rejected_by_schema(client: TestClient) -> None:
    response = client.post(
        "/dashboard/units/record",
        json={"key_id": "key-abc-123"},
    )
    assert response.status_code == 422
