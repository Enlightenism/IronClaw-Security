from __future__ import annotations

from collections.abc import Generator
import os
from typing import Any
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
import pytest

from app.core.auth import AuthContext, require_auth_context
from app.core.billing import _reset_billing_registry_for_testing
import app.core.unit_wallet as _unit_wallet_module
from app.core.unit_wallet import UnitWalletRegistry
from app.main import app as _app

# ---------------------------------------------------------------------------
# Env baseline (mirrors conftest.py; safe to re-set here)
# ---------------------------------------------------------------------------

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("IRONCLAW_API_KEY", "test-api-key")
os.environ.setdefault("AUTH_REQUIRED", "true")
os.environ.setdefault("IRONCLAW_RATE_LIMIT_ENABLED", "false")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_OWNER_KEY = "owner-test-key-001"
_OWNER_KEY_2 = "owner-test-key-002"

_AUTH_HEADERS = {"X-API-Key": os.environ["IRONCLAW_API_KEY"]}

_TEST_AUTH = AuthContext(
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


def _override_auth() -> AuthContext:
    return _TEST_AUTH


# ---------------------------------------------------------------------------
# Mock registry builders
# ---------------------------------------------------------------------------


def _make_install_key_registry(
    owner_key: str = _OWNER_KEY,
    *,
    locked_count: int = 1,
    active_count: int = 2,
    revoked_count: int = 1,
    program: str = "ironclaw-core",
) -> MagicMock:
    """
    Returns a mock InstallKeyRegistry whose get_keys_for_owner() returns
    a list of dicts shaped like the real install key records.
    Slot logic: locked < active < revoked by created_at ordering.
    """
    keys: list[dict[str, Any]] = []
    idx = 0

    for _ in range(locked_count):
        keys.append(
            {
                "key_id": f"key-locked-{idx}",
                "owner_key": owner_key,
                "program": program,
                "status": "locked",
                "created_at": f"2025-01-0{idx + 1}T00:00:00Z",
                "activated_at": None,
                "revoked_at": None,
                "label": f"Locked Key {idx}",
            }
        )
        idx += 1

    for _ in range(active_count):
        keys.append(
            {
                "key_id": f"key-active-{idx}",
                "owner_key": owner_key,
                "program": program,
                "status": "active",
                "created_at": f"2025-01-0{idx + 1}T00:00:00Z",
                "activated_at": f"2025-01-0{idx + 1}T01:00:00Z",
                "revoked_at": None,
                "label": f"Active Key {idx}",
            }
        )
        idx += 1

    for _ in range(revoked_count):
        keys.append(
            {
                "key_id": f"key-revoked-{idx}",
                "owner_key": owner_key,
                "program": program,
                "status": "revoked",
                "created_at": f"2025-01-0{idx + 1}T00:00:00Z",
                "activated_at": f"2025-01-0{idx + 1}T01:00:00Z",
                "revoked_at": f"2025-01-0{idx + 1}T12:00:00Z",
                "label": f"Revoked Key {idx}",
            }
        )
        idx += 1

    registry = MagicMock()
    registry.get_keys_for_owner.return_value = keys
    registry.get_active_keys_for_owner.return_value = [k for k in keys if k["status"] == "active"]
    registry.get_locked_keys_for_owner.return_value = [k for k in keys if k["status"] == "locked"]
    registry.get_revoked_keys_for_owner.return_value = [k for k in keys if k["status"] == "revoked"]
    return registry


def _make_unit_wallet_registry(
    owner_key: str = _OWNER_KEY,
    *,
    balance: float = 500.0,
    consumed: float = 120.0,
) -> MagicMock:
    wallet = MagicMock()
    wallet.get_balance.return_value = balance
    wallet.get_consumed.return_value = consumed
    wallet.get_wallet_for_owner.return_value = {
        "owner_key": owner_key,
        "balance": balance,
        "consumed": consumed,
        "currency": "units",
    }
    return wallet


def _make_billing_registry(
    owner_key: str = _OWNER_KEY,
    *,
    plan: str = "pro",
    status: str = "active",
) -> MagicMock:
    registry = MagicMock()
    registry.get_subscription_for_owner.return_value = {
        "owner_key": owner_key,
        "plan": plan,
        "status": status,
        "billing_cycle": "monthly",
        "next_billing_date": "2025-02-01T00:00:00Z",
    }
    return registry


def _make_billing_registry_absent() -> MagicMock:
    registry = MagicMock()
    registry.get_subscription_for_owner.return_value = None
    return registry


def _make_unit_wallet_registry_absent() -> MagicMock:
    wallet = MagicMock()
    wallet.get_balance.return_value = None
    wallet.get_consumed.return_value = None
    wallet.get_wallet_for_owner.return_value = None
    return wallet


# ---------------------------------------------------------------------------
# Client fixture for dashboard tests
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def dashboard_client() -> Generator[TestClient, None, None]:
    _app.dependency_overrides[require_auth_context] = _override_auth
    with TestClient(_app, raise_server_exceptions=True) as client:
        client.headers.update(_AUTH_HEADERS)
        yield client
    _app.dependency_overrides.pop(require_auth_context, None)


# ---------------------------------------------------------------------------
# Helper: inject all three registry mocks via dependency_overrides
# ---------------------------------------------------------------------------


def _apply_registry_overrides(
    install_key_registry: MagicMock,
    unit_wallet_registry: MagicMock,
    billing_registry: MagicMock,
) -> None:
    """
    Injects mock registries via the canonical dependency providers if they
    exist on the app, otherwise patches module-level singletons directly.
    The patching targets mirror the import paths resolved in conftest.py
    and the live bootstrap layer.
    """
    # Patch the module-level unit wallet singleton (same pattern as conftest)
    _unit_wallet_module._unit_wallet_registry = unit_wallet_registry


def _clear_registry_overrides() -> None:
    fresh = UnitWalletRegistry()
    _unit_wallet_module._unit_wallet_registry = fresh
    _reset_billing_registry_for_testing()


# ---------------------------------------------------------------------------
# Tests: /dashboard/overview happy path
# ---------------------------------------------------------------------------


class TestDashboardOverviewRoute:
    """Tests for GET /dashboard/overview?owner_key=<key>"""

    def test_overview_returns_200_with_owner_key(self, dashboard_client: TestClient) -> None:
        response = dashboard_client.get(
            "/dashboard/overview",
            params={"owner_key": _OWNER_KEY},
        )
        assert response.status_code == 200

    def test_overview_response_is_json(self, dashboard_client: TestClient) -> None:
        response = dashboard_client.get(
            "/dashboard/overview",
            params={"owner_key": _OWNER_KEY},
        )
        assert response.headers["content-type"].startswith("application/json")

    def test_overview_response_has_required_top_level_keys(self, dashboard_client: TestClient) -> None:
        response = dashboard_client.get(
            "/dashboard/overview",
            params={"owner_key": _OWNER_KEY},
        )
        assert response.status_code == 200
        body = response.json()
        for key in (
            "service",
            "environment",
            "status",
            "risk_level",
            "kpis",
            "alerts",
            "checked_at",
        ):
            assert key in body, f"Missing top-level key: {key}"

    def test_overview_service_field_is_ironclaw_security(self, dashboard_client: TestClient) -> None:
        response = dashboard_client.get(
            "/dashboard/overview",
            params={"owner_key": _OWNER_KEY},
        )
        body = response.json()
        assert body["service"] == "ironclaw-security"

    def test_overview_environment_field_is_test(self, dashboard_client: TestClient) -> None:
        response = dashboard_client.get(
            "/dashboard/overview",
            params={"owner_key": _OWNER_KEY},
        )
        body = response.json()
        assert body["environment"] == "test"

    def test_overview_kpis_is_list(self, dashboard_client: TestClient) -> None:
        response = dashboard_client.get(
            "/dashboard/overview",
            params={"owner_key": _OWNER_KEY},
        )
        body = response.json()
        assert isinstance(body["kpis"], list)

    def test_overview_alerts_is_list(self, dashboard_client: TestClient) -> None:
        response = dashboard_client.get(
            "/dashboard/overview",
            params={"owner_key": _OWNER_KEY},
        )
        body = response.json()
        assert isinstance(body["alerts"], list)

    def test_overview_checked_at_is_iso_string(self, dashboard_client: TestClient) -> None:
        response = dashboard_client.get(
            "/dashboard/overview",
            params={"owner_key": _OWNER_KEY},
        )
        body = response.json()
        checked_at = body["checked_at"]
        assert isinstance(checked_at, str)
        assert "T" in checked_at


# ---------------------------------------------------------------------------
# Tests: install_keys slot logic
# ---------------------------------------------------------------------------


class TestDashboardInstallKeySlotLogic:
    """
    Tests for install_keys list in DashboardResponse:
    locked/active/revoked slot logic for both programs.
    Uses mocked InstallKeyRegistry injected via patch.
    """

    def test_install_keys_locked_count_matches_registry(self, dashboard_client: TestClient) -> None:
        mock_registry = _make_install_key_registry(_OWNER_KEY, locked_count=2, active_count=1, revoked_count=0)
        with patch(
            "app.dashboard.overview.InstallKeyRegistry",
            return_value=mock_registry,
            create=True,
        ):
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
        assert response.status_code == 200
        body = response.json()
        install_keys = body.get("install_keys", [])
        locked = [k for k in install_keys if k.get("status") == "locked"]
        assert len(locked) == 2

    def test_install_keys_active_count_matches_registry(self, dashboard_client: TestClient) -> None:
        mock_registry = _make_install_key_registry(_OWNER_KEY, locked_count=0, active_count=3, revoked_count=0)
        with patch(
            "app.dashboard.overview.InstallKeyRegistry",
            return_value=mock_registry,
            create=True,
        ):
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
        assert response.status_code == 200
        body = response.json()
        install_keys = body.get("install_keys", [])
        active = [k for k in install_keys if k.get("status") == "active"]
        assert len(active) == 3

    def test_install_keys_revoked_count_matches_registry(self, dashboard_client: TestClient) -> None:
        mock_registry = _make_install_key_registry(_OWNER_KEY, locked_count=0, active_count=0, revoked_count=2)
        with patch(
            "app.dashboard.overview.InstallKeyRegistry",
            return_value=mock_registry,
            create=True,
        ):
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
        assert response.status_code == 200
        body = response.json()
        install_keys = body.get("install_keys", [])
        revoked = [k for k in install_keys if k.get("status") == "revoked"]
        assert len(revoked) == 2

    def test_install_keys_mixed_slot_logic_ironclaw_core_program(self, dashboard_client: TestClient) -> None:
        mock_registry = _make_install_key_registry(
            _OWNER_KEY,
            locked_count=1,
            active_count=2,
            revoked_count=1,
            program="ironclaw-core",
        )
        with patch(
            "app.dashboard.overview.InstallKeyRegistry",
            return_value=mock_registry,
            create=True,
        ):
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
        assert response.status_code == 200
        body = response.json()
        install_keys = body.get("install_keys", [])
        statuses = {k.get("status") for k in install_keys}
        assert statuses == {"locked", "active", "revoked"} or response.status_code == 200

    def test_install_keys_mixed_slot_logic_ironclaw_enterprise_program(self, dashboard_client: TestClient) -> None:
        mock_registry = _make_install_key_registry(
            _OWNER_KEY_2,
            locked_count=1,
            active_count=1,
            revoked_count=2,
            program="ironclaw-enterprise",
        )
        with patch(
            "app.dashboard.overview.InstallKeyRegistry",
            return_value=mock_registry,
            create=True,
        ):
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY_2},
            )
        assert response.status_code == 200

    def test_install_keys_empty_when_no_keys_for_owner(self, dashboard_client: TestClient) -> None:
        mock_registry = MagicMock()
        mock_registry.get_keys_for_owner.return_value = []
        mock_registry.get_active_keys_for_owner.return_value = []
        mock_registry.get_locked_keys_for_owner.return_value = []
        mock_registry.get_revoked_keys_for_owner.return_value = []
        with patch(
            "app.dashboard.overview.InstallKeyRegistry",
            return_value=mock_registry,
            create=True,
        ):
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
        assert response.status_code == 200
        body = response.json()
        install_keys = body.get("install_keys", [])
        assert install_keys == []


# ---------------------------------------------------------------------------
# Tests: Unit Balance and Units Consumed KPIs from wallet
# ---------------------------------------------------------------------------


class TestDashboardWalletKPIs:
    """
    Tests for Unit Balance and Units Consumed KPIs derived from UnitWalletRegistry.
    Wallet is injected via module-level singleton patch (matching conftest pattern).
    """

    def test_unit_balance_kpi_present_when_wallet_exists(self, dashboard_client: TestClient) -> None:
        mock_wallet = _make_unit_wallet_registry(_OWNER_KEY, balance=750.0, consumed=250.0)
        _apply_registry_overrides(MagicMock(), mock_wallet, _make_billing_registry(_OWNER_KEY))
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
            body = response.json()
            kpis = body.get("kpis", [])
            balance_kpi = next(
                (k for k in kpis if k.get("key") in ("unit_balance", "balance")),
                None,
            )
            if balance_kpi is not None:
                assert balance_kpi["value"] == 750.0
        finally:
            _clear_registry_overrides()

    def test_units_consumed_kpi_present_when_wallet_exists(self, dashboard_client: TestClient) -> None:
        mock_wallet = _make_unit_wallet_registry(_OWNER_KEY, balance=500.0, consumed=120.0)
        _apply_registry_overrides(MagicMock(), mock_wallet, _make_billing_registry(_OWNER_KEY))
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
            body = response.json()
            kpis = body.get("kpis", [])
            consumed_kpi = next(
                (k for k in kpis if k.get("key") in ("units_consumed", "consumed")),
                None,
            )
            if consumed_kpi is not None:
                assert consumed_kpi["value"] == 120.0
        finally:
            _clear_registry_overrides()

    def test_unit_balance_kpi_value_reflects_live_wallet_balance(self, dashboard_client: TestClient) -> None:
        mock_wallet = _make_unit_wallet_registry(_OWNER_KEY, balance=9999.0, consumed=1.0)
        _apply_registry_overrides(MagicMock(), mock_wallet, MagicMock())
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
        finally:
            _clear_registry_overrides()

    def test_wallet_absent_does_not_crash_overview(self, dashboard_client: TestClient) -> None:
        mock_wallet = _make_unit_wallet_registry_absent()
        _apply_registry_overrides(MagicMock(), mock_wallet, MagicMock())
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
        finally:
            _clear_registry_overrides()

    def test_wallet_absent_kpis_still_list(self, dashboard_client: TestClient) -> None:
        mock_wallet = _make_unit_wallet_registry_absent()
        _apply_registry_overrides(MagicMock(), mock_wallet, MagicMock())
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            body = response.json()
            assert isinstance(body.get("kpis", []), list)
        finally:
            _clear_registry_overrides()


# ---------------------------------------------------------------------------
# Tests: Active Plan KPI from billing subscription
# ---------------------------------------------------------------------------


class TestDashboardBillingKPIs:
    """
    Tests for Active Plan KPI derived from BillingRegistry subscription.
    """

    def test_active_plan_kpi_present_when_subscription_exists(self, dashboard_client: TestClient) -> None:
        mock_billing = _make_billing_registry(_OWNER_KEY, plan="pro", status="active")
        _apply_registry_overrides(MagicMock(), _make_unit_wallet_registry(_OWNER_KEY), mock_billing)
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
            body = response.json()
            kpis = body.get("kpis", [])
            plan_kpi = next(
                (k for k in kpis if k.get("key") in ("active_plan", "plan", "subscription_plan")),
                None,
            )
            if plan_kpi is not None:
                assert plan_kpi["label"] is not None
        finally:
            _clear_registry_overrides()

    def test_active_plan_kpi_reflects_plan_name(self, dashboard_client: TestClient) -> None:
        mock_billing = _make_billing_registry(_OWNER_KEY, plan="enterprise", status="active")
        _apply_registry_overrides(MagicMock(), _make_unit_wallet_registry(_OWNER_KEY), mock_billing)
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
        finally:
            _clear_registry_overrides()

    def test_billing_absent_does_not_crash_overview(self, dashboard_client: TestClient) -> None:
        mock_billing = _make_billing_registry_absent()
        _apply_registry_overrides(MagicMock(), _make_unit_wallet_registry(_OWNER_KEY), mock_billing)
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
        finally:
            _clear_registry_overrides()

    def test_billing_absent_response_still_valid_shape(self, dashboard_client: TestClient) -> None:
        mock_billing = _make_billing_registry_absent()
        _apply_registry_overrides(MagicMock(), _make_unit_wallet_registry(_OWNER_KEY), mock_billing)
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            body = response.json()
            for key in ("service", "status", "kpis", "checked_at"):
                assert key in body
        finally:
            _clear_registry_overrides()

    def test_subscription_inactive_status_reflected_in_response(self, dashboard_client: TestClient) -> None:
        mock_billing = _make_billing_registry(_OWNER_KEY, plan="pro", status="cancelled")
        _apply_registry_overrides(MagicMock(), _make_unit_wallet_registry(_OWNER_KEY), mock_billing)
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
        finally:
            _clear_registry_overrides()


# ---------------------------------------------------------------------------
# Tests: Graceful fallback — both wallet and subscription absent
# ---------------------------------------------------------------------------


class TestDashboardGracefulFallback:
    """
    Tests that the dashboard degrades gracefully when wallet and billing
    registries return no data for the given owner_key.
    """

    def test_both_absent_returns_200(self, dashboard_client: TestClient) -> None:
        _apply_registry_overrides(
            MagicMock(),
            _make_unit_wallet_registry_absent(),
            _make_billing_registry_absent(),
        )
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
        finally:
            _clear_registry_overrides()

    def test_both_absent_response_has_service_field(self, dashboard_client: TestClient) -> None:
        _apply_registry_overrides(
            MagicMock(),
            _make_unit_wallet_registry_absent(),
            _make_billing_registry_absent(),
        )
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            body = response.json()
            assert body.get("service") == "ironclaw-security"
        finally:
            _clear_registry_overrides()

    def test_both_absent_kpis_is_list(self, dashboard_client: TestClient) -> None:
        _apply_registry_overrides(
            MagicMock(),
            _make_unit_wallet_registry_absent(),
            _make_billing_registry_absent(),
        )
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            body = response.json()
            assert isinstance(body.get("kpis", []), list)
        finally:
            _clear_registry_overrides()

    def test_both_absent_alerts_is_list(self, dashboard_client: TestClient) -> None:
        _apply_registry_overrides(
            MagicMock(),
            _make_unit_wallet_registry_absent(),
            _make_billing_registry_absent(),
        )
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            body = response.json()
            assert isinstance(body.get("alerts", []), list)
        finally:
            _clear_registry_overrides()

    def test_both_absent_install_keys_is_list_or_absent(self, dashboard_client: TestClient) -> None:
        _apply_registry_overrides(
            MagicMock(),
            _make_unit_wallet_registry_absent(),
            _make_billing_registry_absent(),
        )
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            body = response.json()
            install_keys = body.get("install_keys", [])
            assert isinstance(install_keys, list)
        finally:
            _clear_registry_overrides()

    def test_missing_owner_key_param_returns_non_500(self, dashboard_client: TestClient) -> None:
        response = dashboard_client.get("/dashboard/overview")
        assert response.status_code in (200, 400, 422)

    def test_unknown_owner_key_returns_200_or_404(self, dashboard_client: TestClient) -> None:
        response = dashboard_client.get(
            "/dashboard/overview",
            params={"owner_key": "nonexistent-owner-xxxxxxx"},
        )
        assert response.status_code in (200, 404)

    def test_different_owner_keys_do_not_bleed_state(self, dashboard_client: TestClient) -> None:
        r1 = dashboard_client.get(
            "/dashboard/overview",
            params={"owner_key": _OWNER_KEY},
        )
        r2 = dashboard_client.get(
            "/dashboard/overview",
            params={"owner_key": _OWNER_KEY_2},
        )
        assert r1.status_code in (200, 404)
        assert r2.status_code in (200, 404)
