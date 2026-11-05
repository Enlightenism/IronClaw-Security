from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime
import os
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
import pytest

from app.core.auth import AuthContext, get_auth_context, require_auth_context
from app.core.billing import (
    UNIT_PACKAGE_CATALOG,
    BillingRegistry,
    _reset_billing_registry_for_testing,
    get_billing_registry,
)
from app.core.install_keys import (
    InstallKeyRegistry,
    get_install_key_registry,
)
import app.core.unit_wallet as _unit_wallet_module
from app.core.unit_wallet import UnitWalletRegistry, get_unit_wallet_registry
from app.dependencies.hybrid_auth import HybridAuthResult
from app.main import app as _app
from app.routes.dashboard import _build_install_key_slots, _resolve_dashboard_owner
from app.services.audit_store import reset_security_audit_store
from app.services.block_store import record_block, reset_block_store
from app.services.incident_store import get_incident_store, reset_incident_store
from app.services.install_key_provisioning import provision_install_key_service

# ---------------------------------------------------------------------------
# Env baseline
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


def _auth_context_for_owner(owner_key: str) -> AuthContext:
    return AuthContext(
        api_key="test-api-key",
        principal_type="customer",
        principal_id=owner_key,
        session_id=None,
        org_id=None,
        permissions=("customer:read", "customer:write"),
        roles=("customer_admin",),
        authenticated=True,
        auth_source="test",
        auth_method="test",
        metadata={"owner_key": owner_key},
    )


_TEST_AUTH = _auth_context_for_owner(_OWNER_KEY)


def _override_auth() -> AuthContext:
    return _TEST_AUTH


# ---------------------------------------------------------------------------
# Mock record builders — attribute-based (matching InstallKeyRecord dataclass)
# ---------------------------------------------------------------------------


def _make_key_record(
    key_id: str,
    owner_key: str,
    program: str,
    *,
    active: bool,
    revoked_at: datetime | None = None,
    activated_at: datetime | None = None,
    label: str = "",
) -> MagicMock:
    """
    Returns a MagicMock shaped like an InstallKeyRecord dataclass.
    The router accesses attributes directly via getattr; dicts will not work.
    """
    prefix_map = {
        "openclaw": "ic_install_openclaw_",
        "claude_code": "ic_install_claude_code_",
        "cursor": "ic_install_cursor_",
        "goose": "ic_install_goose_",
        "gemini_cli": "ic_install_gemini_cli_",
        "copilot": "ic_install_copilot_",
        "hermes": "ic_install_hermes_",
        "security_guardian": "ic_install_security_guardian_",
    }
    r = MagicMock()
    r.key_id = key_id
    r.owner_key = owner_key
    r.program = program
    r.masked_key = f"{prefix_map.get(program, 'ic_install_openclaw_')}{key_id[:8]}...abcd"
    r.label = label
    r.active = active
    r.units_consumed = 0
    r.status = "revoked" if revoked_at is not None else ("active" if active else "locked")
    r.created_at = datetime(2025, 1, 1, tzinfo=UTC)
    r.activated_at = activated_at
    r.revoked_at = revoked_at
    r.last_used_at = None
    return r


def _make_install_key_registry(
    owner_key: str = _OWNER_KEY,
    *,
    locked_count: int = 1,
    active_count: int = 2,
    revoked_count: int = 1,
    program: str = "openclaw",
) -> MagicMock:
    """
    Returns a mock InstallKeyRegistry whose get_keys_for_owner() returns
    a list of MagicMock objects shaped like real InstallKeyRecord dataclasses.
    Slot logic: locked (active=False, no revoked_at), active (active=True),
    revoked (revoked_at set).
    """
    records: list[MagicMock] = []
    idx = 0

    for _i in range(locked_count):
        records.append(
            _make_key_record(
                f"key-locked-{idx}",
                owner_key,
                program,
                active=False,
                label=f"Locked Key {idx}",
            )
        )
        idx += 1

    for _i in range(active_count):
        records.append(
            _make_key_record(
                f"key-active-{idx}",
                owner_key,
                program,
                active=True,
                activated_at=datetime(2025, 1, idx + 1, 1, tzinfo=UTC),
                label=f"Active Key {idx}",
            )
        )
        idx += 1

    for _i in range(revoked_count):
        records.append(
            _make_key_record(
                f"key-revoked-{idx}",
                owner_key,
                program,
                active=False,
                activated_at=datetime(2025, 1, idx + 1, 1, tzinfo=UTC),
                revoked_at=datetime(2025, 1, idx + 1, 12, tzinfo=UTC),
                label=f"Revoked Key {idx}",
            )
        )
        idx += 1

    registry = MagicMock(spec=InstallKeyRegistry)
    registry.get_keys_for_owner.return_value = records
    return registry


def _make_unit_wallet_registry(
    owner_key: str = _OWNER_KEY,
    *,
    balance: int = 500,
    consumed: int = 120,
    purchased: int = 620,
) -> MagicMock:
    """
    Returns a mock UnitWalletRegistry.
    The router calls registry.get_wallet(owner_key) and then accesses
    wallet.balance_units, wallet.total_consumed_units,
    wallet.total_purchased_units, wallet.updated_at on the returned object.
    """
    wallet = MagicMock()
    wallet.balance_units = balance
    wallet.total_consumed_units = consumed
    wallet.total_purchased_units = purchased
    wallet.updated_at = datetime(2025, 6, 1, tzinfo=UTC)

    registry = MagicMock(spec=UnitWalletRegistry)
    registry.get_wallet.return_value = wallet
    registry.get_or_create_wallet.return_value = wallet
    return registry


def _make_billing_registry(
    owner_key: str = _OWNER_KEY,
    *,
    plan: str = "starter-5k",
    status: str = "active",
) -> MagicMock:
    """
    Returns a mock BillingRegistry.
    The router calls registry.get_active_subscription_for_customer(owner_key)
    and accesses subscription.plan, .status, .units_consumed,
    .unit_limit, .remaining_units on the returned object.
    """
    subscription = MagicMock()
    subscription.plan = plan
    subscription.status = status
    subscription.units_consumed = 0
    subscription.unit_limit = 5000
    subscription.remaining_units = 5000

    registry = MagicMock(spec=BillingRegistry)
    registry.get_active_subscription_for_customer.return_value = subscription
    return registry


def _make_billing_registry_absent() -> MagicMock:
    registry = MagicMock(spec=BillingRegistry)
    registry.get_active_subscription_for_customer.return_value = None
    return registry


def _make_unit_wallet_registry_absent() -> MagicMock:
    registry = MagicMock(spec=UnitWalletRegistry)
    registry.get_wallet.return_value = None
    registry.get_or_create_wallet.side_effect = Exception("no wallet")
    return registry


# ---------------------------------------------------------------------------
# Client fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def dashboard_client() -> Generator[TestClient, None, None]:
    _app.dependency_overrides[require_auth_context] = _override_auth
    _app.dependency_overrides[get_auth_context] = _override_auth
    with TestClient(_app, raise_server_exceptions=True) as client:
        client.headers.update(_AUTH_HEADERS)
        yield client
    _app.dependency_overrides.pop(require_auth_context, None)
    _app.dependency_overrides.pop(get_auth_context, None)


# ---------------------------------------------------------------------------
# Helper: inject all three registry mocks via dependency_overrides
# ---------------------------------------------------------------------------


def _apply_registry_overrides(
    install_key_registry: MagicMock,
    unit_wallet_registry: MagicMock,
    billing_registry: MagicMock,
) -> None:
    """
    Injects mock registries via FastAPI dependency_overrides so that
    the route's Depends(get_install_key_registry),
    Depends(get_unit_wallet_registry), and Depends(get_billing_registry)
    all receive the mocks. Also patches the module-level unit wallet
    singleton for compatibility with direct module access.
    """
    _app.dependency_overrides[get_install_key_registry] = lambda: install_key_registry
    _app.dependency_overrides[get_unit_wallet_registry] = lambda: unit_wallet_registry
    _app.dependency_overrides[get_billing_registry] = lambda: billing_registry
    _unit_wallet_module._unit_wallet_registry = unit_wallet_registry


def _clear_registry_overrides() -> None:
    _app.dependency_overrides.pop(get_install_key_registry, None)
    _app.dependency_overrides.pop(get_unit_wallet_registry, None)
    _app.dependency_overrides.pop(get_billing_registry, None)
    _unit_wallet_module._unit_wallet_registry = UnitWalletRegistry()
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
            "wallet_units",
            "kpis",
            "alerts",
            "timestamp",
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

    def test_overview_timestamp_is_iso_string(self, dashboard_client: TestClient) -> None:
        response = dashboard_client.get(
            "/dashboard/overview",
            params={"owner_key": _OWNER_KEY},
        )
        body = response.json()
        ts = body["timestamp"]
        assert isinstance(ts, str)
        assert "T" in ts


# ---------------------------------------------------------------------------
# Tests: install_keys slot logic
# ---------------------------------------------------------------------------


class TestDashboardInstallKeySlotLogic:
    """
    Tests for install_keys list in DashboardResponse:
    locked/active/revoked slot logic injected via dependency_overrides.
    """

    def test_install_keys_locked_count_matches_registry(self, dashboard_client: TestClient) -> None:
        mock_registry = _make_install_key_registry(_OWNER_KEY, locked_count=2, active_count=1, revoked_count=0)
        _apply_registry_overrides(mock_registry, _make_unit_wallet_registry(), _make_billing_registry())
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
            body = response.json()
            install_keys = body.get("install_keys", [])
            locked = [k for k in install_keys if k.get("status") == "locked"]
            assert len(locked) == 6
            assert {k.get("program") for k in locked} == {
                "claude_code",
                "cursor",
                "goose",
                "gemini_cli",
                "copilot",
                "hermes",
            }
        finally:
            _clear_registry_overrides()

    def test_install_key_slot_requires_active_paid_record_with_issued_after_payment(self, dashboard_client: TestClient) -> None:
        record = MagicMock()
        record.key_id = "key-pending"
        record.owner_key = _OWNER_KEY
        record.program = "openclaw"
        record.masked_key = "ic_install_openclaw_...1234"
        record.active = True
        record.payment_status = "pending"
        record.entitlements_status = "active"
        record.issued_after_payment = False
        record.units_consumed = 0
        record.subscription_id = "sub_123"
        record.checkout_session_id = None
        record.purchase_reference = None
        record.last_used_at = None
        record.revoked_at = None

        mock_registry = MagicMock(spec=InstallKeyRegistry)
        mock_registry.get_keys_for_owner.return_value = [record]
        _apply_registry_overrides(mock_registry, _make_unit_wallet_registry(), _make_billing_registry())
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
            body = response.json()
            install_keys = body.get("install_keys", [])
            slot = next(item for item in install_keys if item.get("program") == "openclaw")
            assert slot["status"] == "locked"
            assert slot["active"] is False
        finally:
            _clear_registry_overrides()

    def test_dashboard_resolve_owner_rejects_generic_api_key_fallback(self) -> None:
        auth_result = HybridAuthResult(
            api_key="ic_legacy_system_key",
            auth_context=None,
            bearer_context=None,
            authenticated=True,
            auth_method="api_key",
        )
        owner = _resolve_dashboard_owner(None, auth_result, provision_install_key_service())
        assert owner == "demo@ironclaw.local"

    def test_install_keys_active_count_matches_registry(self, dashboard_client: TestClient) -> None:
        mock_registry = _make_install_key_registry(_OWNER_KEY, locked_count=0, active_count=3, revoked_count=0)
        _apply_registry_overrides(mock_registry, _make_unit_wallet_registry(), _make_billing_registry())
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
            body = response.json()
            install_keys = body.get("install_keys", [])
            active = [k for k in install_keys if k.get("status") == "active"]
            assert len(active) == 1
            assert {k.get("program") for k in active} == {"openclaw"}
        finally:
            _clear_registry_overrides()

    def test_install_keys_revoked_count_matches_registry(self, dashboard_client: TestClient) -> None:
        mock_registry = _make_install_key_registry(_OWNER_KEY, locked_count=0, active_count=0, revoked_count=2)
        _apply_registry_overrides(mock_registry, _make_unit_wallet_registry(), _make_billing_registry())
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
            body = response.json()
            install_keys = body.get("install_keys", [])
            revoked = [k for k in install_keys if k.get("status") == "revoked"]
            assert len(revoked) == 1
            assert {k.get("program") for k in revoked} == {"openclaw"}
        finally:
            _clear_registry_overrides()

    def test_install_keys_refunded_status_when_revoked_for_refund(self, dashboard_client: TestClient) -> None:
        mock_registry = _make_install_key_registry(_OWNER_KEY, locked_count=0, active_count=0, revoked_count=1)
        mock_registry.get_keys_for_owner.return_value[0].metadata = {"revoke_reason": "refunded"}
        _apply_registry_overrides(mock_registry, _make_unit_wallet_registry(), _make_billing_registry())
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
            body = response.json()
            install_keys = body.get("install_keys", [])
            refunded = [k for k in install_keys if k.get("status") == "refunded"]
            assert len(refunded) == 1
            assert refunded[0].get("revoked") is True
        finally:
            _clear_registry_overrides()

    def test_install_keys_mixed_slot_logic_openclaw_program(self, dashboard_client: TestClient) -> None:
        mock_registry = _make_install_key_registry(
            _OWNER_KEY,
            locked_count=1,
            active_count=2,
            revoked_count=1,
            program="openclaw",
        )
        _apply_registry_overrides(mock_registry, _make_unit_wallet_registry(), _make_billing_registry())
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
            body = response.json()
            install_keys = body.get("install_keys", [])
            statuses = {k.get("status") for k in install_keys}
            assert statuses == {"locked", "revoked"}
            assert any(k.get("program") == "openclaw" and k.get("status") == "revoked" for k in install_keys)
        finally:
            _clear_registry_overrides()

    def test_install_keys_mixed_slot_logic_claude_code_program(self, dashboard_client: TestClient) -> None:
        mock_registry = _make_install_key_registry(
            _OWNER_KEY_2,
            locked_count=1,
            active_count=1,
            revoked_count=2,
            program="claude_code",
        )
        _apply_registry_overrides(mock_registry, _make_unit_wallet_registry(_OWNER_KEY_2), _make_billing_registry(_OWNER_KEY_2))
        dashboard_client.app.dependency_overrides[get_auth_context] = lambda: _auth_context_for_owner(_OWNER_KEY_2)
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY_2},
            )
            assert response.status_code == 200
        finally:
            _clear_registry_overrides()

    def test_install_keys_empty_when_no_keys_for_owner(self, dashboard_client: TestClient) -> None:
        mock_registry = MagicMock(spec=InstallKeyRegistry)
        mock_registry.get_keys_for_owner.return_value = []
        _apply_registry_overrides(mock_registry, _make_unit_wallet_registry(), _make_billing_registry())
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
            body = response.json()
            install_keys = body.get("install_keys", [])
            assert len(install_keys) == 7
            assert {item["program"] for item in install_keys} == {
                "openclaw",
                "claude_code",
                "cursor",
                "goose",
                "gemini_cli",
                "copilot",
                "hermes",
            }
            assert all(item["status"] == "locked" for item in install_keys)
            assert all(item["masked_key"] is None for item in install_keys)
        finally:
            _clear_registry_overrides()

    def test_install_keys_show_placeholder_before_purchase(self) -> None:
        mock_registry = MagicMock(spec=InstallKeyRegistry)
        mock_registry.get_keys_for_owner.return_value = []
        slots = _build_install_key_slots(
            _OWNER_KEY,
            mock_registry,
            _make_unit_wallet_registry(),
            provision_install_key_service(),
        )

        assert len(slots) == 7
        assert {slot.program for slot in slots} == {
            "openclaw",
            "claude_code",
            "cursor",
            "goose",
            "gemini_cli",
            "copilot",
            "hermes",
        }
        assert all(slot.status == "locked" for slot in slots)
        assert all(slot.masked_key is None for slot in slots)
        assert any("Keys will be generated after purchase" in str(slot.metadata.get("placeholder_text") or slot.metadata.get("placeholder") or slot.metadata.get("status_message") or "") for slot in slots)

    def test_install_keys_hermes_slot_shows_active_paid_masked_key(self, dashboard_client: TestClient) -> None:
        mock_registry = MagicMock(spec=InstallKeyRegistry)
        hermes_record = _make_key_record(
            "key-hermes-active",
            _OWNER_KEY,
            "hermes",
            active=True,
            activated_at=datetime(2025, 1, 1, tzinfo=UTC),
            label="Hermes Key",
        )
        hermes_record.payment_status = "paid"
        hermes_record.entitlements_status = "active"
        hermes_record.issued_after_payment = True
        hermes_record.masked_key = "ic_install_hermes_...abcd"
        mock_registry.get_keys_for_owner.return_value = [hermes_record]
        _apply_registry_overrides(mock_registry, _make_unit_wallet_registry(), _make_billing_registry())
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
            body = response.json()
            slot = next(item for item in body.get("install_keys", []) if item.get("program") == "hermes")
            assert slot["status"] == "active"
            assert slot["active"] is True
            assert slot["payment_status"] == "paid"
            assert slot["masked_key"] == "ic_install_hermes_...abcd"
        finally:
            _clear_registry_overrides()

    def test_install_keys_each_entry_has_required_fields(self, dashboard_client: TestClient) -> None:
        mock_registry = _make_install_key_registry(_OWNER_KEY, locked_count=1, active_count=1, revoked_count=0)
        _apply_registry_overrides(mock_registry, _make_unit_wallet_registry(), _make_billing_registry())
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
            body = response.json()
            for key_entry in body.get("install_keys", []):
                for field in ("key_id", "program", "masked_key", "label", "status", "active", "locked", "revoked"):
                    assert field in key_entry, f"Missing field {field!r} in install_keys entry"
        finally:
            _clear_registry_overrides()


# ---------------------------------------------------------------------------
# Tests: Unit Balance and Units Consumed KPIs from wallet
# ---------------------------------------------------------------------------


class TestDashboardWalletKPIs:
    """
    Tests for wallet block in DashboardResponse derived from UnitWalletRegistry.
    """

    def test_wallet_block_present_when_wallet_exists(self, dashboard_client: TestClient) -> None:
        mock_wallet = _make_unit_wallet_registry(_OWNER_KEY, balance=750, consumed=250, purchased=1000)
        _apply_registry_overrides(_make_install_key_registry(), mock_wallet, _make_billing_registry(_OWNER_KEY))
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
            body = response.json()
            assert body["wallet_units"] == 750
        finally:
            _clear_registry_overrides()

    def test_last_payment_reflects_newest_package_credit(self, dashboard_client: TestClient) -> None:
        older_package = UNIT_PACKAGE_CATALOG[0]
        newer_package = UNIT_PACKAGE_CATALOG[-1]

        def _ledger_entry(package_id: str | None, entry_type: str, units: int, created_at: datetime) -> _unit_wallet_module.RegistryUnitLedgerEntry:
            return _unit_wallet_module.RegistryUnitLedgerEntry(
                entry_id=f"ledger_{entry_type}_{created_at.day}",
                wallet_id="wallet_test",
                owner_key=_OWNER_KEY,
                entry_type=entry_type,
                units=units,
                balance_after=units,
                created_at=created_at,
                metadata={"package_id": package_id} if package_id else {},
            )

        mock_wallet = _make_unit_wallet_registry(_OWNER_KEY)
        mock_wallet.list_ledger_entries.return_value = [
            _ledger_entry(older_package["package_id"], "credit", older_package["units"], datetime(2025, 6, 1, tzinfo=UTC)),
            _ledger_entry(newer_package["package_id"], "credit", newer_package["units"], datetime(2025, 6, 2, tzinfo=UTC)),
            _ledger_entry(None, "debit", 5, datetime(2025, 6, 3, tzinfo=UTC)),
        ]
        _apply_registry_overrides(_make_install_key_registry(), mock_wallet, _make_billing_registry(_OWNER_KEY))
        try:
            response = dashboard_client.get("/dashboard/overview", params={"owner_key": _OWNER_KEY})
            assert response.status_code == 200
            body = response.json()
            assert body["has_paid"] is True
            assert body["last_payment"]["package_id"] == newer_package["package_id"]
            assert body["last_payment"]["label"] == newer_package["name"]
            assert body["last_payment"]["amount"] == float(newer_package["price_usd"])
            assert body["last_payment"]["units"] == newer_package["units"]
        finally:
            _clear_registry_overrides()

    def test_last_payment_absent_without_package_credit(self, dashboard_client: TestClient) -> None:
        mock_wallet = _make_unit_wallet_registry(_OWNER_KEY)
        mock_wallet.list_ledger_entries.return_value = []
        _apply_registry_overrides(_make_install_key_registry(), mock_wallet, _make_billing_registry(_OWNER_KEY))
        try:
            response = dashboard_client.get("/dashboard/overview", params={"owner_key": _OWNER_KEY})
            assert response.status_code == 200
            body = response.json()
            assert body["has_paid"] is False
            assert body["last_payment"] is None
        finally:
            _clear_registry_overrides()

    def test_wallet_absent_does_not_crash_overview(self, dashboard_client: TestClient) -> None:
        mock_wallet = _make_unit_wallet_registry_absent()
        _apply_registry_overrides(_make_install_key_registry(), mock_wallet, _make_billing_registry())
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
            assert response.json()["wallet_units"] == 0
        finally:
            _clear_registry_overrides()

    def test_wallet_absent_kpis_still_list(self, dashboard_client: TestClient) -> None:
        mock_wallet = _make_unit_wallet_registry_absent()
        _apply_registry_overrides(_make_install_key_registry(), mock_wallet, _make_billing_registry())
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            body = response.json()
            assert isinstance(body.get("kpis", []), list)
        finally:
            _clear_registry_overrides()

    def test_wallet_balance_reflects_mock_value(self, dashboard_client: TestClient) -> None:
        mock_wallet = _make_unit_wallet_registry(_OWNER_KEY, balance=9999, consumed=1, purchased=10000)
        _apply_registry_overrides(_make_install_key_registry(), mock_wallet, _make_billing_registry())
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
            body = response.json()
            assert body["wallet_units"] == 9999
        finally:
            _clear_registry_overrides()


# ---------------------------------------------------------------------------
# Tests: Active Plan KPI from billing subscription
# ---------------------------------------------------------------------------


class TestDashboardBillingKPIs:
    """
    Tests for billing block in DashboardResponse derived from BillingRegistry subscription.
    """

    def test_billing_block_present_when_subscription_exists(self, dashboard_client: TestClient) -> None:
        mock_billing = _make_billing_registry(_OWNER_KEY, plan="starter-5k", status="active")
        _apply_registry_overrides(_make_install_key_registry(), _make_unit_wallet_registry(_OWNER_KEY), mock_billing)
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
            body = response.json()
            billing = body.get("billing")
            if billing is not None:
                assert billing["plan"] == "starter-5k"
                assert billing["status"] == "active"
        finally:
            _clear_registry_overrides()

    def test_billing_block_reflects_plan_name(self, dashboard_client: TestClient) -> None:
        mock_billing = _make_billing_registry(_OWNER_KEY, plan="enterprise-60k", status="active")
        _apply_registry_overrides(_make_install_key_registry(), _make_unit_wallet_registry(_OWNER_KEY), mock_billing)
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            assert response.status_code == 200
            body = response.json()
            billing = body.get("billing")
            if billing is not None:
                assert billing["plan"] == "enterprise-60k"
        finally:
            _clear_registry_overrides()

    def test_billing_absent_does_not_crash_overview(self, dashboard_client: TestClient) -> None:
        mock_billing = _make_billing_registry_absent()
        _apply_registry_overrides(_make_install_key_registry(), _make_unit_wallet_registry(_OWNER_KEY), mock_billing)
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
        _apply_registry_overrides(_make_install_key_registry(), _make_unit_wallet_registry(_OWNER_KEY), mock_billing)
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            body = response.json()
            for key in ("service", "status", "kpis", "timestamp"):
                assert key in body
        finally:
            _clear_registry_overrides()

    def test_subscription_inactive_status_reflected_in_response(self, dashboard_client: TestClient) -> None:
        mock_billing = _make_billing_registry(_OWNER_KEY, plan="starter-5k", status="cancelled")
        _apply_registry_overrides(_make_install_key_registry(), _make_unit_wallet_registry(_OWNER_KEY), mock_billing)
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
            _make_install_key_registry(),
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
            _make_install_key_registry(),
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
            _make_install_key_registry(),
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
            _make_install_key_registry(),
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

    def test_both_absent_install_keys_is_list(self, dashboard_client: TestClient) -> None:
        _apply_registry_overrides(
            _make_install_key_registry(),
            _make_unit_wallet_registry_absent(),
            _make_billing_registry_absent(),
        )
        try:
            response = dashboard_client.get(
                "/dashboard/overview",
                params={"owner_key": _OWNER_KEY},
            )
            body = response.json()
            assert isinstance(body.get("install_keys", []), list)
        finally:
            _clear_registry_overrides()

    def test_missing_owner_key_param_returns_non_500(self, dashboard_client: TestClient) -> None:
        response = dashboard_client.get("/dashboard/overview")
        assert response.status_code in (200, 400, 422)

    def test_unknown_owner_key_is_rejected_for_authenticated_customer(self, dashboard_client: TestClient) -> None:
        response = dashboard_client.get(
            "/dashboard/overview",
            params={"owner_key": "nonexistent-owner-xxxxxxx"},
        )
        assert response.status_code == 403

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
        assert r2.status_code == 403


class TestDashboardRuntimeBlocks:
    def test_runtime_blocks_route_returns_owner_blocks(self, dashboard_client: TestClient) -> None:
        reset_block_store()
        record_block(gate="install", platform="claude_code", reason_codes=["unpinned_install"], owner_key=_OWNER_KEY)
        try:
            response = dashboard_client.get("/dashboard/runtime-blocks", params={"owner_key": _OWNER_KEY})
            assert response.status_code == 200
            body = response.json()
            assert body["owner_key"] == _OWNER_KEY
            assert body["total"] == 1
            block = body["blocks"][0]
            assert block["gate"] == "install"
            assert block["verdict"] == "block"
            assert block["id"]
            assert "owner_key" not in block
        finally:
            reset_block_store()

    def test_runtime_blocks_route_rejects_unknown_owner(self, dashboard_client: TestClient) -> None:
        response = dashboard_client.get("/dashboard/runtime-blocks", params={"owner_key": "nonexistent-owner-xxxxxxx"})
        assert response.status_code == 403

    def test_runtime_blocks_limit_is_bounded(self, dashboard_client: TestClient) -> None:
        assert dashboard_client.get("/dashboard/runtime-blocks", params={"owner_key": _OWNER_KEY, "limit": 0}).status_code == 422
        assert dashboard_client.get("/dashboard/runtime-blocks", params={"owner_key": _OWNER_KEY, "limit": 501}).status_code == 422

    def test_overview_includes_runtime_blocks(self, dashboard_client: TestClient) -> None:
        reset_block_store()
        record_block(gate="install", platform="claude_code", reason_codes=["unpinned_install"], owner_key=_OWNER_KEY)
        mock_wallet = _make_unit_wallet_registry(_OWNER_KEY)
        mock_wallet.list_ledger_entries.return_value = []
        _apply_registry_overrides(_make_install_key_registry(), mock_wallet, _make_billing_registry(_OWNER_KEY))
        try:
            response = dashboard_client.get("/dashboard/overview", params={"owner_key": _OWNER_KEY})
            assert response.status_code == 200
            runtime_blocks = response.json()["runtime_blocks"]
            assert len(runtime_blocks) == 1
            assert runtime_blocks[0]["gate"] == "install"
        finally:
            _clear_registry_overrides()
            reset_block_store()

    def test_overview_kpis_exclude_seeded_incidents(self, dashboard_client: TestClient) -> None:
        mock_wallet = _make_unit_wallet_registry(_OWNER_KEY)
        mock_wallet.list_ledger_entries.return_value = []
        _apply_registry_overrides(_make_install_key_registry(), mock_wallet, _make_billing_registry(_OWNER_KEY))

        def _open_incidents() -> int:
            body = dashboard_client.get("/dashboard/overview", params={"owner_key": _OWNER_KEY}).json()
            return next(kpi["value"] for kpi in body["kpis"] if kpi["key"] == "open_incidents")

        try:
            baseline = _open_incidents()
            get_incident_store().create_incident(
                title="Seeded sample",
                summary="Seeded sample",
                severity="high",
                source="guard",
                status="open",
                metadata={"seeded": True, "owner_key": _OWNER_KEY},
            )
            assert _open_incidents() == baseline
            get_incident_store().create_incident(
                title="Live gate block",
                summary="Live gate block",
                severity="high",
                source="guard",
                status="open",
                metadata={"owner_key": _OWNER_KEY},
            )
            assert _open_incidents() == baseline + 1
        finally:
            _clear_registry_overrides()
            reset_incident_store()
            reset_security_audit_store()
