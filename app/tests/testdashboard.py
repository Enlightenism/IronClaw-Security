from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.core.install_key_formats import InstallKeyFormatRegistry
from app.core.install_keys import (
    InstallKeyNotFoundError,
    InstallKeyRecord,
    InstallKeyUsageError,
    _reset_install_key_registry_for_testing,
    get_install_key_registry,
)
from app.core.unit_wallet import get_unit_wallet_registry
from app.dependencies.hybrid_auth import HybridAuthResult, require_hybrid_auth
from app.routes.dashboard import router

_OWNER = "owner_dash_001"
_KEY_ID = "ik_dash_aabb"


@pytest.fixture(scope="module")
def app() -> FastAPI:
    application = FastAPI()
    application.include_router(router)
    return application


@pytest.fixture(scope="module")
def client(app: FastAPI) -> TestClient:
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture(autouse=True)
def _reset_singleton() -> Generator[None, None, None]:
    _reset_install_key_registry_for_testing()
    yield
    _reset_install_key_registry_for_testing()


def _auth_override() -> HybridAuthResult:
    return HybridAuthResult(
        api_key=None,
        auth_context=None,
        bearer_context=None,
        authenticated=True,
        auth_method="test",
    )


def _make_record(
    *,
    key_id: str = _KEY_ID,
    owner_key: str = _OWNER,
    program: str = "openclaw",
    masked_key: str = "ic_install_op...alue",
    label: str = "",
    active: bool = True,
    units_consumed: int = 0,
    payment_status: str = "paid",
    entitlements_status: str = "active",
    issued_after_payment: bool = True,
    subscription_id: str = "sub_123",
    last_used_at: Any = None,
    checkout_session_id: str | None = None,
    purchase_reference: str | None = None,
) -> MagicMock:
    r = MagicMock(spec=InstallKeyRecord)
    r.key_id = key_id
    r.owner_key = owner_key
    r.program = program
    r.masked_key = masked_key
    r.label = label
    r.active = active
    r.units_consumed = units_consumed
    r.payment_status = payment_status
    r.entitlements_status = entitlements_status
    r.issued_after_payment = issued_after_payment
    r.subscription_id = subscription_id
    r.last_used_at = last_used_at
    r.checkout_session_id = checkout_session_id
    r.purchase_reference = purchase_reference
    return r


def _make_registry(
    records: list[MagicMock] | None = None,
    *,
    usage_return: MagicMock | None = None,
    usage_side_effect: Any = None,
) -> MagicMock:
    reg = MagicMock()
    reg.get_keys_for_owner.return_value = records if records is not None else []
    if usage_side_effect is not None:
        reg.record_key_usage.side_effect = usage_side_effect
    else:
        reg.record_key_usage.return_value = usage_return
    return reg


def _make_wallet_registry(
    *,
    balance_units: int = 100,
    total_consumed_units: int = 15,
    usage_payload: dict[str, Any] | None = None,
) -> MagicMock:
    wallet = MagicMock()
    wallet.balance_units = balance_units
    wallet.total_consumed_units = total_consumed_units
    wallet.install_key_usage = {}
    if usage_payload is not None:
        wallet.install_key_usage = usage_payload
    wallet.list_ledger_entries.return_value = []
    wallet.get_wallet.return_value = wallet
    return wallet


# ---------------------------------------------------------------------------
# GET /dashboard/overview
# ---------------------------------------------------------------------------


class TestDashboardOverview:
    def test_returns_200(self, app: FastAPI, client: TestClient) -> None:
        app.dependency_overrides[require_hybrid_auth] = lambda: _auth_override()
        try:
            resp = client.get("/dashboard/overview?owner_key=_OWNER")
        finally:
            app.dependency_overrides.clear()
        assert resp.status_code == 200

    def test_response_shape(self, app: FastAPI, client: TestClient) -> None:
        app.dependency_overrides[require_hybrid_auth] = lambda: _auth_override()
        try:
            body = client.get(f"/dashboard/overview?owner_key={_OWNER}").json()
        finally:
            app.dependency_overrides.clear()
        assert body["status"] == "ok"
        assert body["service"] == "ironclaw-dashboard"
        assert "timestamp" in body
        assert "kpis" in body
        assert "alerts" in body
        assert "activity" in body

    def test_dashboard_slot_includes_install_key_health(self, app: FastAPI, client: TestClient) -> None:
        record = _make_record(
            key_id=_KEY_ID,
            owner_key=_OWNER,
            program="openclaw",
            masked_key="ic_install_openclaw_...9f5a",
            units_consumed=12,
            payment_status="paid",
            entitlements_status="active",
            issued_after_payment=True,
            subscription_id="sub_abc",
            checkout_session_id="cs_abc",
            purchase_reference="purchase_ref_abc",
        )
        usage_summary = MagicMock()
        usage_summary.as_summary.return_value = {
            "key_id": _KEY_ID,
            "owner_key": _OWNER,
            "program": "openclaw",
            "balance_units": 72,
            "total_consumed_units": 12,
            "last_action_at": "2026-06-22T12:00:00Z",
            "metadata": {"action_type": "prompt"},
        }
        wallet = _make_wallet_registry(balance_units=72, total_consumed_units=12)
        wallet.install_key_usage = {_KEY_ID: usage_summary}
        wallet.list_ledger_entries.return_value = [
            MagicMock(
                units=4,
                metadata={"key_id": _KEY_ID, "action_type": "prompt"},
            ),
            MagicMock(
                units=6,
                metadata={"key_id": _KEY_ID, "action_type": "tool_call"},
            ),
        ]
        wallet.get_key_usage_summary.return_value = {
            "owner_key": _OWNER,
            "wallet_balance_units": 72,
            "total_consumed_units": 12,
            "install_key_usage": {_KEY_ID: usage_summary.as_summary.return_value},
        }
        reg = _make_registry(records=[record])
        app.dependency_overrides[get_install_key_registry] = lambda: reg
        app.dependency_overrides[get_unit_wallet_registry] = lambda: wallet
        app.dependency_overrides[require_hybrid_auth] = lambda: _auth_override()
        try:
            body = client.get(f"/dashboard/overview?owner_key={_OWNER}").json()
        finally:
            app.dependency_overrides.clear()
        slot = next(item for item in body["install_keys"] if item["program"] == "openclaw")
        assert slot["program"] == "openclaw"
        assert slot["status"] == "active"
        assert slot["remaining_units"] == 72
        assert slot["units_consumed"] == 12
        assert slot["usage_by_action"]["prompt"] == 4
        assert slot["usage_by_action"]["tool_call"] == 6
        assert slot["payment_status"] == "paid"
        assert slot["entitlements_status"] == "active"
        assert slot["metadata"]["subscription_id"] == "sub_abc"

    def test_dashboard_rejects_unpaid_or_non_entitled_key_state(self, app: FastAPI, client: TestClient) -> None:
        record = _make_record(
            key_id="ik_revoked",
            owner_key=_OWNER,
            program="claude_code",
            active=False,
            payment_status="pending",
            entitlements_status="not_active",
            issued_after_payment=False,
            last_used_at="2026-06-22T12:00:00Z",
        )
        record.revoked_at = "2026-06-22T12:05:00Z"
        wallet = _make_wallet_registry(balance_units=0, total_consumed_units=0)
        reg = _make_registry(records=[record])
        app.dependency_overrides[get_install_key_registry] = lambda: reg
        app.dependency_overrides[get_unit_wallet_registry] = lambda: wallet
        app.dependency_overrides[require_hybrid_auth] = lambda: _auth_override()
        try:
            body = client.get(f"/dashboard/overview?owner_key={_OWNER}").json()
        finally:
            app.dependency_overrides.clear()
        slot = next(item for item in body["install_keys"] if item["program"] == "claude_code")
        assert slot["status"] == "revoked"
        assert slot["active"] is False
        assert slot["remaining_units"] == 0
        assert slot["payment_status"] == "pending"
        assert slot["entitlements_status"] == "not_active"

    def test_dashboard_marks_postpayment_gate_required_key_as_locked(self, app: FastAPI, client: TestClient) -> None:
        record = _make_record(
            key_id="ik_gate_fail",
            owner_key=_OWNER,
            program="cursor",
            masked_key="ic_install_cursor_...dead",
            active=True,
            payment_status="paid",
            entitlements_status="active",
            issued_after_payment=False,
            units_consumed=7,
        )
        wallet = _make_wallet_registry(balance_units=9, total_consumed_units=7)
        reg = _make_registry(records=[record])
        app.dependency_overrides[get_install_key_registry] = lambda: reg
        app.dependency_overrides[get_unit_wallet_registry] = lambda: wallet
        app.dependency_overrides[require_hybrid_auth] = lambda: _auth_override()
        try:
            body = client.get(f"/dashboard/overview?owner_key={_OWNER}").json()
        finally:
            app.dependency_overrides.clear()
        slot = next(item for item in body["install_keys"] if item["program"] == "cursor")
        assert slot["status"] == "locked"
        assert slot["active"] is False
        assert slot["payment_status"] == "paid"
        assert slot["entitlements_status"] == "active"

    def test_dashboard_includes_all_supported_runtime_slots(self, app: FastAPI, client: TestClient) -> None:
        records = [
            _make_record(key_id="ik_cursor_1", owner_key=_OWNER, program="cursor", masked_key="ic_install_cursor_...ffff"),
            _make_record(key_id="ik_goose_1", owner_key=_OWNER, program="goose", masked_key="ic_install_goose_...aaaa"),
            _make_record(key_id="ik_gemini_1", owner_key=_OWNER, program="gemini_cli", masked_key="ic_install_gemini_cli_...bbbb"),
            _make_record(key_id="ik_copilot_1", owner_key=_OWNER, program="copilot", masked_key="ic_install_copilot_...cccc"),
            _make_record(key_id="ik_hermes_1", owner_key=_OWNER, program="hermes", masked_key="ic_install_hermes_...eeee"),
        ]
        wallet = _make_wallet_registry(balance_units=125, total_consumed_units=18)
        reg = _make_registry(records=records)
        app.dependency_overrides[get_install_key_registry] = lambda: reg
        app.dependency_overrides[get_unit_wallet_registry] = lambda: wallet
        app.dependency_overrides[require_hybrid_auth] = lambda: _auth_override()
        try:
            body = client.get(f"/dashboard/overview?owner_key={_OWNER}").json()
        finally:
            app.dependency_overrides.clear()

        payload_programs = [slot["program"] for slot in body["install_keys"]]
        expected_programs = list(InstallKeyFormatRegistry.list_programs())
        assert payload_programs == expected_programs
        assert "hermes" in payload_programs
        assert "security_guardian" not in payload_programs
        assert any(slot["program"] == "cursor" and slot["status"] == "active" for slot in body["install_keys"])
        assert all(slot["program"] in expected_programs for slot in body["install_keys"])


# ---------------------------------------------------------------------------
# GET /dashboard/units
# ---------------------------------------------------------------------------


class TestGetUnitsForOwner:
    def test_returns_200_with_empty_owner(self, app: FastAPI, client: TestClient) -> None:
        reg = _make_registry(records=[])
        app.dependency_overrides[get_install_key_registry] = lambda: reg
        app.dependency_overrides[require_hybrid_auth] = lambda: _auth_override()
        try:
            resp = client.get(f"/dashboard/units?owner_key={_OWNER}")
        finally:
            app.dependency_overrides.clear()
        assert resp.status_code == 200
        body = resp.json()
        assert body["owner_key"] == _OWNER
        assert body["total_keys"] == 0
        assert body["total_units_consumed"] == 0
        assert body["keys"] == []

    def test_aggregates_units_across_keys(self, app: FastAPI, client: TestClient) -> None:
        r1 = _make_record(key_id="ik_a", units_consumed=10)
        r2 = _make_record(key_id="ik_b", units_consumed=25)
        reg = _make_registry(records=[r1, r2])
        app.dependency_overrides[get_install_key_registry] = lambda: reg
        app.dependency_overrides[require_hybrid_auth] = lambda: _auth_override()
        try:
            resp = client.get(f"/dashboard/units?owner_key={_OWNER}")
        finally:
            app.dependency_overrides.clear()
        body = resp.json()
        assert body["total_keys"] == 2
        assert body["total_units_consumed"] == 35
        assert len(body["keys"]) == 2

    def test_entry_fields_are_correct(self, app: FastAPI, client: TestClient) -> None:
        r = _make_record(units_consumed=5, active=True, label="prod")
        reg = _make_registry(records=[r])
        app.dependency_overrides[get_install_key_registry] = lambda: reg
        app.dependency_overrides[require_hybrid_auth] = lambda: _auth_override()
        try:
            resp = client.get(f"/dashboard/units?owner_key={_OWNER}")
        finally:
            app.dependency_overrides.clear()
        entry = resp.json()["keys"][0]
        assert entry["key_id"] == _KEY_ID
        assert entry["program"] == "openclaw"
        assert entry["active"] is True
        assert entry["units_consumed"] == 5
        assert entry["label"] == "prod"

    def test_last_used_at_none_when_not_set(self, app: FastAPI, client: TestClient) -> None:
        r = _make_record(last_used_at=None)
        reg = _make_registry(records=[r])
        app.dependency_overrides[get_install_key_registry] = lambda: reg
        app.dependency_overrides[require_hybrid_auth] = lambda: _auth_override()
        try:
            resp = client.get(f"/dashboard/units?owner_key={_OWNER}")
        finally:
            app.dependency_overrides.clear()
        assert resp.json()["keys"][0]["last_used_at"] is None

    def test_last_used_at_iso_when_set(self, app: FastAPI, client: TestClient) -> None:
        dt = datetime(2026, 6, 22, 12, 0, 0, tzinfo=UTC)
        r = _make_record(last_used_at=dt)
        reg = _make_registry(records=[r])
        app.dependency_overrides[get_install_key_registry] = lambda: reg
        app.dependency_overrides[require_hybrid_auth] = lambda: _auth_override()
        try:
            resp = client.get(f"/dashboard/units?owner_key={_OWNER}")
        finally:
            app.dependency_overrides.clear()
        assert resp.json()["keys"][0]["last_used_at"] is not None

    def test_calls_registry_with_owner_key(self, app: FastAPI, client: TestClient) -> None:
        reg = _make_registry(records=[])
        app.dependency_overrides[get_install_key_registry] = lambda: reg
        app.dependency_overrides[require_hybrid_auth] = lambda: _auth_override()
        try:
            client.get(f"/dashboard/units?owner_key={_OWNER}")
        finally:
            app.dependency_overrides.clear()
        reg.get_keys_for_owner.assert_called_once_with(_OWNER)

    def test_missing_owner_key_returns_401_when_unauthenticated(self, client: TestClient) -> None:
        resp = client.get("/dashboard/units")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# POST /dashboard/units/record
# ---------------------------------------------------------------------------


class TestRecordUnitUsage:
    def test_returns_200_on_success(self, app: FastAPI, client: TestClient) -> None:
        updated = _make_record(units_consumed=10)
        reg = _make_registry(usage_return=updated)
        app.dependency_overrides[get_install_key_registry] = lambda: reg
        app.dependency_overrides[require_hybrid_auth] = lambda: _auth_override()
        try:
            resp = client.post(
                "/dashboard/units/record",
                json={"key_id": _KEY_ID, "units": 10},
            )
        finally:
            app.dependency_overrides.clear()
        assert resp.status_code == 200
        body = resp.json()
        assert body["key_id"] == _KEY_ID
        assert body["units_consumed"] == 10
        assert "timestamp" in body

    def test_404_on_unknown_key(self, app: FastAPI, client: TestClient) -> None:
        reg = _make_registry(usage_side_effect=InstallKeyNotFoundError("ik_ghost"))
        app.dependency_overrides[get_install_key_registry] = lambda: reg
        app.dependency_overrides[require_hybrid_auth] = lambda: _auth_override()
        try:
            resp = client.post(
                "/dashboard/units/record",
                json={"key_id": "ik_ghost", "units": 1},
            )
        finally:
            app.dependency_overrides.clear()
        assert resp.status_code == 404

    def test_409_on_inactive_key(self, app: FastAPI, client: TestClient) -> None:
        reg = _make_registry(usage_side_effect=InstallKeyUsageError(_KEY_ID, "key is inactive"))
        app.dependency_overrides[get_install_key_registry] = lambda: reg
        app.dependency_overrides[require_hybrid_auth] = lambda: _auth_override()
        try:
            resp = client.post(
                "/dashboard/units/record",
                json={"key_id": _KEY_ID, "units": 5},
            )
        finally:
            app.dependency_overrides.clear()
        assert resp.status_code == 409

    def test_401_when_unauthenticated_and_units_zero(self, client: TestClient) -> None:
        resp = client.post(
            "/dashboard/units/record",
            json={"key_id": _KEY_ID, "units": 0},
        )
        assert resp.status_code == 401

    def test_401_when_unauthenticated_and_units_negative(self, client: TestClient) -> None:
        resp = client.post(
            "/dashboard/units/record",
            json={"key_id": _KEY_ID, "units": -1},
        )
        assert resp.status_code == 401

    def test_calls_registry_with_keyword_units(self, app: FastAPI, client: TestClient) -> None:
        updated = _make_record(units_consumed=3)
        reg = _make_registry(usage_return=updated)
        app.dependency_overrides[get_install_key_registry] = lambda: reg
        app.dependency_overrides[require_hybrid_auth] = lambda: _auth_override()
        try:
            client.post(
                "/dashboard/units/record",
                json={"key_id": _KEY_ID, "units": 3},
            )
        finally:
            app.dependency_overrides.clear()
        reg.record_key_usage.assert_called_once_with(_KEY_ID, units=3)
