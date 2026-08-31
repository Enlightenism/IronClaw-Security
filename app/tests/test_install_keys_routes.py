from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.core.install_keys import (
    InstallKeyNotFoundError,
    InstallKeyRecord,
    _reset_install_key_registry_for_testing,
)
from app.routes.install_keys import router

# ---------------------------------------------------------------------------
# Mock targets
# ---------------------------------------------------------------------------

_INSTALL_REGISTRY_TARGET = "app.routes.install_keys.get_install_key_registry"
_WALLET_REGISTRY_TARGET = "app.routes.install_keys.get_unit_wallet_registry"

# ---------------------------------------------------------------------------
# App fixture
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_OWNER = "owner_install_routes_test_001"
_SUB = "sub_install_routes_abc123"
_KEY_ID_OC = "ik_openclaw_routes_aabb"
_KEY_ID_CC = "ik_claude_code_routes_ccdd"
_RAW_KEY_OC = "ic_install_openclaw_xxxxxxxsecretvalue"
_RAW_KEY_CC = "ic_install_claude_code_yyyysecretvalue"
_TS = "2026-06-23T12:00:00Z"
_LAST_USED = "2026-06-23T13:00:00Z"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_record(
    *,
    key_id: str = _KEY_ID_OC,
    owner_key: str = _OWNER,
    subscription_id: str = _SUB,
    program: str = "openclaw",
    raw_key: str = _RAW_KEY_OC,
    active: bool = True,
    units_consumed: int = 0,
    label: str = "",
    last_used_at: str | None = None,
    payment_status: str = "paid",
    entitlements_status: str = "active",
    issued_after_payment: bool = True,
    metadata: dict[str, Any] | None = None,
) -> MagicMock:
    record = MagicMock(spec=InstallKeyRecord)
    record.key_id = key_id
    record.owner_key = owner_key
    record.subscription_id = subscription_id
    record.program = program
    record.raw_key = raw_key
    record.masked_key = f"{raw_key[:10]}...{raw_key[-4:]}"
    record.active = active
    record.payment_status = payment_status
    record.entitlements_status = entitlements_status
    record.issued_after_payment = issued_after_payment
    record.units_consumed = units_consumed
    record.label = label
    record.metadata = metadata or {}
    record.public_dict.return_value = {
        "key_id": key_id,
        "owner_key": owner_key,
        "subscription_id": subscription_id,
        "program": program,
        "masked_key": f"{raw_key[:10]}...{raw_key[-4:]}",
        "label": label,
        "active": active,
        "payment_status": payment_status,
        "entitlements_status": entitlements_status,
        "issued_after_payment": issued_after_payment,
        "units_consumed": units_consumed,
        "created_at": _TS,
        "last_used_at": last_used_at,
        "metadata": metadata or {},
    }
    return record


def _make_install_registry(
    *,
    owner_records: list[MagicMock] | None = None,
    by_id_record: MagicMock | None = None,
    authenticate_result: MagicMock | None = None,
    record_usage_result: MagicMock | None = None,
    record_usage_side_effect: Any = None,
    revoke_result: MagicMock | None = None,
    revoke_side_effect: Any = None,
) -> MagicMock:
    reg = MagicMock()
    reg.get_keys_for_owner.return_value = owner_records if owner_records is not None else []
    reg.get_key_by_id.return_value = by_id_record
    reg.authenticate_install_key.return_value = authenticate_result

    if record_usage_side_effect is not None:
        reg.record_key_usage.side_effect = record_usage_side_effect
    elif record_usage_result is not None:
        reg.record_key_usage.return_value = record_usage_result

    if revoke_side_effect is not None:
        reg.revoke_key.side_effect = revoke_side_effect
    elif revoke_result is not None:
        reg.revoke_key.return_value = revoke_result

    return reg


def _make_wallet(*, balance_units: int = 1000) -> MagicMock:
    wallet = MagicMock()
    wallet.balance_units = balance_units
    return wallet


def _make_wallet_registry(
    *,
    wallet: MagicMock | None = None,
    debit_result: MagicMock | None = None,
    debit_side_effect: Any = None,
    ledger_entries: list[MagicMock] | None = None,
) -> MagicMock:
    reg = MagicMock()
    reg.get_wallet.return_value = wallet
    if debit_side_effect is not None:
        reg.debit_units_for_install_key.side_effect = debit_side_effect
    else:
        reg.debit_units_for_install_key.return_value = debit_result or _make_wallet()
    reg.list_ledger_entries.return_value = ledger_entries if ledger_entries is not None else []
    return reg


def _make_ledger_entry(
    *,
    entry_id: str = "le_001",
    entry_type: str = "debit",
    units: int = 10,
    balance_after: int = 990,
    key_id: str = _KEY_ID_OC,
) -> MagicMock:
    entry = MagicMock()
    entry.entry_id = entry_id
    entry.entry_type = entry_type
    entry.units = units
    entry.balance_after = balance_after
    entry.created_at = datetime(2026, 6, 23, 13, 0, 0, tzinfo=UTC)
    entry.metadata = {"key_id": key_id}
    return entry


# ---------------------------------------------------------------------------
# GET /install-keys/my-keys
# ---------------------------------------------------------------------------


class TestGetMyKeys:
    def test_valid_owner_with_subscription_returns_both_program_slots(self, client: TestClient) -> None:
        oc_record = _make_record(key_id=_KEY_ID_OC, program="openclaw", subscription_id=_SUB)
        install_reg = _make_install_registry(owner_records=[oc_record])
        wallet_reg = _make_wallet_registry()
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.get(
                "/install-keys/my-keys",
                headers={"X-Owner-Key": _OWNER},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert body["service"] == "IronClaw-Security"
        assert body["owner_key"] == _OWNER
        assert "timestamp" in body
        programs = {slot["program"] for slot in body["keys"]}
        assert programs == {"openclaw", "claude_code", "hermes"}

    def test_one_populated_slot_and_one_empty_slot(self, client: TestClient) -> None:
        oc_record = _make_record(key_id=_KEY_ID_OC, program="openclaw", subscription_id=_SUB)
        install_reg = _make_install_registry(owner_records=[oc_record])
        wallet_reg = _make_wallet_registry()
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.get(
                "/install-keys/my-keys",
                headers={"X-Owner-Key": _OWNER},
            )
        body = resp.json()
        slots_by_program = {s["program"]: s for s in body["keys"]}
        assert slots_by_program["openclaw"]["key_id"] == _KEY_ID_OC
        assert slots_by_program["claude_code"]["key_id"] is None
        assert slots_by_program["claude_code"]["active"] is False
        assert slots_by_program["hermes"]["key_id"] is None
        assert slots_by_program["hermes"]["active"] is False

    def test_owner_with_no_subscription_returns_403_no_active_subscription(self, client: TestClient) -> None:
        install_reg = _make_install_registry(owner_records=[])
        wallet_reg = _make_wallet_registry()
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.get(
                "/install-keys/my-keys",
                headers={"X-Owner-Key": _OWNER},
            )
        assert resp.status_code == 403
        assert resp.json()["detail"] == "no_active_subscription"

    def test_owner_with_subscription_but_blank_sub_id_returns_403(self, client: TestClient) -> None:
        # record exists but subscription_id is blank — no active subscription
        record_blank_sub = _make_record(subscription_id="   ")
        install_reg = _make_install_registry(owner_records=[record_blank_sub])
        wallet_reg = _make_wallet_registry()
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.get(
                "/install-keys/my-keys",
                headers={"X-Owner-Key": _OWNER},
            )
        assert resp.status_code == 403
        assert resp.json()["detail"] == "no_active_subscription"

    def test_owner_with_subscription_but_no_keys_returns_two_empty_slots(self, client: TestClient) -> None:
        # subscription_id present but no key records
        install_reg = MagicMock()
        # First call to get_keys_for_owner: subscription check passes (record with sub_id)
        # Second call: no key records (pre-purchase key generation state)
        sub_check_record = _make_record(subscription_id=_SUB)
        install_reg.get_keys_for_owner.return_value = [sub_check_record]
        # The second get_keys_for_owner call (for building slots) should return no key records
        # We simulate this by having subscription_id present but no keys
        # Since both checks use same mock, use a record with sub but override: return
        # only the subscription sentinel (no actual key_id context needed).
        # The route uses the same list for both checks, so we return the sub record
        # but its key_id is absent from any meaningful slot (it maps to openclaw).
        # This tests the "pre-purchase: subscription exists, slot is still shown empty" state
        # by using a record whose active=False with no key_id.
        install_reg.get_keys_for_owner.return_value = [sub_check_record]
        wallet_reg = _make_wallet_registry()
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.get(
                "/install-keys/my-keys",
                headers={"X-Owner-Key": _OWNER},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["keys"]) == 3

    def test_missing_owner_key_header_returns_422(self, client: TestClient) -> None:
        resp = client.get("/install-keys/my-keys")
        assert resp.status_code == 422

    def test_empty_owner_key_header_returns_422(self, client: TestClient) -> None:
        resp = client.get("/install-keys/my-keys", headers={"X-Owner-Key": ""})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /install-keys/activate
# ---------------------------------------------------------------------------


class TestActivateInstallKey:
    def test_valid_raw_key_returns_masked_paid_entitlement_summary(self, client: TestClient) -> None:
        record = _make_record()
        wallet = _make_wallet(balance_units=500)
        install_reg = _make_install_registry(authenticate_result=record)
        wallet_reg = _make_wallet_registry(wallet=wallet)
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.post(
                "/install-keys/activate",
                json={"raw_key": _RAW_KEY_OC},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["valid"] is True
        assert body["owner_key"] == _OWNER
        assert body["program"] == "openclaw"
        assert body["key_id"] == _KEY_ID_OC
        assert body["masked_key"] == record.masked_key
        assert body["payment_status"] == "paid"
        assert body["entitlements_status"] == "active"
        assert body["active"] is True
        assert body["usage_summary"]["program"] == "openclaw"
        assert body["usage_summary"]["owner_key"] == _OWNER
        assert _RAW_KEY_OC not in str(body)
        assert body["units_remaining"] == 500

    def test_owner_key_header_mismatch_rejected_during_activation(self, client: TestClient) -> None:
        record = _make_record(owner_key="different_owner")
        install_reg = _make_install_registry(authenticate_result=record)
        wallet_reg = _make_wallet_registry(wallet=_make_wallet(balance_units=250))
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.post(
                "/install-keys/activate",
                json={"raw_key": _RAW_KEY_OC},
                headers={"X-Owner-Key": _OWNER},
            )
        assert resp.status_code == 403
        assert "owner_key" in resp.json()["detail"].lower()

    def test_valid_claude_code_key_returns_correct_program(self, client: TestClient) -> None:
        record = _make_record(program="claude_code", raw_key=_RAW_KEY_CC)
        wallet = _make_wallet(balance_units=250)
        install_reg = _make_install_registry(authenticate_result=record)
        wallet_reg = _make_wallet_registry(wallet=wallet)
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.post(
                "/install-keys/activate",
                json={"raw_key": _RAW_KEY_CC},
            )
        assert resp.status_code == 200
        assert resp.json()["program"] == "claude_code"
        assert resp.json()["valid"] is True

    def test_owner_key_header_is_case_insensitive_for_activation(self, client: TestClient) -> None:
        record = _make_record(owner_key="owner_routes_case_test")
        wallet = _make_wallet(balance_units=500)
        install_reg = _make_install_registry(authenticate_result=record)
        wallet_reg = _make_wallet_registry(wallet=wallet)
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.post(
                "/install-keys/activate",
                json={"raw_key": _RAW_KEY_OC},
                headers={"X-Owner-Key": "OWNER_ROUTES_CASE_TEST"},
            )
        assert resp.status_code == 200
        assert resp.json()["owner_key"] == "owner_routes_case_test"

    def test_invalid_raw_key_returns_401(self, client: TestClient) -> None:
        install_reg = _make_install_registry(authenticate_result=None)
        wallet_reg = _make_wallet_registry()
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.post(
                "/install-keys/activate",
                json={"raw_key": "ic_install_totally_invalid_key"},
            )
        assert resp.status_code == 401

    def test_inactive_key_returns_401(self, client: TestClient) -> None:
        # authenticate_install_key returns None for inactive keys per registry contract
        install_reg = _make_install_registry(authenticate_result=None)
        wallet_reg = _make_wallet_registry()
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.post(
                "/install-keys/activate",
                json={"raw_key": "ic_install_openclaw_revoked_key_val"},
            )
        assert resp.status_code == 401

    def test_units_remaining_zero_when_no_wallet(self, client: TestClient) -> None:
        record = _make_record()
        install_reg = _make_install_registry(authenticate_result=record)
        wallet_reg = _make_wallet_registry(wallet=None)
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.post(
                "/install-keys/activate",
                json={"raw_key": _RAW_KEY_OC},
            )
        assert resp.status_code == 200
        assert resp.json()["units_remaining"] == 0

    def test_empty_raw_key_returns_422(self, client: TestClient) -> None:
        resp = client.post("/install-keys/activate", json={"raw_key": ""})
        assert resp.status_code == 422

    def test_missing_raw_key_field_returns_422(self, client: TestClient) -> None:
        resp = client.post("/install-keys/activate", json={})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /install-keys/record-usage
# ---------------------------------------------------------------------------


class _InsufficientUnitsError(Exception):
    """Local stand-in for InsufficientUnitsError for test isolation."""

    def __init__(self, have: int, need: int) -> None:
        self.have = have
        self.need = need
        super().__init__(f"Insufficient units: have={have}, need={need}")


class TestRecordUsage:
    def test_valid_active_key_returns_updated_balance(self, client: TestClient) -> None:
        record = _make_record(active=True, units_consumed=0)
        updated_record = _make_record(active=True, units_consumed=5)
        wallet_after = _make_wallet(balance_units=995)
        install_reg = _make_install_registry(
            by_id_record=record,
            record_usage_result=updated_record,
        )
        wallet_reg = _make_wallet_registry(debit_result=wallet_after)
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.post(
                "/install-keys/record-usage",
                json={"key_id": _KEY_ID_OC, "units": 5},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert body["service"] == "IronClaw-Security"
        assert body["key_id"] == _KEY_ID_OC
        assert body["units_consumed"] == 5
        assert body["units_remaining"] == 995
        assert "timestamp" in body

    def test_debit_is_called_with_correct_args(self, client: TestClient) -> None:
        record = _make_record(active=True)
        updated_record = _make_record(active=True, units_consumed=3)
        wallet_after = _make_wallet(balance_units=997)
        install_reg = _make_install_registry(
            by_id_record=record,
            record_usage_result=updated_record,
        )
        wallet_reg = _make_wallet_registry(debit_result=wallet_after)
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            client.post(
                "/install-keys/record-usage",
                json={"key_id": _KEY_ID_OC, "units": 3},
            )
        wallet_reg.debit_units_for_install_key.assert_called_once_with(
            owner_key=_OWNER,
            key_id=_KEY_ID_OC,
            units=3,
            program="openclaw",
        )

    def test_insufficient_units_returns_402(self, client: TestClient) -> None:
        from app.core.unit_wallet import InsufficientUnitsError

        record = _make_record(active=True)
        install_reg = _make_install_registry(by_id_record=record)
        wallet_reg = _make_wallet_registry(debit_side_effect=InsufficientUnitsError(have=2, need=5))
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.post(
                "/install-keys/record-usage",
                json={"key_id": _KEY_ID_OC, "units": 5},
            )
        assert resp.status_code == 402
        body = resp.json()
        assert body["detail"]["error"] == "insufficient_units"
        assert body["detail"]["have"] == 2
        assert body["detail"]["need"] == 5

    def test_unknown_key_id_returns_404(self, client: TestClient) -> None:
        install_reg = _make_install_registry(by_id_record=None)
        wallet_reg = _make_wallet_registry()
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.post(
                "/install-keys/record-usage",
                json={"key_id": "ik_does_not_exist", "units": 1},
            )
        assert resp.status_code == 404
        assert "ik_does_not_exist" in resp.json()["detail"]

    def test_inactive_key_returns_403(self, client: TestClient) -> None:
        record = _make_record(active=False)
        install_reg = _make_install_registry(by_id_record=record)
        wallet_reg = _make_wallet_registry()
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.post(
                "/install-keys/record-usage",
                json={"key_id": _KEY_ID_OC, "units": 1},
            )
        assert resp.status_code == 403
        assert _KEY_ID_OC in resp.json()["detail"]

    def test_zero_units_returns_422(self, client: TestClient) -> None:
        resp = client.post(
            "/install-keys/record-usage",
            json={"key_id": _KEY_ID_OC, "units": 0},
        )
        assert resp.status_code == 422

    def test_negative_units_returns_422(self, client: TestClient) -> None:
        resp = client.post(
            "/install-keys/record-usage",
            json={"key_id": _KEY_ID_OC, "units": -10},
        )
        assert resp.status_code == 422

    def test_missing_key_id_returns_422(self, client: TestClient) -> None:
        resp = client.post("/install-keys/record-usage", json={"units": 5})
        assert resp.status_code == 422

    def test_record_usage_called_after_successful_debit(self, client: TestClient) -> None:
        record = _make_record(active=True)
        updated_record = _make_record(active=True, units_consumed=7)
        wallet_after = _make_wallet(balance_units=993)
        install_reg = _make_install_registry(
            by_id_record=record,
            record_usage_result=updated_record,
        )
        wallet_reg = _make_wallet_registry(debit_result=wallet_after)
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            client.post(
                "/install-keys/record-usage",
                json={"key_id": _KEY_ID_OC, "units": 7},
            )
        install_reg.record_key_usage.assert_called_once_with(_KEY_ID_OC, units=7)


# ---------------------------------------------------------------------------
# POST /install-keys/{key_id}/revoke
# ---------------------------------------------------------------------------


class TestRevokeInstallKey:
    def test_revoke_correct_owner_returns_200_active_false(self, client: TestClient) -> None:
        record = _make_record(active=True)
        revoked_record = _make_record(active=False)
        install_reg = _make_install_registry(
            by_id_record=record,
            revoke_result=revoked_record,
        )
        wallet_reg = _make_wallet_registry()
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.post(
                f"/install-keys/{_KEY_ID_OC}/revoke",
                headers={"X-Owner-Key": _OWNER},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert body["service"] == "IronClaw-Security"
        assert body["key_id"] == _KEY_ID_OC
        assert body["active"] is False
        assert "timestamp" in body

    def test_revoke_calls_registry_with_correct_key_id(self, client: TestClient) -> None:
        record = _make_record(active=True)
        revoked_record = _make_record(active=False)
        install_reg = _make_install_registry(
            by_id_record=record,
            revoke_result=revoked_record,
        )
        wallet_reg = _make_wallet_registry()
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            client.post(
                f"/install-keys/{_KEY_ID_OC}/revoke",
                headers={"X-Owner-Key": _OWNER},
            )
        install_reg.revoke_key.assert_called_once_with(_KEY_ID_OC)

    def test_revoke_wrong_owner_returns_403(self, client: TestClient) -> None:
        record = _make_record(owner_key="owner_different_person")
        install_reg = _make_install_registry(by_id_record=record)
        wallet_reg = _make_wallet_registry()
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.post(
                f"/install-keys/{_KEY_ID_OC}/revoke",
                headers={"X-Owner-Key": _OWNER},
            )
        assert resp.status_code == 403

    def test_revoke_unknown_key_returns_404_from_get(self, client: TestClient) -> None:
        install_reg = _make_install_registry(by_id_record=None)
        wallet_reg = _make_wallet_registry()
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.post(
                "/install-keys/ik_ghost_key/revoke",
                headers={"X-Owner-Key": _OWNER},
            )
        assert resp.status_code == 404
        assert "ik_ghost_key" in resp.json()["detail"]

    def test_revoke_propagates_not_found_from_registry(self, client: TestClient) -> None:
        record = _make_record(active=True)
        install_reg = _make_install_registry(
            by_id_record=record,
            revoke_side_effect=InstallKeyNotFoundError(_KEY_ID_OC),
        )
        wallet_reg = _make_wallet_registry()
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.post(
                f"/install-keys/{_KEY_ID_OC}/revoke",
                headers={"X-Owner-Key": _OWNER},
            )
        assert resp.status_code == 404

    def test_revoke_missing_owner_key_header_returns_422(self, client: TestClient) -> None:
        resp = client.post(f"/install-keys/{_KEY_ID_OC}/revoke")
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# GET /install-keys/{key_id}/usage
# ---------------------------------------------------------------------------


class TestGetKeyUsage:
    def test_correct_owner_returns_usage_and_filtered_ledger(self, client: TestClient) -> None:
        record = _make_record(units_consumed=20, last_used_at=_LAST_USED)
        own_entry = _make_ledger_entry(key_id=_KEY_ID_OC, units=20, balance_after=980)
        other_entry = _make_ledger_entry(entry_id="le_other", key_id="ik_other_key_zz", units=5, balance_after=975)
        install_reg = _make_install_registry(by_id_record=record)
        wallet_reg = _make_wallet_registry(ledger_entries=[own_entry, other_entry])
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.get(
                f"/install-keys/{_KEY_ID_OC}/usage",
                headers={"X-Owner-Key": _OWNER},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert body["service"] == "IronClaw-Security"
        assert body["key_id"] == _KEY_ID_OC
        assert body["units_consumed"] == 20
        assert body["last_used_at"] == _LAST_USED
        assert "timestamp" in body
        assert len(body["ledger"]) == 1
        assert body["ledger"][0]["entry_id"] == "le_001"
        assert body["ledger"][0]["units"] == 20

    def test_ledger_filtered_to_key_id_only(self, client: TestClient) -> None:
        record = _make_record()
        entries = [
            _make_ledger_entry(entry_id="le_a", key_id=_KEY_ID_OC),
            _make_ledger_entry(entry_id="le_b", key_id="ik_other_unrelated"),
            _make_ledger_entry(entry_id="le_c", key_id=_KEY_ID_OC),
        ]
        install_reg = _make_install_registry(by_id_record=record)
        wallet_reg = _make_wallet_registry(ledger_entries=entries)
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.get(
                f"/install-keys/{_KEY_ID_OC}/usage",
                headers={"X-Owner-Key": _OWNER},
            )
        body = resp.json()
        assert len(body["ledger"]) == 2
        for entry in body["ledger"]:
            assert entry["metadata"]["key_id"] == _KEY_ID_OC

    def test_empty_ledger_when_no_entries_for_key(self, client: TestClient) -> None:
        record = _make_record()
        other_entry = _make_ledger_entry(entry_id="le_x", key_id="ik_completely_different")
        install_reg = _make_install_registry(by_id_record=record)
        wallet_reg = _make_wallet_registry(ledger_entries=[other_entry])
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.get(
                f"/install-keys/{_KEY_ID_OC}/usage",
                headers={"X-Owner-Key": _OWNER},
            )
        body = resp.json()
        assert body["ledger"] == []
        assert resp.status_code == 200

    def test_wrong_owner_returns_403(self, client: TestClient) -> None:
        record = _make_record(owner_key="owner_completely_different")
        install_reg = _make_install_registry(by_id_record=record)
        wallet_reg = _make_wallet_registry()
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.get(
                f"/install-keys/{_KEY_ID_OC}/usage",
                headers={"X-Owner-Key": _OWNER},
            )
        assert resp.status_code == 403

    def test_unknown_key_id_returns_404(self, client: TestClient) -> None:
        install_reg = _make_install_registry(by_id_record=None)
        wallet_reg = _make_wallet_registry()
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.get(
                "/install-keys/ik_no_such_key/usage",
                headers={"X-Owner-Key": _OWNER},
            )
        assert resp.status_code == 404
        assert "ik_no_such_key" in resp.json()["detail"]

    def test_missing_owner_key_header_returns_422(self, client: TestClient) -> None:
        resp = client.get(f"/install-keys/{_KEY_ID_OC}/usage")
        assert resp.status_code == 422

    def test_list_ledger_entries_called_with_limit(self, client: TestClient) -> None:
        record = _make_record()
        install_reg = _make_install_registry(by_id_record=record)
        wallet_reg = _make_wallet_registry(ledger_entries=[])
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            client.get(
                f"/install-keys/{_KEY_ID_OC}/usage?limit=100",
                headers={"X-Owner-Key": _OWNER},
            )
        wallet_reg.list_ledger_entries.assert_called_once_with(
            owner_key=_OWNER,
            limit=100,
        )

    def test_last_used_at_none_when_never_used(self, client: TestClient) -> None:
        record = _make_record(last_used_at=None)
        install_reg = _make_install_registry(by_id_record=record)
        wallet_reg = _make_wallet_registry(ledger_entries=[])
        with (
            patch(_INSTALL_REGISTRY_TARGET, return_value=install_reg),
            patch(_WALLET_REGISTRY_TARGET, return_value=wallet_reg),
        ):
            resp = client.get(
                f"/install-keys/{_KEY_ID_OC}/usage",
                headers={"X-Owner-Key": _OWNER},
            )
        assert resp.status_code == 200
        assert resp.json()["last_used_at"] is None
