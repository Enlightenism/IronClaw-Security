from __future__ import annotations

from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.core.install_keys import (
    InstallKeyAlreadyExistsError,
    InstallKeyNotFoundError,
    InstallKeyRecord,
    InstallKeyUsageError,
    _reset_install_key_registry_for_testing,
)
from app.routes.customerkeys import router

# ---------------------------------------------------------------------------
# App fixture
# ---------------------------------------------------------------------------

_MOCK_TARGET = "app.routes.customerkeys.get_install_key_registry"


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
# Helpers
# ---------------------------------------------------------------------------

_OWNER = "owner_test_http_001"
_SUB = "sub_http_abc123"
_KEY_ID = "ik_aabbccddee"


def _make_record(
    *,
    key_id: str = _KEY_ID,
    owner_key: str = _OWNER,
    subscription_id: str = _SUB,
    program: str = "openclaw",
    raw_key: str = "ic_install_openclaw_supersecretvalue",
    active: bool = True,
    units_consumed: int = 0,
    label: str = "",
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
        "units_consumed": units_consumed,
        "created_at": "2026-06-22T20:00:00Z",
        "last_used_at": None,
        "metadata": metadata or {},
    }
    return record


def _make_registry(
    record: MagicMock | None = None,
    *,
    generate_side_effect: Any = None,
    revoke_side_effect: Any = None,
    usage_side_effect: Any = None,
    owner_records: list[MagicMock] | None = None,
    summary_data: dict[str, Any] | None = None,
) -> MagicMock:
    reg = MagicMock()
    if generate_side_effect is not None:
        reg.generate_install_key.side_effect = generate_side_effect
    elif record is not None:
        reg.generate_install_key.return_value = record

    if revoke_side_effect is not None:
        reg.revoke_key.side_effect = revoke_side_effect
    elif record is not None:
        reg.revoke_key.return_value = record

    if usage_side_effect is not None:
        reg.record_key_usage.side_effect = usage_side_effect
    elif record is not None:
        reg.record_key_usage.return_value = record

    reg.get_key_by_id.return_value = record
    reg.get_keys_for_owner.return_value = owner_records if owner_records is not None else ([] if record is None else [record])
    reg.summary.return_value = summary_data or {
        "total": 0,
        "active": 0,
        "revoked": 0,
        "openclaw_keys": 0,
        "claude_code_keys": 0,
    }
    return reg


# ---------------------------------------------------------------------------
# POST /generate — happy path
# ---------------------------------------------------------------------------


class TestGenerateHappyPath:
    def test_openclaw_returns_201_with_raw_key(self, client: TestClient) -> None:
        record = _make_record(program="openclaw")
        registry = _make_registry(record)
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.post(
                "/customer-keys/generate",
                json={
                    "owner_key": _OWNER,
                    "subscription_id": _SUB,
                    "program": "openclaw",
                },
            )
        assert resp.status_code == 201
        body = resp.json()
        assert body["status"] == "ok"
        assert body["service"] == "IronClaw-Security"
        assert "raw_key" in body
        assert body["raw_key"] == record.raw_key
        assert body["key"]["program"] == "openclaw"
        assert body["key"]["active"] is True

    def test_claude_code_returns_201_with_raw_key(self, client: TestClient) -> None:
        record = _make_record(
            program="claude_code",
            raw_key="ic_install_claude_code_supersecretvalue",
        )
        registry = _make_registry(record)
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.post(
                "/customer-keys/generate",
                json={
                    "owner_key": _OWNER,
                    "subscription_id": _SUB,
                    "program": "claude_code",
                },
            )
        assert resp.status_code == 201
        body = resp.json()
        assert body["key"]["program"] == "claude_code"
        assert "raw_key" in body

    def test_generate_calls_registry_with_correct_args(self, client: TestClient) -> None:
        record = _make_record()
        registry = _make_registry(record)
        with patch(_MOCK_TARGET, return_value=registry):
            client.post(
                "/customer-keys/generate",
                json={
                    "owner_key": _OWNER,
                    "subscription_id": _SUB,
                    "program": "openclaw",
                    "label": "prod-key",
                    "metadata": {"env": "production"},
                },
            )
        registry.generate_install_key.assert_called_once_with(
            owner_key=_OWNER,
            subscription_id=_SUB,
            program="openclaw",
            label="prod-key",
            metadata={"env": "production"},
        )

    def test_response_key_id_matches_record(self, client: TestClient) -> None:
        record = _make_record(key_id="ik_unique123")
        registry = _make_registry(record)
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.post(
                "/customer-keys/generate",
                json={"owner_key": _OWNER, "subscription_id": _SUB, "program": "openclaw"},
            )
        assert resp.json()["key"]["key_id"] == "ik_unique123"


# ---------------------------------------------------------------------------
# POST /generate — post-purchase gate: 402 on blank subscription_id
# ---------------------------------------------------------------------------


class TestGeneratePostPurchaseGate:
    def test_blank_subscription_id_returns_402(self, client: TestClient) -> None:
        registry = _make_registry()
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.post(
                "/customer-keys/generate",
                json={"owner_key": _OWNER, "subscription_id": "   ", "program": "openclaw"},
            )
        assert resp.status_code == 402

    def test_empty_subscription_id_returns_402(self, client: TestClient) -> None:
        registry = _make_registry()
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.post(
                "/customer-keys/generate",
                json={"owner_key": _OWNER, "subscription_id": " ", "program": "openclaw"},
            )
        assert resp.status_code == 402

    def test_402_does_not_call_registry(self, client: TestClient) -> None:
        registry = _make_registry()
        with patch(_MOCK_TARGET, return_value=registry):
            client.post(
                "/customer-keys/generate",
                json={"owner_key": _OWNER, "subscription_id": "   ", "program": "openclaw"},
            )
        registry.generate_install_key.assert_not_called()

    def test_invalid_program_returns_422(self, client: TestClient) -> None:
        registry = _make_registry()
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.post(
                "/customer-keys/generate",
                json={"owner_key": _OWNER, "subscription_id": _SUB, "program": "unknown_prog"},
            )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /generate — 409 on duplicate active key
# ---------------------------------------------------------------------------


class TestGenerateDuplicate:
    def test_409_on_duplicate_active_key(self, client: TestClient) -> None:
        registry = _make_registry(generate_side_effect=InstallKeyAlreadyExistsError(_OWNER, "openclaw"))
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.post(
                "/customer-keys/generate",
                json={"owner_key": _OWNER, "subscription_id": _SUB, "program": "openclaw"},
            )
        assert resp.status_code == 409

    def test_409_detail_mentions_program(self, client: TestClient) -> None:
        registry = _make_registry(generate_side_effect=InstallKeyAlreadyExistsError(_OWNER, "claude_code"))
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.post(
                "/customer-keys/generate",
                json={"owner_key": _OWNER, "subscription_id": _SUB, "program": "claude_code"},
            )
        assert "claude_code" in resp.json()["detail"]

    def test_409_detail_mentions_owner(self, client: TestClient) -> None:
        registry = _make_registry(generate_side_effect=InstallKeyAlreadyExistsError(_OWNER, "openclaw"))
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.post(
                "/customer-keys/generate",
                json={"owner_key": _OWNER, "subscription_id": _SUB, "program": "openclaw"},
            )
        assert _OWNER in resp.json()["detail"]


# ---------------------------------------------------------------------------
# GET /customer-keys/{key_id} — 404 on unknown key_id
# ---------------------------------------------------------------------------


class TestGetInstallKey:
    def test_returns_200_with_key_view(self, client: TestClient) -> None:
        record = _make_record()
        registry = _make_registry(record)
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.get(f"/customer-keys/{_KEY_ID}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["key"]["key_id"] == _KEY_ID
        assert body["status"] == "ok"

    def test_404_on_unknown_key_id(self, client: TestClient) -> None:
        registry = _make_registry(record=None)
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.get("/customer-keys/ik_does_not_exist")
        assert resp.status_code == 404

    def test_404_detail_contains_key_id(self, client: TestClient) -> None:
        registry = _make_registry(record=None)
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.get("/customer-keys/ik_ghost")
        assert "ik_ghost" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# GET /customer-keys/owner/{owner_key}
# ---------------------------------------------------------------------------


class TestListKeysForOwner:
    def test_returns_all_keys_for_owner(self, client: TestClient) -> None:
        r1 = _make_record(key_id="ik_001", active=True)
        r2 = _make_record(key_id="ik_002", active=False)
        registry = _make_registry(owner_records=[r1, r2])
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.get(f"/customer-keys/owner/{_OWNER}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 2
        assert len(body["items"]) == 2

    def test_active_only_filters_revoked_keys(self, client: TestClient) -> None:
        active_record = _make_record(key_id="ik_active", active=True)
        revoked_record = _make_record(key_id="ik_revoked", active=False)
        registry = _make_registry(owner_records=[active_record, revoked_record])
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.get(f"/customer-keys/owner/{_OWNER}?active_only=true")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert body["items"][0]["key_id"] == "ik_active"

    def test_empty_owner_returns_empty_list(self, client: TestClient) -> None:
        registry = _make_registry(owner_records=[])
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.get("/customer-keys/owner/unknown_owner")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 0
        assert body["items"] == []

    def test_without_active_only_returns_all(self, client: TestClient) -> None:
        r1 = _make_record(key_id="ik_a", active=True)
        r2 = _make_record(key_id="ik_b", active=False)
        registry = _make_registry(owner_records=[r1, r2])
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.get(f"/customer-keys/owner/{_OWNER}?active_only=false")
        assert resp.json()["total"] == 2


# ---------------------------------------------------------------------------
# POST /customer-keys/{key_id}/revoke
# ---------------------------------------------------------------------------


class TestRevokeInstallKey:
    def test_revoke_returns_200_active_false(self, client: TestClient) -> None:
        revoked = _make_record(active=False)
        registry = _make_registry(record=revoked)
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.post(f"/customer-keys/{_KEY_ID}/revoke")
        assert resp.status_code == 200
        body = resp.json()
        assert body["active"] is False
        assert body["key_id"] == _KEY_ID

    def test_revoke_404_on_unknown_key(self, client: TestClient) -> None:
        registry = _make_registry(revoke_side_effect=InstallKeyNotFoundError("ik_ghost"))
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.post("/customer-keys/ik_ghost/revoke")
        assert resp.status_code == 404

    def test_revoke_404_detail_contains_key_id(self, client: TestClient) -> None:
        registry = _make_registry(revoke_side_effect=InstallKeyNotFoundError("ik_missing"))
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.post("/customer-keys/ik_missing/revoke")
        assert "ik_missing" in resp.json()["detail"]

    def test_revoke_calls_registry_with_correct_key_id(self, client: TestClient) -> None:
        revoked = _make_record(active=False)
        registry = _make_registry(record=revoked)
        with patch(_MOCK_TARGET, return_value=registry):
            client.post(f"/customer-keys/{_KEY_ID}/revoke")
        registry.revoke_key.assert_called_once_with(_KEY_ID)


# ---------------------------------------------------------------------------
# POST /customer-keys/{key_id}/usage
# ---------------------------------------------------------------------------


class TestRecordKeyUsage:
    def test_records_usage_and_returns_200(self, client: TestClient) -> None:
        updated = _make_record(units_consumed=10)
        registry = _make_registry(record=updated)
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.post(
                f"/customer-keys/{_KEY_ID}/usage",
                json={"units": 10},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["units_consumed"] == 10
        assert body["key_id"] == _KEY_ID

    def test_409_on_inactive_key(self, client: TestClient) -> None:
        registry = _make_registry(usage_side_effect=InstallKeyUsageError(_KEY_ID, "key is inactive and cannot record usage"))
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.post(
                f"/customer-keys/{_KEY_ID}/usage",
                json={"units": 5},
            )
        assert resp.status_code == 409

    def test_404_on_unknown_key_id(self, client: TestClient) -> None:
        registry = _make_registry(usage_side_effect=InstallKeyNotFoundError("ik_missing"))
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.post(
                "/customer-keys/ik_missing/usage",
                json={"units": 1},
            )
        assert resp.status_code == 404

    def test_422_when_units_zero(self, client: TestClient) -> None:
        registry = _make_registry()
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.post(
                f"/customer-keys/{_KEY_ID}/usage",
                json={"units": 0},
            )
        assert resp.status_code == 422

    def test_422_when_units_negative(self, client: TestClient) -> None:
        registry = _make_registry()
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.post(
                f"/customer-keys/{_KEY_ID}/usage",
                json={"units": -3},
            )
        assert resp.status_code == 422

    def test_calls_registry_with_correct_units(self, client: TestClient) -> None:
        updated = _make_record(units_consumed=7)
        registry = _make_registry(record=updated)
        with patch(_MOCK_TARGET, return_value=registry):
            client.post(f"/customer-keys/{_KEY_ID}/usage", json={"units": 7})
        registry.record_key_usage.assert_called_once_with(_KEY_ID, units=7)


# ---------------------------------------------------------------------------
# GET /customer-keys/summary
# ---------------------------------------------------------------------------


class TestInstallKeySummary:
    def test_summary_returns_correct_shape(self, client: TestClient) -> None:
        summary_data = {
            "total": 10,
            "active": 7,
            "revoked": 3,
            "openclaw_keys": 5,
            "claude_code_keys": 5,
        }
        registry = _make_registry(summary_data=summary_data)
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.get("/customer-keys/summary")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 10
        assert body["active"] == 7
        assert body["revoked"] == 3
        assert body["openclaw_keys"] == 5
        assert body["claude_code_keys"] == 5
        assert body["status"] == "ok"
        assert body["service"] == "IronClaw-Security"
        assert "timestamp" in body

    def test_summary_zero_state(self, client: TestClient) -> None:
        registry = _make_registry()
        with patch(_MOCK_TARGET, return_value=registry):
            resp = client.get("/customer-keys/summary")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 0
        assert body["active"] == 0

    def test_summary_calls_registry_summary(self, client: TestClient) -> None:
        registry = _make_registry()
        with patch(_MOCK_TARGET, return_value=registry):
            client.get("/customer-keys/summary")
        registry.summary.assert_called_once()
