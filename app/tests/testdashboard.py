from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.core.install_keys import (
    InstallKeyNotFoundError,
    InstallKeyRecord,
    InstallKeyUsageError,
    _reset_install_key_registry_for_testing,
    get_install_key_registry,
)
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


def _make_record(
    *,
    key_id: str = _KEY_ID,
    owner_key: str = _OWNER,
    program: str = "openclaw",
    masked_key: str = "ic_install_op...alue",
    label: str = "",
    active: bool = True,
    units_consumed: int = 0,
    last_used_at: Any = None,
) -> MagicMock:
    r = MagicMock(spec=InstallKeyRecord)
    r.key_id = key_id
    r.owner_key = owner_key
    r.program = program
    r.masked_key = masked_key
    r.label = label
    r.active = active
    r.units_consumed = units_consumed
    r.last_used_at = last_used_at
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


# ---------------------------------------------------------------------------
# GET /dashboard/overview
# ---------------------------------------------------------------------------


class TestDashboardOverview:
    def test_returns_200(self, client: TestClient) -> None:
        resp = client.get("/dashboard/overview")
        assert resp.status_code == 200

    def test_response_shape(self, client: TestClient) -> None:
        body = client.get("/dashboard/overview").json()
        assert body["status"] == "ok"
        assert body["service"] == "ironclaw-dashboard"
        assert "timestamp" in body
        assert "kpis" in body
        assert "alerts" in body
        assert "activity" in body

    def test_kpis_are_present(self, client: TestClient) -> None:
        body = client.get("/dashboard/overview").json()
        assert len(body["kpis"]) >= 1

    def test_alerts_are_present(self, client: TestClient) -> None:
        body = client.get("/dashboard/overview").json()
        assert len(body["alerts"]) >= 1

    def test_activity_items_present(self, client: TestClient) -> None:
        body = client.get("/dashboard/overview").json()
        assert len(body["activity"]) >= 1


# ---------------------------------------------------------------------------
# GET /dashboard/units
# ---------------------------------------------------------------------------


class TestGetUnitsForOwner:
    def test_returns_200_with_empty_owner(self, app: FastAPI, client: TestClient) -> None:
        reg = _make_registry(records=[])
        app.dependency_overrides[get_install_key_registry] = lambda: reg
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
        try:
            resp = client.get(f"/dashboard/units?owner_key={_OWNER}")
        finally:
            app.dependency_overrides.clear()
        assert resp.json()["keys"][0]["last_used_at"] is not None

    def test_calls_registry_with_owner_key(self, app: FastAPI, client: TestClient) -> None:
        reg = _make_registry(records=[])
        app.dependency_overrides[get_install_key_registry] = lambda: reg
        try:
            client.get(f"/dashboard/units?owner_key={_OWNER}")
        finally:
            app.dependency_overrides.clear()
        reg.get_keys_for_owner.assert_called_once_with(_OWNER)

    def test_missing_owner_key_returns_422(self, client: TestClient) -> None:
        resp = client.get("/dashboard/units")
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /dashboard/units/record
# ---------------------------------------------------------------------------


class TestRecordUnitUsage:
    def test_returns_200_on_success(self, app: FastAPI, client: TestClient) -> None:
        updated = _make_record(units_consumed=10)
        reg = _make_registry(usage_return=updated)
        app.dependency_overrides[get_install_key_registry] = lambda: reg
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
        try:
            resp = client.post(
                "/dashboard/units/record",
                json={"key_id": _KEY_ID, "units": 5},
            )
        finally:
            app.dependency_overrides.clear()
        assert resp.status_code == 409

    def test_422_when_units_zero(self, client: TestClient) -> None:
        resp = client.post(
            "/dashboard/units/record",
            json={"key_id": _KEY_ID, "units": 0},
        )
        assert resp.status_code == 422

    def test_422_when_units_negative(self, client: TestClient) -> None:
        resp = client.post(
            "/dashboard/units/record",
            json={"key_id": _KEY_ID, "units": -1},
        )
        assert resp.status_code == 422

    def test_calls_registry_with_keyword_units(self, app: FastAPI, client: TestClient) -> None:
        updated = _make_record(units_consumed=3)
        reg = _make_registry(usage_return=updated)
        app.dependency_overrides[get_install_key_registry] = lambda: reg
        try:
            client.post(
                "/dashboard/units/record",
                json={"key_id": _KEY_ID, "units": 3},
            )
        finally:
            app.dependency_overrides.clear()
        reg.record_key_usage.assert_called_once_with(_KEY_ID, units=3)
