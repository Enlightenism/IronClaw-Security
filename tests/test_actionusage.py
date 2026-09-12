from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import app.api.actionusage as actionusage_module
import app.core.unit_wallet as unit_wallet_module
from app.api.actionusage import router
from app.services.actionexecuteservice import ActionExecuteService
from app.services.usagemetering import UsageMeteringService

app = FastAPI()
app.include_router(router)
client = TestClient(app)


@pytest.fixture(autouse=True)
def _force_action_usage_memory_runtime(monkeypatch: pytest.MonkeyPatch):
    wallet_registry = unit_wallet_module.UnitWalletRegistry()
    wallet_registry._repo = unit_wallet_module.MemoryUnitWalletRepository()
    unit_wallet_module._unit_wallet_registry = wallet_registry

    service = ActionExecuteService(usage_metering_service=UsageMeteringService())
    service._usage_metering_service._wallet_registry = wallet_registry

    monkeypatch.setattr(actionusage_module, "get_action_execute_service", lambda: service)
    yield


def test_getactionusage_returns_snapshot_for_owner() -> None:
    response = client.get("/action/usage/test-owner")

    assert response.status_code == 200
    body = response.json()

    assert body["ownerkey"] == "test-owner"
    assert isinstance(body["snapshot"], dict)


def test_getactionusage_trims_ownerkey_in_response() -> None:
    response = client.get("/action/usage/%20owner-123%20")

    assert response.status_code == 200
    body = response.json()

    assert body["ownerkey"] == "owner-123"
    assert isinstance(body["snapshot"], dict)
