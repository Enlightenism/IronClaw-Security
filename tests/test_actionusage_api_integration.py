from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

import app.api.actionusage as actionusage_module
from app.api.actionusage import router as actionusage_router
import app.core.unit_wallet as unit_wallet_module
from app.services.actionexecuteservice import ActionExecuteService
from app.services.usagemetering import UsageMeteringService

app = FastAPI()
app.include_router(actionusage_router)
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


def test_actionusage_api_returns_ownerkey_and_snapshot_dict() -> None:
    response = client.get("/action/usage/api-owner-001")

    assert response.status_code == 200
    body = response.json()

    assert body["ownerkey"] == "api-owner-001"
    assert isinstance(body["snapshot"], dict)


def test_actionusage_api_preserves_trimmed_ownerkey() -> None:
    response = client.get("/action/usage/%20api-owner-002%20")

    assert response.status_code == 200
    body = response.json()

    assert body["ownerkey"] == "api-owner-002"
    assert isinstance(body["snapshot"], dict)


def test_actionusage_api_response_shape_is_stable() -> None:
    response = client.get("/action/usage/api-owner-003")

    assert response.status_code == 200
    body = response.json()

    assert set(body.keys()) == {"ownerkey", "snapshot"}
