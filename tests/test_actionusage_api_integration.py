from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.actionusage import router as actionusage_router

app = FastAPI()
app.include_router(actionusage_router)
client = TestClient(app)


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
