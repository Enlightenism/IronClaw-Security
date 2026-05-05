from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.actionusage import router


app = FastAPI()
app.include_router(router)
client = TestClient(app)


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