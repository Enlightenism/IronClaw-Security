from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.actionexecute import router

app = FastAPI()
app.include_router(router)
client = TestClient(app)


def test_executeaction_rejects_blank_target_after_trimming() -> None:
    response = client.post(
        "/action/execute",
        json={
            "actiontype": "httpfetch",
            "target": "   ",
            "content": "Fetch content.",
            "clientid": "client-edge-001",
            "sessionid": "session-edge-001",
            "ownerkey": "owner-edge-001",
            "requestedunits": 1,
            "riskscore": 0,
            "metadata": {},
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "target must not be empty"


def test_executeaction_uses_default_ownerkey_when_not_provided() -> None:
    response = client.post(
        "/action/execute",
        json={
            "actiontype": "httpfetch",
            "target": "https://example.com",
            "content": "Fetch the public homepage and summarize it.",
            "clientid": "client-edge-002",
            "sessionid": "session-edge-002",
            "requestedunits": 1,
            "riskscore": 0,
            "metadata": {
                "source": "web",
                "documenttext": "Example Domain is for use in illustrative examples.",
            },
        },
    )

    assert response.status_code == 200
    body = response.json()

    assert body["ownerkey"] == "system"
    assert body["status"] == "allowed"


def test_executeaction_preserves_trimmed_target_in_response() -> None:
    response = client.post(
        "/action/execute",
        json={
            "actiontype": "browseropen",
            "target": "  https://example.com/docs  ",
            "content": "Open the public docs page.",
            "clientid": "client-edge-003",
            "sessionid": "session-edge-003",
            "ownerkey": "owner-edge-003",
            "requestedunits": 1,
            "riskscore": 0,
            "metadata": {
                "source": "web",
                "documenttext": "Public documentation for safe browsing.",
            },
        },
    )

    assert response.status_code == 200
    body = response.json()

    assert body["target"] == "https://example.com/docs"
    assert body["status"] == "allowed"
