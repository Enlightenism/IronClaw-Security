from __future__ import annotations

from typing import cast

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.api.actionexecute import (
    ActionExecuteRequestModel,
    _detection_to_promptinjection,
    _run_detection,
    router,
)
from app.config import RISK_THRESHOLD_BLOCK_MIN
from app.services.action_guard import ActionGuardDecision

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
    assert body["status"] == "review"
    assert body["executionallowed"] is False


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
    assert body["status"] == "review"
    assert body["executionallowed"] is False


def test_executeaction_blocks_when_detection_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_detection(**_kwargs: object) -> None:
        raise RuntimeError("detection unavailable")

    monkeypatch.setattr("app.api.actionexecute.analyze_action", fail_detection)
    request = ActionExecuteRequestModel(
        actiontype="httpfetch",
        target="https://example.com",
        content="Fetch a public page.",
        clientid="client-edge-004",
        sessionid="session-edge-004",
    )

    promptinjection = _detection_to_promptinjection(_run_detection(request))

    assert promptinjection["verdict"] == "block"
    assert promptinjection["riskdelta"] >= RISK_THRESHOLD_BLOCK_MIN
    assert promptinjection["shouldquarantine"] is False
    assert promptinjection["matchedpatterns"] == ["detection_unavailable"]


def test_executeaction_blocks_invalid_detection_verdict() -> None:
    invalid_detection = cast(
        ActionGuardDecision,
        {
            "action_type": "network_request",
            "verdict": "quarantine",
            "scan_id": None,
            "summary": "",
            "risk_score": 5,
            "matched_patterns": [],
            "categories": [],
            "reasons": [],
            "drift_report": None,
        },
    )

    promptinjection = _detection_to_promptinjection(invalid_detection)

    assert promptinjection["verdict"] == "block"
    assert promptinjection["riskdelta"] >= RISK_THRESHOLD_BLOCK_MIN
    assert promptinjection["shouldquarantine"] is False
