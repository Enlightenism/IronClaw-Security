from __future__ import annotations

from fastapi.testclient import TestClient

from app.config import (
    RISK_THRESHOLD_ALLOW_MAX,
    RISK_THRESHOLD_BLOCK_MIN,
    RISK_THRESHOLD_QUARANTINE_MIN,
)
from app.main import app

client = TestClient(app)


def test_ui_runtime_status_route_returns_ok() -> None:
    response = client.get("/ui/runtime/status")

    assert response.status_code == 200


def test_ui_runtime_status_response_shape() -> None:
    response = client.get("/ui/runtime/status")
    payload = response.json()

    assert isinstance(payload["generatedat"], str)

    runtime = payload["runtime"]
    assert runtime["status"] == "healthy"
    assert runtime["pipelineavailable"] is True
    assert runtime["boundaryavailable"] is True
    assert runtime["reviewqueueenabled"] is True
    assert runtime["realexecutionenabled"] is False

    thresholds = payload["thresholds"]
    assert thresholds["allowmaxriskscore"] == RISK_THRESHOLD_ALLOW_MAX
    assert thresholds["reviewminriskscore"] == RISK_THRESHOLD_QUARANTINE_MIN
    assert thresholds["reviewmaxriskscore"] == max(
        RISK_THRESHOLD_ALLOW_MAX,
        RISK_THRESHOLD_BLOCK_MIN - 1,
    )
    assert thresholds["blockminriskscore"] == RISK_THRESHOLD_BLOCK_MIN

    executor = payload["executor"]
    assert executor["executorname"] == "dryrunexecutor"
    assert executor["mode"] == "dryrun"
    assert executor["sandboxrequired"] is True
    assert executor["fallbackexecutorname"] == "dryrunexecutor"

    metrics = payload["metrics"]
    assert metrics["totalevents"] == 0
    assert metrics["allowcount"] == 0
    assert metrics["reviewcount"] == 0
    assert metrics["blockedcount"] == 0
    assert metrics["quarantinecount"] == 0
    assert metrics["latesteventat"] is None

    assert payload["defaultfilepath"] == "app/api/actionexecute.py"

    notes = payload["notes"]
    assert isinstance(notes, list)
    assert len(notes) >= 3
    assert "Guarded execution pipeline is available." in notes
