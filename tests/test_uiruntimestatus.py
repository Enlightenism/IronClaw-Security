from __future__ import annotations

from fastapi.testclient import TestClient

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
    assert thresholds["allowmaxriskscore"] == 49
    assert thresholds["reviewminriskscore"] == 50
    assert thresholds["reviewmaxriskscore"] == 89
    assert thresholds["blockminriskscore"] == 90

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