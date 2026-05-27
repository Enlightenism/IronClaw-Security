from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.ui.runtime.status import (
    ActiveExecutorView,
    BoundaryThresholdView,
    RuntimeHealthView,
    RuntimeMetricsView,
    RuntimePolicyView,
    RuntimeStatusResponse,
)
from app.ui.runtime.status import (
    router as ui_runtime_router,
)
from app.ui.runtimestatus import get_runtime_status_page

# ---------------------------------------------------------------------------
# Shared test app — GET /ui/runtime/status (no auth; direct router mount)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def client() -> TestClient:
    app = FastAPI()
    app.include_router(ui_runtime_router)
    return TestClient(app)


# ---------------------------------------------------------------------------
# GET /ui/runtime/status — 200 + shape
# ---------------------------------------------------------------------------


class TestUIRuntimeStatus:
    def test_status_200(self, client: TestClient) -> None:
        response = client.get("/ui/runtime/status")
        assert response.status_code == 200

    def test_response_is_json(self, client: TestClient) -> None:
        response = client.get("/ui/runtime/status")
        assert response.headers["content-type"].startswith("application/json")

    def test_response_model_parses(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        model = RuntimeStatusResponse(**data)
        assert isinstance(model, RuntimeStatusResponse)

    def test_top_level_fields_present(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        required = {
            "generatedat",
            "runtime",
            "thresholds",
            "runtimeavailable",
            "boundaryactive",
            "reviewqueueenabled",
            "executor",
            "metrics",
            "policy",
            "defaultfilepath",
            "notes",
        }
        for field in required:
            assert field in data, f"Missing top-level field '{field}'"

    def test_generatedat_is_str(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        assert isinstance(data["generatedat"], str)
        assert len(data["generatedat"]) > 0

    def test_runtimeavailable_is_bool(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        assert isinstance(data["runtimeavailable"], bool)

    def test_boundaryactive_is_bool(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        assert isinstance(data["boundaryactive"], bool)

    def test_reviewqueueenabled_is_bool(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        assert isinstance(data["reviewqueueenabled"], bool)

    def test_runtime_is_healthy(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        assert data["runtimeavailable"] is True
        assert data["boundaryactive"] is True
        assert data["reviewqueueenabled"] is True

    # runtime sub-object

    def test_runtime_block_shape(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        runtime = data["runtime"]
        model = RuntimeHealthView(**runtime)
        assert model.status == "healthy"
        assert model.pipelineavailable is True
        assert model.boundaryavailable is True
        assert model.reviewqueueenabled is True
        assert model.realexecutionenabled is False

    def test_runtime_status_value(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        assert data["runtime"]["status"] == "healthy"

    def test_runtime_realexecution_disabled(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        assert data["runtime"]["realexecutionenabled"] is False

    # thresholds sub-object

    def test_thresholds_shape(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        thresholds = data["thresholds"]
        model = BoundaryThresholdView(**thresholds)
        assert model.allowmaxriskscore == 49
        assert model.reviewminriskscore == 50
        assert model.reviewmaxriskscore == 89
        assert model.blockminriskscore == 90

    def test_thresholds_band_continuity(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        t = data["thresholds"]
        assert t["allowmaxriskscore"] + 1 == t["reviewminriskscore"]
        assert t["reviewmaxriskscore"] + 1 == t["blockminriskscore"]

    # executor sub-object

    def test_executor_shape(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        executor = data["executor"]
        model = ActiveExecutorView(**executor)
        assert model.executorname == "dryrunexecutor"
        assert model.defaultmode == "dryrun"
        assert model.sandboxrequired is True
        assert model.mode == "dryrun"

    def test_executor_name(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        assert data["executor"]["executorname"] == "dryrunexecutor"

    def test_executor_sandbox_required(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        assert data["executor"]["sandboxrequired"] is True

    def test_executor_fallback_present(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        assert "fallbackexecutorname" in data["executor"]

    # metrics sub-object

    def test_metrics_shape(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        metrics = data["metrics"]
        model = RuntimeMetricsView(**metrics)
        assert model.totalrequests == 0
        assert model.allowcount == 0
        assert model.reviewcount == 0
        assert model.blockedcount == 0
        assert model.quarantinecount == 0

    def test_metrics_counts_are_ints(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        m = data["metrics"]
        for key in ("totalevents", "totalrequests", "allowcount", "reviewcount", "blockedcount", "quarantinecount"):
            assert isinstance(m[key], int), f"metrics.{key} must be int"

    def test_metrics_latesteventat_nullable(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        val = data["metrics"].get("latesteventat")
        assert val is None or isinstance(val, str)

    # policy sub-object

    def test_policy_shape(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        policy = data["policy"]
        model = RuntimePolicyView(**policy)
        assert model.policymode == "dryrun"
        assert model.defaultaction == "review"

    def test_policy_mode_value(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        assert data["policy"]["policymode"] == "dryrun"

    def test_policy_default_action(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        assert data["policy"]["defaultaction"] == "review"

    # notes

    def test_notes_is_list(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        assert isinstance(data["notes"], list)

    def test_notes_are_strings(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        for note in data["notes"]:
            assert isinstance(note, str)

    def test_notes_not_empty(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        assert len(data["notes"]) > 0

    # defaultfilepath

    def test_defaultfilepath_is_str(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        assert isinstance(data["defaultfilepath"], str)
        assert len(data["defaultfilepath"]) > 0

    def test_defaultfilepath_value(self, client: TestClient) -> None:
        data = client.get("/ui/runtime/status").json()
        assert data["defaultfilepath"] == "app/api/actionexecute.py"


# ---------------------------------------------------------------------------
# GET /runtime/status — get_runtime_status_page() payload shape
# (canonical data-layer function; tested directly without HTTP overhead)
# ---------------------------------------------------------------------------


class TestRuntimeStatusPage:
    def test_returns_dict(self) -> None:
        payload = get_runtime_status_page()
        assert isinstance(payload, dict)

    def test_status_ok(self) -> None:
        payload = get_runtime_status_page()
        assert payload["status"] == "ok"

    def test_top_level_fields_present(self) -> None:
        payload = get_runtime_status_page()
        required = {
            "status",
            "pageid",
            "title",
            "path",
            "summary",
            "runtimeavailable",
            "boundaryactive",
            "reviewqueueenabled",
            "executor",
            "metrics",
            "policy",
            "defaultfilepath",
            "metadata",
        }
        for field in required:
            assert field in payload, f"Missing field '{field}'"

    def test_pageid(self) -> None:
        payload = get_runtime_status_page()
        assert payload["pageid"] == "runtime-status"

    def test_path(self) -> None:
        payload = get_runtime_status_page()
        assert payload["path"] == "/runtime/status"

    def test_runtimeavailable_true(self) -> None:
        payload = get_runtime_status_page()
        assert payload["runtimeavailable"] is True

    def test_boundaryactive_true(self) -> None:
        payload = get_runtime_status_page()
        assert payload["boundaryactive"] is True

    def test_reviewqueueenabled_true(self) -> None:
        payload = get_runtime_status_page()
        assert payload["reviewqueueenabled"] is True

    def test_executor_shape(self) -> None:
        executor = get_runtime_status_page()["executor"]
        assert executor["executorname"] == "dryrunexecutor"
        assert executor["fallbackexecutorname"] == "dryrunexecutor"
        assert executor["defaultmode"] == "dryrun"
        assert executor["sandboxrequired"] is True

    def test_metrics_shape(self) -> None:
        metrics = get_runtime_status_page()["metrics"]
        for key in ("totalrequests", "allowcount", "reviewcount", "blockedcount", "quarantinecount"):
            assert isinstance(metrics[key], int)
            assert metrics[key] == 0

    def test_metrics_latesteventat_default(self) -> None:
        metrics = get_runtime_status_page()["metrics"]
        val = metrics.get("latesteventat")
        assert val is None or isinstance(val, str)

    def test_policy_shape(self) -> None:
        policy = get_runtime_status_page()["policy"]
        assert policy["policymode"] == "dryrun"
        assert policy["defaultaction"] == "review"

    def test_defaultfilepath(self) -> None:
        payload = get_runtime_status_page()
        assert payload["defaultfilepath"] == "app/api/actionexecute.py"

    def test_metadata_present(self) -> None:
        metadata = get_runtime_status_page()["metadata"]
        assert isinstance(metadata, dict)
        assert "tags" in metadata
        assert "runtime" in metadata["tags"]

    def test_title_and_summary_are_str(self) -> None:
        payload = get_runtime_status_page()
        assert isinstance(payload["title"], str)
        assert isinstance(payload["summary"], str)
        assert len(payload["title"]) > 0
        assert len(payload["summary"]) > 0

    def test_multiple_calls_are_consistent(self) -> None:
        first = get_runtime_status_page()
        second = get_runtime_status_page()
        assert first["pageid"] == second["pageid"]
        assert first["runtimeavailable"] == second["runtimeavailable"]
        assert first["executor"]["executorname"] == second["executor"]["executorname"]
