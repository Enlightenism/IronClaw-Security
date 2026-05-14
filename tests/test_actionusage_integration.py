from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.actionusage import router as actionusage_router
from app.ui.actionusage import build_action_usage_view
from app.ui.actionusagedetail import build_action_usage_detail_view
from app.ui.actionusagetest import build_action_usage_test_view

app = FastAPI()
app.include_router(actionusage_router)
client = TestClient(app)


def test_action_usage_api_and_ui_views_work_together() -> None:
    response = client.get("/action/usage/integration-owner")

    assert response.status_code == 200
    body = response.json()

    assert body["ownerkey"] == "integration-owner"
    assert isinstance(body["snapshot"], dict)

    summary = build_action_usage_view(
        ownerkey=body["ownerkey"],
        snapshot=body["snapshot"],
        requested_by="integration-test",
    )
    detail = build_action_usage_detail_view(
        ownerkey=body["ownerkey"],
        snapshot=body["snapshot"],
        requested_by="integration-test",
    )
    test_view = build_action_usage_test_view(
        ownerkey=body["ownerkey"],
        snapshot=body["snapshot"],
        requested_by="integration-test",
    )

    assert summary.ownerkey == "integration-owner"
    assert detail.ownerkey == "integration-owner"
    assert test_view.ownerkey == "integration-owner"
    assert test_view.summary.ownerkey == summary.ownerkey
    assert test_view.detail.ownerkey == detail.ownerkey
    assert test_view.metadata["requested_by"] == "integration-test"


def test_action_usage_empty_snapshot_flows_across_views() -> None:
    response = client.get("/action/usage/empty-owner")

    assert response.status_code == 200
    body = response.json()

    summary = build_action_usage_view(
        ownerkey=body["ownerkey"],
        snapshot=body["snapshot"],
    )
    detail = build_action_usage_detail_view(
        ownerkey=body["ownerkey"],
        snapshot=body["snapshot"],
    )
    test_view = build_action_usage_test_view(
        ownerkey=body["ownerkey"],
        snapshot=body["snapshot"],
    )

    assert isinstance(summary.stats, list)
    assert isinstance(detail.rows, list)
    assert "snapshot_empty" in test_view.checks or "snapshot_loaded" in test_view.checks
