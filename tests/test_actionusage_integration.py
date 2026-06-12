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

_EXPECTED_SNAPSHOT_KEYS = {
    "owner_key",
    "has_active_subscription",
    "plan",
    "package_id",
    "unit_limit",
    "units_consumed",
    "remaining_units",
    "tokens_per_unit",
    "token_coverage_limit",
    "remaining_token_coverage",
    "wallet_balance_units",
    "checked_at",
}

_ABSENT_SNAPSHOT_KEYS = {
    "wallet_balance",
    "max_tokens_covered",
    "tokens_covered",
    "tokens_in_wallet",
}


def test_action_usage_api_and_ui_views_work_together() -> None:
    response = client.get("/action/usage/integration-owner")

    assert response.status_code == 200
    body = response.json()

    assert body["ownerkey"] == "integration-owner"
    assert isinstance(body["snapshot"], dict)

    snapshot = body["snapshot"]

    for key in _EXPECTED_SNAPSHOT_KEYS:
        assert key in snapshot, f"snapshot missing expected key: {key}"

    for key in _ABSENT_SNAPSHOT_KEYS:
        assert key not in snapshot, f"snapshot contains forbidden key: {key}"

    assert "wallet_balance_units" in snapshot
    assert isinstance(snapshot["wallet_balance_units"], int)
    assert snapshot["tokens_per_unit"] == 25_000
    assert snapshot["has_active_subscription"] is False
    assert snapshot["remaining_units"] == 0
    assert snapshot["wallet_balance_units"] == 0

    summary = build_action_usage_view(
        ownerkey=body["ownerkey"],
        snapshot=snapshot,
        requested_by="integration-test",
    )
    detail = build_action_usage_detail_view(
        ownerkey=body["ownerkey"],
        snapshot=snapshot,
        requested_by="integration-test",
    )
    test_view = build_action_usage_test_view(
        ownerkey=body["ownerkey"],
        snapshot=snapshot,
        requested_by="integration-test",
    )

    assert summary.ownerkey == "integration-owner"
    assert detail.ownerkey == "integration-owner"
    assert test_view.ownerkey == "integration-owner"
    assert test_view.summary.ownerkey == summary.ownerkey
    assert test_view.detail.ownerkey == detail.ownerkey
    assert test_view.metadata["requested_by"] == "integration-test"
    assert "snapshot_loaded" in test_view.checks
    assert "remaining_units_present" in test_view.checks


def test_action_usage_empty_snapshot_flows_across_views() -> None:
    response = client.get("/action/usage/empty-owner")

    assert response.status_code == 200
    body = response.json()

    snapshot = body["snapshot"]

    for key in _EXPECTED_SNAPSHOT_KEYS:
        assert key in snapshot, f"snapshot missing expected key: {key}"

    for key in _ABSENT_SNAPSHOT_KEYS:
        assert key not in snapshot, f"snapshot contains forbidden key: {key}"

    summary = build_action_usage_view(
        ownerkey=body["ownerkey"],
        snapshot=snapshot,
    )
    detail = build_action_usage_detail_view(
        ownerkey=body["ownerkey"],
        snapshot=snapshot,
    )
    test_view = build_action_usage_test_view(
        ownerkey=body["ownerkey"],
        snapshot=snapshot,
    )

    assert isinstance(summary.stats, list)
    assert isinstance(detail.rows, list)
    assert "snapshot_empty" in test_view.checks or "snapshot_loaded" in test_view.checks


def test_action_usage_summary_route_is_reachable() -> None:
    response = client.get("/action/usage")

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    assert "generatedat" in body
    assert isinstance(body["generatedat"], str)
    assert len(body["generatedat"]) > 0


def test_action_usage_snapshot_owner_key_matches_request() -> None:
    response = client.get("/action/usage/owner-xyz-999")

    assert response.status_code == 200
    body = response.json()

    assert body["ownerkey"] == "owner-xyz-999"
    assert body["snapshot"]["owner_key"] == "owner-xyz-999"


def test_action_usage_snapshot_checked_at_is_non_empty_string() -> None:
    response = client.get("/action/usage/owner-ts-check")

    assert response.status_code == 200
    snapshot = response.json()["snapshot"]

    assert isinstance(snapshot["checked_at"], str)
    assert len(snapshot["checked_at"]) > 0
    assert "Z" in snapshot["checked_at"] or "+" in snapshot["checked_at"]
