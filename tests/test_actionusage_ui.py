from __future__ import annotations

from app.ui.actionusage import build_action_usage_view
from app.ui.actionusagedetail import build_action_usage_detail_view
from app.ui.actionusagetest import build_action_usage_test_view


def test_build_action_usage_view_creates_expected_stats() -> None:
    view = build_action_usage_view(
        ownerkey="owner-001",
        snapshot={
            "plan": "pro",
            "package_id": "sub_123",
            "remaining_units": 12,
            "wallet_balance": 7,
            "allowed": True,
        },
        requested_by="tester",
    )

    assert view.title == "Action Usage"
    assert view.ownerkey == "owner-001"
    assert len(view.stats) >= 5
    assert view.metadata["requested_by"] == "tester"
    assert any(item.label == "remaining_units" and item.value == "12" for item in view.stats)
    assert any(item.label == "wallet_balance" and item.tone == "good" for item in view.stats)
    assert any(item.label == "allowed" and item.tone == "good" for item in view.stats)


def test_build_action_usage_detail_view_formats_rows() -> None:
    view = build_action_usage_detail_view(
        ownerkey="owner-002",
        snapshot={
            "plan": "starter",
            "status": "authorized",
            "remaining_units": 0,
            "flags": ["prepaid", "active"],
            "context": {"region": "mx", "tier": "edge"},
        },
        requested_by="tester",
    )

    assert view.title == "Action Usage Detail"
    assert view.ownerkey == "owner-002"
    assert view.metadata["requested_by"] == "tester"
    assert any(row.key == "status" and row.tone == "good" for row in view.rows)
    assert any(row.key == "remaining_units" and row.tone == "warning" for row in view.rows)
    assert any(row.key == "flags" and row.value == "prepaid, active" for row in view.rows)
    assert any(row.key == "context" and row.value == "region=mx, tier=edge" for row in view.rows)


def test_build_action_usage_test_view_combines_summary_detail_and_checks() -> None:
    view = build_action_usage_test_view(
        ownerkey="owner-003",
        snapshot={
            "plan": "enterprise",
            "remaining_units": 25,
            "wallet_balance": 100,
        },
        requested_by="tester",
    )

    assert view.title == "Action Usage Test"
    assert view.ownerkey == "owner-003"
    assert view.summary.ownerkey == "owner-003"
    assert view.detail.ownerkey == "owner-003"
    assert view.metadata["requested_by"] == "tester"
    assert "snapshot_loaded" in view.checks
    assert "remaining_units_present" in view.checks
    assert "wallet_balance_present" in view.checks
    assert "plan_present" in view.checks
