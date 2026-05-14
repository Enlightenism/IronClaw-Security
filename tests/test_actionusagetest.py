from __future__ import annotations

from app.ui.actionusagetest import build_action_usage_test_view


def test_build_action_usage_test_view_marks_present_checks() -> None:
    view = build_action_usage_test_view(
        ownerkey="owner-201",
        snapshot={
            "plan": "pro",
            "remaining_units": 15,
            "wallet_balance": 80,
        },
        requested_by="tester",
    )

    assert view.title == "Action Usage Test"
    assert view.ownerkey == "owner-201"
    assert view.summary.ownerkey == "owner-201"
    assert view.detail.ownerkey == "owner-201"
    assert view.metadata["requested_by"] == "tester"
    assert "snapshot_loaded" in view.checks
    assert "remaining_units_present" in view.checks
    assert "wallet_balance_present" in view.checks
    assert "plan_present" in view.checks


def test_build_action_usage_test_view_marks_missing_checks() -> None:
    view = build_action_usage_test_view(
        ownerkey="owner-202",
        snapshot={},
    )

    assert view.title == "Action Usage Test"
    assert view.ownerkey == "owner-202"
    assert "snapshot_empty" in view.checks
    assert "remaining_units_missing" in view.checks
    assert "wallet_balance_missing" in view.checks
    assert "plan_missing" in view.checks


def test_build_action_usage_test_view_trims_ownerkey() -> None:
    view = build_action_usage_test_view(
        ownerkey="  owner-203  ",
        snapshot={
            "remaining_units": 1,
        },
    )

    assert view.ownerkey == "owner-203"
    assert view.summary.ownerkey == "owner-203"
    assert view.detail.ownerkey == "owner-203"
