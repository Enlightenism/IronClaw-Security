from __future__ import annotations

from app.ui.actionusage import build_action_usage_view
from app.ui.actionusagedetail import build_action_usage_detail_view
from app.ui.actionusagetest import build_action_usage_test_view


def test_action_usage_views_handle_none_snapshot() -> None:
    summary = build_action_usage_view(
        ownerkey="owner-501",
        snapshot=None,
    )
    detail = build_action_usage_detail_view(
        ownerkey="owner-501",
        snapshot=None,
    )
    test_view = build_action_usage_test_view(
        ownerkey="owner-501",
        snapshot=None,
    )

    assert summary.ownerkey == "owner-501"
    assert detail.ownerkey == "owner-501"
    assert test_view.ownerkey == "owner-501"
    assert summary.snapshot == {}
    assert detail.snapshot == {}
    assert test_view.summary.snapshot == {}
    assert test_view.detail.snapshot == {}
    assert "snapshot_empty" in test_view.checks


def test_action_usage_views_handle_whitespace_ownerkey() -> None:
    summary = build_action_usage_view(
        ownerkey="  owner-502  ",
        snapshot={"remaining_units": 2},
    )
    detail = build_action_usage_detail_view(
        ownerkey="  owner-502  ",
        snapshot={"remaining_units": 2},
    )
    test_view = build_action_usage_test_view(
        ownerkey="  owner-502  ",
        snapshot={"remaining_units": 2},
    )

    assert summary.ownerkey == "owner-502"
    assert detail.ownerkey == "owner-502"
    assert test_view.ownerkey == "owner-502"


def test_action_usage_detail_formats_empty_collections() -> None:
    detail = build_action_usage_detail_view(
        ownerkey="owner-503",
        snapshot={
            "items": [],
            "attributes": {},
        },
    )

    assert any(row.key == "items" and row.value == "[]" for row in detail.rows)
    assert any(row.key == "attributes" and row.value == "{}" for row in detail.rows)


def test_action_usage_summary_uses_neutral_tone_for_non_numeric_balance() -> None:
    summary = build_action_usage_view(
        ownerkey="owner-504",
        snapshot={
            "wallet_balance": "unknown",
        },
    )

    assert any(
        item.label == "wallet_balance" and item.tone == "neutral"
        for item in summary.stats
    )