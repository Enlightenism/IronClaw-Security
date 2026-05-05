from __future__ import annotations

from app.ui.actionusagedetail import build_action_usage_detail_view


def test_build_action_usage_detail_view_orders_preferred_fields_first() -> None:
    view = build_action_usage_detail_view(
        ownerkey="owner-100",
        snapshot={
            "status": "authorized",
            "wallet_balance": 50,
            "plan": "pro",
            "remaining_units": 8,
            "subscription_id": "sub_100",
            "custom_flag": "enabled",
        },
        requested_by="tester",
    )

    ordered_keys = [row.key for row in view.rows[:5]]
    assert ordered_keys == [
        "plan",
        "subscription_id",
        "remaining_units",
        "wallet_balance",
        "status",
    ]
    assert view.metadata["requested_by"] == "tester"


def test_build_action_usage_detail_view_formats_special_value_types() -> None:
    view = build_action_usage_detail_view(
        ownerkey="owner-101",
        snapshot={
            "flags": ["metered", "active"],
            "attributes": {"region": "mx", "tier": "pro"},
            "active": True,
            "notes": None,
        },
    )

    assert any(row.key == "flags" and row.value == "metered, active" for row in view.rows)
    assert any(
        row.key == "attributes" and row.value == "region=mx, tier=pro"
        for row in view.rows
    )
    assert any(row.key == "active" and row.value == "Yes" for row in view.rows)
    assert any(row.key == "notes" and row.value == "—" for row in view.rows)


def test_build_action_usage_detail_view_assigns_expected_tones() -> None:
    view = build_action_usage_detail_view(
        ownerkey="owner-102",
        snapshot={
            "remaining_units": 0,
            "wallet_balance": -1,
            "status": "denied",
            "allowed": False,
        },
    )

    assert any(
        row.key == "remaining_units" and row.tone == "warning"
        for row in view.rows
    )
    assert any(
        row.key == "wallet_balance" and row.tone == "critical"
        for row in view.rows
    )
    assert any(row.key == "status" and row.tone == "critical" for row in view.rows)
    assert any(row.key == "allowed" and row.tone == "warning" for row in view.rows)