from __future__ import annotations

from app.ui.actionhistory import build_action_history_view


def test_action_history_view_handles_none_actions() -> None:
    view = build_action_history_view(actions=None)

    assert view.title == "Action History"
    assert view.total == 0
    assert view.items == []
    assert view.allowed_count == 0
    assert view.review_count == 0
    assert view.quarantined_count == 0
    assert view.denied_count == 0


def test_action_history_view_handles_empty_action_record() -> None:
    view = build_action_history_view(actions=[{}])

    assert view.total == 1
    item = view.items[0]
    assert item.actionid == "action-1"
    assert item.actiontype == "unknown"
    assert item.target == "unknown"
    assert item.status == "unknown"
    assert item.status_tone == "neutral"
    assert item.summary.startswith("unknown -> unknown")


def test_action_history_view_uses_fallback_usage_field_names() -> None:
    view = build_action_history_view(
        actions=[
            {
                "status": "allowed",
                "usage": {
                    "remaining_units": 14,
                    "wallet_balance": 9,
                },
            }
        ]
    )

    item = view.items[0]
    assert item.remainingunits == "14"
    assert item.walletbalance == "9"
    assert item.usage_tone == "good"


def test_action_history_view_marks_zero_remaining_units_as_warning() -> None:
    view = build_action_history_view(
        actions=[
            {
                "status": "allowed",
                "usage": {
                    "remainingunits": 0,
                    "walletbalance": 3,
                },
            }
        ]
    )

    item = view.items[0]
    assert item.usage_tone == "warning"


def test_action_history_view_marks_negative_wallet_balance_as_critical() -> None:
    view = build_action_history_view(
        actions=[
            {
                "status": "allowed",
                "usage": {
                    "remainingunits": 5,
                    "walletbalance": -2,
                },
            }
        ]
    )

    item = view.items[0]
    assert item.usage_tone == "critical"