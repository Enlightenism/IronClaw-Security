from __future__ import annotations

from app.ui.actionhistorydetail import build_action_history_detail_view


def test_action_history_detail_view_marks_quarantined_status_as_critical() -> None:
    view = build_action_history_detail_view(
        record={
            "actionid": "act-801",
            "status": "quarantined",
            "riskscore": 12,
            "remainingunits": 0,
            "walletbalance": -1,
            "promptinjectiondetected": True,
        }
    )

    assert any(row.key == "status" and row.tone == "critical" for row in view.rows)
    assert any(row.key == "riskscore" and row.tone == "critical" for row in view.rows)
    assert any(row.key == "remainingunits" and row.tone == "warning" for row in view.rows)
    assert any(row.key == "walletbalance" and row.tone == "critical" for row in view.rows)
    assert any(
        row.key == "promptinjectiondetected" and row.tone == "critical"
        for row in view.rows
    )


def test_action_history_detail_view_marks_allowed_policyverdict_as_good() -> None:
    view = build_action_history_detail_view(
        record={
            "actionid": "act-802",
            "policyverdict": "allow",
            "status": "allowed",
            "riskscore": 1,
            "remainingunits": 5,
            "walletbalance": 2,
            "promptinjectiondetected": False,
        }
    )

    assert any(row.key == "policyverdict" and row.tone == "good" for row in view.rows)
    assert any(row.key == "status" and row.tone == "good" for row in view.rows)
    assert any(row.key == "riskscore" and row.tone == "good" for row in view.rows)
    assert any(row.key == "remainingunits" and row.tone == "good" for row in view.rows)
    assert any(row.key == "walletbalance" and row.tone == "good" for row in view.rows)
    assert any(
        row.key == "promptinjectiondetected" and row.tone == "good"
        for row in view.rows
    )


def test_action_history_detail_view_handles_unknown_values_neutrally() -> None:
    view = build_action_history_detail_view(
        record={
            "actionid": "act-803",
            "status": "mystery",
            "riskscore": "unknown",
            "remainingunits": "n/a",
            "walletbalance": "n/a",
        }
    )

    assert any(row.key == "status" and row.tone == "neutral" for row in view.rows)
    assert any(row.key == "riskscore" and row.tone == "neutral" for row in view.rows)
    assert any(row.key == "remainingunits" and row.tone == "neutral" for row in view.rows)
    assert any(row.key == "walletbalance" and row.tone == "neutral" for row in view.rows)


def test_action_history_detail_view_keeps_unknown_actionid_when_blank_values_are_provided() -> None:
    view = build_action_history_detail_view(
        record={
            "actionid": "   ",
            "executionid": "   ",
            "status": "review",
        }
    )

    assert view.actionid == "unknown-action"