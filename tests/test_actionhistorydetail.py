from __future__ import annotations

from app.ui.actionhistorydetail import build_action_history_detail_view


def test_build_action_history_detail_view_uses_actionid_and_preserves_metadata() -> None:
    view = build_action_history_detail_view(
        record={
            "actionid": "act-701",
            "actiontype": "httpfetch",
            "target": "https://example.com",
            "status": "allowed",
            "riskscore": 2,
        },
        requested_by="tester",
    )

    assert view.title == "Action History Detail"
    assert view.actionid == "act-701"
    assert view.metadata["requested_by"] == "tester"
    assert any(row.key == "actionid" and row.value == "act-701" for row in view.rows)
    assert any(row.key == "status" and row.tone == "good" for row in view.rows)
    assert any(row.key == "riskscore" and row.tone == "good" for row in view.rows)


def test_build_action_history_detail_view_falls_back_to_executionid() -> None:
    view = build_action_history_detail_view(
        record={
            "executionid": "exec-702",
            "status": "review",
            "riskscore": 5,
        },
    )

    assert view.actionid == "exec-702"
    assert any(row.key == "status" and row.tone == "warning" for row in view.rows)
    assert any(row.key == "riskscore" and row.tone == "warning" for row in view.rows)


def test_build_action_history_detail_view_formats_special_values() -> None:
    view = build_action_history_detail_view(
        record={
            "promptinjectiondetected": True,
            "tags": ["security", "runtime"],
            "metadata": {"region": "mx", "tier": "prod"},
            "notes": None,
        },
    )

    assert any(row.key == "promptinjectiondetected" and row.tone == "critical" for row in view.rows)
    assert any(row.key == "tags" and row.value == "security, runtime" for row in view.rows)
    assert any(row.key == "metadata" and row.value == "region=mx, tier=prod" for row in view.rows)
    assert any(row.key == "notes" and row.value == "—" for row in view.rows)


def test_build_action_history_detail_view_handles_missing_record() -> None:
    view = build_action_history_detail_view(record=None)

    assert view.title == "Action History Detail"
    assert view.actionid == "unknown-action"
    assert view.rows == []
    assert view.record == {}
