from __future__ import annotations

from app.ui.actionhistorytest import (
    ActionHistoryTestView,
    build_action_history_test_view,
)


def test_build_action_history_test_view_with_matching_selection() -> None:
    actions = [
        {
            "actionid": "act-1",
            "kind": "scan",
            "status": "completed",
            "summary": "First action",
        },
        {
            "actionid": "act-2",
            "kind": "block",
            "status": "failed",
            "summary": "Second action",
        },
    ]

    result = build_action_history_test_view(
        actions=actions,
        selected_actionid="act-2",
        requested_by="tester",
    )

    assert isinstance(result, ActionHistoryTestView)
    assert result.title == "Action History Test"
    assert result.total == 2
    assert result.summary.total == 2
    assert result.selected is not None
    assert "actions_loaded" in result.checks
    assert "selection_requested" in result.checks
    assert "selection_resolved" in result.checks
    assert result.metadata["requested_by"] == "tester"


def test_build_action_history_test_view_defaults_to_first_action() -> None:
    actions = [
        {
            "actionid": "act-1",
            "kind": "scan",
            "status": "completed",
            "summary": "First action",
        },
        {
            "actionid": "act-2",
            "kind": "block",
            "status": "failed",
            "summary": "Second action",
        },
    ]

    result = build_action_history_test_view(
        actions=actions,
        selected_actionid="missing-action",
    )

    assert result.total == 2
    assert "actions_loaded" in result.checks
    assert "selection_requested" in result.checks
    assert "selection_resolved" in result.checks
    assert result.selected is not None


def test_build_action_history_test_view_uses_default_selection_when_none_requested() -> None:
    actions = [
        {
            "actionid": "act-9",
            "kind": "review",
            "status": "queued",
            "summary": "Queued action",
        }
    ]

    result = build_action_history_test_view(
        actions=actions,
        selected_actionid=None,
    )

    assert result.total == 1
    assert "actions_loaded" in result.checks
    assert "selection_defaulted" in result.checks
    assert "selection_resolved" in result.checks
    assert result.selected is not None


def test_build_action_history_test_view_handles_empty_actions() -> None:
    result = build_action_history_test_view(
        actions=[],
        selected_actionid=None,
        requested_by="tester",
    )

    assert isinstance(result, ActionHistoryTestView)
    assert result.title == "Action History Test"
    assert result.total == 0
    assert result.summary.total == 0
    assert "actions_empty" in result.checks
    assert "selection_defaulted" in result.checks
    assert "selection_missing" in result.checks
    assert result.metadata["requested_by"] == "tester"


def test_build_action_history_test_view_matches_executionid_when_actionid_missing() -> None:
    actions = [
        {
            "executionid": "exec-7",
            "kind": "sync",
            "status": "completed",
            "summary": "Execution-backed action",
        }
    ]

    result = build_action_history_test_view(
        actions=actions,
        selected_actionid="exec-7",
    )

    assert result.total == 1
    assert "actions_loaded" in result.checks
    assert "selection_requested" in result.checks
    assert "selection_resolved" in result.checks
    assert result.selected is not None