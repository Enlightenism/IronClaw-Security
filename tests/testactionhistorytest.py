from __future__ import annotations

from app.ui.actionhistorytest import (
    ActionHistoryTestView,
    build_action_history_test_view,
)


def test_build_action_history_test_view_returns_expected_defaults() -> None:
    result = build_action_history_test_view()

    assert isinstance(result, ActionHistoryTestView)
    assert result.title == "Action History Test"
    assert result.total == 3
    assert result.summary.total == 3
    assert result.selected is not None
    assert "actions_loaded" in result.checks
    assert "selection_defaulted" in result.checks
    assert "selection_resolved" in result.checks
    assert result.metadata["requested_by"] == "tester"


def test_build_action_history_test_view_honors_selected_actionid() -> None:
    result = build_action_history_test_view(selected_actionid="act-1002")

    assert result.title == "Action History Test"
    assert result.total == 3
    assert result.selected is not None
    assert "selection_requested" in result.checks
    assert "selection_resolved" in result.checks


def test_build_action_history_test_view_matches_executionid() -> None:
    result = build_action_history_test_view(selected_actionid="exec-1003")

    assert result.total == 3
    assert result.selected is not None
    assert "selection_requested" in result.checks
    assert "selection_resolved" in result.checks


def test_build_action_history_test_view_honors_requested_by_override() -> None:
    result = build_action_history_test_view(requested_by="integration-test")

    assert result.metadata["requested_by"] == "integration-test"
    assert result.title == "Action History Test"
    assert result.total == 3


def test_build_action_history_test_view_returns_fallback_selection_when_missing() -> None:
    result = build_action_history_test_view(selected_actionid="missing-action")

    assert result.total == 3
    assert result.selected is not None
    assert "selection_requested" in result.checks
    assert "selection_resolved" in result.checks
