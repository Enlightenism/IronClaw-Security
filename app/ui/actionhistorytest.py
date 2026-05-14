from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.ui.actionhistory import ActionHistoryView, build_action_history_view
from app.ui.actionhistorydetail import (
    ActionHistoryDetailView,
    build_action_history_detail_view,
)


@dataclass(slots=True)
class ActionHistoryTestView:
    title: str
    total: int
    summary: ActionHistoryView
    selected: ActionHistoryDetailView
    checks: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def build_action_history_test_view(
    *,
    actions: list[dict[str, Any]] | None,
    selected_actionid: str | None = None,
    requested_by: str | None = None,
) -> ActionHistoryTestView:
    normalized_actions = list(actions or [])
    summary = build_action_history_view(
        actions=normalized_actions,
        requested_by=requested_by,
    )

    selected_record: dict[str, Any] | None = None
    normalized_selected_actionid = str(selected_actionid or "").strip()

    if normalized_selected_actionid:
        for record in normalized_actions:
            record_actionid = str(
                record.get("actionid") or record.get("executionid") or "",
            ).strip()
            if record_actionid == normalized_selected_actionid:
                selected_record = record
                break

    if selected_record is None and normalized_actions:
        selected_record = normalized_actions[0]

    selected = build_action_history_detail_view(
        record=selected_record,
        requested_by=requested_by,
    )

    checks: list[str] = []

    if normalized_actions:
        checks.append("actions_loaded")
    else:
        checks.append("actions_empty")

    if normalized_selected_actionid:
        checks.append("selection_requested")
    else:
        checks.append("selection_defaulted")

    if selected_record is not None:
        checks.append("selection_resolved")
    else:
        checks.append("selection_missing")

    return ActionHistoryTestView(
        title="Action History Test",
        total=summary.total,
        summary=summary,
        selected=selected,
        checks=checks,
        metadata={
            "requested_by": requested_by,
        },
    )
