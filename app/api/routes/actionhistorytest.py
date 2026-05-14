from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from app.ui.actionhistorytest import (
    ActionHistoryTestView,
    build_action_history_test_view,
)

router = APIRouter(prefix="/actionhistorytest", tags=["actionhistorytest"])


def _sample_actions() -> list[dict[str, Any]]:
    return [
        {
            "actionid": "act-1001",
            "kind": "scan",
            "status": "completed",
            "summary": "Scanned upload and cleared request",
            "requested_by": "tester",
        },
        {
            "actionid": "act-1002",
            "kind": "block",
            "status": "failed",
            "summary": "Block action failed during downstream execution",
            "requested_by": "tester",
        },
        {
            "executionid": "exec-1003",
            "kind": "review",
            "status": "queued",
            "summary": "Queued action for analyst review",
            "requested_by": "tester",
        },
    ]


@router.get("", response_model=ActionHistoryTestView)
def get_action_history_test(
    selected_actionid: str | None = Query(default=None),
    requested_by: str | None = Query(default="tester"),
) -> ActionHistoryTestView:
    return build_action_history_test_view(
        actions=_sample_actions(),
        selected_actionid=selected_actionid,
        requested_by=requested_by,
    )
