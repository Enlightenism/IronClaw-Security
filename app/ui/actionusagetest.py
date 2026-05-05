from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.ui.actionusage import ActionUsageView, build_action_usage_view
from app.ui.actionusagedetail import (
    ActionUsageDetailView,
    build_action_usage_detail_view,
)


@dataclass(slots=True)
class ActionUsageTestView:
    title: str
    ownerkey: str
    summary: ActionUsageView
    detail: ActionUsageDetailView
    checks: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def build_action_usage_test_view(
    *,
    ownerkey: str,
    snapshot: dict[str, Any] | None,
    requested_by: str | None = None,
) -> ActionUsageTestView:
    normalized_ownerkey = ownerkey.strip()
    normalized_snapshot = dict(snapshot or {})

    summary = build_action_usage_view(
        ownerkey=normalized_ownerkey,
        snapshot=normalized_snapshot,
        requested_by=requested_by,
    )
    detail = build_action_usage_detail_view(
        ownerkey=normalized_ownerkey,
        snapshot=normalized_snapshot,
        requested_by=requested_by,
    )

    checks: list[str] = []

    if normalized_snapshot:
        checks.append("snapshot_loaded")
    else:
        checks.append("snapshot_empty")

    if "remaining_units" in normalized_snapshot:
        checks.append("remaining_units_present")
    else:
        checks.append("remaining_units_missing")

    if "wallet_balance" in normalized_snapshot:
        checks.append("wallet_balance_present")
    else:
        checks.append("wallet_balance_missing")

    if "plan" in normalized_snapshot:
        checks.append("plan_present")
    else:
        checks.append("plan_missing")

    return ActionUsageTestView(
        title="Action Usage Test",
        ownerkey=normalized_ownerkey,
        summary=summary,
        detail=detail,
        checks=checks,
        metadata={
            "requested_by": requested_by,
        },
    )