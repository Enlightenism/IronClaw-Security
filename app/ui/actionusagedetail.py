from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ActionUsageDetailRow:
    key: str
    value: str
    tone: str = "neutral"


@dataclass(slots=True)
class ActionUsageDetailView:
    title: str
    ownerkey: str
    rows: list[ActionUsageDetailRow] = field(default_factory=list)
    snapshot: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


def _format_detail_value(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (list, tuple, set)):
        if not value:
            return "[]"
        return ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        if not value:
            return "{}"
        return ", ".join(f"{key}={value[key]}" for key in sorted(value))
    return str(value)


def _infer_detail_tone(key: str, value: Any) -> str:
    normalized_key = key.lower()

    if normalized_key in {"remaining_units", "wallet_balance"}:
        try:
            numeric_value = float(value)
        except (TypeError, ValueError):
            return "neutral"
        if numeric_value > 0:
            return "good"
        if numeric_value == 0:
            return "warning"
        return "critical"

    if normalized_key in {"allowed", "active", "enabled"} and isinstance(value, bool):
        return "good" if value else "warning"

    if normalized_key in {"status", "reason"}:
        normalized_value = str(value).strip().lower()
        if normalized_value in {"authorized", "active", "ok", "success", "allowed"}:
            return "good"
        if normalized_value in {"review", "pending"}:
            return "warning"
        if normalized_value in {"denied", "blocked", "failed", "inactive"}:
            return "critical"

    return "neutral"


def build_action_usage_detail_view(
    *,
    ownerkey: str,
    snapshot: dict[str, Any] | None,
    requested_by: str | None = None,
) -> ActionUsageDetailView:
    normalized_ownerkey = ownerkey.strip()
    normalized_snapshot = dict(snapshot or {})

    preferred_order = [
        "plan",
        "subscription_id",
        "remaining_units",
        "wallet_balance",
        "allowed",
        "active",
        "status",
        "reason",
    ]

    rows: list[ActionUsageDetailRow] = []
    seen_keys: set[str] = set()

    for key in preferred_order:
        if key in normalized_snapshot:
            value = normalized_snapshot.get(key)
            rows.append(
                ActionUsageDetailRow(
                    key=key,
                    value=_format_detail_value(value),
                    tone=_infer_detail_tone(key, value),
                ),
            )
            seen_keys.add(key)

    for key in sorted(normalized_snapshot):
        if key in seen_keys:
            continue
        value = normalized_snapshot[key]
        rows.append(
            ActionUsageDetailRow(
                key=key,
                value=_format_detail_value(value),
                tone=_infer_detail_tone(key, value),
            ),
        )

    return ActionUsageDetailView(
        title="Action Usage Detail",
        ownerkey=normalized_ownerkey,
        rows=rows,
        snapshot=normalized_snapshot,
        metadata={
            "requested_by": requested_by,
        },
    )
