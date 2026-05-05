from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ActionUsageStat:
    label: str
    value: str
    tone: str = "neutral"


@dataclass(slots=True)
class ActionUsageView:
    title: str
    ownerkey: str
    stats: list[ActionUsageStat] = field(default_factory=list)
    snapshot: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


def _format_value(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return str(value)


def _infer_tone(label: str, value: Any) -> str:
    normalized_label = label.lower()
    if normalized_label in {"remaining_units", "wallet_balance"}:
        try:
            numeric_value = float(value)
        except (TypeError, ValueError):
            return "neutral"
        return "good" if numeric_value > 0 else "warning"

    if normalized_label in {"allowed", "active", "enabled"} and isinstance(value, bool):
        return "good" if value else "warning"

    return "neutral"


def build_action_usage_view(
    *,
    ownerkey: str,
    snapshot: dict[str, Any] | None,
    requested_by: str | None = None,
) -> ActionUsageView:
    normalized_ownerkey = ownerkey.strip()
    normalized_snapshot = dict(snapshot or {})

    stats: list[ActionUsageStat] = []

    preferred_order = [
        "plan",
        "subscription_id",
        "remaining_units",
        "wallet_balance",
        "allowed",
        "active",
    ]

    seen_keys: set[str] = set()

    for key in preferred_order:
        if key in normalized_snapshot:
            stats.append(
                ActionUsageStat(
                    label=key,
                    value=_format_value(normalized_snapshot.get(key)),
                    tone=_infer_tone(key, normalized_snapshot.get(key)),
                )
            )
            seen_keys.add(key)

    for key, value in normalized_snapshot.items():
        if key in seen_keys:
            continue
        stats.append(
            ActionUsageStat(
                label=key,
                value=_format_value(value),
                tone=_infer_tone(key, value),
            )
        )

    return ActionUsageView(
        title="Action Usage",
        ownerkey=normalized_ownerkey,
        stats=stats,
        snapshot=normalized_snapshot,
        metadata={
            "requested_by": requested_by,
        },
    )