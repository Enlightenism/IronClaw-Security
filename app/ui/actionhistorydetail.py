from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def _format_detail_value(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, list | tuple | set):
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

    if normalized_key in {"status", "policyverdict", "policy_verdict"}:
        normalized_value = str(value).strip().lower()
        if normalized_value in {"allowed", "allow", "approved", "executed", "success"}:
            return "good"
        if normalized_value in {"review", "pending"}:
            return "warning"
        if normalized_value in {"quarantined", "denied", "blocked", "failed"}:
            return "critical"

    if normalized_key in {"riskscore", "risk_score"}:
        try:
            numeric_value = int(value)
        except (TypeError, ValueError):
            return "neutral"
        if numeric_value >= 10:
            return "critical"
        if numeric_value >= 5:
            return "warning"
        return "good"

    if normalized_key in {"remainingunits", "remaining_units", "walletbalance", "wallet_balance"}:
        try:
            numeric_value = float(value)
        except (TypeError, ValueError):
            return "neutral"
        if numeric_value < 0:
            return "critical"
        if numeric_value == 0:
            return "warning"
        return "good"

    if normalized_key in {"promptinjectiondetected", "prompt_injection_detected"}:
        return "critical" if bool(value) else "good"

    return "neutral"


@dataclass(slots=True)
class ActionHistoryDetailRow:
    key: str
    value: str
    tone: str = "neutral"


@dataclass(slots=True)
class ActionHistoryDetailView:
    title: str
    actionid: str
    rows: list[ActionHistoryDetailRow] = field(default_factory=list)
    record: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


def build_action_history_detail_view(
    *,
    record: dict[str, Any] | None,
    requested_by: str | None = None,
) -> ActionHistoryDetailView:
    normalized_record = dict(record or {})

    actionid = str(
        normalized_record.get("actionid") or normalized_record.get("executionid") or "unknown-action",
    ).strip()

    preferred_order = [
        "actionid",
        "actiontype",
        "target",
        "status",
        "timestamp",
        "clientid",
        "sessionid",
        "ownerkey",
        "riskscore",
        "requestedunits",
        "remainingunits",
        "walletbalance",
        "promptinjectiondetected",
        "policyverdict",
        "executorname",
        "reason",
        "summary",
    ]

    rows: list[ActionHistoryDetailRow] = []
    seen_keys: set[str] = set()

    for key in preferred_order:
        if key in normalized_record:
            value = normalized_record.get(key)
            rows.append(
                ActionHistoryDetailRow(
                    key=key,
                    value=_format_detail_value(value),
                    tone=_infer_detail_tone(key, value),
                ),
            )
            seen_keys.add(key)

    for key in sorted(normalized_record):
        if key in seen_keys:
            continue
        value = normalized_record.get(key)
        rows.append(
            ActionHistoryDetailRow(
                key=key,
                value=_format_detail_value(value),
                tone=_infer_detail_tone(key, value),
            ),
        )

    return ActionHistoryDetailView(
        title="Action History Detail",
        actionid=actionid or "unknown-action",
        rows=rows,
        record=normalized_record,
        metadata={
            "requested_by": requested_by,
        },
    )
