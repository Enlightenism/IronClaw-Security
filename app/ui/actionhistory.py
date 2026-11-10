from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _format_datetime(value: Any) -> str:
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    text = _normalize_text(value)
    return text or "—"


def _format_compact_value(value: Any) -> str:
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
        parts = [f"{key}={value[key]}" for key in sorted(value)]
        return ", ".join(parts)
    return str(value)


def _tone_for_status(status: str) -> str:
    normalized = status.strip().lower()
    if normalized in {"allowed", "approved", "executed", "success"}:
        return "good"
    if normalized in {"review", "pending"}:
        return "warning"
    if normalized in {"denied", "blocked", "quarantined", "failed"}:
        return "critical"
    return "neutral"


def _tone_for_risk(risk_score: int) -> str:
    if risk_score >= 10:
        return "critical"
    if risk_score >= 5:
        return "warning"
    return "good"


def _tone_for_usage(remaining_units: Any, wallet_balance: Any) -> str:
    numeric_remaining: float | None = None
    numeric_balance: float | None = None

    try:
        if remaining_units is not None:
            numeric_remaining = float(remaining_units)
    except (TypeError, ValueError):
        numeric_remaining = None

    try:
        if wallet_balance is not None:
            numeric_balance = float(wallet_balance)
    except (TypeError, ValueError):
        numeric_balance = None

    if numeric_remaining is not None and numeric_remaining <= 0:
        return "warning"
    if numeric_balance is not None and numeric_balance < 0:
        return "critical"
    if numeric_remaining is not None or numeric_balance is not None:
        return "good"
    return "neutral"


@dataclass(slots=True)
class ActionHistoryKpi:
    label: str
    value: str
    tone: str = "neutral"


@dataclass(slots=True)
class ActionHistoryItem:
    actionid: str
    actiontype: str
    target: str
    status: str
    status_tone: str
    timestamp: str
    clientid: str
    sessionid: str
    ownerkey: str
    riskscore: int
    risk_tone: str
    requestedunits: int
    remainingunits: str
    walletbalance: str
    usage_tone: str
    promptinjectiondetected: bool
    reason: str
    policyverdict: str
    executorname: str
    summary: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ActionHistoryView:
    title: str
    total: int
    allowed_count: int
    review_count: int
    denied_count: int
    items: list[ActionHistoryItem] = field(default_factory=list)
    kpis: list[ActionHistoryKpi] = field(default_factory=list)
    filters: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    generatedat: str = field(default_factory=lambda: _utc_now().isoformat())


def _build_summary(
    *,
    actiontype: str,
    target: str,
    status: str,
    riskscore: int,
    requestedunits: int,
    remainingunits: Any,
) -> str:
    return f"{actiontype} -> {target} | status={status} | risk={riskscore} | requested_units={requestedunits} | remaining_units={_format_compact_value(remainingunits)}"


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def build_action_history_view(
    *,
    actions: list[dict[str, Any]] | None,
    requested_by: str | None = None,
    ownerkey: str | None = None,
    clientid: str | None = None,
    sessionid: str | None = None,
    status: str | None = None,
) -> ActionHistoryView:
    normalized_actions = list(actions or [])
    items: list[ActionHistoryItem] = []

    allowed_count = 0
    review_count = 0
    denied_count = 0

    for index, record in enumerate(normalized_actions, start=1):
        usage = record.get("usage") or {}
        promptinjection = record.get("promptinjection") or {}

        action_status = _normalize_text(record.get("status")) or "unknown"
        normalized_status = action_status.lower()

        if normalized_status == "allowed":
            allowed_count += 1
        elif normalized_status == "review":
            review_count += 1
        elif normalized_status == "denied":
            denied_count += 1

        risk_score = _coerce_int(record.get("finalriskscore", record.get("riskscore", 0)))
        requested_units = _coerce_int(record.get("requestedunits", 0))

        remaining_units = usage.get("remainingunits", usage.get("remaining_units"))
        wallet_balance = usage.get("walletbalance", usage.get("wallet_balance"))

        action_id = _normalize_text(record.get("actionid")) or _normalize_text(record.get("executionid")) or _normalize_text(usage.get("executionid")) or f"action-{index}"

        action_type = _normalize_text(record.get("actiontype")) or "unknown"
        target = _normalize_text(record.get("target")) or "unknown"
        timestamp = _format_datetime(
            record.get("timestamp") or record.get("createdat") or record.get("executedat"),
        )
        reason = _normalize_text(record.get("message") or usage.get("reason") or record.get("reason"))
        policy_verdict = _normalize_text(record.get("policyverdict") or record.get("policy_verdict"))
        executor_name = _normalize_text(record.get("executorname") or record.get("executor_name"))
        prompt_injection_detected = bool(
            promptinjection.get("detected") or promptinjection.get("suspicious") or promptinjection.get("flagged"),
        )

        items.append(
            ActionHistoryItem(
                actionid=action_id,
                actiontype=action_type,
                target=target,
                status=action_status,
                status_tone=_tone_for_status(action_status),
                timestamp=timestamp,
                clientid=_normalize_text(record.get("clientid")) or "—",
                sessionid=_normalize_text(record.get("sessionid")) or "—",
                ownerkey=_normalize_text(record.get("ownerkey")) or "—",
                riskscore=risk_score,
                risk_tone=_tone_for_risk(risk_score),
                requestedunits=requested_units,
                remainingunits=_format_compact_value(remaining_units),
                walletbalance=_format_compact_value(wallet_balance),
                usage_tone=_tone_for_usage(remaining_units, wallet_balance),
                promptinjectiondetected=prompt_injection_detected,
                reason=reason or "—",
                policyverdict=policy_verdict or "—",
                executorname=executor_name or "—",
                summary=_build_summary(
                    actiontype=action_type,
                    target=target,
                    status=action_status,
                    riskscore=risk_score,
                    requestedunits=requested_units,
                    remainingunits=remaining_units,
                ),
                metadata=dict(record.get("metadata") or {}),
            ),
        )

    total = len(items)
    kpis = [
        ActionHistoryKpi(label="Total Actions", value=str(total), tone="neutral"),
        ActionHistoryKpi(label="Allowed", value=str(allowed_count), tone="good"),
        ActionHistoryKpi(label="Review", value=str(review_count), tone="warning"),
        ActionHistoryKpi(label="Denied", value=str(denied_count), tone="critical"),
    ]

    return ActionHistoryView(
        title="Action History",
        total=total,
        allowed_count=allowed_count,
        review_count=review_count,
        denied_count=denied_count,
        items=items,
        kpis=kpis,
        filters={
            "ownerkey": ownerkey,
            "clientid": clientid,
            "sessionid": sessionid,
            "status": status,
        },
        metadata={
            "requested_by": requested_by,
        },
    )
