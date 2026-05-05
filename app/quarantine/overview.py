from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _isoformat(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _coerce_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on", "enabled"}:
            return True
        if normalized in {"0", "false", "no", "off", "disabled"}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return default


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_datetime(value: Any, default: datetime | None = None) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return default
        candidate = candidate.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            return default
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    return default


@dataclass(frozen=True, slots=True)
class QuarantineBucket:
    name: str
    count: int = 0
    severity: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "count": self.count,
            "severity": self.severity,
        }


@dataclass(frozen=True, slots=True)
class QuarantineItem:
    item_id: str
    category: str
    severity: str
    verdict: str
    reason: str
    source: str
    status: str = "quarantined"
    review_required: bool = True
    created_at: datetime = field(default_factory=_utc_now)
    updated_at: datetime = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "category": self.category,
            "severity": self.severity,
            "verdict": self.verdict,
            "reason": self.reason,
            "source": self.source,
            "status": self.status,
            "review_required": self.review_required,
            "created_at": _isoformat(self.created_at),
            "updated_at": _isoformat(self.updated_at),
        }


@dataclass(frozen=True, slots=True)
class QuarantineOverview:
    service: str = "ironclaw-security"
    environment: str = "local"
    total_items: int = 0
    pending_review: int = 0
    auto_contained: int = 0
    high_severity: int = 0
    critical_severity: int = 0
    oldest_item_age_hours: int = 0
    queue_healthy: bool = True
    escalation_required: bool = False
    buckets: tuple[QuarantineBucket, ...] = ()
    recent_items: tuple[QuarantineItem, ...] = ()
    checked_at: datetime = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "environment": self.environment,
            "total_items": self.total_items,
            "pending_review": self.pending_review,
            "auto_contained": self.auto_contained,
            "high_severity": self.high_severity,
            "critical_severity": self.critical_severity,
            "oldest_item_age_hours": self.oldest_item_age_hours,
            "queue_healthy": self.queue_healthy,
            "escalation_required": self.escalation_required,
            "buckets": [bucket.to_dict() for bucket in self.buckets],
            "recent_items": [item.to_dict() for item in self.recent_items],
            "checked_at": _isoformat(self.checked_at),
        }


def _normalize_bucket(item: Any) -> QuarantineBucket | None:
    if not isinstance(item, dict):
        return None
    name = _coerce_str(item.get("name"))
    if not name:
        return None
    return QuarantineBucket(
        name=name,
        count=max(0, _coerce_int(item.get("count"), 0)),
        severity=_coerce_str(item.get("severity"), "medium") or "medium",
    )


def _normalize_recent_item(item: Any) -> QuarantineItem | None:
    if not isinstance(item, dict):
        return None

    item_id = _coerce_str(item.get("item_id"))
    if not item_id:
        return None

    created_at = _coerce_datetime(item.get("created_at"), _utc_now()) or _utc_now()
    updated_at = _coerce_datetime(item.get("updated_at"), created_at) or created_at

    return QuarantineItem(
        item_id=item_id,
        category=_coerce_str(item.get("category"), "unknown") or "unknown",
        severity=_coerce_str(item.get("severity"), "medium") or "medium",
        verdict=_coerce_str(item.get("verdict"), "quarantine") or "quarantine",
        reason=_coerce_str(item.get("reason"), "Security policy triggered.") or "Security policy triggered.",
        source=_coerce_str(item.get("source"), "runtime") or "runtime",
        status=_coerce_str(item.get("status"), "quarantined") or "quarantined",
        review_required=_coerce_bool(item.get("review_required"), True),
        created_at=created_at,
        updated_at=updated_at,
    )


def _default_buckets() -> tuple[QuarantineBucket, ...]:
    return (
        QuarantineBucket(name="prompt_injection", count=0, severity="high"),
        QuarantineBucket(name="unsafe_tool_call", count=0, severity="critical"),
        QuarantineBucket(name="data_exfiltration", count=0, severity="critical"),
        QuarantineBucket(name="sandbox_violation", count=0, severity="high"),
    )


def default_quarantine_overview() -> QuarantineOverview:
    return QuarantineOverview(buckets=_default_buckets())


def build_quarantine_overview(
    data: dict[str, Any] | None = None,
    *,
    baseline: QuarantineOverview | None = None,
) -> QuarantineOverview:
    source = data or {}
    current = baseline or default_quarantine_overview()

    raw_buckets = source.get("buckets")
    if isinstance(raw_buckets, list):
        normalized_buckets = tuple(bucket for item in raw_buckets if (bucket := _normalize_bucket(item)) is not None)
        buckets = normalized_buckets or current.buckets
    else:
        buckets = current.buckets

    raw_recent_items = source.get("recent_items")
    if isinstance(raw_recent_items, list):
        normalized_items = tuple(item for entry in raw_recent_items if (item := _normalize_recent_item(entry)) is not None)
        recent_items = normalized_items
    else:
        recent_items = current.recent_items

    total_items = max(0, _coerce_int(source.get("total_items"), current.total_items))
    pending_review = max(0, _coerce_int(source.get("pending_review"), current.pending_review))
    auto_contained = max(0, _coerce_int(source.get("auto_contained"), current.auto_contained))
    high_severity = max(0, _coerce_int(source.get("high_severity"), current.high_severity))
    critical_severity = max(0, _coerce_int(source.get("critical_severity"), current.critical_severity))
    oldest_item_age_hours = max(0, _coerce_int(source.get("oldest_item_age_hours"), current.oldest_item_age_hours))

    queue_healthy = _coerce_bool(source.get("queue_healthy"), current.queue_healthy)
    escalation_required = _coerce_bool(
        source.get("escalation_required"),
        current.escalation_required or critical_severity > 0 or pending_review > 25,
    )

    checked_at = _coerce_datetime(source.get("checked_at"), _utc_now()) or _utc_now()

    return QuarantineOverview(
        service=_coerce_str(source.get("service"), current.service) or current.service,
        environment=_coerce_str(source.get("environment"), current.environment) or current.environment,
        total_items=total_items,
        pending_review=pending_review,
        auto_contained=auto_contained,
        high_severity=high_severity,
        critical_severity=critical_severity,
        oldest_item_age_hours=oldest_item_age_hours,
        queue_healthy=queue_healthy,
        escalation_required=escalation_required,
        buckets=buckets,
        recent_items=recent_items,
        checked_at=checked_at,
    )


def quarantine_overview_summary(overview: QuarantineOverview) -> dict[str, Any]:
    review_required_items = sum(1 for item in overview.recent_items if item.review_required)
    active_buckets = [bucket.to_dict() for bucket in overview.buckets if bucket.count > 0]

    return {
        "service": overview.service,
        "environment": overview.environment,
        "queue_healthy": overview.queue_healthy,
        "escalation_required": overview.escalation_required,
        "counts": {
            "total_items": overview.total_items,
            "pending_review": overview.pending_review,
            "auto_contained": overview.auto_contained,
            "high_severity": overview.high_severity,
            "critical_severity": overview.critical_severity,
            "review_required_recent_items": review_required_items,
        },
        "timing": {
            "oldest_item_age_hours": overview.oldest_item_age_hours,
            "checked_at": _isoformat(overview.checked_at),
        },
        "active_buckets": active_buckets,
        "recent_items": [item.to_dict() for item in overview.recent_items],
    }