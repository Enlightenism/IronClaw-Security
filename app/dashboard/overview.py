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


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
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
class DashboardKPI:
    key: str
    label: str
    value: float
    unit: str = ""
    trend_direction: str = "steady"
    trend_value: float = 0.0
    status: str = "ok"

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "value": self.value,
            "unit": self.unit,
            "trend_direction": self.trend_direction,
            "trend_value": self.trend_value,
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class DashboardAlert:
    alert_id: str
    title: str
    severity: str
    status: str
    source: str
    created_at: datetime
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "source": self.source,
            "created_at": _isoformat(self.created_at),
            "summary": self.summary,
        }


@dataclass(frozen=True, slots=True)
class DashboardOverview:
    service: str = "ironclaw-security"
    environment: str = "local"
    status: str = "healthy"
    risk_level: str = "moderate"
    total_requests: int = 0
    guarded_requests: int = 0
    blocked_actions: int = 0
    quarantined_actions: int = 0
    active_incidents: int = 0
    pending_reviews: int = 0
    policy_coverage_percent: float = 0.0
    tool_execution_allow_rate: float = 0.0
    telemetry_online: bool = True
    review_backlog_present: bool = False
    quarantine_pressure: bool = False
    kpis: tuple[DashboardKPI, ...] = ()
    alerts: tuple[DashboardAlert, ...] = ()
    checked_at: datetime = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "environment": self.environment,
            "status": self.status,
            "risk_level": self.risk_level,
            "total_requests": self.total_requests,
            "guarded_requests": self.guarded_requests,
            "blocked_actions": self.blocked_actions,
            "quarantined_actions": self.quarantined_actions,
            "active_incidents": self.active_incidents,
            "pending_reviews": self.pending_reviews,
            "policy_coverage_percent": self.policy_coverage_percent,
            "tool_execution_allow_rate": self.tool_execution_allow_rate,
            "telemetry_online": self.telemetry_online,
            "review_backlog_present": self.review_backlog_present,
            "quarantine_pressure": self.quarantine_pressure,
            "kpis": [item.to_dict() for item in self.kpis],
            "alerts": [item.to_dict() for item in self.alerts],
            "checked_at": _isoformat(self.checked_at),
        }


def _normalize_kpi(value: Any) -> DashboardKPI | None:
    if not isinstance(value, dict):
        return None

    key = _coerce_str(value.get("key"))
    label = _coerce_str(value.get("label"))
    if not key and not label:
        return None

    return DashboardKPI(
        key=key or label.lower().replace(" ", "_") or "metric",
        label=label or "Metric",
        value=_coerce_float(value.get("value"), 0.0),
        unit=_coerce_str(value.get("unit")),
        trend_direction=_coerce_str(value.get("trend_direction"), "steady") or "steady",
        trend_value=_coerce_float(value.get("trend_value"), 0.0),
        status=_coerce_str(value.get("status"), "ok") or "ok",
    )


def _normalize_alert(value: Any) -> DashboardAlert | None:
    if not isinstance(value, dict):
        return None

    alert_id = _coerce_str(value.get("alert_id"))
    title = _coerce_str(value.get("title"))
    if not alert_id and not title:
        return None

    return DashboardAlert(
        alert_id=alert_id or title.lower().replace(" ", "-") or "alert",
        title=title or "Alert",
        severity=_coerce_str(value.get("severity"), "medium") or "medium",
        status=_coerce_str(value.get("status"), "open") or "open",
        source=_coerce_str(value.get("source"), "runtime") or "runtime",
        created_at=_coerce_datetime(value.get("created_at"), _utc_now()) or _utc_now(),
        summary=_coerce_str(value.get("summary"), "No alert summary provided.") or "No alert summary provided.",
    )


def default_dashboard_overview() -> DashboardOverview:
    return DashboardOverview()


def build_dashboard_overview(
    data: dict[str, Any] | None = None,
    *,
    baseline: DashboardOverview | None = None,
) -> DashboardOverview:
    source = data or {}
    current = baseline or default_dashboard_overview()

    raw_kpis = source.get("kpis")
    if isinstance(raw_kpis, list):
        kpis = tuple(item for entry in raw_kpis if (item := _normalize_kpi(entry)) is not None)
    else:
        kpis = current.kpis

    raw_alerts = source.get("alerts")
    if isinstance(raw_alerts, list):
        alerts = tuple(item for entry in raw_alerts if (item := _normalize_alert(entry)) is not None)
    else:
        alerts = current.alerts

    active_incidents = max(0, _coerce_int(source.get("active_incidents"), current.active_incidents))
    pending_reviews = max(0, _coerce_int(source.get("pending_reviews"), current.pending_reviews))
    quarantined_actions = max(0, _coerce_int(source.get("quarantined_actions"), current.quarantined_actions))

    review_backlog_present = _coerce_bool(
        source.get("review_backlog_present"),
        current.review_backlog_present or pending_reviews > 0,
    )
    quarantine_pressure = _coerce_bool(
        source.get("quarantine_pressure"),
        current.quarantine_pressure or quarantined_actions > 0,
    )

    return DashboardOverview(
        service=_coerce_str(source.get("service"), current.service) or current.service,
        environment=_coerce_str(source.get("environment"), current.environment) or current.environment,
        status=_coerce_str(source.get("status"), current.status) or current.status,
        risk_level=_coerce_str(source.get("risk_level"), current.risk_level) or current.risk_level,
        total_requests=max(0, _coerce_int(source.get("total_requests"), current.total_requests)),
        guarded_requests=max(0, _coerce_int(source.get("guarded_requests"), current.guarded_requests)),
        blocked_actions=max(0, _coerce_int(source.get("blocked_actions"), current.blocked_actions)),
        quarantined_actions=quarantined_actions,
        active_incidents=active_incidents,
        pending_reviews=pending_reviews,
        policy_coverage_percent=max(0.0, _coerce_float(source.get("policy_coverage_percent"), current.policy_coverage_percent)),
        tool_execution_allow_rate=max(0.0, _coerce_float(source.get("tool_execution_allow_rate"), current.tool_execution_allow_rate)),
        telemetry_online=_coerce_bool(source.get("telemetry_online"), current.telemetry_online),
        review_backlog_present=review_backlog_present,
        quarantine_pressure=quarantine_pressure,
        kpis=kpis,
        alerts=alerts,
        checked_at=_coerce_datetime(source.get("checked_at"), _utc_now()) or _utc_now(),
    )


def dashboard_overview_summary(overview: DashboardOverview) -> dict[str, Any]:
    protection_rate = 0.0
    if overview.total_requests > 0:
        protected_events = overview.blocked_actions + overview.quarantined_actions
        protection_rate = round((protected_events / overview.total_requests) * 100.0, 2)

    return {
        "service": overview.service,
        "environment": overview.environment,
        "status": overview.status,
        "risk_level": overview.risk_level,
        "telemetry_online": overview.telemetry_online,
        "signals": {
            "total_requests": overview.total_requests,
            "guarded_requests": overview.guarded_requests,
            "blocked_actions": overview.blocked_actions,
            "quarantined_actions": overview.quarantined_actions,
            "active_incidents": overview.active_incidents,
            "pending_reviews": overview.pending_reviews,
        },
        "coverage": {
            "policy_coverage_percent": round(overview.policy_coverage_percent, 2),
            "tool_execution_allow_rate": round(overview.tool_execution_allow_rate, 2),
            "protection_rate": protection_rate,
        },
        "pressure": {
            "review_backlog_present": overview.review_backlog_present,
            "quarantine_pressure": overview.quarantine_pressure,
        },
        "kpis": [item.to_dict() for item in overview.kpis],
        "alerts": [item.to_dict() for item in overview.alerts],
        "checked_at": _isoformat(overview.checked_at),
    }