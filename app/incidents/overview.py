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
    if isinstance(value, int | float):
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
class IncidentOwner:
    owner_id: str
    display_name: str
    team: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "owner_id": self.owner_id,
            "display_name": self.display_name,
            "team": self.team,
        }


@dataclass(frozen=True, slots=True)
class IncidentRecord:
    incident_id: str
    title: str
    severity: str
    status: str
    source: str
    affected_surface: str
    opened_at: datetime
    updated_at: datetime
    owner: IncidentOwner
    requires_human_review: bool = False
    quarantined_actions: int = 0
    blocked_actions: int = 0
    evidence_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "source": self.source,
            "affected_surface": self.affected_surface,
            "opened_at": _isoformat(self.opened_at),
            "updated_at": _isoformat(self.updated_at),
            "owner": self.owner.to_dict(),
            "requires_human_review": self.requires_human_review,
            "quarantined_actions": self.quarantined_actions,
            "blocked_actions": self.blocked_actions,
            "evidence_count": self.evidence_count,
        }


@dataclass(frozen=True, slots=True)
class IncidentsOverview:
    total_open: int = 0
    critical_open: int = 0
    high_open: int = 0
    under_review: int = 0
    contained: int = 0
    mean_time_to_contain_minutes: int = 0
    incidents: tuple[IncidentRecord, ...] = ()
    generated_at: datetime = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_open": self.total_open,
            "critical_open": self.critical_open,
            "high_open": self.high_open,
            "under_review": self.under_review,
            "contained": self.contained,
            "mean_time_to_contain_minutes": self.mean_time_to_contain_minutes,
            "incidents": [item.to_dict() for item in self.incidents],
            "generated_at": _isoformat(self.generated_at),
        }


def _normalize_owner(value: Any) -> IncidentOwner:
    if not isinstance(value, dict):
        return IncidentOwner(owner_id="", display_name="Unassigned", team="")
    return IncidentOwner(
        owner_id=_coerce_str(value.get("owner_id")),
        display_name=_coerce_str(value.get("display_name"), "Unassigned") or "Unassigned",
        team=_coerce_str(value.get("team")),
    )


def _normalize_incident(value: Any) -> IncidentRecord | None:
    if not isinstance(value, dict):
        return None

    incident_id = _coerce_str(value.get("incident_id"))
    title = _coerce_str(value.get("title"))
    if not incident_id and not title:
        return None

    opened_at = _coerce_datetime(value.get("opened_at"), _utc_now()) or _utc_now()
    updated_at = _coerce_datetime(value.get("updated_at"), opened_at) or opened_at

    return IncidentRecord(
        incident_id=incident_id or "incident",
        title=title or "Untitled incident",
        severity=_coerce_str(value.get("severity"), "medium") or "medium",
        status=_coerce_str(value.get("status"), "open") or "open",
        source=_coerce_str(value.get("source"), "runtime") or "runtime",
        affected_surface=_coerce_str(value.get("affected_surface"), "agent") or "agent",
        opened_at=opened_at,
        updated_at=updated_at,
        owner=_normalize_owner(value.get("owner")),
        requires_human_review=_coerce_bool(value.get("requires_human_review"), False),
        quarantined_actions=max(0, _coerce_int(value.get("quarantined_actions"), 0)),
        blocked_actions=max(0, _coerce_int(value.get("blocked_actions"), 0)),
        evidence_count=max(0, _coerce_int(value.get("evidence_count"), 0)),
    )


def default_incidents_overview() -> IncidentsOverview:
    return IncidentsOverview()


def build_incidents_overview(
    data: dict[str, Any] | None = None,
    *,
    baseline: IncidentsOverview | None = None,
) -> IncidentsOverview:
    source = data or {}
    current = baseline or default_incidents_overview()

    raw_incidents = source.get("incidents")
    if isinstance(raw_incidents, list):
        incidents = tuple(item for entry in raw_incidents if (item := _normalize_incident(entry)) is not None)
    else:
        incidents = current.incidents

    total_open = max(0, _coerce_int(source.get("total_open"), current.total_open or len(incidents)))
    critical_open = max(0, _coerce_int(source.get("critical_open"), current.critical_open))
    high_open = max(0, _coerce_int(source.get("high_open"), current.high_open))
    under_review = max(0, _coerce_int(source.get("under_review"), current.under_review))
    contained = max(0, _coerce_int(source.get("contained"), current.contained))
    mean_time_to_contain_minutes = max(
        0,
        _coerce_int(source.get("mean_time_to_contain_minutes"), current.mean_time_to_contain_minutes),
    )

    if not source.get("total_open") and incidents:
        total_open = sum(1 for item in incidents if item.status.lower() in {"open", "investigating", "triage", "contained", "under_review"})
    if not source.get("critical_open") and incidents:
        critical_open = sum(1 for item in incidents if item.severity.lower() == "critical" and item.status.lower() not in {"resolved", "closed"})
    if not source.get("high_open") and incidents:
        high_open = sum(1 for item in incidents if item.severity.lower() == "high" and item.status.lower() not in {"resolved", "closed"})
    if not source.get("under_review") and incidents:
        under_review = sum(1 for item in incidents if item.requires_human_review or item.status.lower() in {"under_review", "triage", "investigating"})
    if not source.get("contained") and incidents:
        contained = sum(1 for item in incidents if item.status.lower() == "contained")

    return IncidentsOverview(
        total_open=total_open,
        critical_open=critical_open,
        high_open=high_open,
        under_review=under_review,
        contained=contained,
        mean_time_to_contain_minutes=mean_time_to_contain_minutes,
        incidents=incidents,
        generated_at=_coerce_datetime(source.get("generated_at"), _utc_now()) or _utc_now(),
    )


def incidents_overview_summary(overview: IncidentsOverview) -> dict[str, Any]:
    total_quarantined_actions = sum(item.quarantined_actions for item in overview.incidents)
    total_blocked_actions = sum(item.blocked_actions for item in overview.incidents)
    total_evidence = sum(item.evidence_count for item in overview.incidents)

    return {
        "counts": {
            "total_open": overview.total_open,
            "critical_open": overview.critical_open,
            "high_open": overview.high_open,
            "under_review": overview.under_review,
            "contained": overview.contained,
        },
        "metrics": {
            "mean_time_to_contain_minutes": overview.mean_time_to_contain_minutes,
            "total_quarantined_actions": total_quarantined_actions,
            "total_blocked_actions": total_blocked_actions,
            "total_evidence": total_evidence,
        },
        "incidents": [item.to_dict() for item in overview.incidents],
        "generated_at": _isoformat(overview.generated_at),
    }
