from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Literal
from uuid import uuid4


IncidentSeverity = Literal["low", "medium", "high", "critical"]
IncidentStatus = Literal["open", "triaged", "contained", "resolved"]
IncidentSource = Literal["scan", "guard", "sandbox", "review", "system"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class IncidentRecord:
    incident_id: str
    title: str
    summary: str
    severity: IncidentSeverity
    status: IncidentStatus
    source: IncidentSource
    created_at: datetime
    updated_at: datetime
    request_id: str | None = None
    trace_id: str | None = None
    asset_ref: str | None = None
    verdict: str | None = None
    owner: str | None = None
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["created_at"] = self.created_at.isoformat().replace("+00:00", "Z")
        payload["updated_at"] = self.updated_at.isoformat().replace("+00:00", "Z")
        return payload


class IncidentStore:
    def __init__(self) -> None:
        self._lock = Lock()
        self._items: list[IncidentRecord] = []

    def seed_defaults(self) -> None:
        with self._lock:
            if self._items:
                return

            now = _utcnow()
            self._items.extend(
                [
                    IncidentRecord(
                        incident_id=f"inc-{uuid4().hex[:12]}",
                        title="Prompt injection attempt quarantined",
                        summary="A prompt payload matched high-risk injection heuristics and was quarantined before execution.",
                        severity="high",
                        status="open",
                        source="scan",
                        created_at=now,
                        updated_at=now,
                        request_id="req-seed-001",
                        trace_id="trace-seed-001",
                        asset_ref="prompt:user-input",
                        verdict="quarantine",
                        tags=["prompt-injection", "quarantine", "scanner"],
                        metadata={"seeded": True},
                    ),
                    IncidentRecord(
                        incident_id=f"inc-{uuid4().hex[:12]}",
                        title="Unsafe tool action blocked",
                        summary="A guarded execution request was blocked due to policy restrictions on high-risk tool use.",
                        severity="critical",
                        status="triaged",
                        source="guard",
                        created_at=now,
                        updated_at=now,
                        request_id="req-seed-002",
                        trace_id="trace-seed-002",
                        asset_ref="tool:filesystem",
                        verdict="block",
                        owner="ironclaw",
                        tags=["tool-guard", "policy", "block"],
                        metadata={"seeded": True},
                    ),
                    IncidentRecord(
                        incident_id=f"inc-{uuid4().hex[:12]}",
                        title="Sandbox isolation event recorded",
                        summary="Returned content was isolated in sandbox flow for additional review after suspicious output analysis.",
                        severity="medium",
                        status="contained",
                        source="sandbox",
                        created_at=now,
                        updated_at=now,
                        request_id="req-seed-003",
                        trace_id="trace-seed-003",
                        asset_ref="response:model-output",
                        verdict="warn",
                        owner="sandbox-review",
                        tags=["sandbox", "review", "containment"],
                        metadata={"seeded": True},
                    ),
                ]
            )

    def list_incidents(
        self,
        *,
        severity: IncidentSeverity | None = None,
        status: IncidentStatus | None = None,
        source: IncidentSource | None = None,
    ) -> list[IncidentRecord]:
        with self._lock:
            items = list(self._items)

        if severity is not None:
            items = [item for item in items if item.severity == severity]
        if status is not None:
            items = [item for item in items if item.status == status]
        if source is not None:
            items = [item for item in items if item.source == source]

        return items

    def get_incident(self, incident_id: str) -> IncidentRecord | None:
        with self._lock:
            for item in self._items:
                if item.incident_id == incident_id:
                    return item
        return None

    def create_incident(
        self,
        *,
        title: str,
        summary: str,
        severity: IncidentSeverity,
        source: IncidentSource,
        status: IncidentStatus = "open",
        request_id: str | None = None,
        trace_id: str | None = None,
        asset_ref: str | None = None,
        verdict: str | None = None,
        owner: str | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> IncidentRecord:
        now = _utcnow()
        record = IncidentRecord(
            incident_id=f"inc-{uuid4().hex[:12]}",
            title=title.strip(),
            summary=summary.strip(),
            severity=severity,
            status=status,
            source=source,
            created_at=now,
            updated_at=now,
            request_id=request_id,
            trace_id=trace_id,
            asset_ref=asset_ref,
            verdict=verdict,
            owner=owner,
            tags=list(tags or []),
            metadata=dict(metadata or {}),
        )

        with self._lock:
            self._items.append(record)

        return record

    def update_incident_status(
        self,
        incident_id: str,
        *,
        status: IncidentStatus,
        owner: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> IncidentRecord | None:
        with self._lock:
            for index, item in enumerate(self._items):
                if item.incident_id != incident_id:
                    continue

                updated = IncidentRecord(
                    incident_id=item.incident_id,
                    title=item.title,
                    summary=item.summary,
                    severity=item.severity,
                    status=status,
                    source=item.source,
                    created_at=item.created_at,
                    updated_at=_utcnow(),
                    request_id=item.request_id,
                    trace_id=item.trace_id,
                    asset_ref=item.asset_ref,
                    verdict=item.verdict,
                    owner=owner if owner is not None else item.owner,
                    tags=list(item.tags),
                    metadata={
                        **item.metadata,
                        **dict(metadata or {}),
                    },
                )
                self._items[index] = updated
                return updated

        return None

    def reset(self) -> None:
        with self._lock:
            self._items.clear()


_INCIDENT_STORE = IncidentStore()
_INCIDENT_STORE.seed_defaults()


def get_incident_store() -> IncidentStore:
    return _INCIDENT_STORE


def list_incidents(
    *,
    severity: IncidentSeverity | None = None,
    status: IncidentStatus | None = None,
    source: IncidentSource | None = None,
) -> list[IncidentRecord]:
    return _INCIDENT_STORE.list_incidents(
        severity=severity,
        status=status,
        source=source,
    )


def reset_incident_store() -> None:
    _INCIDENT_STORE.reset()
    _INCIDENT_STORE.seed_defaults()