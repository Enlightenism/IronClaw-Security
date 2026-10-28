from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from threading import Lock
from typing import Any, Literal
from uuid import uuid4

IncidentSeverity = Literal["low", "medium", "high", "critical"]
IncidentStatus = Literal["open", "triaged", "contained", "resolved", "closed", "investigating", "inprogress"]
IncidentSource = Literal["scan", "guard", "sandbox", "review", "system", "ironclaw", "engine", "scanner", "tester"]

_ALLOWED_SEVERITIES: frozenset[str] = frozenset({"low", "medium", "high", "critical"})
_ALLOWED_STATUSES: frozenset[str] = frozenset({"open", "triaged", "contained", "resolved", "closed", "investigating", "inprogress"})
_ALLOWED_SOURCES: frozenset[str] = frozenset({"scan", "guard", "sandbox", "review", "system", "ironclaw", "engine", "scanner", "tester"})


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _norm_severity(value: str | None, default: str = "medium") -> str:
    v = (value or default).strip().lower()
    return v if v in _ALLOWED_SEVERITIES else default


def _norm_status(value: str | None, default: str = "open") -> str:
    v = (value or default).strip().lower()
    return v if v in _ALLOWED_STATUSES else default


def _norm_source(value: str | None, default: str = "ironclaw") -> str:
    v = (value or default).strip().lower()
    return v if v in _ALLOWED_SOURCES else default


@dataclass(slots=True)
class IncidentRecordInMemory:
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
    description: str | None = None
    category: str | None = None
    organization_id: str | None = None
    assigned_to: str | None = None
    scan_id: str | None = None
    review_id: str | None = None
    resolved_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["created_at"] = self.created_at.isoformat().replace("+00:00", "Z")
        payload["updated_at"] = self.updated_at.isoformat().replace("+00:00", "Z")
        payload["resolved_at"] = self.resolved_at.isoformat().replace("+00:00", "Z") if self.resolved_at is not None else None
        # Dual-key aliases so routers using either naming convention work
        payload["incidentid"] = self.incident_id
        payload["id"] = self.incident_id
        payload["createdat"] = payload["created_at"]
        payload["updatedat"] = payload["updated_at"]
        payload["resolvedat"] = payload["resolved_at"]
        payload["request_id"] = self.request_id
        payload["requestid"] = self.request_id
        payload["trace_id"] = self.trace_id
        payload["traceid"] = self.trace_id
        payload["asset_ref"] = self.asset_ref
        payload["assetref"] = self.asset_ref
        payload["assigned_to"] = self.assigned_to or self.owner
        payload["assignedto"] = self.assigned_to or self.owner
        payload["description"] = self.description or self.summary
        payload["category"] = self.category or "security"
        payload["incident_type"] = self.category or "security"
        payload["priority"] = self.severity
        payload["timestamp"] = payload["created_at"]
        return payload

    def dict(self) -> dict[str, Any]:
        return self.to_dict()

    def model_dump(self) -> dict[str, Any]:
        return self.to_dict()

    def as_dict(self) -> dict[str, Any]:
        return self.to_dict()


class IncidentStoreInMemory:
    def __init__(self) -> None:
        self._lock = Lock()
        self._items: list[IncidentRecordInMemory] = []

    def seed_defaults(self) -> None:
        with self._lock:
            if self._items:
                return
            now = _utcnow()
            self._items.extend(
                [
                    IncidentRecordInMemory(
                        incident_id=f"inc-{uuid4().hex[:12]}",
                        title="Prompt injection attempt blocked",
                        summary="A prompt payload matched high-risk injection heuristics and was blocked before execution.",
                        severity="high",
                        status="open",
                        source="scan",
                        created_at=now,
                        updated_at=now,
                        request_id="req-seed-001",
                        trace_id="trace-seed-001",
                        asset_ref="prompt:user-input",
                        verdict="block",
                        tags=["prompt-injection", "quarantine", "scanner"],
                        metadata={"seeded": True},
                        category="security",
                    ),
                    IncidentRecordInMemory(
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
                        category="security",
                    ),
                    IncidentRecordInMemory(
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
                        verdict="block",
                        owner="sandbox-review",
                        tags=["sandbox", "review", "containment"],
                        metadata={"seeded": True},
                        category="security",
                    ),
                ]
            )

    # ------------------------------------------------------------------
    # List / query
    # ------------------------------------------------------------------

    def list_incidents(
        self,
        *,
        severity: str | None = None,
        status: str | None = None,
        source: str | None = None,
        organization_id: str | None = None,
        assigned_to: str | None = None,
        category: str | None = None,
        scan_id: str | None = None,
        limit: int = 100,
    ) -> list[IncidentRecordInMemory]:
        with self._lock:
            items = list(self._items)

        if severity is not None:
            items = [i for i in items if i.severity == _norm_severity(severity)]
        if status is not None:
            items = [i for i in items if i.status == _norm_status(status)]
        if source is not None:
            items = [i for i in items if i.source == _norm_source(source)]
        if organization_id is not None:
            items = [i for i in items if i.organization_id == organization_id]
        if assigned_to is not None:
            items = [i for i in items if (i.assigned_to or i.owner) == assigned_to]
        if category is not None:
            items = [i for i in items if i.category == category]
        if scan_id is not None:
            items = [i for i in items if i.scan_id == scan_id]

        items.sort(key=lambda r: r.updated_at, reverse=True)
        return items[:limit]

    def listincidents(self, **kwargs: Any) -> list[IncidentRecordInMemory]:
        return self.list_incidents(**kwargs)

    def list(self, **kwargs: Any) -> list[IncidentRecordInMemory]:
        return self.list_incidents(**kwargs)

    def all(self, **kwargs: Any) -> list[IncidentRecordInMemory]:
        return self.list_incidents(**kwargs)

    def query(self, **kwargs: Any) -> list[IncidentRecordInMemory]:
        return self.list_incidents(**kwargs)

    def search(self, **kwargs: Any) -> list[IncidentRecordInMemory]:
        return self.list_incidents(**kwargs)

    def latest(self) -> IncidentRecordInMemory | None:
        items = self.list_incidents(limit=1)
        return items[0] if items else None

    def last(self) -> IncidentRecordInMemory | None:
        return self.latest()

    # ------------------------------------------------------------------
    # Get
    # ------------------------------------------------------------------

    def get_incident(self, incident_id: str) -> IncidentRecordInMemory | None:
        iid = (incident_id or "").strip()
        if not iid:
            raise ValueError("incident_id is required")
        with self._lock:
            for item in self._items:
                if item.incident_id == iid:
                    return item
        return None

    def getincident(self, incident_id: str) -> IncidentRecordInMemory | None:
        return self.get_incident(incident_id)

    def get(self, incident_id: str) -> IncidentRecordInMemory | None:
        return self.get_incident(incident_id)

    def getbyid(self, incident_id: str) -> IncidentRecordInMemory | None:
        return self.get_incident(incident_id)

    def findbyid(self, incident_id: str) -> IncidentRecordInMemory | None:
        return self.get_incident(incident_id)

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def create_incident(
        self,
        *,
        title: str,
        summary: str,
        severity: str,
        source: str,
        status: str = "open",
        request_id: str | None = None,
        trace_id: str | None = None,
        asset_ref: str | None = None,
        verdict: str | None = None,
        owner: str | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        description: str | None = None,
        category: str | None = None,
        organization_id: str | None = None,
        assigned_to: str | None = None,
        scan_id: str | None = None,
        review_id: str | None = None,
        **_extra: Any,
    ) -> IncidentRecordInMemory:
        now = _utcnow()
        record = IncidentRecordInMemory(
            incident_id=f"inc-{uuid4().hex[:12]}",
            title=title.strip(),
            summary=summary.strip(),
            severity=_norm_severity(severity),
            status=_norm_status(status),
            source=_norm_source(source),
            created_at=now,
            updated_at=now,
            request_id=request_id,
            trace_id=trace_id,
            asset_ref=asset_ref,
            verdict=verdict,
            owner=owner,
            tags=list(tags or []),
            metadata=dict(metadata or {}),
            description=description,
            category=category or "security",
            organization_id=organization_id,
            assigned_to=assigned_to or owner,
            scan_id=scan_id,
            review_id=review_id,
        )
        with self._lock:
            self._items.append(record)
        return record

    def createincident(self, **kwargs: Any) -> IncidentRecordInMemory:
        return self.create_incident(**kwargs)

    def create(self, **kwargs: Any) -> IncidentRecordInMemory:
        return self.create_incident(**kwargs)

    def add(self, **kwargs: Any) -> IncidentRecordInMemory:
        return self.create_incident(**kwargs)

    def open_incident(self, **kwargs: Any) -> IncidentRecordInMemory:
        return self.create_incident(**kwargs)

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    def update_incident_status(
        self,
        incident_id: str,
        *,
        status: str,
        owner: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> IncidentRecordInMemory | None:
        norm = _norm_status(status)
        with self._lock:
            for index, item in enumerate(self._items):
                if item.incident_id != incident_id:
                    continue
                now = _utcnow()
                resolved_at = item.resolved_at
                if norm in {"resolved", "closed"} and resolved_at is None:
                    resolved_at = now
                updated = IncidentRecordInMemory(
                    incident_id=item.incident_id,
                    title=item.title,
                    summary=item.summary,
                    severity=item.severity,
                    status=norm,
                    source=item.source,
                    created_at=item.created_at,
                    updated_at=now,
                    request_id=item.request_id,
                    trace_id=item.trace_id,
                    asset_ref=item.asset_ref,
                    verdict=item.verdict,
                    owner=owner if owner is not None else item.owner,
                    tags=list(item.tags),
                    metadata={**item.metadata, **dict(metadata or {})},
                    description=item.description,
                    category=item.category,
                    organization_id=item.organization_id,
                    assigned_to=owner if owner is not None else item.assigned_to,
                    scan_id=item.scan_id,
                    review_id=item.review_id,
                    resolved_at=resolved_at,
                )
                self._items[index] = updated
                return updated
        return None

    def updateincidentstatus(
        self,
        incident_id: str,
        *,
        status: str,
        owner: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> IncidentRecordInMemory | None:
        return self.update_incident_status(incident_id, status=status, owner=owner, metadata=metadata)

    def update_incident(
        self,
        incident_id: str,
        updates: dict[str, Any],
    ) -> IncidentRecordInMemory | None:
        status = updates.get("status")
        owner = updates.get("owner") or updates.get("assigned_to") or updates.get("assignedto")
        metadata = updates.get("metadata")
        if status is not None:
            return self.update_incident_status(incident_id, status=status, owner=owner, metadata=metadata)
        with self._lock:
            for index, item in enumerate(self._items):
                if item.incident_id != incident_id:
                    continue
                now = _utcnow()
                updated = IncidentRecordInMemory(
                    incident_id=item.incident_id,
                    title=updates.get("title", item.title),
                    summary=updates.get("summary", item.summary),
                    severity=_norm_severity(updates.get("severity", item.severity)),
                    status=item.status,
                    source=_norm_source(updates.get("source", item.source)),
                    created_at=item.created_at,
                    updated_at=now,
                    request_id=updates.get("request_id", item.request_id),
                    trace_id=updates.get("trace_id", item.trace_id),
                    asset_ref=updates.get("asset_ref", item.asset_ref),
                    verdict=updates.get("verdict", item.verdict),
                    owner=owner or item.owner,
                    tags=list(updates.get("tags", item.tags)),
                    metadata={**item.metadata, **dict(metadata or {})},
                    description=updates.get("description", item.description),
                    category=updates.get("category", item.category),
                    organization_id=updates.get("organization_id", item.organization_id),
                    assigned_to=owner or item.assigned_to,
                    scan_id=updates.get("scan_id", item.scan_id),
                    review_id=updates.get("review_id", item.review_id),
                    resolved_at=item.resolved_at,
                )
                self._items[index] = updated
                return updated
        return None

    def update(self, incident_id: str, updates: dict[str, Any]) -> IncidentRecordInMemory | None:
        return self.update_incident(incident_id, updates)

    def resolve_incident(
        self,
        incident_id: str,
        *,
        resolution: str | None = None,
        verdict: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> IncidentRecordInMemory | None:
        extra: dict[str, Any] = {}
        if resolution is not None:
            extra["resolution"] = resolution
        if verdict is not None:
            extra["verdict"] = verdict
        return self.update_incident_status(incident_id, status="resolved", metadata={**extra, **(metadata or {})})

    def close_incident(
        self,
        incident_id: str,
        *,
        resolution: str | None = None,
        verdict: str | None = None,
    ) -> IncidentRecordInMemory | None:
        extra: dict[str, Any] = {}
        if resolution is not None:
            extra["resolution"] = resolution
        if verdict is not None:
            extra["verdict"] = verdict
        return self.update_incident_status(incident_id, status="closed", metadata=extra or None)

    def assign_incident(self, incident_id: str, assigned_to: str) -> IncidentRecordInMemory | None:
        return self.update_incident_status(incident_id, status="triaged", owner=assigned_to)

    # ------------------------------------------------------------------
    # Summarize
    # ------------------------------------------------------------------

    def summarize(self, *, organization_id: str | None = None) -> dict[str, Any]:
        items = self.list_incidents(limit=10000, organization_id=organization_id)
        by_status: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        for item in items:
            by_status[item.status] = by_status.get(item.status, 0) + 1
            by_severity[item.severity] = by_severity.get(item.severity, 0) + 1
            cat = item.category or "security"
            by_category[cat] = by_category.get(cat, 0) + 1
        return {
            "total": len(items),
            "open": by_status.get("open", 0),
            "triaged": by_status.get("triaged", 0),
            "contained": by_status.get("contained", 0),
            "resolved": by_status.get("resolved", 0),
            "closed": by_status.get("closed", 0),
            "by_status": by_status,
            "by_severity": by_severity,
            "by_category": by_category,
            "backend_name": "memory",
        }

    def summary(self, **kwargs: Any) -> dict[str, Any]:
        return self.summarize(**kwargs)

    # ------------------------------------------------------------------
    # Reset
    # ------------------------------------------------------------------

    def reset(self) -> None:
        with self._lock:
            self._items.clear()

    def is_ready(self) -> bool:
        return True

    def healthcheck(self) -> bool:
        return True

    def as_dict(self) -> dict[str, Any]:
        return {"backend_name": "memory", "table_name": "incidents_memory", "ready": True}

    def dict(self) -> dict[str, Any]:
        return self.as_dict()

    def model_dump(self) -> dict[str, Any]:
        return self.as_dict()


# ---------------------------------------------------------------------------
# Backward-compat aliases
# ---------------------------------------------------------------------------
IncidentRecord = IncidentRecordInMemory
IncidentStore = IncidentStoreInMemory


# ---------------------------------------------------------------------------
# Module-level singleton — eagerly initialized
# ---------------------------------------------------------------------------
_INCIDENT_STORE_MEMORY: IncidentStoreInMemory = IncidentStoreInMemory()
_INCIDENT_STORE_MEMORY.seed_defaults()


def get_incident_store_memory() -> IncidentStoreInMemory:
    return _INCIDENT_STORE_MEMORY


def reset_incident_store_memory() -> None:
    _INCIDENT_STORE_MEMORY.reset()
    _INCIDENT_STORE_MEMORY.seed_defaults()


# ---------------------------------------------------------------------------
# Legacy free-function API — test and router compatibility
# ---------------------------------------------------------------------------


def get_incident_store() -> IncidentStoreInMemory:
    return _INCIDENT_STORE_MEMORY


def build_incident_store(**_kwargs: Any) -> IncidentStoreInMemory:
    return _INCIDENT_STORE_MEMORY


def create_incident_store(**_kwargs: Any) -> IncidentStoreInMemory:
    return _INCIDENT_STORE_MEMORY


def list_incidents(
    *,
    severity: str | None = None,
    status: str | None = None,
    source: str | None = None,
) -> list[IncidentRecordInMemory]:
    return _INCIDENT_STORE_MEMORY.list_incidents(severity=severity, status=status, source=source)


def reset_incident_store() -> None:
    _INCIDENT_STORE_MEMORY.reset()
    _INCIDENT_STORE_MEMORY.seed_defaults()
