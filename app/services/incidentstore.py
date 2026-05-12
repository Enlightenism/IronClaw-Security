from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.persistencebootstrap import build_store

DEFAULT_INCIDENT_TABLE = "incidents"
_ALLOWED_INCIDENT_STATUSES = {
    "open",
    "triaged",
    "contained",
    "resolved",
    "closed",
    "investigating",
    "inprogress",
}
_ALLOWED_INCIDENT_SEVERITIES = {"low", "medium", "high", "critical"}
_ALLOWED_INCIDENT_SOURCES = {
    "scan",
    "guard",
    "sandbox",
    "review",
    "system",
    "ironclaw",
    "engine",
    "scanner",
    "tester",
}


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _normalize_timestamp(value: str | datetime | None) -> str:
    if value is None:
        return _utc_now()
    if isinstance(value, datetime):
        dt = value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
        return dt.isoformat().replace("+00:00", "Z")
    text = str(value).strip()
    if not text:
        return _utc_now()
    if text.endswith("+00:00"):
        return text[:-6] + "Z"
    return text


def _string(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _mapping(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, "model_dump") and callable(value.model_dump):
        dumped = value.model_dump()
        if isinstance(dumped, Mapping):
            return dict(dumped)
    if hasattr(value, "dict") and callable(value.dict):
        dumped = value.dict()
        if isinstance(dumped, Mapping):
            return dict(dumped)
    if hasattr(value, "to_dict") and callable(value.to_dict):
        dumped = value.to_dict()
        if isinstance(dumped, Mapping):
            return dict(dumped)
    if hasattr(value, "as_dict") and callable(value.as_dict):
        dumped = value.as_dict()
        if isinstance(dumped, Mapping):
            return dict(dumped)
    if hasattr(value, "__dict__"):
        return {
            key: val
            for key, val in vars(value).items()
            if not key.startswith("_") and not callable(val)
        }
    raise TypeError("value is not serializable to dict")


def _listify(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def _string_list(value: Any) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for item in _listify(value):
        text = _string(item)
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _normalize_status(value: Any) -> str:
    normalized = _string(value, "open").lower()
    return normalized if normalized in _ALLOWED_INCIDENT_STATUSES else "open"


def _normalize_severity(value: Any) -> str:
    normalized = _string(value, "medium").lower()
    return normalized if normalized in _ALLOWED_INCIDENT_SEVERITIES else "medium"


def _normalize_source(value: Any) -> str:
    normalized = _string(value, "ironclaw").lower()
    return normalized if normalized in _ALLOWED_INCIDENT_SOURCES else "ironclaw"


def _normalize_incident_payload(
    payload: dict[str, Any] | None = None,
    *,
    incidentid: str | None = None,
    incident_id: str | None = None,
    id: str | None = None,
    title: str | None = None,
    summary: str | None = None,
    description: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    priority: str | None = None,
    category: str | None = None,
    incident_type: str | None = None,
    source: str | None = None,
    verdict: str | None = None,
    organization_id: str | None = None,
    org_id: str | None = None,
    tenant_id: str | None = None,
    customer_id: str | None = None,
    scan_id: str | None = None,
    review_id: str | None = None,
    request_id: str | None = None,
    requestid: str | None = None,
    trace_id: str | None = None,
    traceid: str | None = None,
    session_id: str | None = None,
    owner_id: str | None = None,
    owner: str | None = None,
    assigned_to: str | None = None,
    assignedto: str | None = None,
    assetref: str | None = None,
    actor: dict[str, Any] | None = None,
    target: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
    evidence: list[Any] | None = None,
    tags: list[Any] | None = None,
    created_at: str | datetime | None = None,
    createdat: str | datetime | None = None,
    updated_at: str | datetime | None = None,
    updatedat: str | datetime | None = None,
    detected_at: str | datetime | None = None,
    detectedat: str | datetime | None = None,
    resolved_at: str | datetime | None = None,
    resolvedat: str | datetime | None = None,
    timestamp: str | datetime | None = None,
    **extra: Any,
) -> dict[str, Any]:
    source_payload = _mapping(payload)
    source_payload.update({key: value for key, value in extra.items() if value is not None})

    resolved_incident_id = (
        _string(incidentid)
        or _string(incident_id)
        or _string(id)
        or _string(source_payload.get("incidentid"))
        or _string(source_payload.get("incident_id"))
        or _string(source_payload.get("id"))
        or str(uuid4())
    )

    resolved_title = (
        _string(title)
        or _string(source_payload.get("title"))
        or _string(summary)
        or _string(source_payload.get("summary"))
        or _string(description)
        or _string(source_payload.get("description"))
        or "Security incident"
    )

    if not resolved_title:
        raise ValueError("title is required")

    resolved_summary = (
        _string(summary)
        or _string(source_payload.get("summary"))
        or _string(description)
        or _string(source_payload.get("description"))
        or resolved_title
    )

    resolved_description = (
        _string(description)
        or _string(source_payload.get("description"))
        or resolved_summary
    )

    resolved_severity = _string(severity or source_payload.get("severity"))
    if not resolved_severity:
        raise ValueError("severity is required")
    resolved_severity = _normalize_severity(resolved_severity)

    resolved_status = _normalize_status(status or source_payload.get("status"))

    resolved_priority = (
        _string(priority)
        or _string(source_payload.get("priority"))
        or resolved_severity
    )

    resolved_category = (
        _string(category)
        or _string(incident_type)
        or _string(source_payload.get("category"))
        or _string(source_payload.get("incident_type"))
        or "security"
    )

    resolved_source = _normalize_source(source or source_payload.get("source"))
    resolved_verdict = _string(verdict) or _string(source_payload.get("verdict")) or "pending"

    resolved_org = (
        _string(organization_id)
        or _string(org_id)
        or _string(tenant_id)
        or _string(customer_id)
        or _string(source_payload.get("organization_id"))
        or _string(source_payload.get("org_id"))
        or _string(source_payload.get("tenant_id"))
        or _string(source_payload.get("customer_id"))
    )

    resolved_created_at = _normalize_timestamp(
        created_at
        or createdat
        or source_payload.get("created_at")
        or source_payload.get("createdat")
        or detected_at
        or detectedat
        or timestamp
        or source_payload.get("detected_at")
        or source_payload.get("detectedat")
        or source_payload.get("timestamp")
    )
    resolved_updated_at = _normalize_timestamp(
        updated_at
        or updatedat
        or source_payload.get("updated_at")
        or source_payload.get("updatedat")
        or resolved_created_at
    )
    resolved_detected_at = _normalize_timestamp(
        detected_at
        or detectedat
        or source_payload.get("detected_at")
        or source_payload.get("detectedat")
        or timestamp
        or source_payload.get("timestamp")
        or resolved_created_at
    )
    resolved_resolved_at = (
        _normalize_timestamp(
            resolved_at
            or resolvedat
            or source_payload.get("resolved_at")
            or source_payload.get("resolvedat")
        )
        if (
            resolved_at is not None
            or resolvedat is not None
            or source_payload.get("resolved_at") is not None
            or source_payload.get("resolvedat") is not None
        )
        else None
    )

    resolved_actor = actor if isinstance(actor, dict) else _mapping(source_payload.get("actor"))
    resolved_target = target if isinstance(target, dict) else _mapping(source_payload.get("target"))
    resolved_metadata = metadata if isinstance(metadata, dict) else _mapping(source_payload.get("metadata"))

    resolved_request_id = (
        _string(request_id)
        or _string(requestid)
        or _string(source_payload.get("request_id"))
        or _string(source_payload.get("requestid"))
        or None
    )
    resolved_trace_id = (
        _string(trace_id)
        or _string(traceid)
        or _string(source_payload.get("trace_id"))
        or _string(source_payload.get("traceid"))
        or None
    )
    resolved_owner = (
        _string(owner)
        or _string(owner_id)
        or _string(assigned_to)
        or _string(assignedto)
        or _string(source_payload.get("owner"))
        or _string(source_payload.get("owner_id"))
        or _string(source_payload.get("assigned_to"))
        or _string(source_payload.get("assignedto"))
        or None
    )
    resolved_assetref = (
        _string(assetref)
        or _string(source_payload.get("assetref"))
        or _string(source_payload.get("asset_ref"))
        or None
    )

    normalized = {
        "incidentid": resolved_incident_id,
        "incident_id": resolved_incident_id,
        "id": resolved_incident_id,
        "title": resolved_title,
        "summary": resolved_summary,
        "description": resolved_description,
        "severity": resolved_severity,
        "status": resolved_status,
        "priority": resolved_priority,
        "category": resolved_category,
        "incident_type": resolved_category,
        "source": resolved_source,
        "verdict": resolved_verdict,
        "organization_id": resolved_org or None,
        "org_id": resolved_org or None,
        "tenant_id": resolved_org or None,
        "customer_id": resolved_org or None,
        "scan_id": _string(scan_id) or _string(source_payload.get("scan_id")) or None,
        "review_id": _string(review_id) or _string(source_payload.get("review_id")) or None,
        "request_id": resolved_request_id,
        "requestid": resolved_request_id,
        "trace_id": resolved_trace_id,
        "traceid": resolved_trace_id,
        "session_id": _string(session_id) or _string(source_payload.get("session_id")) or None,
        "owner_id": _string(owner_id) or _string(source_payload.get("owner_id")) or None,
        "assigned_to": _string(assigned_to) or _string(assignedto) or _string(source_payload.get("assigned_to")) or resolved_owner,
        "assignedto": _string(assignedto) or _string(assigned_to) or _string(source_payload.get("assignedto")) or resolved_owner,
        "owner": resolved_owner,
        "assetref": resolved_assetref,
        "actor": resolved_actor,
        "target": resolved_target,
        "metadata": resolved_metadata,
        "evidence": _listify(evidence if evidence is not None else source_payload.get("evidence")),
        "tags": _string_list(tags if tags is not None else source_payload.get("tags")),
        "timestamp": resolved_detected_at,
        "created_at": resolved_created_at,
        "createdat": resolved_created_at,
        "updated_at": resolved_updated_at,
        "updatedat": resolved_updated_at,
        "detected_at": resolved_detected_at,
        "detectedat": resolved_detected_at,
        "resolved_at": resolved_resolved_at,
        "resolvedat": resolved_resolved_at,
    }
    return normalized


# ---------------------------------------------------------------------------
# IncidentRecord — persistence-backed, str timestamps
# Distinct from incident_store.IncidentRecordInMemory (datetime timestamps).
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class IncidentRecord:
    incidentid: str
    title: str
    summary: str
    severity: str
    status: str
    source: str
    createdat: str
    updatedat: str
    requestid: str | None = None
    traceid: str | None = None
    assetref: str | None = None
    verdict: str | None = None
    owner: str | None = None
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    description: str | None = None
    timestamp: str | None = None
    category: str | None = None
    incident_type: str | None = None
    organization_id: str | None = None
    assigned_to: str | None = None
    scan_id: str | None = None
    review_id: str | None = None
    resolvedat: str | None = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> IncidentRecord:
        normalized = _normalize_incident_payload(dict(value))
        return cls(
            incidentid=_string(normalized.get("incidentid")),
            title=_string(normalized.get("title"), "Security incident"),
            summary=_string(normalized.get("summary")),
            severity=_normalize_severity(normalized.get("severity")),
            status=_normalize_status(normalized.get("status")),
            source=_normalize_source(normalized.get("source")),
            createdat=_string(normalized.get("createdat") or normalized.get("created_at"), _utc_now()),
            updatedat=_string(normalized.get("updatedat") or normalized.get("updated_at"), _utc_now()),
            requestid=_string(normalized.get("requestid") or normalized.get("request_id")) or None,
            traceid=_string(normalized.get("traceid") or normalized.get("trace_id")) or None,
            assetref=_string(normalized.get("assetref")) or None,
            verdict=_string(normalized.get("verdict")) or None,
            owner=_string(normalized.get("owner") or normalized.get("assigned_to") or normalized.get("owner_id")) or None,
            tags=_string_list(normalized.get("tags")),
            metadata=_mapping(normalized.get("metadata")),
            description=_string(normalized.get("description")) or None,
            timestamp=_string(normalized.get("timestamp") or normalized.get("detected_at") or normalized.get("createdat")) or None,
            category=_string(normalized.get("category")) or None,
            incident_type=_string(normalized.get("incident_type") or normalized.get("category")) or None,
            organization_id=_string(normalized.get("organization_id") or normalized.get("org_id")) or None,
            assigned_to=_string(normalized.get("assigned_to") or normalized.get("assignedto")) or None,
            scan_id=_string(normalized.get("scan_id")) or None,
            review_id=_string(normalized.get("review_id")) or None,
            resolvedat=_string(normalized.get("resolvedat") or normalized.get("resolved_at")) or None,
        )

    def to_dict(self) -> dict[str, Any]:
        description = self.description or self.summary
        category = self.category or "security"
        assigned_to = self.assigned_to or self.owner
        timestamp = self.timestamp or self.createdat
        return {
            "incidentid": self.incidentid,
            "incident_id": self.incidentid,
            "id": self.incidentid,
            "title": self.title,
            "summary": self.summary,
            "description": description,
            "severity": _normalize_severity(self.severity),
            "status": _normalize_status(self.status),
            "source": _normalize_source(self.source),
            "category": category,
            "incident_type": self.incident_type or category,
            "timestamp": timestamp,
            "createdat": self.createdat,
            "created_at": self.createdat,
            "updatedat": self.updatedat,
            "updated_at": self.updatedat,
            "resolvedat": self.resolvedat,
            "resolved_at": self.resolvedat,
            "requestid": self.requestid,
            "request_id": self.requestid,
            "traceid": self.traceid,
            "trace_id": self.traceid,
            "assetref": self.assetref,
            "verdict": self.verdict,
            "owner": self.owner,
            "assigned_to": assigned_to,
            "assignedto": assigned_to,
            "organization_id": self.organization_id,
            "scan_id": self.scan_id,
            "review_id": self.review_id,
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
        }

    def dict(self) -> dict[str, Any]:
        return self.to_dict()

    def model_dump(self) -> dict[str, Any]:
        return self.to_dict()

    def as_dict(self) -> dict[str, Any]:
        return self.to_dict()


# ---------------------------------------------------------------------------
# Seed helper
# ---------------------------------------------------------------------------

def _seed_demo_incident() -> IncidentRecord:
    now = _utc_now()
    return IncidentRecord(
        incidentid="incident-demo-001",
        title="Demo security incident",
        summary="Seeded in-memory incident for operations and dashboard routes.",
        description="Seeded in-memory incident for operations and dashboard routes.",
        severity="medium",
        status="open",
        source="system",
        category="security",
        incident_type="security",
        timestamp=now,
        createdat=now,
        updatedat=now,
        requestid="req-demo-incident-001",
        traceid="trace-demo-incident-001",
        assetref="asset-demo-incident-001",
        verdict="pending",
        owner="soc@ironclaw.local",
        assigned_to="soc@ironclaw.local",
        tags=["demo", "operations"],
        metadata={"seeded": True, "source": "incidentstore"},
    )


# ---------------------------------------------------------------------------
# IncidentStore — persistence-backed
# Distinct from incident_store.IncidentStoreInMemory (thread-locked list).
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class IncidentStore:
    backend: Any = field(default_factory=build_store)
    table_name: str = DEFAULT_INCIDENT_TABLE

    @property
    def backend_name(self) -> str:
        return str(getattr(self.backend, "backend_name", "memory"))

    def as_dict(self) -> dict[str, Any]:
        return {
            "backend_name": self.backend_name,
            "table_name": self.table_name,
            "ready": True,
        }

    def dict(self) -> dict[str, Any]:
        return self.as_dict()

    def model_dump(self) -> dict[str, Any]:
        return self.as_dict()

    def is_ready(self) -> bool:
        return True

    def healthcheck(self) -> bool:
        health = getattr(self.backend, "healthcheck", None)
        if callable(health):
            try:
                return bool(health())
            except Exception:
                return False
        try:
            self.backend.select(self.table_name, limit=1)
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Internal backend wrappers
    # ------------------------------------------------------------------

    def _safe_select(
        self,
        *,
        limit: int | None = None,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        try:
            rows = self.backend.select(
                self.table_name,
                limit=limit,
                filters=filters,
            )
        except TypeError:
            rows = self.backend.select(self.table_name)

        if isinstance(rows, dict):
            candidates = [rows]
        elif rows is None:
            candidates = []
        else:
            candidates = list(rows)

        normalized_rows: list[dict[str, Any]] = []
        for row in candidates:
            try:
                normalized_rows.append(_mapping(row))
            except Exception:
                continue

        if filters:
            filtered_rows: list[dict[str, Any]] = []
            for row in normalized_rows:
                matched = True
                for key, expected in filters.items():
                    if expected is None:
                        continue
                    if row.get(key) != expected:
                        matched = False
                        break
                if matched:
                    filtered_rows.append(row)
            normalized_rows = filtered_rows

        if limit is not None:
            normalized_rows = normalized_rows[:limit]

        return normalized_rows

    def _safe_insert(self, payload: dict[str, Any]) -> dict[str, Any]:
        inserted = self.backend.insert(self.table_name, payload)
        if isinstance(inserted, list) and inserted:
            return _mapping(inserted[0])
        if isinstance(inserted, dict):
            return _mapping(inserted)
        return dict(payload)

    def _safe_update(
        self, payload: dict[str, Any], *, filters: dict[str, Any]
    ) -> dict[str, Any] | None:
        try:
            updated = self.backend.update(
                self.table_name,
                payload,
                filters=filters,
            )
        except TypeError:
            updated = self.backend.update(self.table_name, payload)

        if isinstance(updated, list) and updated:
            return _mapping(updated[0])
        if isinstance(updated, dict):
            return _mapping(updated)

        rows = self._safe_select(filters=filters, limit=1)
        return rows[0] if rows else None

    def _safe_delete(self, *, filters: dict[str, Any]) -> dict[str, Any] | None:
        try:
            deleted = self.backend.delete(self.table_name, filters=filters)
        except TypeError:
            deleted = self.backend.delete(self.table_name)

        if isinstance(deleted, list) and deleted:
            return _mapping(deleted[0])
        if isinstance(deleted, dict):
            return _mapping(deleted)
        return None

    def _ensure_seed_data(self) -> None:
        if self.backend_name != "memory":
            return
        existing = self._safe_select(limit=1)
        if existing:
            return
        self._safe_insert(_seed_demo_incident().to_dict())

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def create_incident(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> IncidentRecord:
        incident = _normalize_incident_payload(payload, **kwargs)
        inserted = self._safe_insert(incident)
        return IncidentRecord.from_mapping(inserted)

    def createincident(self, **kwargs: Any) -> IncidentRecord:
        payload = _normalize_incident_payload(**kwargs)
        return self.create_incident(payload)

    def create(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> IncidentRecord:
        return self.create_incident(payload, **kwargs)

    def insert(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> IncidentRecord:
        return self.create_incident(payload, **kwargs)

    def add(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> IncidentRecord:
        return self.create_incident(payload, **kwargs)

    def save(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> IncidentRecord:
        return self.create_incident(payload, **kwargs)

    def append(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> IncidentRecord:
        return self.create_incident(payload, **kwargs)

    def write(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> IncidentRecord:
        return self.create_incident(payload, **kwargs)

    def open_incident(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> IncidentRecord:
        return self.create_incident(payload, **kwargs)

    def openincident(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> IncidentRecord:
        return self.create_incident(payload, **kwargs)

    # ------------------------------------------------------------------
    # List / query
    # ------------------------------------------------------------------

    def list_incidents(
        self,
        *,
        limit: int = 100,
        filters: dict[str, Any] | None = None,
        organization_id: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        source: str | None = None,
        assigned_to: str | None = None,
        assignedto: str | None = None,
        category: str | None = None,
        scan_id: str | None = None,
    ) -> list[IncidentRecord]:
        self._ensure_seed_data()

        query_filters: dict[str, Any] = dict(filters or {})
        if organization_id:
            query_filters.setdefault("organization_id", organization_id)
        if status:
            query_filters.setdefault("status", _normalize_status(status))
        if severity:
            query_filters.setdefault("severity", _normalize_severity(severity))
        if source:
            query_filters.setdefault("source", _normalize_source(source))
        if assigned_to:
            query_filters.setdefault("assigned_to", assigned_to)
        if assignedto:
            query_filters.setdefault("assignedto", assignedto)
        if category:
            query_filters.setdefault("category", category)
        if scan_id:
            query_filters.setdefault("scan_id", scan_id)

        raw_rows = self._safe_select(
            limit=limit,
            filters=query_filters or None,
        )

        incidents = [IncidentRecord.from_mapping(row) for row in raw_rows]
        incidents.sort(
            key=lambda row: _normalize_timestamp(row.updatedat or row.createdat),
            reverse=True,
        )
        return incidents

    def listincidents(
        self,
        *,
        limit: int = 100,
        filters: dict[str, Any] | None = None,
        organization_id: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        source: str | None = None,
        assigned_to: str | None = None,
        assignedto: str | None = None,
        category: str | None = None,
        scan_id: str | None = None,
    ) -> list[IncidentRecord]:
        return self.list_incidents(
            limit=limit,
            filters=filters,
            organization_id=organization_id,
            status=status,
            severity=severity,
            source=source,
            assigned_to=assigned_to,
            assignedto=assignedto,
            category=category,
            scan_id=scan_id,
        )

    def list(self, **kwargs: Any) -> list[IncidentRecord]:
        return self.list_incidents(**kwargs)

    def fetch(self, **kwargs: Any) -> list[IncidentRecord]:
        return self.list_incidents(**kwargs)

    def read(self, **kwargs: Any) -> list[IncidentRecord]:
        return self.list_incidents(**kwargs)

    def all(self, **kwargs: Any) -> list[IncidentRecord]:
        return self.list_incidents(**kwargs)

    def query(self, **kwargs: Any) -> list[IncidentRecord]:
        return self.list_incidents(**kwargs)

    def search(self, **kwargs: Any) -> list[IncidentRecord]:
        return self.list_incidents(**kwargs)

    def latest(self) -> IncidentRecord | None:
        incidents = self.list_incidents(limit=100)
        return incidents[0] if incidents else None

    def last(self) -> IncidentRecord | None:
        return self.latest()

    def mostrecent(self) -> IncidentRecord | None:
        return self.latest()

    def getlatest(self) -> IncidentRecord | None:
        return self.latest()

    # ------------------------------------------------------------------
    # Get
    # ------------------------------------------------------------------

    def get_incident(self, incident_id: str) -> IncidentRecord | None:
        self._ensure_seed_data()

        iid = _string(incident_id)
        if not iid:
            raise ValueError("incident_id is required")

        for key in ("incident_id", "incidentid", "id"):
            rows = self._safe_select(filters={key: iid}, limit=1)
            if rows:
                return IncidentRecord.from_mapping(rows[0])

        return None

    def getincident(self, incidentid: str) -> IncidentRecord | None:
        return self.get_incident(incidentid)

    def get(self, incident_id: str) -> IncidentRecord | None:
        return self.get_incident(incident_id)

    def getbyid(self, incident_id: str) -> IncidentRecord | None:
        return self.get_incident(incident_id)

    def findbyid(self, incident_id: str) -> IncidentRecord | None:
        return self.get_incident(incident_id)

    def fetchone(self, incident_id: str) -> IncidentRecord | None:
        return self.get_incident(incident_id)

    def readone(self, incident_id: str) -> IncidentRecord | None:
        return self.get_incident(incident_id)

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    def update_incident(self, incident_id: str, updates: dict[str, Any]) -> IncidentRecord | None:
        existing = self.get_incident(incident_id)
        if existing is None:
            return None

        merged = existing.to_dict()
        merged.update(_mapping(updates))
        merged["incidentid"] = existing.incidentid
        merged["incident_id"] = existing.incidentid
        merged["id"] = existing.incidentid
        merged["updated_at"] = _utc_now()
        merged["updatedat"] = merged["updated_at"]

        normalized = _normalize_incident_payload(merged)

        if _normalize_status(normalized.get("status")) in {"resolved", "closed"} and not normalized.get("resolved_at"):
            normalized["resolved_at"] = normalized["updated_at"]
            normalized["resolvedat"] = normalized["updatedat"]

        for key in ("incident_id", "incidentid", "id"):
            updated = self._safe_update(normalized, filters={key: existing.incidentid})
            if updated is not None:
                return IncidentRecord.from_mapping(updated)

        return IncidentRecord.from_mapping(normalized)

    def updateincidentstatus(
        self,
        incidentid: str,
        *,
        status: str,
        owner: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> IncidentRecord | None:
        updates: dict[str, Any] = {"status": _normalize_status(status)}
        if owner is not None:
            updates["owner"] = owner
            updates["assigned_to"] = owner
            updates["assignedto"] = owner
        if metadata:
            current = self.get_incident(incidentid)
            merged_metadata = current.metadata.copy() if current is not None else {}
            merged_metadata.update(_mapping(metadata))
            updates["metadata"] = merged_metadata
        return self.update_incident(incidentid, updates)

    def update(self, incident_id: str, updates: dict[str, Any]) -> IncidentRecord | None:
        return self.update_incident(incident_id, updates)

    def assign_incident(self, incident_id: str, assigned_to: str) -> IncidentRecord | None:
        return self.update_incident(
            incident_id,
            {
                "assigned_to": assigned_to,
                "assignedto": assigned_to,
                "owner": assigned_to,
                "status": "triaged",
            },
        )

    def assignincident(self, incident_id: str, assigned_to: str) -> IncidentRecord | None:
        return self.assign_incident(incident_id, assigned_to)

    def resolve_incident(
        self,
        incident_id: str,
        *,
        resolution: str | None = None,
        verdict: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> IncidentRecord | None:
        now = _utc_now()
        updates: dict[str, Any] = {
            "status": "resolved",
            "resolved_at": now,
            "resolvedat": now,
        }
        if resolution is not None:
            updates["resolution"] = resolution
        if verdict is not None:
            updates["verdict"] = verdict
        if metadata:
            current = self.get_incident(incident_id)
            merged_metadata = current.metadata.copy() if current is not None else {}
            merged_metadata.update(_mapping(metadata))
            updates["metadata"] = merged_metadata
        return self.update_incident(incident_id, updates)

    def resolveincident(
        self,
        incident_id: str,
        *,
        resolution: str | None = None,
        verdict: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> IncidentRecord | None:
        return self.resolve_incident(
            incident_id,
            resolution=resolution,
            verdict=verdict,
            metadata=metadata,
        )

    def close_incident(
        self,
        incident_id: str,
        *,
        resolution: str | None = None,
        verdict: str | None = None,
    ) -> IncidentRecord | None:
        now = _utc_now()
        return self.update_incident(
            incident_id,
            {
                "status": "closed",
                "resolved_at": now,
                "resolvedat": now,
                "resolution": resolution,
                "verdict": verdict,
            },
        )

    def closeincident(
        self,
        incident_id: str,
        *,
        resolution: str | None = None,
        verdict: str | None = None,
    ) -> IncidentRecord | None:
        return self.close_incident(
            incident_id,
            resolution=resolution,
            verdict=verdict,
        )

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def delete_incident(self, incident_id: str) -> dict[str, Any] | None:
        iid = _string(incident_id)
        if not iid:
            raise ValueError("incident_id is required")

        for key in ("incident_id", "incidentid", "id"):
            deleted = self._safe_delete(filters={key: iid})
            if deleted is not None:
                return deleted

        return None

    def deleteincident(self, incident_id: str) -> dict[str, Any] | None:
        return self.delete_incident(incident_id)

    def delete(self, incident_id: str) -> dict[str, Any] | None:
        return self.delete_incident(incident_id)

    # ------------------------------------------------------------------
    # Summarize
    # ------------------------------------------------------------------

    def summarize(
        self,
        *,
        organization_id: str | None = None,
        limit: int = 1000,
    ) -> dict[str, Any]:
        incidents = self.list_incidents(limit=limit, organization_id=organization_id)

        by_status: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}

        for item in incidents:
            payload = item.to_dict()
            status_value = _string(payload.get("status"), "unknown")
            severity_value = _string(payload.get("severity"), "unknown")
            category_value = _string(payload.get("category"), "unknown")
            by_status[status_value] = by_status.get(status_value, 0) + 1
            by_severity[severity_value] = by_severity.get(severity_value, 0) + 1
            by_category[category_value] = by_category.get(category_value, 0) + 1

        return {
            "total": len(incidents),
            "open": by_status.get("open", 0),
            "triaged": by_status.get("triaged", 0),
            "contained": by_status.get("contained", 0),
            "resolved": by_status.get("resolved", 0),
            "closed": by_status.get("closed", 0),
            "by_status": by_status,
            "by_severity": by_severity,
            "by_category": by_category,
            "backend_name": self.backend_name,
            "table_name": self.table_name,
        }

    def summary(
        self,
        *,
        organization_id: str | None = None,
        limit: int = 1000,
    ) -> dict[str, Any]:
        return self.summarize(organization_id=organization_id, limit=limit)

    # ------------------------------------------------------------------
    # Reset / seed
    # ------------------------------------------------------------------

    def reset(self) -> None:
        try:
            self.backend.delete(self.table_name, filters={})
        except Exception:
            pass
        self._ensure_seed_data()

    def seeddefaults(self) -> None:
        self._ensure_seed_data()


# ---------------------------------------------------------------------------
# Subclass aliases (kept for any router that imports them by name)
# ---------------------------------------------------------------------------

class InMemoryIncidentStore(IncidentStore):
    pass


class SupabaseIncidentStore(IncidentStore):
    pass


# ---------------------------------------------------------------------------
# Module-level singleton + factory functions
# ---------------------------------------------------------------------------

# Eagerly initialized at import time so runtime introspection (is not None)
# passes without requiring a prior call to get_incident_store().
_SINGLETON_STORE: IncidentStore = IncidentStore()


def build_incident_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_INCIDENT_TABLE,
    **store_kwargs: Any,
) -> IncidentStore:
    resolved_backend = backend if backend is not None else build_store(**store_kwargs)
    return IncidentStore(backend=resolved_backend, table_name=table_name)


def create_incident_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_INCIDENT_TABLE,
    **store_kwargs: Any,
) -> IncidentStore:
    return build_incident_store(backend=backend, table_name=table_name, **store_kwargs)


def get_incident_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_INCIDENT_TABLE,
    **store_kwargs: Any,
) -> IncidentStore:
    global _SINGLETON_STORE
    if backend is None and not store_kwargs and table_name == DEFAULT_INCIDENT_TABLE:
        return _SINGLETON_STORE
    return build_incident_store(backend=backend, table_name=table_name, **store_kwargs)


def buildincidentstore(
    *,
    backend: Any | None = None,
    tablename: str = DEFAULT_INCIDENT_TABLE,
    mode: str | None = None,
    **store_kwargs: Any,
) -> IncidentStore:
    if mode is not None:
        store_kwargs.setdefault("mode", mode)
    return build_incident_store(backend=backend, table_name=tablename, **store_kwargs)


def createincidentstore(
    *,
    backend: Any | None = None,
    tablename: str = DEFAULT_INCIDENT_TABLE,
    mode: str | None = None,
    **store_kwargs: Any,
) -> IncidentStore:
    if mode is not None:
        store_kwargs.setdefault("mode", mode)
    return build_incident_store(backend=backend, table_name=tablename, **store_kwargs)


def getincidentstore(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_INCIDENT_TABLE,
    tablename: str | None = None,
    mode: str | None = None,
    **store_kwargs: Any,
) -> IncidentStore:
    if mode is not None:
        store_kwargs.setdefault("mode", mode)
    resolved_table = tablename or table_name
    return get_incident_store(backend=backend, table_name=resolved_table, **store_kwargs)


def buildstore(
    *,
    backend: Any | None = None,
    tablename: str = DEFAULT_INCIDENT_TABLE,
    mode: str | None = None,
    **store_kwargs: Any,
) -> IncidentStore:
    return buildincidentstore(backend=backend, tablename=tablename, mode=mode, **store_kwargs)


def createstore(
    *,
    backend: Any | None = None,
    tablename: str = DEFAULT_INCIDENT_TABLE,
    mode: str | None = None,
    **store_kwargs: Any,
) -> IncidentStore:
    return createincidentstore(backend=backend, tablename=tablename, mode=mode, **store_kwargs)


def getstore(
    *,
    backend: Any | None = None,
    tablename: str = DEFAULT_INCIDENT_TABLE,
    mode: str | None = None,
    **store_kwargs: Any,
) -> IncidentStore:
    return getincidentstore(backend=backend, tablename=tablename, mode=mode, **store_kwargs)


def reset_incident_store() -> None:
    _SINGLETON_STORE.reset()