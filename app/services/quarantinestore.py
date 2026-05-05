from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Mapping
from uuid import uuid4

from app.persistencebootstrap import build_store


DEFAULT_QUARANTINE_TABLE = "quarantine"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_timestamp(value: str | datetime | None) -> str:
    if value is None:
        return _utc_now()
    if isinstance(value, datetime):
        dt = value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
        return dt.isoformat()
    text = str(value).strip()
    return text or _utc_now()


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
    return [value]


def _normalize_quarantine_payload(
    payload: dict[str, Any] | None = None,
    *,
    quarantine_id: str | None = None,
    item_id: str | None = None,
    artifact_id: str | None = None,
    incident_id: str | None = None,
    scan_id: str | None = None,
    organization_id: str | None = None,
    org_id: str | None = None,
    tenant_id: str | None = None,
    owner_id: str | None = None,
    category: str | None = None,
    item_type: str | None = None,
    source: str | None = None,
    reason: str | None = None,
    verdict: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    location: str | None = None,
    storage_key: str | None = None,
    filename: str | None = None,
    content_hash: str | None = None,
    assigned_to: str | None = None,
    tags: list[Any] | None = None,
    evidence: list[Any] | None = None,
    metadata: dict[str, Any] | None = None,
    created_at: str | datetime | None = None,
    updated_at: str | datetime | None = None,
    quarantined_at: str | datetime | None = None,
    released_at: str | datetime | None = None,
    expires_at: str | datetime | None = None,
    **extra: Any,
) -> dict[str, Any]:
    source_payload = _mapping(payload)
    source_payload.update({key: value for key, value in extra.items() if value is not None})

    resolved_quarantine_id = (
        _string(quarantine_id)
        or _string(source_payload.get("quarantine_id"))
        or _string(source_payload.get("id"))
        or str(uuid4())
    )

    resolved_item_id = (
        _string(item_id)
        or _string(artifact_id)
        or _string(source_payload.get("item_id"))
        or _string(source_payload.get("artifact_id"))
        or resolved_quarantine_id
    )

    resolved_org = (
        _string(organization_id)
        or _string(org_id)
        or _string(tenant_id)
        or _string(source_payload.get("organization_id"))
        or _string(source_payload.get("org_id"))
        or _string(source_payload.get("tenant_id"))
    )

    resolved_category = (
        _string(category)
        or _string(item_type)
        or _string(source_payload.get("category"))
        or _string(source_payload.get("item_type"))
        or "artifact"
    )

    resolved_source = (
        _string(source)
        or _string(source_payload.get("source"))
        or "ironclaw"
    )

    resolved_reason = (
        _string(reason)
        or _string(source_payload.get("reason"))
        or "policy_violation"
    )

    resolved_verdict = (
        _string(verdict)
        or _string(source_payload.get("verdict"))
        or "pending"
    )

    resolved_severity = (
        _string(severity)
        or _string(source_payload.get("severity"))
        or "medium"
    )

    resolved_status = (
        _string(status)
        or _string(source_payload.get("status"))
        or "quarantined"
    )

    resolved_filename = (
        _string(filename)
        or _string(source_payload.get("filename"))
        or _string(source_payload.get("name"))
    )

    resolved_location = (
        _string(location)
        or _string(storage_key)
        or _string(source_payload.get("location"))
        or _string(source_payload.get("storage_key"))
    )

    resolved_created_at = _normalize_timestamp(
        created_at or source_payload.get("created_at") or quarantined_at or source_payload.get("quarantined_at"),
    )
    resolved_updated_at = _normalize_timestamp(
        updated_at or source_payload.get("updated_at") or resolved_created_at,
    )
    resolved_quarantined_at = _normalize_timestamp(
        quarantined_at or source_payload.get("quarantined_at") or resolved_created_at,
    )
    resolved_released_at = (
        _normalize_timestamp(released_at or source_payload.get("released_at"))
        if (released_at is not None or source_payload.get("released_at") is not None)
        else None
    )
    resolved_expires_at = (
        _normalize_timestamp(expires_at or source_payload.get("expires_at"))
        if (expires_at is not None or source_payload.get("expires_at") is not None)
        else None
    )

    normalized = {
        "quarantine_id": resolved_quarantine_id,
        "id": resolved_quarantine_id,
        "item_id": resolved_item_id,
        "artifact_id": _string(artifact_id) or _string(source_payload.get("artifact_id")) or resolved_item_id,
        "incident_id": _string(incident_id) or _string(source_payload.get("incident_id")) or None,
        "scan_id": _string(scan_id) or _string(source_payload.get("scan_id")) or None,
        "organization_id": resolved_org or None,
        "org_id": resolved_org or None,
        "tenant_id": resolved_org or None,
        "owner_id": _string(owner_id) or _string(source_payload.get("owner_id")) or None,
        "category": resolved_category,
        "item_type": resolved_category,
        "source": resolved_source,
        "reason": resolved_reason,
        "verdict": resolved_verdict,
        "severity": resolved_severity,
        "status": resolved_status,
        "location": resolved_location or None,
        "storage_key": resolved_location or None,
        "filename": resolved_filename or None,
        "content_hash": _string(content_hash) or _string(source_payload.get("content_hash")) or None,
        "assigned_to": _string(assigned_to) or _string(source_payload.get("assigned_to")) or None,
        "tags": _listify(tags if tags is not None else source_payload.get("tags")),
        "evidence": _listify(evidence if evidence is not None else source_payload.get("evidence")),
        "metadata": metadata if isinstance(metadata, dict) else _mapping(source_payload.get("metadata")),
        "created_at": resolved_created_at,
        "updated_at": resolved_updated_at,
        "quarantined_at": resolved_quarantined_at,
        "released_at": resolved_released_at,
        "expires_at": resolved_expires_at,
    }

    return normalized


@dataclass(slots=True)
class QuarantineStore:
    backend: Any = field(default_factory=build_store)
    table_name: str = DEFAULT_QUARANTINE_TABLE

    @property
    def backend_name(self) -> str:
        return str(getattr(self.backend, "backend_name", "memory"))

    def as_dict(self) -> dict[str, Any]:
        return {
            "backend_name": self.backend_name,
            "table_name": self.table_name,
            "ready": True,
        }

    def is_ready(self) -> bool:
        return True

    def healthcheck(self) -> bool:
        health = getattr(self.backend, "healthcheck", None)
        if callable(health):
            return bool(health())
        return True

    def quarantine_item(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        record = _normalize_quarantine_payload(payload, **kwargs)
        inserted = self.backend.insert(self.table_name, record)
        if isinstance(inserted, list) and inserted:
            return dict(inserted[0])
        if isinstance(inserted, dict):
            return dict(inserted)
        return record

    def create(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        return self.quarantine_item(payload, **kwargs)

    def put(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        return self.quarantine_item(payload, **kwargs)

    def list_quarantine(
        self,
        *,
        limit: int = 100,
        filters: dict[str, Any] | None = None,
        organization_id: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        incident_id: str | None = None,
        scan_id: str | None = None,
        owner_id: str | None = None,
        category: str | None = None,
    ) -> list[dict[str, Any]]:
        query_filters: dict[str, Any] = dict(filters or {})
        if organization_id:
            query_filters.setdefault("organization_id", organization_id)
        if status:
            query_filters.setdefault("status", status)
        if severity:
            query_filters.setdefault("severity", severity)
        if incident_id:
            query_filters.setdefault("incident_id", incident_id)
        if scan_id:
            query_filters.setdefault("scan_id", scan_id)
        if owner_id:
            query_filters.setdefault("owner_id", owner_id)
        if category:
            query_filters.setdefault("category", category)

        rows = self.backend.select(
            self.table_name,
            limit=limit,
            filters=query_filters or None,
        )
        items = [dict(row) for row in rows]
        items.sort(
            key=lambda row: _normalize_timestamp(
                row.get("updated_at") or row.get("created_at"),
            ),
            reverse=True,
        )
        return items

    def list(self, **kwargs: Any) -> list[dict[str, Any]]:
        return self.list_quarantine(**kwargs)

    def get_quarantine_item(self, quarantine_id: str) -> dict[str, Any] | None:
        qid = _string(quarantine_id)
        if not qid:
            raise ValueError("quarantine_id is required")
        rows = self.backend.select(self.table_name, filters={"quarantine_id": qid}, limit=1)
        if rows:
            return dict(rows[0])
        rows = self.backend.select(self.table_name, filters={"id": qid}, limit=1)
        if rows:
            return dict(rows[0])
        return None

    def get(self, quarantine_id: str) -> dict[str, Any] | None:
        return self.get_quarantine_item(quarantine_id)

    def find_by_item_id(self, item_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        iid = _string(item_id)
        if not iid:
            raise ValueError("item_id is required")
        return self.list_quarantine(limit=limit, filters={"item_id": iid})

    def update_quarantine_item(self, quarantine_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
        existing = self.get_quarantine_item(quarantine_id)
        if existing is None:
            return None

        merged = dict(existing)
        merged.update(_mapping(updates))
        merged["quarantine_id"] = existing.get("quarantine_id") or existing.get("id") or quarantine_id
        merged["id"] = merged["quarantine_id"]
        merged["updated_at"] = _utc_now()

        status = _string(merged.get("status")).lower()
        if status in {"released", "restored"} and not merged.get("released_at"):
            merged["released_at"] = merged["updated_at"]

        normalized = _normalize_quarantine_payload(merged)

        updated = self.backend.update(
            self.table_name,
            normalized,
            filters={"quarantine_id": quarantine_id},
        )
        if isinstance(updated, list) and updated:
            return dict(updated[0])

        updated = self.backend.update(
            self.table_name,
            normalized,
            filters={"id": quarantine_id},
        )
        if isinstance(updated, list) and updated:
            return dict(updated[0])

        return normalized

    def update(self, quarantine_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
        return self.update_quarantine_item(quarantine_id, updates)

    def assign_item(self, quarantine_id: str, assigned_to: str) -> dict[str, Any] | None:
        return self.update_quarantine_item(
            quarantine_id,
            {
                "assigned_to": assigned_to,
                "status": "under_review",
            },
        )

    def release_item(
        self,
        quarantine_id: str,
        *,
        verdict: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        updates: dict[str, Any] = {
            "status": "released",
            "released_at": _utc_now(),
        }
        if verdict is not None:
            updates["verdict"] = verdict
        if metadata:
            current = self.get_quarantine_item(quarantine_id) or {}
            merged_metadata = _mapping(current.get("metadata"))
            merged_metadata.update(metadata)
            updates["metadata"] = merged_metadata
        return self.update_quarantine_item(quarantine_id, updates)

    def restore_item(
        self,
        quarantine_id: str,
        *,
        verdict: str | None = None,
    ) -> dict[str, Any] | None:
        return self.update_quarantine_item(
            quarantine_id,
            {
                "status": "restored",
                "released_at": _utc_now(),
                "verdict": verdict or "allowed",
            },
        )

    def purge_item(
        self,
        quarantine_id: str,
        *,
        verdict: str | None = None,
    ) -> dict[str, Any] | None:
        return self.update_quarantine_item(
            quarantine_id,
            {
                "status": "purged",
                "verdict": verdict or "blocked",
            },
        )

    def delete_quarantine_item(self, quarantine_id: str) -> dict[str, Any] | None:
        qid = _string(quarantine_id)
        if not qid:
            raise ValueError("quarantine_id is required")

        deleted = self.backend.delete(self.table_name, filters={"quarantine_id": qid})
        if isinstance(deleted, list) and deleted:
            return dict(deleted[0])

        deleted = self.backend.delete(self.table_name, filters={"id": qid})
        if isinstance(deleted, list) and deleted:
            return dict(deleted[0])

        return None

    def summarize(
        self,
        *,
        organization_id: str | None = None,
        limit: int = 1000,
    ) -> dict[str, Any]:
        items = self.list_quarantine(limit=limit, organization_id=organization_id)

        by_status: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}

        for item in items:
            status = _string(item.get("status"), "unknown")
            severity = _string(item.get("severity"), "unknown")
            category = _string(item.get("category"), "unknown")
            by_status[status] = by_status.get(status, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_category[category] = by_category.get(category, 0) + 1

        return {
            "total": len(items),
            "quarantined": by_status.get("quarantined", 0),
            "under_review": by_status.get("under_review", 0),
            "released": by_status.get("released", 0),
            "restored": by_status.get("restored", 0),
            "purged": by_status.get("purged", 0),
            "by_status": by_status,
            "by_severity": by_severity,
            "by_category": by_category,
            "backend_name": self.backend_name,
            "table_name": self.table_name,
        }


def build_quarantine_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_QUARANTINE_TABLE,
    **store_kwargs: Any,
) -> QuarantineStore:
    resolved_backend = backend if backend is not None else build_store(**store_kwargs)
    return QuarantineStore(backend=resolved_backend, table_name=table_name)


def create_quarantine_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_QUARANTINE_TABLE,
    **store_kwargs: Any,
) -> QuarantineStore:
    return build_quarantine_store(backend=backend, table_name=table_name, **store_kwargs)


def get_quarantine_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_QUARANTINE_TABLE,
    **store_kwargs: Any,
) -> QuarantineStore:
    return build_quarantine_store(backend=backend, table_name=table_name, **store_kwargs)