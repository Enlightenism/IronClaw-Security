from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
import json
import logging
import os
import threading
from typing import Any, Protocol

from app.core.supabase import get_supabase_service_client
from app.services import mitre_utils as mu  # canonical MITRE helpers
from app.services.threat_feed_ingestion import FeedIngestResult, IOCFilterRequest, IOCRecord

logger = logging.getLogger(__name__)

MAX_BULK_UPSERT_BATCH = 500
TTL_PRUNE_BATCH = 1000
TABLE_IOCS = "ioc_records"
TABLE_INGEST_LOG = "feed_ingest_log"
STORE_LOCK = threading.Lock()

IOCSTOREBACKEND: IOCStoreBackend | None = None
IOCSTORE: IOCStore | None = None


def _get_client():
    return get_supabase_service_client()


def _looks_like_test_runtime() -> bool:
    return bool(os.environ.get("PYTEST_CURRENT_TEST") or os.environ.get("IRONCLAW_TEST_MODE") or os.environ.get("TESTING") or os.environ.get("PYTEST_VERSION"))


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def _detect_ioc_type(value: str) -> str:
    lowered = (value or "").strip().lower()
    if not lowered:
        return "unknown"
    if lowered.startswith(("http://", "https://")):
        return "url"
    if ":" in lowered and "/" in lowered:
        return "cidr"
    if lowered.count(".") == 3 and all(part.isdigit() and 0 <= int(part) <= 255 for part in lowered.split(".") if part != ""):
        return "ip"
    if "." in lowered and " " not in lowered and "/" not in lowered:
        return "domain"
    if len(lowered) in (32, 40, 64) and all(ch in "0123456789abcdef" for ch in lowered):
        return "hash"
    return "unknown"


def _normalize_value(value: str, ioc_type: str) -> str:
    normalized = (value or "").strip()
    if ioc_type in {"domain", "url", "hash", "cve", "mitre"}:
        return normalized.lower()
    return normalized


def _record_attr(record: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        if hasattr(record, name):
            return getattr(record, name)
    return default


def _filter_attr(obj: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        if hasattr(obj, name):
            return getattr(obj, name)
    return default


def _record_to_row(record: IOCRecord) -> dict[str, Any]:
    """
    Convert an IOCRecord-like object into a DB row dict. MITRE technique IDs
    are normalized to the canonical uppercase form here to ensure consistent
    storage and lookups across the system.
    """
    mitre_raw = _record_attr(record, "mitre_technique_id", "mitretechniqueid")
    mitre_norm = mu.normalize_mitre(mitre_raw)
    return {
        "ioc_id": _record_attr(record, "ioc_id", "iocid", default=""),
        "ioc_type": _record_attr(record, "ioc_type", "ioctype", default="unknown"),
        "value": _record_attr(record, "value", default=""),
        "source": _record_attr(record, "source", default="internal"),
        "severity": _record_attr(record, "severity", default="medium"),
        "confidence": float(_record_attr(record, "confidence", default=0.0) or 0.0),
        "tags": list(_record_attr(record, "tags", default=[]) or []),
        "description": _record_attr(record, "description", default="") or "",
        "org_id": _record_attr(record, "org_id", "orgid"),
        "mitre_technique_id": mitre_norm,
        "mitre_tactic": _record_attr(record, "mitre_tactic", "mitretactic"),
        "cve_id": _record_attr(record, "cve_id", "cveid"),
        "first_seen": _record_attr(record, "first_seen", "firstseen", default=_utcnow_iso()),
        "last_seen": _record_attr(record, "last_seen", "lastseen", default=_utcnow_iso()),
        "expiry": _record_attr(record, "expiry"),
        "active": bool(_record_attr(record, "active", default=True)),
        "feed_ingest_id": _record_attr(record, "feed_ingest_id", "feedingestid", default=""),
        "extra": dict(_record_attr(record, "extra", default={}) or {}),
    }


def _parse_tags(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [str(item) for item in raw]
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(item) for item in parsed]
        except Exception:
            pass
        return [item.strip() for item in raw.split(",") if item.strip()]
    return []


def _parse_extra(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return {}
    return {}


def _row_to_record(row: dict[str, Any]) -> IOCRecord:
    tags = _parse_tags(row.get("tags"))
    extra = _parse_extra(row.get("extra"))
    return IOCRecord(
        ioc_id=row.get("ioc_id", ""),
        ioc_type=row.get("ioc_type", "unknown"),
        value=row.get("value", ""),
        source=row.get("source", "internal"),
        severity=row.get("severity", "medium"),
        confidence=float(row.get("confidence", 0.0) or 0.0),
        tags=tags,
        description=row.get("description", "") or "",
        org_id=row.get("org_id"),
        mitre_technique_id=row.get("mitre_technique_id"),
        mitre_tactic=row.get("mitre_tactic"),
        cve_id=row.get("cve_id"),
        first_seen=row.get("first_seen") or _utcnow_iso(),
        last_seen=row.get("last_seen") or _utcnow_iso(),
        expiry=row.get("expiry"),
        active=bool(row.get("active", True)),
        feed_ingest_id=row.get("feed_ingest_id", "") or "",
        extra=extra,
    )


def _ingest_result_to_row(result: FeedIngestResult) -> dict[str, Any]:
    return {
        "ingest_id": _record_attr(result, "ingest_id", "ingestid", default=""),
        "source": _record_attr(result, "source", default="internal"),
        "status": _record_attr(result, "status", default="completed"),
        "iocs_parsed": int(_record_attr(result, "iocs_parsed", "iocsparsed", default=0) or 0),
        "iocs_inserted": int(_record_attr(result, "iocs_inserted", "iocsinserted", default=0) or 0),
        "iocs_updated": int(_record_attr(result, "iocs_updated", "iocsupdated", default=0) or 0),
        "iocs_skipped": int(_record_attr(result, "iocs_skipped", "iocsskipped", default=0) or 0),
        "errors": list(_record_attr(result, "errors", default=[]) or []),
        "started_at": _record_attr(result, "started_at", "startedat", default=_utcnow_iso()),
        "completed_at": _record_attr(result, "completed_at", "completedat"),
        "org_id": _record_attr(result, "org_id", "orgid"),
        "metadata": dict(_record_attr(result, "metadata", default={}) or {}),
    }


def _merge_record_update(existing: dict[str, Any], record: IOCRecord) -> dict[str, Any]:
    """
    Merge an incoming IOCRecord into an existing row. Ensure mitre_technique_id
    is preserved and normalized. Incoming fields override or augment existing
    values where appropriate.
    """
    merged_tags = sorted(set(_parse_tags(existing.get("tags"))) | set(_record_attr(record, "tags", default=[]) or []))
    merged_extra = {**_parse_extra(existing.get("extra")), **dict(_record_attr(record, "extra", default={}) or {})}
    incoming_description = _record_attr(record, "description", default="") or ""

    # Normalize incoming mitre id if present, otherwise preserve existing normalized value
    incoming_mitre_raw = _record_attr(record, "mitre_technique_id", "mitretechniqueid")
    incoming_mitre = mu.normalize_mitre(incoming_mitre_raw) if incoming_mitre_raw is not None else None
    existing_mitre = mu.normalize_mitre(existing.get("mitre_technique_id")) if existing.get("mitre_technique_id") is not None else None
    final_mitre = incoming_mitre or existing_mitre

    return {
        "severity": _record_attr(record, "severity", default=existing.get("severity", "medium")),
        "confidence": max(float(existing.get("confidence", 0.0) or 0.0), float(_record_attr(record, "confidence", default=0.0) or 0.0)),
        "tags": merged_tags,
        "description": incoming_description or existing.get("description", "") or "",
        "last_seen": _record_attr(record, "last_seen", "lastseen", default=_utcnow_iso()),
        "expiry": _record_attr(record, "expiry") or existing.get("expiry"),
        "active": bool(_record_attr(record, "active", default=True)),
        "feed_ingest_id": _record_attr(record, "feed_ingest_id", "feedingestid", default=existing.get("feed_ingest_id", "")),
        "extra": merged_extra,
        "mitre_technique_id": final_mitre,
    }


def _overwrite_record_update(record: IOCRecord) -> dict[str, Any]:
    """
    Build a payload that overwrites stored fields with incoming record fields.
    Normalize MITRE technique id for canonical storage.
    """
    mitre_raw = _record_attr(record, "mitre_technique_id", "mitretechniqueid")
    mitre_norm = mu.normalize_mitre(mitre_raw)
    return {
        "ioc_type": _record_attr(record, "ioc_type", "ioctype", default="unknown"),
        "value": _record_attr(record, "value", default=""),
        "source": _record_attr(record, "source", default="internal"),
        "severity": _record_attr(record, "severity", default="medium"),
        "confidence": float(_record_attr(record, "confidence", default=0.0) or 0.0),
        "tags": list(_record_attr(record, "tags", default=[]) or []),
        "description": _record_attr(record, "description", default="") or "",
        "org_id": _record_attr(record, "org_id", "orgid"),
        "mitre_technique_id": mitre_norm,
        "mitre_tactic": _record_attr(record, "mitre_tactic", "mitretactic"),
        "cve_id": _record_attr(record, "cve_id", "cveid"),
        "last_seen": _record_attr(record, "last_seen", "lastseen", default=_utcnow_iso()),
        "expiry": _record_attr(record, "expiry"),
        "active": bool(_record_attr(record, "active", default=True)),
        "feed_ingest_id": _record_attr(record, "feed_ingest_id", "feedingestid", default=""),
        "extra": dict(_record_attr(record, "extra", default={}) or {}),
    }


def _is_unconfigured_client_error(exc: Exception) -> bool:
    text = str(exc)
    markers = (
        "missing SUPABASE_URL",
        "missing SUPABASE_SERVICE_ROLE_KEY",
        "missing SUPABASE_ANON_KEY",
        "Supabase credentials not set",
    )
    return any(marker in text for marker in markers)


class IOCStoreConfigurationError(RuntimeError):
    pass


class IOCStoreBackend(Protocol):
    def upsert_ioc(self, record: IOCRecord) -> bool: ...
    def bulk_upsert(self, records: list[IOCRecord], *, overwrite: bool = False) -> tuple[int, int, int]: ...
    def get_ioc(self, ioc_id: str) -> IOCRecord | None: ...
    def lookup_by_value(self, value: str, *, org_id: str | None = None, active_only: bool = True) -> list[IOCRecord]: ...
    def lookup_by_cve(self, cve_id: str, *, org_id: str | None = None, active_only: bool = True) -> list[IOCRecord]: ...
    def lookup_by_mitre_technique(
        self,
        technique_id: str,
        *,
        org_id: str | None = None,
        active_only: bool = True,
    ) -> list[IOCRecord]: ...
    def lookup_by_values(
        self,
        values: list[str],
        *,
        org_id: str | None = None,
        active_only: bool = True,
    ) -> list[IOCRecord]: ...
    def filter_iocs(self, req: IOCFilterRequest) -> list[IOCRecord]: ...
    def deactivate_ioc(self, ioc_id: str) -> bool: ...
    def delete_ioc(self, ioc_id: str) -> bool: ...
    def delete_by_ingest_id(self, feed_ingest_id: str) -> int: ...
    def prune_expired(self) -> int: ...
    def count_iocs(self, *, source: str | None = None, active: bool | None = None, org_id: str | None = None) -> int: ...
    def persist_ingest_result(self, result: FeedIngestResult) -> bool: ...
    def get_ingest_result(self, ingest_id: str) -> dict[str, Any] | None: ...
    def list_ingest_history(
        self,
        *,
        source: str | None = None,
        org_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]: ...
    def delete_ingest_log(self, ingest_id: str) -> bool: ...
    def health_check(self) -> dict[str, Any]: ...


class InMemoryIOCStoreBackend:
    def __init__(self) -> None:
        self.fallback_iocs: dict[str, dict[str, Any]] = {}
        self.fallback_ingest_log: dict[str, dict[str, Any]] = {}

    def _iter_fallback_iocs(self) -> list[dict[str, Any]]:
        return list(self.fallback_iocs.values())

    def _fallback_scope_match(self, row: dict[str, Any], org_id: str | None) -> bool:
        row_org_id = row.get("org_id")
        if org_id is None:
            return True
        return row_org_id is None or row_org_id == org_id

    @staticmethod
    def _fallback_active_match(row: dict[str, Any], active_only: bool) -> bool:
        if not active_only:
            return True
        return bool(row.get("active", True))

    def _lookup_in_fallback(
        self,
        *,
        predicate: Callable[[dict[str, Any]], bool],
        org_id: str | None,
        active_only: bool,
    ) -> list[IOCRecord]:
        results: list[IOCRecord] = []
        for row in self._iter_fallback_iocs():
            if not self._fallback_scope_match(row, org_id):
                continue
            if not self._fallback_active_match(row, active_only):
                continue
            if predicate(row):
                results.append(_row_to_record(row))
        return results

    def upsert_ioc(self, record: IOCRecord) -> bool:
        row = _record_to_row(record)
        # Ensure stored mitre_technique_id is normalized (canonical storage)
        if row.get("mitre_technique_id"):
            row["mitre_technique_id"] = mu.normalize_mitre(row["mitre_technique_id"])
        existing = self.fallback_iocs.get(row["ioc_id"])
        if existing:
            merged = dict(existing)
            merged.update(_merge_record_update(existing, record))
            # Normalize stored existing mitre id if present
            if merged.get("mitre_technique_id"):
                merged["mitre_technique_id"] = mu.normalize_mitre(merged["mitre_technique_id"])
            self.fallback_iocs[row["ioc_id"]] = merged
        else:
            self.fallback_iocs[row["ioc_id"]] = row
        return True

    def bulk_upsert(self, records: list[IOCRecord], *, overwrite: bool = False) -> tuple[int, int, int]:
        if not records:
            return 0, 0, 0

        deduped: dict[str, IOCRecord] = {}
        for record in records:
            deduped[_record_attr(record, "ioc_id", "iocid", default="")] = record

        inserted = 0
        updated = 0
        for record in deduped.values():
            row = _record_to_row(record)
            # normalize mitre on insert
            if row.get("mitre_technique_id"):
                row["mitre_technique_id"] = mu.normalize_mitre(row["mitre_technique_id"])
            existing = self.fallback_iocs.get(row["ioc_id"])
            if existing:
                merged = dict(existing)
                merged.update(_overwrite_record_update(record) if overwrite else _merge_record_update(existing, record))
                # normalize merged mitre
                if merged.get("mitre_technique_id"):
                    merged["mitre_technique_id"] = mu.normalize_mitre(merged["mitre_technique_id"])
                self.fallback_iocs[row["ioc_id"]] = merged
                updated += 1
            else:
                self.fallback_iocs[row["ioc_id"]] = row
                inserted += 1
        return inserted, updated, 0

    def get_ioc(self, ioc_id: str) -> IOCRecord | None:
        row = self.fallback_iocs.get(ioc_id)
        return _row_to_record(row) if row else None

    def lookup_by_value(self, value: str, *, org_id: str | None = None, active_only: bool = True) -> list[IOCRecord]:
        ioc_type = _detect_ioc_type(value)
        normalized = _normalize_value(value, ioc_type)
        return self._lookup_in_fallback(
            predicate=lambda row: row.get("value") == normalized,
            org_id=org_id,
            active_only=active_only,
        )

    def lookup_by_cve(self, cve_id: str, *, org_id: str | None = None, active_only: bool = True) -> list[IOCRecord]:
        normalized = (cve_id or "").strip().upper()
        return self._lookup_in_fallback(
            predicate=lambda row: str(row.get("cve_id") or "").upper() == normalized,
            org_id=org_id,
            active_only=active_only,
        )

    def lookup_by_mitre_technique(
        self,
        technique_id: str,
        *,
        org_id: str | None = None,
        active_only: bool = True,
    ) -> list[IOCRecord]:
        """
        Lookup by technique id. Input is normalized to uppercase. The store
        persists mitre_technique_id in normalized uppercase form, so equality
        comparison is safe and efficient.
        """
        normalized = (technique_id or "").strip().upper()
        return self._lookup_in_fallback(
            predicate=lambda row: str(row.get("mitre_technique_id") or "").upper() == normalized,
            org_id=org_id,
            active_only=active_only,
        )

    def lookup_by_values(
        self,
        values: list[str],
        *,
        org_id: str | None = None,
        active_only: bool = True,
    ) -> list[IOCRecord]:
        if not values:
            return []
        normalized_values = {_normalize_value(value, _detect_ioc_type(value)) for value in values}
        return self._lookup_in_fallback(
            predicate=lambda row: row.get("value") in normalized_values,
            org_id=org_id,
            active_only=active_only,
        )

    def filter_iocs(self, req: IOCFilterRequest) -> list[IOCRecord]:
        source = _filter_attr(req, "source")
        ioc_type = _filter_attr(req, "ioc_type", "ioctype")
        severity = _filter_attr(req, "severity")
        org_id = _filter_attr(req, "org_id", "orgid")
        active = _filter_attr(req, "active")
        technique_id = _filter_attr(req, "mitre_technique_id", "mitretechniqueid")
        cve_id = _filter_attr(req, "cve_id", "cveid")
        value_contains = _filter_attr(req, "value_contains", "valuecontains")
        tag = _filter_attr(req, "tag")
        limit = int(_filter_attr(req, "limit", default=100) or 100)
        offset = int(_filter_attr(req, "offset", default=0) or 0)

        matches: list[IOCRecord] = []
        for row in self._iter_fallback_iocs():
            if source is not None and row.get("source") != source:
                continue
            if ioc_type is not None and row.get("ioc_type") != ioc_type:
                continue
            if severity is not None and row.get("severity") != severity:
                continue
            if org_id is not None and not self._fallback_scope_match(row, org_id):
                continue
            if active is not None and bool(row.get("active", True)) != active:
                continue
            if technique_id is not None:
                # Normalize both sides to ensure matches even if row had mixed case
                desired = mu.normalize_mitre(technique_id)
                if mu.normalize_mitre(row.get("mitre_technique_id")) != desired:
                    continue
            if cve_id is not None and row.get("cve_id") != cve_id:
                continue
            if value_contains is not None and value_contains not in str(row.get("value") or ""):
                continue
            if tag is not None and tag not in _parse_tags(row.get("tags")):
                continue
            matches.append(_row_to_record(row))
        return matches[offset : offset + limit]

    def deactivate_ioc(self, ioc_id: str) -> bool:
        row = self.fallback_iocs.get(ioc_id)
        if not row:
            return False
        row["active"] = False
        row["last_seen"] = _utcnow_iso()
        return True

    def delete_ioc(self, ioc_id: str) -> bool:
        return self.fallback_iocs.pop(ioc_id, None) is not None

    def delete_by_ingest_id(self, feed_ingest_id: str) -> int:
        targets = [ioc_id for ioc_id, row in self.fallback_iocs.items() if row.get("feed_ingest_id") == feed_ingest_id]
        for ioc_id in targets:
            self.fallback_iocs.pop(ioc_id, None)
        return len(targets)

    def prune_expired(self) -> int:
        now_iso = _utcnow_iso()
        count = 0
        for row in self._iter_fallback_iocs():
            expiry = row.get("expiry")
            if row.get("active", True) and expiry is not None and str(expiry) < now_iso:
                row["active"] = False
                row["last_seen"] = now_iso
                count += 1
        return count

    def count_iocs(self, *, source: str | None = None, active: bool | None = None, org_id: str | None = None) -> int:
        count = 0
        for row in self._iter_fallback_iocs():
            if source is not None and row.get("source") != source:
                continue
            if active is not None and bool(row.get("active", True)) != active:
                continue
            if org_id is not None and not self._fallback_scope_match(row, org_id):
                continue
            count += 1
        return count

    def persist_ingest_result(self, result: FeedIngestResult) -> bool:
        row = _ingest_result_to_row(result)
        self.fallback_ingest_log[row["ingest_id"]] = row
        return True

    def get_ingest_result(self, ingest_id: str) -> dict[str, Any] | None:
        row = self.fallback_ingest_log.get(ingest_id)
        return dict(row) if row else None

    def list_ingest_history(
        self,
        *,
        source: str | None = None,
        org_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        rows = list(self.fallback_ingest_log.values())
        if source is not None:
            rows = [row for row in rows if row.get("source") == source]
        if org_id is not None:
            rows = [row for row in rows if row.get("org_id") is None or row.get("org_id") == org_id]
        rows.sort(key=lambda row: str(row.get("started_at") or ""), reverse=True)
        return [dict(row) for row in rows[offset : offset + limit]]

    def delete_ingest_log(self, ingest_id: str) -> bool:
        return self.fallback_ingest_log.pop(ingest_id, None) is not None

    def health_check(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "backend": "fallback",
            "ioc_count": len(self.fallback_iocs),
        }

    def upsertioc(self, record: IOCRecord) -> bool:
        return self.upsert_ioc(record)

    def bulkupsert(self, records: list[IOCRecord], *, overwrite: bool = False) -> tuple[int, int, int]:
        return self.bulk_upsert(records, overwrite=overwrite)

    def getioc(self, iocid: str) -> IOCRecord | None:
        return self.get_ioc(iocid)

    def lookupbyvalue(self, value: str, *, orgid: str | None = None, activeonly: bool = True) -> list[IOCRecord]:
        return self.lookup_by_value(value, org_id=orgid, active_only=activeonly)

    def lookupbycve(self, cveid: str, *, orgid: str | None = None, activeonly: bool = True) -> list[IOCRecord]:
        return self.lookup_by_cve(cveid, org_id=orgid, active_only=activeonly)

    def lookupbymitretechnique(
        self,
        techniqueid: str,
        *,
        orgid: str | None = None,
        activeonly: bool = True,
    ) -> list[IOCRecord]:
        return self.lookup_by_mitre_technique(techniqueid, org_id=orgid, active_only=activeonly)

    def lookupbyvalues(self, values: list[str], *, orgid: str | None = None, activeonly: bool = True) -> list[IOCRecord]:
        return self.lookup_by_values(values, org_id=orgid, active_only=activeonly)

    def filteriocs(self, req: IOCFilterRequest) -> list[IOCRecord]:
        return self.filter_iocs(req)

    def deactivateioc(self, iocid: str) -> bool:
        return self.deactivate_ioc(iocid)

    def deleteioc(self, iocid: str) -> bool:
        return self.delete_ioc(iocid)

    def deletebyingestid(self, feedingestid: str) -> int:
        return self.delete_by_ingest_id(feedingestid)

    def pruneexpired(self) -> int:
        return self.prune_expired()

    def countiocs(self, *, source: str | None = None, active: bool | None = None, orgid: str | None = None) -> int:
        return self.count_iocs(source=source, active=active, org_id=orgid)

    def persistingestresult(self, result: FeedIngestResult) -> bool:
        return self.persist_ingest_result(result)

    def getingestresult(self, ingestid: str) -> dict[str, Any] | None:
        return self.get_ingest_result(ingestid)

    def listingesthistory(
        self,
        *,
        source: str | None = None,
        orgid: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        return self.list_ingest_history(source=source, org_id=orgid, limit=limit, offset=offset)

    def deleteingestlog(self, ingestid: str) -> bool:
        return self.delete_ingest_log(ingestid)

    def healthcheck(self) -> dict[str, Any]:
        return self.health_check()


class IOCStore:
    def __init__(
        self,
        *,
        client: Any | None = None,
        backend: IOCStoreBackend | None = None,
        allow_fallback_store: bool = False,
    ) -> None:
        self.client = client
        self.backend = backend
        self._client = client
        self._backend = backend
        self.allow_fallback_store = allow_fallback_store

    def set_client(self, client: Any | None) -> None:
        self.client = client
        self._client = client

    def set_backend(self, backend: IOCStoreBackend | None) -> None:
        self.backend = backend
        self._backend = backend

    def _resolve_backend(self) -> IOCStoreBackend | None:
        if self._backend is not None:
            return self._backend
        if IOCSTOREBACKEND is not None:
            return IOCSTOREBACKEND
        return None

    def _can_use_fallback(self) -> bool:
        if self._resolve_backend() is not None:
            return True
        if _looks_like_test_runtime():
            return True
        if self.allow_fallback_store:
            return True
        return False

    def _resolve_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            client = _get_client()
        except Exception as exc:
            if _is_unconfigured_client_error(exc):
                raise IOCStoreConfigurationError(str(exc)) from exc
            raise
        if client is None:
            raise IOCStoreConfigurationError("Supabase credentials not set")
        return client

    def _resolve_runtime(self) -> tuple[str, Any]:
        backend = self._resolve_backend()
        if backend is not None:
            return "backend", backend
        try:
            client = self._resolve_client()
            return "client", client
        except IOCStoreConfigurationError as exc:
            if self._can_use_fallback():
                backend = InMemoryIOCStoreBackend()
                self.backend = backend
                self._backend = backend
                logger.info("iocstore using in-memory backend due to unconfigured supabase: %s", exc)
                return "backend", backend
            raise

    def upsert_ioc(self, record: IOCRecord) -> bool:
        try:
            runtime_type, runtime = self._resolve_runtime()
            if runtime_type == "backend":
                return runtime.upsert_ioc(record)

            row = _record_to_row(record)
            # ensure canonical mitre normalization on DB path as well
            if row.get("mitre_technique_id"):
                row["mitre_technique_id"] = mu.normalize_mitre(row["mitre_technique_id"])

            table = runtime.table(TABLE_IOCS)
            existing_resp = table.select("ioc_id,confidence,tags,description,extra,expiry,mitre_technique_id").eq("ioc_id", row["ioc_id"]).maybe_single().execute()
            existing = existing_resp.data if existing_resp else None

            if existing:
                # ensure existing mitre value normalized before merging
                if existing.get("mitre_technique_id"):
                    existing["mitre_technique_id"] = mu.normalize_mitre(existing.get("mitre_technique_id"))
                table.update(_merge_record_update(existing, record)).eq("ioc_id", row["ioc_id"]).execute()
            else:
                table.insert(row).execute()
            return True
        except IOCStoreConfigurationError:
            logger.warning("iocstore.upsert_ioc Supabase not configured")
            return False
        except Exception as exc:
            logger.error("iocstore.upsert_ioc.error %s", exc)
            return False

    def bulk_upsert(self, records: list[IOCRecord], *, overwrite: bool = False) -> tuple[int, int, int]:
        if not records:
            return 0, 0, 0

        deduped: dict[str, IOCRecord] = {}
        for record in records:
            deduped[_record_attr(record, "ioc_id", "iocid", default="")] = record
        unique_records = list(deduped.values())

        try:
            runtime_type, runtime = self._resolve_runtime()
            if runtime_type == "backend":
                return runtime.bulk_upsert(unique_records, overwrite=overwrite)

            inserted = 0
            updated = 0
            skipped = 0

            for batch_start in range(0, len(unique_records), MAX_BULK_UPSERT_BATCH):
                batch = unique_records[batch_start : batch_start + MAX_BULK_UPSERT_BATCH]
                ioc_ids = [_record_attr(record, "ioc_id", "iocid", default="") for record in batch]
                batch_inserted = 0
                batch_updated = 0
                try:
                    table = runtime.table(TABLE_IOCS)
                    existing_resp = table.select("ioc_id,confidence,tags,description,extra,expiry,mitre_technique_id").in_("ioc_id", ioc_ids).execute()
                    existing_map: dict[str, dict[str, Any]] = {}
                    existing_data = existing_resp.data if existing_resp else []
                    if isinstance(existing_data, dict):
                        existing_map[existing_data["ioc_id"]] = existing_data
                    else:
                        for row in existing_data or []:
                            # normalize existing mitre values for safe merges
                            if row.get("mitre_technique_id"):
                                row["mitre_technique_id"] = mu.normalize_mitre(row.get("mitre_technique_id"))
                            existing_map[row["ioc_id"]] = row

                    rows_to_insert: list[dict[str, Any]] = []
                    rows_to_update: list[tuple[str, dict[str, Any]]] = []

                    for record in batch:
                        row = _record_to_row(record)
                        # normalize incoming mitre
                        if row.get("mitre_technique_id"):
                            row["mitre_technique_id"] = mu.normalize_mitre(row["mitre_technique_id"])
                        if row["ioc_id"] in existing_map:
                            payload = _overwrite_record_update(record) if overwrite else _merge_record_update(existing_map[row["ioc_id"]], record)
                            # normalize payload mitre field if present
                            if payload.get("mitre_technique_id"):
                                payload["mitre_technique_id"] = mu.normalize_mitre(payload.get("mitre_technique_id"))
                            rows_to_update.append((row["ioc_id"], payload))
                            updated += 1
                            batch_updated += 1
                        else:
                            rows_to_insert.append(row)
                            inserted += 1
                            batch_inserted += 1

                    if rows_to_insert:
                        table.insert(rows_to_insert).execute()

                    for ioc_id, payload in rows_to_update:
                        try:
                            table.update(payload).eq("ioc_id", ioc_id).execute()
                        except Exception as exc:
                            logger.error("iocstore.bulk_upsert.update_error ioc_id=%s %s", ioc_id, exc)
                            updated -= 1
                            skipped += 1
                except Exception as exc:
                    logger.error("iocstore.bulk_upsert.batch_error batch_start=%d %s", batch_start, exc)
                    inserted -= batch_inserted
                    updated -= batch_updated
                    skipped += len(batch)

            return inserted, updated, skipped
        except IOCStoreConfigurationError:
            logger.warning("iocstore.bulk_upsert Supabase not configured")
            return 0, 0, 0

    def get_ioc(self, ioc_id: str) -> IOCRecord | None:
        try:
            runtime_type, runtime = self._resolve_runtime()
            if runtime_type == "backend":
                return runtime.get_ioc(ioc_id)

            resp = runtime.table(TABLE_IOCS).select("*").eq("ioc_id", ioc_id).maybe_single().execute()
            if resp and resp.data:
                return _row_to_record(resp.data)
            return None
        except IOCStoreConfigurationError:
            logger.warning("iocstore.get_ioc Supabase not configured")
            return None
        except Exception as exc:
            logger.error("iocstore.get_ioc.error %s", exc)
            return None

    def lookup_by_value(self, value: str, *, org_id: str | None = None, active_only: bool = True) -> list[IOCRecord]:
        normalized = _normalize_value(value, _detect_ioc_type(value))
        try:
            runtime_type, runtime = self._resolve_runtime()
            if runtime_type == "backend":
                return runtime.lookup_by_value(normalized, org_id=org_id, active_only=active_only)

            q = runtime.table(TABLE_IOCS).select("*").eq("value", normalized)
            if active_only:
                q = q.eq("active", True)
            if org_id is not None:
                q = q.or_(f"org_id.eq.{org_id},org_id.is.null")
            resp = q.execute()
            return [_row_to_record(row) for row in (resp.data or [])] if resp else []
        except IOCStoreConfigurationError:
            logger.warning("iocstore.lookup_by_value Supabase not configured")
            return []
        except Exception as exc:
            logger.error("iocstore.lookup_by_value.error %s", exc)
            return []

    def lookup_by_values(self, values: list[str], *, org_id: str | None = None, active_only: bool = True) -> list[IOCRecord]:
        if not values:
            return []
        normalized_values = [_normalize_value(value, _detect_ioc_type(value)) for value in values]
        try:
            runtime_type, runtime = self._resolve_runtime()
            if runtime_type == "backend":
                return runtime.lookup_by_values(normalized_values, org_id=org_id, active_only=active_only)

            q = runtime.table(TABLE_IOCS).select("*").in_("value", normalized_values)
            if active_only:
                q = q.eq("active", True)
            if org_id is not None:
                q = q.or_(f"org_id.eq.{org_id},org_id.is.null")
            resp = q.execute()
            return [_row_to_record(row) for row in (resp.data or [])] if resp else []
        except IOCStoreConfigurationError:
            logger.warning("iocstore.lookup_by_values Supabase not configured")
            return []
        except Exception as exc:
            logger.error("iocstore.lookup_by_values.error %s", exc)
            return []

    def lookup_by_cve(self, cve_id: str, *, org_id: str | None = None, active_only: bool = True) -> list[IOCRecord]:
        normalized = (cve_id or "").strip().upper()
        try:
            runtime_type, runtime = self._resolve_runtime()
            if runtime_type == "backend":
                return runtime.lookup_by_cve(normalized, org_id=org_id, active_only=active_only)

            q = runtime.table(TABLE_IOCS).select("*").eq("cve_id", normalized)
            if active_only:
                q = q.eq("active", True)
            if org_id is not None:
                q = q.or_(f"org_id.eq.{org_id},org_id.is.null")
            resp = q.execute()
            return [_row_to_record(row) for row in (resp.data or [])] if resp else []
        except IOCStoreConfigurationError:
            logger.warning("iocstore.lookup_by_cve Supabase not configured")
            return []
        except Exception as exc:
            logger.error("iocstore.lookup_by_cve.error %s", exc)
            return []

    def lookup_by_mitre_technique(
        self,
        technique_id: str,
        *,
        org_id: str | None = None,
        active_only: bool = True,
    ) -> list[IOCRecord]:
        normalized = (technique_id or "").strip().upper()
        try:
            runtime_type, runtime = self._resolve_runtime()
            if runtime_type == "backend":
                return runtime.lookup_by_mitre_technique(normalized, org_id=org_id, active_only=active_only)

            q = runtime.table(TABLE_IOCS).select("*").eq("mitre_technique_id", normalized)
            if active_only:
                q = q.eq("active", True)
            if org_id is not None:
                q = q.or_(f"org_id.eq.{org_id},org_id.is.null")
            resp = q.execute()
            return [_row_to_record(row) for row in (resp.data or [])] if resp else []
        except IOCStoreConfigurationError:
            logger.warning("iocstore.lookup_by_mitre_technique Supabase not configured")
            return []
        except Exception as exc:
            logger.error("iocstore.lookup_by_mitre_technique.error %s", exc)
            return []

    def filter_iocs(self, req: IOCFilterRequest) -> list[IOCRecord]:
        try:
            runtime_type, runtime = self._resolve_runtime()
            if runtime_type == "backend":
                # Ensure technique param normalised before building query
                technique_id = _filter_attr(req, "mitre_technique_id", "mitretechniqueid")
                if technique_id is not None:
                    technique_id = mu.normalize_mitre(technique_id)
                return runtime.filter_iocs(req)

            q = runtime.table(TABLE_IOCS).select("*")
            source = _filter_attr(req, "source")
            ioc_type = _filter_attr(req, "ioc_type", "ioctype")
            severity = _filter_attr(req, "severity")
            org_id = _filter_attr(req, "org_id", "orgid")
            active = _filter_attr(req, "active")
            technique_id = _filter_attr(req, "mitre_technique_id", "mitretechniqueid")
            cve_id = _filter_attr(req, "cve_id", "cveid")
            value_contains = _filter_attr(req, "value_contains", "valuecontains")
            tag = _filter_attr(req, "tag")
            limit = int(_filter_attr(req, "limit", default=100) or 100)
            offset = int(_filter_attr(req, "offset", default=0) or 0)

            if source is not None:
                q = q.eq("source", source)
            if ioc_type is not None:
                q = q.eq("ioc_type", ioc_type)
            if severity is not None:
                q = q.eq("severity", severity)
            if org_id is not None:
                q = q.or_(f"org_id.eq.{org_id},org_id.is.null")
            if active is not None:
                q = q.eq("active", active)
            if technique_id is not None:
                technique_id = mu.normalize_mitre(technique_id)
                q = q.eq("mitre_technique_id", technique_id)
            if cve_id is not None:
                q = q.eq("cve_id", cve_id)
            if value_contains is not None:
                q = q.ilike("value", f"%{value_contains}%")
            if tag is not None:
                q = q.contains("tags", [tag])
            q = q.range(offset, offset + limit - 1)
            resp = q.execute()
            return [_row_to_record(row) for row in (resp.data or [])] if resp else []
        except IOCStoreConfigurationError:
            logger.warning("iocstore.filter_iocs Supabase not configured")
            return []
        except Exception as exc:
            logger.error("iocstore.filter_iocs.error %s", exc)
            return []

    def deactivate_ioc(self, ioc_id: str) -> bool:
        try:
            runtime_type, runtime = self._resolve_runtime()
            if runtime_type == "backend":
                return runtime.deactivate_ioc(ioc_id)

            resp = runtime.table(TABLE_IOCS).update({"active": False, "last_seen": _utcnow_iso()}).eq("ioc_id", ioc_id).execute()
            return bool(resp and resp.data)
        except IOCStoreConfigurationError:
            logger.warning("iocstore.deactivate_ioc Supabase not configured")
            return False
        except Exception as exc:
            logger.error("iocstore.deactivate_ioc.error %s", exc)
            return False

    def delete_ioc(self, ioc_id: str) -> bool:
        try:
            runtime_type, runtime = self._resolve_runtime()
            if runtime_type == "backend":
                return runtime.delete_ioc(ioc_id)

            resp = runtime.table(TABLE_IOCS).delete().eq("ioc_id", ioc_id).execute()
            return bool(resp and resp.data)
        except IOCStoreConfigurationError:
            logger.warning("iocstore.delete_ioc Supabase not configured")
            return False
        except Exception as exc:
            logger.error("iocstore.delete_ioc.error %s", exc)
            return False

    def delete_by_ingest_id(self, feed_ingest_id: str) -> int:
        try:
            runtime_type, runtime = self._resolve_runtime()
            if runtime_type == "backend":
                return runtime.delete_by_ingest_id(feed_ingest_id)

            resp = runtime.table(TABLE_IOCS).delete().eq("feed_ingest_id", feed_ingest_id).execute()
            return len(resp.data) if resp and resp.data else 0
        except IOCStoreConfigurationError:
            logger.warning("iocstore.delete_by_ingest_id Supabase not configured")
            return 0
        except Exception as exc:
            logger.error("iocstore.delete_by_ingest_id.error %s", exc)
            return 0

    def prune_expired(self) -> int:
        now_iso = _utcnow_iso()
        try:
            runtime_type, runtime = self._resolve_runtime()
            if runtime_type == "backend":
                return runtime.prune_expired()

            resp = runtime.table(TABLE_IOCS).update({"active": False, "last_seen": now_iso}).eq("active", True).lt("expiry", now_iso).not_.is_("expiry", "null").execute()
            return len(resp.data) if resp and resp.data else 0
        except IOCStoreConfigurationError:
            logger.warning("iocstore.prune_expired Supabase not configured")
            return 0
        except Exception as exc:
            logger.error("iocstore.prune_expired.error %s", exc)
            return 0

    def count_iocs(self, *, source: str | None = None, active: bool | None = None, org_id: str | None = None) -> int:
        try:
            runtime_type, runtime = self._resolve_runtime()
            if runtime_type == "backend":
                return runtime.count_iocs(source=source, active=active, org_id=org_id)

            q = runtime.table(TABLE_IOCS).select("ioc_id", count="exact")
            if source is not None:
                q = q.eq("source", source)
            if active is not None:
                q = q.eq("active", active)
            if org_id is not None:
                q = q.or_(f"org_id.eq.{org_id},org_id.is.null")
            resp = q.execute()
            return resp.count if resp and resp.count is not None else 0
        except IOCStoreConfigurationError:
            logger.warning("iocstore.count_iocs Supabase not configured")
            return 0
        except Exception as exc:
            logger.error("iocstore.count_iocs.error %s", exc)
            return 0

    def persist_ingest_result(self, result: FeedIngestResult) -> bool:
        try:
            runtime_type, runtime = self._resolve_runtime()
            if runtime_type == "backend":
                return runtime.persist_ingest_result(result)

            row = _ingest_result_to_row(result)
            table = runtime.table(TABLE_INGEST_LOG)
            try:
                table.upsert(row, on_conflict="ingest_id").execute()
            except Exception:
                try:
                    table.insert(row).execute()
                except Exception as inner_exc:
                    err = str(inner_exc).lower()
                    if "409" in err or "duplicate key" in err or "unique constraint" in err:
                        return True
                    raise
            return True
        except IOCStoreConfigurationError:
            logger.warning("iocstore.persist_ingest_result Supabase not configured")
            return False
        except Exception as exc:
            logger.error("iocstore.persist_ingest_result.error %s", exc)
            return False

    def get_ingest_result(self, ingest_id: str) -> dict[str, Any] | None:
        try:
            runtime_type, runtime = self._resolve_runtime()
            if runtime_type == "backend":
                return runtime.get_ingest_result(ingest_id)

            resp = runtime.table(TABLE_INGEST_LOG).select("*").eq("ingest_id", ingest_id).maybe_single().execute()
            return resp.data if resp and resp.data else None
        except IOCStoreConfigurationError:
            logger.warning("iocstore.get_ingest_result Supabase not configured")
            return None
        except Exception as exc:
            logger.error("iocstore.get_ingest_result.error %s", exc)
            return None

    def list_ingest_history(
        self,
        *,
        source: str | None = None,
        org_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        try:
            runtime_type, runtime = self._resolve_runtime()
            if runtime_type == "backend":
                return runtime.list_ingest_history(source=source, org_id=org_id, limit=limit, offset=offset)

            q = runtime.table(TABLE_INGEST_LOG).select("*").order("started_at", desc=True)
            if source is not None:
                q = q.eq("source", source)
            if org_id is not None:
                q = q.or_(f"org_id.eq.{org_id},org_id.is.null")
            q = q.range(offset, offset + limit - 1)
            resp = q.execute()
            return resp.data if resp and resp.data else []
        except IOCStoreConfigurationError:
            logger.warning("iocstore.list_ingest_history Supabase not configured")
            return []
        except Exception as exc:
            logger.error("iocstore.list_ingest_history.error %s", exc)
            return []

    def delete_ingest_log(self, ingest_id: str) -> bool:
        try:
            runtime_type, runtime = self._resolve_runtime()
            if runtime_type == "backend":
                return runtime.delete_ingest_log(ingest_id)

            resp = runtime.table(TABLE_INGEST_LOG).delete().eq("ingest_id", ingest_id).execute()
            return bool(resp and resp.data)
        except IOCStoreConfigurationError:
            logger.warning("iocstore.delete_ingest_log Supabase not configured")
            return False
        except Exception as exc:
            logger.error("iocstore.delete_ingest_log.error %s", exc)
            return False

    def health_check(self) -> dict[str, Any]:
        try:
            runtime_type, runtime = self._resolve_runtime()
            if runtime_type == "backend":
                return runtime.health_check()

            resp = runtime.table(TABLE_IOCS).select("ioc_id", count="exact").limit(1).execute()
            return {
                "status": "ok",
                "backend": "supabase",
                "ioc_count": resp.count if resp and resp.count is not None else 0,
            }
        except IOCStoreConfigurationError:
            return {"status": "unconfigured", "detail": "Supabase credentials not set"}
        except Exception as exc:
            return {"status": "error", "detail": str(exc)}

    def setclient(self, client: Any | None) -> None:
        self.set_client(client)

    def setbackend(self, backend: IOCStoreBackend | None) -> None:
        self.set_backend(backend)

    def resolvebackend(self) -> IOCStoreBackend | None:
        return self._resolve_backend()

    def canusefallback(self) -> bool:
        return self._can_use_fallback()

    def resolveclient(self) -> Any:
        return self._resolve_client()

    def resolveruntime(self) -> tuple[str, Any]:
        return self._resolve_runtime()

    def upsertioc(self, record: IOCRecord) -> bool:
        return self.upsert_ioc(record)

    def bulkupsert(self, records: list[IOCRecord], *, overwrite: bool = False) -> tuple[int, int, int]:
        return self.bulk_upsert(records, overwrite=overwrite)

    def getioc(self, iocid: str) -> IOCRecord | None:
        return self.get_ioc(iocid)

    def lookupbyvalue(self, value: str, *, orgid: str | None = None, activeonly: bool = True) -> list[IOCRecord]:
        return self.lookup_by_value(value, org_id=orgid, active_only=activeonly)

    def lookupbyvalues(self, values: list[str], *, orgid: str | None = None, activeonly: bool = True) -> list[IOCRecord]:
        return self.lookup_by_values(values, org_id=orgid, active_only=activeonly)

    def lookupbycve(self, cveid: str, *, orgid: str | None = None, activeonly: bool = True) -> list[IOCRecord]:
        return self.lookup_by_cve(cveid, org_id=orgid, active_only=activeonly)

    def lookupbymitretechnique(
        self,
        techniqueid: str,
        *,
        orgid: str | None = None,
        activeonly: bool = True,
    ) -> list[IOCRecord]:
        return self.lookup_by_mitre_technique(techniqueid, org_id=orgid, active_only=activeonly)

    def filteriocs(self, req: IOCFilterRequest) -> list[IOCRecord]:
        return self.filter_iocs(req)

    def deactivateioc(self, iocid: str) -> bool:
        return self.deactivate_ioc(iocid)

    def deleteioc(self, iocid: str) -> bool:
        return self.delete_ioc(iocid)

    def deletebyingestid(self, feedingestid: str) -> int:
        return self.delete_by_ingest_id(feedingestid)

    def pruneexpired(self) -> int:
        return self.prune_expired()

    def countiocs(self, *, source: str | None = None, active: bool | None = None, orgid: str | None = None) -> int:
        return self.count_iocs(source=source, active=active, org_id=orgid)

    def persistingestresult(self, result: FeedIngestResult) -> bool:
        return self.persist_ingest_result(result)

    def getingestresult(self, ingestid: str) -> dict[str, Any] | None:
        return self.get_ingest_result(ingestid)

    def listingesthistory(
        self,
        *,
        source: str | None = None,
        orgid: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        return self.list_ingest_history(source=source, org_id=orgid, limit=limit, offset=offset)

    def deleteingestlog(self, ingestid: str) -> bool:
        return self.delete_ingest_log(ingestid)

    def healthcheck(self) -> dict[str, Any]:
        return self.health_check()


def set_ioc_store_backend(backend: IOCStoreBackend | None) -> None:
    global IOCSTOREBACKEND
    with STORE_LOCK:
        IOCSTOREBACKEND = backend


def setiocstorebackend(backend: IOCStoreBackend | None) -> None:
    set_ioc_store_backend(backend)


def get_ioc_store() -> IOCStore:
    global IOCSTORE
    with STORE_LOCK:
        if IOCSTORE is None:
            IOCSTORE = IOCStore()
    return IOCSTORE


def getiocstore() -> IOCStore:
    return get_ioc_store()


IOC_STORE_MIGRATION_SQL = """
CREATE TABLE IF NOT EXISTS ioc_records (
    ioc_id TEXT PRIMARY KEY,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    description TEXT NOT NULL DEFAULT '',
    org_id TEXT,
    mitre_technique_id TEXT,
    mitre_tactic TEXT,
    cve_id TEXT,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    expiry TIMESTAMPTZ,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    feed_ingest_id TEXT NOT NULL,
    extra JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_ioc_records_value ON ioc_records (value);
CREATE INDEX IF NOT EXISTS idx_ioc_records_ioc_type ON ioc_records (ioc_type);
CREATE INDEX IF NOT EXISTS idx_ioc_records_source ON ioc_records (source);
CREATE INDEX IF NOT EXISTS idx_ioc_records_severity ON ioc_records (severity);
CREATE INDEX IF NOT EXISTS idx_ioc_records_active ON ioc_records (active);
CREATE INDEX IF NOT EXISTS idx_ioc_records_org_id ON ioc_records (org_id);
CREATE INDEX IF NOT EXISTS idx_ioc_records_mitre_technique_id ON ioc_records (mitre_technique_id);
CREATE INDEX IF NOT EXISTS idx_ioc_records_cve_id ON ioc_records (cve_id);
CREATE INDEX IF NOT EXISTS idx_ioc_records_expiry ON ioc_records (expiry) WHERE expiry IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ioc_records_feed_ingest_id ON ioc_records (feed_ingest_id);
CREATE INDEX IF NOT EXISTS idx_ioc_records_tags ON ioc_records USING GIN (tags);

CREATE TABLE IF NOT EXISTS feed_ingest_log (
    ingest_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    iocs_parsed INTEGER NOT NULL DEFAULT 0,
    iocs_inserted INTEGER NOT NULL DEFAULT 0,
    iocs_updated INTEGER NOT NULL DEFAULT 0,
    iocs_skipped INTEGER NOT NULL DEFAULT 0,
    errors JSONB NOT NULL DEFAULT '[]'::jsonb,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    org_id TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_feed_ingest_log_source ON feed_ingest_log (source);
CREATE INDEX IF NOT EXISTS idx_feed_ingest_log_status ON feed_ingest_log (status);
CREATE INDEX IF NOT EXISTS idx_feed_ingest_log_started_at ON feed_ingest_log (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_feed_ingest_log_org_id ON feed_ingest_log (org_id);
"""

__all__ = [
    "IOC_STORE_MIGRATION_SQL",
    "IOCFilterRequest",
    "IOCStore",
    "IOCStoreBackend",
    "IOCStoreConfigurationError",
    "InMemoryIOCStoreBackend",
    "_detect_ioc_type",
    "_get_client",
    "_ingest_result_to_row",
    "_is_unconfigured_client_error",
    "_looks_like_test_runtime",
    "_merge_record_update",
    "_normalize_value",
    "_overwrite_record_update",
    "_parse_extra",
    "_parse_tags",
    "_record_to_row",
    "_row_to_record",
    "_utcnow_iso",
    "get_ioc_store",
    "getiocstore",
    "set_ioc_store_backend",
    "setiocstorebackend",
]
