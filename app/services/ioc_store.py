from __future__ import annotations

import logging
from typing import Any

from app.schemas.threat_detection import (
    IOCTypeEnum,
    ThreatFeedSourceEnum,
    ThreatSeverityLevel,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Re-export contracts so callers can import IOCRecord from here
# ---------------------------------------------------------------------------
from app.services.threat_feed_ingestion import (  # noqa: E402
    FeedIngestResult,
    IOCFilterRequest,
    IOCRecord,
    _detect_ioc_type,
    _normalize_value,
    _utcnow_iso,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_BULK_UPSERT_BATCH = 500
_TTL_PRUNE_BATCH = 1000

# ---------------------------------------------------------------------------
# Supabase table names — single source of truth
# ---------------------------------------------------------------------------

_TABLE_IOCS = "ioc_records"
_TABLE_INGEST_LOG = "feed_ingest_log"

# ---------------------------------------------------------------------------
# Supabase client resolution
# ---------------------------------------------------------------------------


def _get_client():  # type: ignore[return]
    """Return the project Supabase client.

    Deferred import to avoid circular imports and allow the client module
    to be located at app.clients.supabase or app.core.supabase depending on
    the project layout actually present at runtime.
    """
    try:
        from app.clients.supabase import get_supabase_client  # type: ignore[import]

        return get_supabase_client()
    except ImportError:
        pass
    try:
        from app.core.supabase import get_supabase_client  # type: ignore[import]

        return get_supabase_client()
    except ImportError:
        pass
    raise RuntimeError("ioc_store: cannot resolve Supabase client — " "expected get_supabase_client() at app.clients.supabase or app.core.supabase")


# ---------------------------------------------------------------------------
# Row ↔ IOCRecord conversion
# ---------------------------------------------------------------------------


def _record_to_row(record: IOCRecord) -> dict[str, Any]:
    """Serialize IOCRecord to a Supabase-compatible row dict."""
    return {
        "ioc_id": record.ioc_id,
        "ioc_type": record.ioc_type,
        "value": record.value,
        "source": record.source,
        "severity": record.severity,
        "confidence": float(record.confidence),
        "tags": list(record.tags),
        "description": record.description,
        "org_id": record.org_id,
        "mitre_technique_id": record.mitre_technique_id,
        "mitre_tactic": record.mitre_tactic,
        "cve_id": record.cve_id,
        "first_seen": record.first_seen,
        "last_seen": record.last_seen,
        "expiry": record.expiry,
        "active": record.active,
        "feed_ingest_id": record.feed_ingest_id,
        "extra": record.extra,
    }


def _row_to_record(row: dict[str, Any]) -> IOCRecord:
    """Deserialize a Supabase row dict into an IOCRecord."""
    tags = row.get("tags") or []
    if isinstance(tags, str):
        import json as _json

        try:
            tags = _json.loads(tags)
        except Exception:  # noqa: BLE001
            tags = [t.strip() for t in tags.split(",") if t.strip()]

    extra = row.get("extra") or {}
    if isinstance(extra, str):
        import json as _json

        try:
            extra = _json.loads(extra)
        except Exception:  # noqa: BLE001
            extra = {}

    return IOCRecord(
        ioc_id=row["ioc_id"],
        ioc_type=row.get("ioc_type", IOCTypeEnum.UNKNOWN),
        value=row.get("value", ""),
        source=row.get("source", ThreatFeedSourceEnum.INTERNAL),
        severity=row.get("severity", ThreatSeverityLevel.MEDIUM),
        confidence=float(row.get("confidence", 0.0)),
        tags=list(tags),
        description=row.get("description", ""),
        org_id=row.get("org_id"),
        mitre_technique_id=row.get("mitre_technique_id"),
        mitre_tactic=row.get("mitre_tactic"),
        cve_id=row.get("cve_id"),
        first_seen=row.get("first_seen", _utcnow_iso()),
        last_seen=row.get("last_seen", _utcnow_iso()),
        expiry=row.get("expiry"),
        active=bool(row.get("active", True)),
        feed_ingest_id=row.get("feed_ingest_id", ""),
        extra=dict(extra),
    )


def _ingest_result_to_row(result: FeedIngestResult) -> dict[str, Any]:
    return {
        "ingest_id": result.ingest_id,
        "source": result.source,
        "status": result.status,
        "iocs_parsed": result.iocs_parsed,
        "iocs_inserted": result.iocs_inserted,
        "iocs_updated": result.iocs_updated,
        "iocs_skipped": result.iocs_skipped,
        "errors": list(result.errors),
        "started_at": result.started_at,
        "completed_at": result.completed_at,
        "org_id": result.org_id,
        "metadata": dict(result.metadata),
    }


# ---------------------------------------------------------------------------
# IOCStore — Supabase-backed persistent IOC store
# ---------------------------------------------------------------------------


class IOCStore:
    """
    Supabase-backed persistent IOC store for IronClaw.

    Replaces the bounded in-memory deque in ThreatFeedIngestionService.
    Provides full CRUD, bulk upsert with deduplication by ioc_id fingerprint,
    TTL expiry pruning, ingest log persistence, and rich filtering.

    All upper services (threat_detection_engine, threat_correlation,
    threat_hunt_service, stix_adapter, threat_feed_scheduler) depend on this
    class as their single IOC persistence interface.

    This store does NOT own parsing logic — it only persists and queries records
    produced by ThreatFeedIngestionService parsers and the STIX adapter.
    """

    # ------------------------------------------------------------------
    # Upsert — single record
    # ------------------------------------------------------------------

    def upsert_ioc(self, record: IOCRecord) -> bool:
        """
        Upsert a single IOCRecord.

        On conflict (ioc_id): updates severity, confidence (max), tags (union),
        description (if non-empty), last_seen, expiry, feed_ingest_id, extra (merge).

        Returns True on success, False on error.
        """
        try:
            client = _get_client()
            existing_resp = client.table(_TABLE_IOCS).select("ioc_id,confidence,tags,description,extra").eq("ioc_id", record.ioc_id).maybe_single().execute()
            existing = existing_resp.data if existing_resp else None

            if existing:
                merged_confidence = max(float(existing.get("confidence", 0.0)), record.confidence)
                existing_tags: list[str] = existing.get("tags") or []
                if isinstance(existing_tags, str):
                    existing_tags = [t.strip() for t in existing_tags.split(",") if t.strip()]
                merged_tags = list(set(existing_tags) | set(record.tags))
                merged_description = record.description if record.description else existing.get("description", "")
                existing_extra: dict[str, Any] = existing.get("extra") or {}
                if isinstance(existing_extra, str):
                    import json as _j

                    try:
                        existing_extra = _j.loads(existing_extra)
                    except Exception:  # noqa: BLE001
                        existing_extra = {}
                merged_extra = {**existing_extra, **record.extra}

                client.table(_TABLE_IOCS).update(
                    {
                        "severity": record.severity,
                        "confidence": merged_confidence,
                        "tags": merged_tags,
                        "description": merged_description,
                        "last_seen": record.last_seen,
                        "expiry": record.expiry or existing.get("expiry"),
                        "active": True,
                        "feed_ingest_id": record.feed_ingest_id,
                        "extra": merged_extra,
                    }
                ).eq("ioc_id", record.ioc_id).execute()
            else:
                client.table(_TABLE_IOCS).insert(_record_to_row(record)).execute()

            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("ioc_store.upsert_ioc.error ioc_id=%s: %s", record.ioc_id, exc)
            return False

    # ------------------------------------------------------------------
    # Bulk upsert — batched for feed ingestion
    # ------------------------------------------------------------------

    def bulk_upsert(
        self,
        records: list[IOCRecord],
        *,
        overwrite: bool = False,
    ) -> tuple[int, int, int]:
        """
        Bulk upsert a list of IOCRecords in batches.

        Deduplicates by ioc_id before hitting the database.
        When overwrite=False, existing records are updated with merge semantics.
        When overwrite=True, the incoming record fully replaces the existing row.

        Returns (inserted, updated, skipped) counts.
        """
        if not records:
            return 0, 0, 0

        # Deduplicate within the incoming batch — keep last occurrence per ioc_id
        deduped: dict[str, IOCRecord] = {}
        for r in records:
            deduped[r.ioc_id] = r
        unique_records = list(deduped.values())

        inserted = updated = skipped = 0

        for batch_start in range(0, len(unique_records), _MAX_BULK_UPSERT_BATCH):
            batch = unique_records[batch_start : batch_start + _MAX_BULK_UPSERT_BATCH]
            ioc_ids = [r.ioc_id for r in batch]

            try:
                client = _get_client()
                existing_resp = client.table(_TABLE_IOCS).select("ioc_id,confidence,tags,description,extra,expiry").in_("ioc_id", ioc_ids).execute()
                existing_map: dict[str, dict[str, Any]] = {}
                if existing_resp and existing_resp.data:
                    for row in existing_resp.data:
                        existing_map[row["ioc_id"]] = row

                rows_to_insert: list[dict[str, Any]] = []
                rows_to_update: list[tuple[str, dict[str, Any]]] = []

                for record in batch:
                    if record.ioc_id in existing_map:
                        if overwrite:
                            rows_to_update.append((record.ioc_id, _record_to_row(record)))
                        else:
                            ex = existing_map[record.ioc_id]
                            merged_confidence = max(float(ex.get("confidence", 0.0)), record.confidence)
                            ex_tags: list[str] = ex.get("tags") or []
                            if isinstance(ex_tags, str):
                                ex_tags = [t.strip() for t in ex_tags.split(",") if t.strip()]
                            merged_tags = list(set(ex_tags) | set(record.tags))
                            merged_desc = record.description if record.description else ex.get("description", "")
                            ex_extra: dict[str, Any] = ex.get("extra") or {}
                            if isinstance(ex_extra, str):
                                import json as _j

                                try:
                                    ex_extra = _j.loads(ex_extra)
                                except Exception:  # noqa: BLE001
                                    ex_extra = {}
                            merged_extra = {**ex_extra, **record.extra}
                            rows_to_update.append(
                                (
                                    record.ioc_id,
                                    {
                                        "severity": record.severity,
                                        "confidence": merged_confidence,
                                        "tags": merged_tags,
                                        "description": merged_desc,
                                        "last_seen": record.last_seen,
                                        "expiry": record.expiry or ex.get("expiry"),
                                        "active": True,
                                        "feed_ingest_id": record.feed_ingest_id,
                                        "extra": merged_extra,
                                    },
                                )
                            )
                        updated += 1
                    else:
                        rows_to_insert.append(_record_to_row(record))
                        inserted += 1

                if rows_to_insert:
                    client.table(_TABLE_IOCS).insert(rows_to_insert).execute()

                for ioc_id, update_payload in rows_to_update:
                    try:
                        client.table(_TABLE_IOCS).update(update_payload).eq("ioc_id", ioc_id).execute()
                    except Exception as exc:  # noqa: BLE001
                        logger.error("ioc_store.bulk_upsert.update_error ioc_id=%s: %s", ioc_id, exc)
                        updated -= 1
                        skipped += 1

            except Exception as exc:  # noqa: BLE001
                logger.error("ioc_store.bulk_upsert.batch_error batch_start=%d: %s", batch_start, exc)
                skipped += len(batch)
                inserted -= sum(1 for r in batch if r.ioc_id not in existing_map)
                updated -= sum(1 for r in batch if r.ioc_id in existing_map)

        logger.info(
            "ioc_store.bulk_upsert.done inserted=%d updated=%d skipped=%d",
            inserted,
            updated,
            skipped,
        )
        return inserted, updated, skipped

    # ------------------------------------------------------------------
    # Fetch single
    # ------------------------------------------------------------------

    def get_ioc(self, ioc_id: str) -> IOCRecord | None:
        try:
            client = _get_client()
            resp = client.table(_TABLE_IOCS).select("*").eq("ioc_id", ioc_id).maybe_single().execute()
            if resp and resp.data:
                return _row_to_record(resp.data)
            return None
        except Exception as exc:  # noqa: BLE001
            logger.error("ioc_store.get_ioc.error ioc_id=%s: %s", ioc_id, exc)
            return None

    # ------------------------------------------------------------------
    # Lookup by value — primary hot path for detection engine
    # ------------------------------------------------------------------

    def lookup_by_value(
        self,
        value: str,
        *,
        org_id: str | None = None,
        active_only: bool = True,
    ) -> list[IOCRecord]:
        ioc_type = _detect_ioc_type(value)
        normalized = _normalize_value(value, ioc_type)
        try:
            client = _get_client()
            q = client.table(_TABLE_IOCS).select("*").eq("value", normalized)
            if active_only:
                q = q.eq("active", True)
            if org_id is not None:
                q = q.or_(f"org_id.eq.{org_id},org_id.is.null")
            resp = q.execute()
            if resp and resp.data:
                return [_row_to_record(r) for r in resp.data]
            return []
        except Exception as exc:  # noqa: BLE001
            logger.error("ioc_store.lookup_by_value.error value=%s: %s", normalized, exc)
            return []

    # ------------------------------------------------------------------
    # Lookup by CVE
    # ------------------------------------------------------------------

    def lookup_by_cve(
        self,
        cve_id: str,
        *,
        org_id: str | None = None,
        active_only: bool = True,
    ) -> list[IOCRecord]:
        normalized = cve_id.strip().upper()
        try:
            client = _get_client()
            q = client.table(_TABLE_IOCS).select("*").eq("cve_id", normalized)
            if active_only:
                q = q.eq("active", True)
            if org_id is not None:
                q = q.or_(f"org_id.eq.{org_id},org_id.is.null")
            resp = q.execute()
            if resp and resp.data:
                return [_row_to_record(r) for r in resp.data]
            return []
        except Exception as exc:  # noqa: BLE001
            logger.error("ioc_store.lookup_by_cve.error cve_id=%s: %s", normalized, exc)
            return []

    # ------------------------------------------------------------------
    # Lookup by MITRE technique
    # ------------------------------------------------------------------

    def lookup_by_mitre_technique(
        self,
        technique_id: str,
        *,
        org_id: str | None = None,
        active_only: bool = True,
    ) -> list[IOCRecord]:
        normalized = technique_id.strip().upper()
        try:
            client = _get_client()
            q = client.table(_TABLE_IOCS).select("*").eq("mitre_technique_id", normalized)
            if active_only:
                q = q.eq("active", True)
            if org_id is not None:
                q = q.or_(f"org_id.eq.{org_id},org_id.is.null")
            resp = q.execute()
            if resp and resp.data:
                return [_row_to_record(r) for r in resp.data]
            return []
        except Exception as exc:  # noqa: BLE001
            logger.error("ioc_store.lookup_by_mitre_technique.error technique=%s: %s", normalized, exc)
            return []

    # ------------------------------------------------------------------
    # Lookup by multiple values — batch detection hot path
    # ------------------------------------------------------------------

    def lookup_by_values(
        self,
        values: list[str],
        *,
        org_id: str | None = None,
        active_only: bool = True,
    ) -> list[IOCRecord]:
        if not values:
            return []
        normalized_values: list[str] = []
        for v in values:
            ioc_type = _detect_ioc_type(v)
            normalized_values.append(_normalize_value(v, ioc_type))
        try:
            client = _get_client()
            q = client.table(_TABLE_IOCS).select("*").in_("value", normalized_values)
            if active_only:
                q = q.eq("active", True)
            if org_id is not None:
                q = q.or_(f"org_id.eq.{org_id},org_id.is.null")
            resp = q.execute()
            if resp and resp.data:
                return [_row_to_record(r) for r in resp.data]
            return []
        except Exception as exc:  # noqa: BLE001
            logger.error("ioc_store.lookup_by_values.error count=%d: %s", len(values), exc)
            return []

    # ------------------------------------------------------------------
    # Filter — structured query matching IOCFilterRequest contract
    # ------------------------------------------------------------------

    def filter_iocs(self, req: IOCFilterRequest) -> list[IOCRecord]:
        try:
            client = _get_client()
            q = client.table(_TABLE_IOCS).select("*")

            if req.source is not None:
                q = q.eq("source", req.source)
            if req.ioc_type is not None:
                q = q.eq("ioc_type", req.ioc_type)
            if req.severity is not None:
                q = q.eq("severity", req.severity)
            if req.org_id is not None:
                q = q.or_(f"org_id.eq.{req.org_id},org_id.is.null")
            if req.active is not None:
                q = q.eq("active", req.active)
            if req.mitre_technique_id is not None:
                q = q.eq("mitre_technique_id", req.mitre_technique_id)
            if req.cve_id is not None:
                q = q.eq("cve_id", req.cve_id)
            if req.value_contains is not None:
                q = q.ilike("value", f"%{req.value_contains}%")
            if req.tag is not None:
                q = q.contains("tags", [req.tag])

            q = q.range(req.offset, req.offset + req.limit - 1)
            resp = q.execute()

            if resp and resp.data:
                return [_row_to_record(r) for r in resp.data]
            return []
        except Exception as exc:  # noqa: BLE001
            logger.error("ioc_store.filter_iocs.error: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Deactivate — soft-disable without deleting
    # ------------------------------------------------------------------

    def deactivate_ioc(self, ioc_id: str) -> bool:
        try:
            client = _get_client()
            resp = client.table(_TABLE_IOCS).update({"active": False, "last_seen": _utcnow_iso()}).eq("ioc_id", ioc_id).execute()
            if resp and resp.data:
                logger.info("ioc_store.deactivate_ioc ioc_id=%s", ioc_id)
                return True
            return False
        except Exception as exc:  # noqa: BLE001
            logger.error("ioc_store.deactivate_ioc.error ioc_id=%s: %s", ioc_id, exc)
            return False

    # ------------------------------------------------------------------
    # Hard delete
    # ------------------------------------------------------------------

    def delete_ioc(self, ioc_id: str) -> bool:
        try:
            client = _get_client()
            resp = client.table(_TABLE_IOCS).delete().eq("ioc_id", ioc_id).execute()
            if resp and resp.data:
                logger.info("ioc_store.delete_ioc ioc_id=%s", ioc_id)
                return True
            return False
        except Exception as exc:  # noqa: BLE001
            logger.error("ioc_store.delete_ioc.error ioc_id=%s: %s", ioc_id, exc)
            return False

    # ------------------------------------------------------------------
    # Bulk delete by ingest_id — used to purge a bad feed batch
    # ------------------------------------------------------------------

    def delete_by_ingest_id(self, feed_ingest_id: str) -> int:
        try:
            client = _get_client()
            resp = client.table(_TABLE_IOCS).delete().eq("feed_ingest_id", feed_ingest_id).execute()
            count = len(resp.data) if resp and resp.data else 0
            logger.info("ioc_store.delete_by_ingest_id ingest_id=%s deleted=%d", feed_ingest_id, count)
            return count
        except Exception as exc:  # noqa: BLE001
            logger.error("ioc_store.delete_by_ingest_id.error ingest_id=%s: %s", feed_ingest_id, exc)
            return 0

    # ------------------------------------------------------------------
    # TTL expiry pruning — callable by scheduler
    # ------------------------------------------------------------------

    def prune_expired(self) -> int:
        """
        Deactivate all IOCs whose expiry timestamp is in the past.
        Called by threat_feed_scheduler on its maintenance cycle.
        Returns count of records deactivated.
        """
        now_iso = _utcnow_iso()
        try:
            client = _get_client()
            resp = client.table(_TABLE_IOCS).update({"active": False, "last_seen": now_iso}).eq("active", True).lt("expiry", now_iso).not_.is_("expiry", "null").execute()
            count = len(resp.data) if resp and resp.data else 0
            if count:
                logger.info("ioc_store.prune_expired deactivated=%d", count)
            return count
        except Exception as exc:  # noqa: BLE001
            logger.error("ioc_store.prune_expired.error: %s", exc)
            return 0

    # ------------------------------------------------------------------
    # Count helpers
    # ------------------------------------------------------------------

    def count_iocs(
        self,
        *,
        source: str | None = None,
        active: bool | None = None,
        org_id: str | None = None,
    ) -> int:
        try:
            client = _get_client()
            q = client.table(_TABLE_IOCS).select("ioc_id", count="exact")
            if source is not None:
                q = q.eq("source", source)
            if active is not None:
                q = q.eq("active", active)
            if org_id is not None:
                q = q.or_(f"org_id.eq.{org_id},org_id.is.null")
            resp = q.execute()
            return resp.count if resp and resp.count is not None else 0
        except Exception as exc:  # noqa: BLE001
            logger.error("ioc_store.count_iocs.error: %s", exc)
            return 0

    # ------------------------------------------------------------------
    # Ingest log persistence — persists FeedIngestResult to Supabase
    # ------------------------------------------------------------------

    def persist_ingest_result(self, result: FeedIngestResult) -> bool:
        try:
            client = _get_client()
            client.table(_TABLE_INGEST_LOG).insert(_ingest_result_to_row(result)).execute()
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("ioc_store.persist_ingest_result.error ingest_id=%s: %s", result.ingest_id, exc)
            return False

    def get_ingest_result(self, ingest_id: str) -> dict[str, Any] | None:
        try:
            client = _get_client()
            resp = client.table(_TABLE_INGEST_LOG).select("*").eq("ingest_id", ingest_id).maybe_single().execute()
            return resp.data if resp and resp.data else None
        except Exception as exc:  # noqa: BLE001
            logger.error("ioc_store.get_ingest_result.error ingest_id=%s: %s", ingest_id, exc)
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
            client = _get_client()
            q = client.table(_TABLE_INGEST_LOG).select("*").order("started_at", desc=True)
            if source is not None:
                q = q.eq("source", source)
            if org_id is not None:
                q = q.or_(f"org_id.eq.{org_id},org_id.is.null")
            q = q.range(offset, offset + limit - 1)
            resp = q.execute()
            return resp.data if resp and resp.data else []
        except Exception as exc:  # noqa: BLE001
            logger.error("ioc_store.list_ingest_history.error: %s", exc)
            return []

    def delete_ingest_log(self, ingest_id: str) -> bool:
        try:
            client = _get_client()
            client.table(_TABLE_INGEST_LOG).delete().eq("ingest_id", ingest_id).execute()
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("ioc_store.delete_ingest_log.error ingest_id=%s: %s", ingest_id, exc)
            return False

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def health_check(self) -> dict[str, Any]:
        try:
            client = _get_client()
            resp = client.table(_TABLE_IOCS).select("ioc_id", count="exact").limit(1).execute()
            return {"status": "ok", "ioc_count": resp.count if resp else 0}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "detail": str(exc)}


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_IOC_STORE: IOCStore | None = None


def get_ioc_store() -> IOCStore:
    """Return the module-level IOCStore singleton."""
    global _IOC_STORE  # noqa: PLW0603
    if _IOC_STORE is None:
        _IOC_STORE = IOCStore()
    return _IOC_STORE


# ---------------------------------------------------------------------------
# SQL migration helper — emits the DDL for the two required tables.
# Apply via Supabase dashboard or apply_migration tool.
# ---------------------------------------------------------------------------

IOC_STORE_MIGRATION_SQL = """
-- ============================================================
-- IronClaw IOC Store — ioc_records table
-- ============================================================
CREATE TABLE IF NOT EXISTS ioc_records (
    ioc_id              TEXT PRIMARY KEY,
    ioc_type            TEXT NOT NULL,
    value               TEXT NOT NULL,
    source              TEXT NOT NULL,
    severity            TEXT NOT NULL DEFAULT 'medium',
    confidence          DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    tags                JSONB NOT NULL DEFAULT '[]',
    description         TEXT NOT NULL DEFAULT '',
    org_id              TEXT,
    mitre_technique_id  TEXT,
    mitre_tactic        TEXT,
    cve_id              TEXT,
    first_seen          TIMESTAMPTZ NOT NULL,
    last_seen           TIMESTAMPTZ NOT NULL,
    expiry              TIMESTAMPTZ,
    active              BOOLEAN NOT NULL DEFAULT TRUE,
    feed_ingest_id      TEXT NOT NULL,
    extra               JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_ioc_records_value       ON ioc_records (value);
CREATE INDEX IF NOT EXISTS idx_ioc_records_ioc_type    ON ioc_records (ioc_type);
CREATE INDEX IF NOT EXISTS idx_ioc_records_source      ON ioc_records (source);
CREATE INDEX IF NOT EXISTS idx_ioc_records_severity    ON ioc_records (severity);
CREATE INDEX IF NOT EXISTS idx_ioc_records_active      ON ioc_records (active);
CREATE INDEX IF NOT EXISTS idx_ioc_records_org_id      ON ioc_records (org_id);
CREATE INDEX IF NOT EXISTS idx_ioc_records_mitre_tech  ON ioc_records (mitre_technique_id);
CREATE INDEX IF NOT EXISTS idx_ioc_records_cve_id      ON ioc_records (cve_id);
CREATE INDEX IF NOT EXISTS idx_ioc_records_expiry      ON ioc_records (expiry) WHERE expiry IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ioc_records_ingest_id   ON ioc_records (feed_ingest_id);
CREATE INDEX IF NOT EXISTS idx_ioc_records_tags        ON ioc_records USING GIN (tags);

-- ============================================================
-- IronClaw IOC Store — feed_ingest_log table
-- ============================================================
CREATE TABLE IF NOT EXISTS feed_ingest_log (
    ingest_id       TEXT PRIMARY KEY,
    source          TEXT NOT NULL,
    status          TEXT NOT NULL,
    iocs_parsed     INTEGER NOT NULL DEFAULT 0,
    iocs_inserted   INTEGER NOT NULL DEFAULT 0,
    iocs_updated    INTEGER NOT NULL DEFAULT 0,
    iocs_skipped    INTEGER NOT NULL DEFAULT 0,
    errors          JSONB NOT NULL DEFAULT '[]',
    started_at      TIMESTAMPTZ NOT NULL,
    completed_at    TIMESTAMPTZ,
    org_id          TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_feed_ingest_log_source     ON feed_ingest_log (source);
CREATE INDEX IF NOT EXISTS idx_feed_ingest_log_status     ON feed_ingest_log (status);
CREATE INDEX IF NOT EXISTS idx_feed_ingest_log_started_at ON feed_ingest_log (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_feed_ingest_log_org_id     ON feed_ingest_log (org_id);
"""


__all__ = [
    "IOC_STORE_MIGRATION_SQL",
    "IOCStore",
    "get_ioc_store",
]
