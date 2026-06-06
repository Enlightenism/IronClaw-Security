from __future__ import annotations

import logging
from typing import Any

from app.schemas.threat_detection import (
    IOCTypeEnum,
    ThreatFeedSourceEnum,
    ThreatSeverityLevel,
)

logger = logging.getLogger(__name__)


from app.services.threat_feed_ingestion import (  # noqa: E402
    FeedIngestResult,
    IOCFilterRequest,
    IOCRecord,
    _detect_ioc_type,
    _normalize_value,
    _utcnow_iso,
)

_MAX_BULK_UPSERT_BATCH = 500
_TTL_PRUNE_BATCH = 1000


_TABLE_IOCS = "ioc_records"
_TABLE_INGEST_LOG = "feed_ingest_log"


def _get_client():
    try:
        from app.clients.supabase import get_supabase_client

        return get_supabase_client()
    except ImportError:
        pass
    try:
        from app.core.supabase import get_supabase_client

        return get_supabase_client()
    except ImportError:
        pass
    raise RuntimeError("ioc_store: cannot resolve Supabase client — " "expected get_supabase_client() at app.clients.supabase or app.core.supabase")


def _is_supabase_configured() -> bool:
    try:
        from app.clients.supabase import is_supabase_configured

        return is_supabase_configured()
    except ImportError:
        pass
    try:
        from app.core.supabase import is_supabase_configured

        return is_supabase_configured()
    except ImportError:
        pass
    return False


def _record_to_row(record: IOCRecord) -> dict[str, Any]:
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
    tags = row.get("tags") or []
    if isinstance(tags, str):
        import json as _json

        try:
            tags = _json.loads(tags)
        except Exception:
            tags = [t.strip() for t in tags.split(",") if t.strip()]

    extra = row.get("extra") or {}
    if isinstance(extra, str):
        import json as _json

        try:
            extra = _json.loads(extra)
        except Exception:
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


def _parse_tags(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [str(t) for t in raw]
    if isinstance(raw, str):
        import json as _j

        try:
            parsed = _j.loads(raw)
            if isinstance(parsed, list):
                return [str(t) for t in parsed]
        except Exception:
            pass
        return [t.strip() for t in raw.split(",") if t.strip()]
    return []


def _parse_extra(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        import json as _j

        try:
            parsed = _j.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
    return {}


def _merge_record_update(existing: dict[str, Any], record: IOCRecord) -> dict[str, Any]:
    merged_confidence = max(float(existing.get("confidence", 0.0)), record.confidence)
    merged_tags = list(set(_parse_tags(existing.get("tags"))) | set(record.tags))
    merged_description = record.description if record.description else existing.get("description", "")
    merged_extra = {**_parse_extra(existing.get("extra")), **record.extra}
    return {
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


class IOCStore:
    def upsert_ioc(self, record: IOCRecord) -> bool:
        try:
            client = _get_client()
        except Exception:
            logger.warning("ioc_store.upsert_ioc: Supabase not configured — skipping")
            return False
        try:
            table = client.table(_TABLE_IOCS)
            existing_resp = table.select("ioc_id,confidence,tags,description,extra,expiry").eq("ioc_id", record.ioc_id).maybe_single().execute()
            existing = existing_resp.data if existing_resp else None

            if existing:
                table.update(_merge_record_update(existing, record)).eq("ioc_id", record.ioc_id).execute()
            else:
                table.insert(_record_to_row(record)).execute()

            return True
        except Exception as exc:
            logger.error("ioc_store.upsert_ioc.error ioc_id=%s: %s", record.ioc_id, exc)
            return False

    def bulk_upsert(
        self,
        records: list[IOCRecord],
        *,
        overwrite: bool = False,
    ) -> tuple[int, int, int]:
        try:
            _get_client()
        except Exception:
            logger.warning("ioc_store.bulk_upsert: Supabase not configured — skipping")
            return 0, 0, 0

        if not records:
            return 0, 0, 0

        deduped: dict[str, IOCRecord] = {}
        for r in records:
            deduped[r.ioc_id] = r
        unique_records = list(deduped.values())

        inserted = updated = skipped = 0

        for batch_start in range(0, len(unique_records), _MAX_BULK_UPSERT_BATCH):
            batch = unique_records[batch_start : batch_start + _MAX_BULK_UPSERT_BATCH]
            ioc_ids = [r.ioc_id for r in batch]
            existing_map: dict[str, dict[str, Any]] = {}
            batch_inserted = 0
            batch_updated = 0

            try:
                client = _get_client()
                table = client.table(_TABLE_IOCS)
                existing_resp = table.select("ioc_id,confidence,tags,description,extra,expiry").in_("ioc_id", ioc_ids).execute()
                if existing_resp and existing_resp.data:
                    rows = existing_resp.data
                    if isinstance(rows, dict):
                        existing_map[rows["ioc_id"]] = rows
                    else:
                        for row in rows:
                            existing_map[row["ioc_id"]] = row

                rows_to_insert: list[dict[str, Any]] = []
                rows_to_update: list[tuple[str, dict[str, Any]]] = []

                for record in batch:
                    if record.ioc_id in existing_map:
                        if overwrite:
                            rows_to_update.append((record.ioc_id, _record_to_row(record)))
                        else:
                            rows_to_update.append((record.ioc_id, _merge_record_update(existing_map[record.ioc_id], record)))
                        updated += 1
                        batch_updated += 1
                    else:
                        rows_to_insert.append(_record_to_row(record))
                        inserted += 1
                        batch_inserted += 1

                if rows_to_insert:
                    table.insert(rows_to_insert).execute()

                for ioc_id, update_payload in rows_to_update:
                    try:
                        table.update(update_payload).eq("ioc_id", ioc_id).execute()
                    except Exception as exc:
                        logger.error("ioc_store.bulk_upsert.update_error ioc_id=%s: %s", ioc_id, exc)
                        updated -= 1
                        skipped += 1

            except Exception as exc:
                logger.error("ioc_store.bulk_upsert.batch_error batch_start=%d: %s", batch_start, exc)
                inserted -= batch_inserted
                updated -= batch_updated
                skipped += len(batch)

        logger.info(
            "ioc_store.bulk_upsert.done inserted=%d updated=%d skipped=%d",
            inserted,
            updated,
            skipped,
        )
        return inserted, updated, skipped

    def get_ioc(self, ioc_id: str) -> IOCRecord | None:
        try:
            client = _get_client()
        except Exception:
            logger.warning("ioc_store.get_ioc: Supabase not configured — skipping")
            return None
        try:
            table = client.table(_TABLE_IOCS)
            resp = table.select("*").eq("ioc_id", ioc_id).maybe_single().execute()
            if resp and resp.data:
                return _row_to_record(resp.data)
            return None
        except Exception as exc:
            logger.error("ioc_store.get_ioc.error ioc_id=%s: %s", ioc_id, exc)
            return None

    def lookup_by_value(
        self,
        value: str,
        *,
        org_id: str | None = None,
        active_only: bool = True,
    ) -> list[IOCRecord]:
        try:
            client = _get_client()
        except Exception:
            logger.warning("ioc_store.lookup_by_value: Supabase not configured — skipping")
            return []
        ioc_type = _detect_ioc_type(value)
        normalized = _normalize_value(value, ioc_type)
        try:
            table = client.table(_TABLE_IOCS)
            q = table.select("*").eq("value", normalized)
            if active_only:
                q = q.eq("active", True)
            if org_id is not None:
                q = q.or_(f"org_id.eq.{org_id},org_id.is.null")
            resp = q.execute()
            if resp and resp.data:
                return [_row_to_record(r) for r in resp.data]
            return []
        except Exception as exc:
            logger.error("ioc_store.lookup_by_value.error value=%s: %s", normalized, exc)
            return []

    def lookup_by_cve(
        self,
        cve_id: str,
        *,
        org_id: str | None = None,
        active_only: bool = True,
    ) -> list[IOCRecord]:
        try:
            client = _get_client()
        except Exception:
            logger.warning("ioc_store.lookup_by_cve: Supabase not configured — skipping")
            return []
        normalized = cve_id.strip().upper()
        try:
            table = client.table(_TABLE_IOCS)
            q = table.select("*").eq("cve_id", normalized)
            if active_only:
                q = q.eq("active", True)
            if org_id is not None:
                q = q.or_(f"org_id.eq.{org_id},org_id.is.null")
            resp = q.execute()
            if resp and resp.data:
                return [_row_to_record(r) for r in resp.data]
            return []
        except Exception as exc:
            logger.error("ioc_store.lookup_by_cve.error cve_id=%s: %s", normalized, exc)
            return []

    def lookup_by_mitre_technique(
        self,
        technique_id: str,
        *,
        org_id: str | None = None,
        active_only: bool = True,
    ) -> list[IOCRecord]:
        try:
            client = _get_client()
        except Exception:
            logger.warning("ioc_store.lookup_by_mitre_technique: Supabase not configured — skipping")
            return []
        normalized = technique_id.strip().upper()
        try:
            table = client.table(_TABLE_IOCS)
            q = table.select("*").eq("mitre_technique_id", normalized)
            if active_only:
                q = q.eq("active", True)
            if org_id is not None:
                q = q.or_(f"org_id.eq.{org_id},org_id.is.null")
            resp = q.execute()
            if resp and resp.data:
                return [_row_to_record(r) for r in resp.data]
            return []
        except Exception as exc:
            logger.error("ioc_store.lookup_by_mitre_technique.error technique=%s: %s", normalized, exc)
            return []

    def lookup_by_values(
        self,
        values: list[str],
        *,
        org_id: str | None = None,
        active_only: bool = True,
    ) -> list[IOCRecord]:
        try:
            client = _get_client()
        except Exception:
            logger.warning("ioc_store.lookup_by_values: Supabase not configured — skipping")
            return []
        if not values:
            return []
        normalized_values: list[str] = []
        for v in values:
            ioc_type = _detect_ioc_type(v)
            normalized_values.append(_normalize_value(v, ioc_type))
        try:
            table = client.table(_TABLE_IOCS)
            q = table.select("*").in_("value", normalized_values)
            if active_only:
                q = q.eq("active", True)
            if org_id is not None:
                q = q.or_(f"org_id.eq.{org_id},org_id.is.null")
            resp = q.execute()
            if resp and resp.data:
                return [_row_to_record(r) for r in resp.data]
            return []
        except Exception as exc:
            logger.error("ioc_store.lookup_by_values.error count=%d: %s", len(values), exc)
            return []

    def filter_iocs(self, req: IOCFilterRequest) -> list[IOCRecord]:
        try:
            client = _get_client()
        except Exception:
            logger.warning("ioc_store.filter_iocs: Supabase not configured — skipping")
            return []
        try:
            table = client.table(_TABLE_IOCS)
            q = table.select("*")

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
        except Exception as exc:
            logger.error("ioc_store.filter_iocs.error: %s", exc)
            return []

    def deactivate_ioc(self, ioc_id: str) -> bool:
        try:
            client = _get_client()
        except Exception:
            logger.warning("ioc_store.deactivate_ioc: Supabase not configured — skipping")
            return False
        try:
            table = client.table(_TABLE_IOCS)
            resp = table.update({"active": False, "last_seen": _utcnow_iso()}).eq("ioc_id", ioc_id).execute()
            if resp and resp.data:
                logger.info("ioc_store.deactivate_ioc ioc_id=%s", ioc_id)
                return True
            return False
        except Exception as exc:
            logger.error("ioc_store.deactivate_ioc.error ioc_id=%s: %s", ioc_id, exc)
            return False

    def delete_ioc(self, ioc_id: str) -> bool:
        try:
            client = _get_client()
        except Exception:
            logger.warning("ioc_store.delete_ioc: Supabase not configured — skipping")
            return False
        try:
            table = client.table(_TABLE_IOCS)
            resp = table.delete().eq("ioc_id", ioc_id).execute()
            if resp and resp.data:
                logger.info("ioc_store.delete_ioc ioc_id=%s", ioc_id)
                return True
            return False
        except Exception as exc:
            logger.error("ioc_store.delete_ioc.error ioc_id=%s: %s", ioc_id, exc)
            return False

    def delete_by_ingest_id(self, feed_ingest_id: str) -> int:
        try:
            client = _get_client()
        except Exception:
            logger.warning("ioc_store.delete_by_ingest_id: Supabase not configured — skipping")
            return 0
        try:
            table = client.table(_TABLE_IOCS)
            resp = table.delete().eq("feed_ingest_id", feed_ingest_id).execute()
            count = len(resp.data) if resp and resp.data else 0
            logger.info("ioc_store.delete_by_ingest_id ingest_id=%s deleted=%d", feed_ingest_id, count)
            return count
        except Exception as exc:
            logger.error("ioc_store.delete_by_ingest_id.error ingest_id=%s: %s", feed_ingest_id, exc)
            return 0

    def prune_expired(self) -> int:
        try:
            client = _get_client()
        except Exception:
            logger.warning("ioc_store.prune_expired: Supabase not configured — skipping")
            return 0
        now_iso = _utcnow_iso()
        try:
            table = client.table(_TABLE_IOCS)
            resp = table.update({"active": False, "last_seen": now_iso}).eq("active", True).lt("expiry", now_iso).not_.is_("expiry", "null").execute()
            count = len(resp.data) if resp and resp.data else 0
            if count:
                logger.info("ioc_store.prune_expired deactivated=%d", count)
            return count
        except Exception as exc:
            logger.error("ioc_store.prune_expired.error: %s", exc)
            return 0

    def count_iocs(
        self,
        *,
        source: str | None = None,
        active: bool | None = None,
        org_id: str | None = None,
    ) -> int:
        try:
            client = _get_client()
        except Exception:
            logger.warning("ioc_store.count_iocs: Supabase not configured — skipping")
            return 0
        try:
            table = client.table(_TABLE_IOCS)
            q = table.select("ioc_id", count="exact")
            if source is not None:
                q = q.eq("source", source)
            if active is not None:
                q = q.eq("active", active)
            if org_id is not None:
                q = q.or_(f"org_id.eq.{org_id},org_id.is.null")
            resp = q.execute()
            return resp.count if resp and resp.count is not None else 0
        except Exception as exc:
            logger.error("ioc_store.count_iocs.error: %s", exc)
            return 0

    def persist_ingest_result(self, result: FeedIngestResult) -> bool:
        try:
            client = _get_client()
        except Exception:
            logger.warning("ioc_store.persist_ingest_result: Supabase not configured — skipping")
            return False
        try:
            table = client.table(_TABLE_INGEST_LOG)
            table.insert(_ingest_result_to_row(result)).execute()
            return True
        except Exception as exc:
            logger.error(
                "ioc_store.persist_ingest_result.error ingest_id=%s: %s",
                result.ingest_id,
                exc,
            )
            return False

    def get_ingest_result(self, ingest_id: str) -> dict[str, Any] | None:
        try:
            client = _get_client()
        except Exception:
            logger.warning("ioc_store.get_ingest_result: Supabase not configured — skipping")
            return None
        try:
            table = client.table(_TABLE_INGEST_LOG)
            resp = table.select("*").eq("ingest_id", ingest_id).maybe_single().execute()
            return resp.data if resp and resp.data else None
        except Exception as exc:
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
        except Exception:
            logger.warning("ioc_store.list_ingest_history: Supabase not configured — skipping")
            return []
        try:
            table = client.table(_TABLE_INGEST_LOG)
            q = table.select("*").order("started_at", desc=True)
            if source is not None:
                q = q.eq("source", source)
            if org_id is not None:
                q = q.or_(f"org_id.eq.{org_id},org_id.is.null")
            q = q.range(offset, offset + limit - 1)
            resp = q.execute()
            return resp.data if resp and resp.data else []
        except Exception as exc:
            logger.error("ioc_store.list_ingest_history.error: %s", exc)
            return []

    def delete_ingest_log(self, ingest_id: str) -> bool:
        try:
            client = _get_client()
        except Exception:
            logger.warning("ioc_store.delete_ingest_log: Supabase not configured — skipping")
            return False
        try:
            table = client.table(_TABLE_INGEST_LOG)
            table.delete().eq("ingest_id", ingest_id).execute()
            return True
        except Exception as exc:
            logger.error("ioc_store.delete_ingest_log.error ingest_id=%s: %s", ingest_id, exc)
            return False

    def health_check(self) -> dict[str, Any]:
        try:
            client = _get_client()
        except Exception:
            return {"status": "unconfigured", "detail": "Supabase credentials not set"}
        try:
            table = client.table(_TABLE_IOCS)
            resp = table.select("ioc_id", count="exact").limit(1).execute()
            return {
                "status": "ok",
                "ioc_count": resp.count if resp and resp.count is not None else 0,
            }
        except Exception as exc:
            return {"status": "error", "detail": str(exc)}


_IOC_STORE: IOCStore | None = None


def get_ioc_store() -> IOCStore:
    global _IOC_STORE  # noqa: PLW0603
    if _IOC_STORE is None:
        _IOC_STORE = IOCStore()
    return _IOC_STORE


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
