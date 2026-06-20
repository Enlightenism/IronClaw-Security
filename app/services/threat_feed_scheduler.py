from __future__ import annotations

from dataclasses import dataclass, field
import logging
import threading
import time
from typing import Any
from uuid import uuid4

from app.schemas.threat_detection import (
    IngestStatusEnum,
    ThreatFeedSourceEnum,
)
from app.services.threat_feed_ingestion import (
    _INGEST_ID_PREFIX,
    FeedIngestResult,
    _utcnow_iso,
    run_feed_ingestion,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_MITRE_INTERVAL_SECONDS: int = 86_400  # 24 h
_DEFAULT_CISA_KEV_INTERVAL_SECONDS: int = 43_200  # 12 h
_DEFAULT_PRUNE_INTERVAL_SECONDS: int = 3_600  # 1 h
_DEFAULT_JITTER_SECONDS: int = 120  # ±2 min jitter
_SCHEDULER_THREAD_NAME: str = "ironclaw-feed-scheduler"
_PRUNE_THREAD_NAME: str = "ironclaw-feed-pruner"
_MAX_RUN_HISTORY: int = 100
_SCHEDULER_TICK_SECONDS: float = 10.0


# ---------------------------------------------------------------------------
# Schedule entry
# ---------------------------------------------------------------------------


@dataclass
class FeedScheduleEntry:
    source: ThreatFeedSourceEnum
    interval_seconds: int
    enabled: bool = True
    org_id: str | None = None
    custom_url: str | None = None
    last_run_at: str | None = None
    last_ingest_id: str | None = None
    last_status: str | None = None
    consecutive_failures: int = 0
    _next_run_epoch: float = field(default=0.0, repr=False)

    def schedule_next(self, *, jitter_seconds: int = _DEFAULT_JITTER_SECONDS) -> None:
        import random

        jitter = random.uniform(-jitter_seconds, jitter_seconds)
        self._next_run_epoch = time.monotonic() + self.interval_seconds + jitter

    def schedule_immediate(self) -> None:
        self._next_run_epoch = 0.0

    def is_due(self) -> bool:
        return time.monotonic() >= self._next_run_epoch


# ---------------------------------------------------------------------------
# Scheduler run record
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SchedulerRunRecord:
    run_id: str
    source: str
    triggered_by: str
    started_at: str
    completed_at: str | None
    status: str
    ingest_id: str | None
    iocs_inserted: int
    iocs_updated: int
    iocs_skipped: int
    errors: list[str]
    org_id: str | None
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "source": self.source,
            "triggered_by": self.triggered_by,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "status": self.status,
            "ingest_id": self.ingest_id,
            "iocs_inserted": self.iocs_inserted,
            "iocs_updated": self.iocs_updated,
            "iocs_skipped": self.iocs_skipped,
            "errors": list(self.errors),
            "org_id": self.org_id,
            "metadata": dict(self.metadata),
        }


# ---------------------------------------------------------------------------
# Scheduler status snapshot
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SchedulerStatus:
    running: bool
    schedule_entries: list[dict[str, Any]]
    recent_runs: list[dict[str, Any]]
    total_runs: int
    total_failures: int
    prune_enabled: bool
    prune_interval_seconds: int
    started_at: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "schedule_entries": self.schedule_entries,
            "recent_runs": self.recent_runs,
            "total_runs": self.total_runs,
            "total_failures": self.total_failures,
            "prune_enabled": self.prune_enabled,
            "prune_interval_seconds": self.prune_interval_seconds,
            "started_at": self.started_at,
        }


# ---------------------------------------------------------------------------
# ThreatFeedScheduler
# ---------------------------------------------------------------------------


class ThreatFeedScheduler:
    """
    Background refresh scheduler for IronClaw threat feed ingestion.

    Responsibilities:
    - Periodically trigger ingest_mitre_attack and ingest_cisa_kev via
      run_feed_ingestion — the single authoritative dispatch adapter.
    - Persist each SchedulerRunRecord to the feed_ingest_log table via
      IOCStore.persist_ingest_result so every background run is auditable.
    - Periodically trigger IOCStore.prune_expired to evict TTL-expired IOCs.
    - Expose start/stop/status/force_run APIs consumed by the router layer.
    - Track consecutive failures per source for backoff and alerting.
    - Apply per-run jitter to avoid thundering-herd against upstream feeds.

    Thread model:
    - One daemon scheduler thread runs the main tick loop.
    - One daemon prune thread handles TTL eviction independently.
    - All shared state is guarded by a single re-entrant lock.

    Does NOT duplicate any ingestion logic — all feed fetching and parsing
    is owned exclusively by ThreatFeedIngestionService / run_feed_ingestion.
    """

    def __init__(
        self,
        *,
        mitre_interval_seconds: int = _DEFAULT_MITRE_INTERVAL_SECONDS,
        cisa_kev_interval_seconds: int = _DEFAULT_CISA_KEV_INTERVAL_SECONDS,
        prune_interval_seconds: int = _DEFAULT_PRUNE_INTERVAL_SECONDS,
        jitter_seconds: int = _DEFAULT_JITTER_SECONDS,
        prune_enabled: bool = True,
        tick_seconds: float = _SCHEDULER_TICK_SECONDS,
    ) -> None:
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._scheduler_thread: threading.Thread | None = None
        self._prune_thread: threading.Thread | None = None
        self._started_at: str | None = None
        self._jitter_seconds = jitter_seconds
        self._tick_seconds = tick_seconds
        self._prune_enabled = prune_enabled
        self._prune_interval_seconds = prune_interval_seconds
        self._run_history: list[SchedulerRunRecord] = []
        self._total_runs: int = 0
        self._total_failures: int = 0
        self._next_prune_epoch: float = time.monotonic() + prune_interval_seconds

        self._entries: dict[ThreatFeedSourceEnum, FeedScheduleEntry] = {
            ThreatFeedSourceEnum.MITRE_ATTACK: FeedScheduleEntry(
                source=ThreatFeedSourceEnum.MITRE_ATTACK,
                interval_seconds=mitre_interval_seconds,
                enabled=True,
            ),
            ThreatFeedSourceEnum.CISA_KEV: FeedScheduleEntry(
                source=ThreatFeedSourceEnum.CISA_KEV,
                interval_seconds=cisa_kev_interval_seconds,
                enabled=True,
            ),
        }
        # Schedule first runs as immediate so startup populates data quickly
        for entry in self._entries.values():
            entry.schedule_immediate()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        with self._lock:
            if self._scheduler_thread is not None and self._scheduler_thread.is_alive():
                logger.warning("threat_feed_scheduler.start: already running")
                return

            self._stop_event.clear()
            self._started_at = _utcnow_iso()

            self._scheduler_thread = threading.Thread(
                target=self._scheduler_loop,
                name=_SCHEDULER_THREAD_NAME,
                daemon=True,
            )
            self._scheduler_thread.start()

            if self._prune_enabled:
                self._prune_thread = threading.Thread(
                    target=self._prune_loop,
                    name=_PRUNE_THREAD_NAME,
                    daemon=True,
                )
                self._prune_thread.start()

        logger.info(
            "threat_feed_scheduler.started mitre_interval=%ds cisa_kev_interval=%ds prune=%s",
            self._entries[ThreatFeedSourceEnum.MITRE_ATTACK].interval_seconds,
            self._entries[ThreatFeedSourceEnum.CISA_KEV].interval_seconds,
            self._prune_enabled,
        )

    def stop(self, *, timeout_seconds: float = 15.0) -> None:
        self._stop_event.set()
        with self._lock:
            scheduler = self._scheduler_thread
            pruner = self._prune_thread

        if scheduler is not None:
            scheduler.join(timeout=timeout_seconds)
        if pruner is not None:
            pruner.join(timeout=timeout_seconds)

        with self._lock:
            self._scheduler_thread = None
            self._prune_thread = None
            self._started_at = None

        logger.info("threat_feed_scheduler.stopped")

    @property
    def is_running(self) -> bool:
        with self._lock:
            t = self._scheduler_thread
        return t is not None and t.is_alive()

    # ------------------------------------------------------------------
    # Scheduler loop
    # ------------------------------------------------------------------

    def _scheduler_loop(self) -> None:
        logger.debug("threat_feed_scheduler._scheduler_loop: entering")
        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception as exc:  # noqa: BLE001
                logger.error("threat_feed_scheduler._scheduler_loop.unhandled: %s", exc)
            self._stop_event.wait(timeout=self._tick_seconds)
        logger.debug("threat_feed_scheduler._scheduler_loop: exiting")

    def _tick(self) -> None:
        with self._lock:
            due_entries = [entry for entry in self._entries.values() if entry.enabled and entry.is_due()]

        for entry in due_entries:
            self._run_entry(entry, triggered_by="scheduler")

    # ------------------------------------------------------------------
    # Prune loop
    # ------------------------------------------------------------------

    def _prune_loop(self) -> None:
        logger.debug("threat_feed_scheduler._prune_loop: entering")
        while not self._stop_event.is_set():
            try:
                if time.monotonic() >= self._next_prune_epoch:
                    self._run_prune()
                    self._next_prune_epoch = time.monotonic() + self._prune_interval_seconds
            except Exception as exc:  # noqa: BLE001
                logger.error("threat_feed_scheduler._prune_loop.unhandled: %s", exc)
            self._stop_event.wait(timeout=self._tick_seconds)
        logger.debug("threat_feed_scheduler._prune_loop: exiting")

    def _run_prune(self) -> None:
        try:
            from app.services.ioc_store import get_ioc_store  # noqa: PLC0415

            pruned = get_ioc_store().prune_expired()
            logger.info("threat_feed_scheduler.prune.done pruned=%d", pruned)
        except Exception as exc:  # noqa: BLE001
            logger.error("threat_feed_scheduler.prune.error: %s", exc)

    # ------------------------------------------------------------------
    # Core run
    # ------------------------------------------------------------------

    def _run_entry(
        self,
        entry: FeedScheduleEntry,
        *,
        triggered_by: str,
    ) -> SchedulerRunRecord:
        run_id = f"sched-{uuid4().hex[:16]}"
        started_at = _utcnow_iso()

        logger.info(
            "threat_feed_scheduler.run source=%s run_id=%s triggered_by=%s",
            entry.source,
            run_id,
            triggered_by,
        )

        ingest_result: FeedIngestResult | None = None
        status = IngestStatusEnum.FAILED
        errors: list[str] = []

        try:
            ingest_result = run_feed_ingestion(
                source=entry.source,
                org_id=entry.org_id,
                force=True,
                custom_url=entry.custom_url,
                taxii_config=None,
            )
            status = ingest_result.status
            errors = list(ingest_result.errors)
        except Exception as exc:  # noqa: BLE001
            error_msg = f"scheduler_run_error source={entry.source}: {exc}"
            errors = [error_msg]
            logger.error("threat_feed_scheduler._run_entry.error run_id=%s: %s", run_id, exc)

        completed_at = _utcnow_iso()
        is_failure = status == IngestStatusEnum.FAILED

        record = SchedulerRunRecord(
            run_id=run_id,
            source=str(entry.source.value if hasattr(entry.source, "value") else entry.source),
            triggered_by=triggered_by,
            started_at=started_at,
            completed_at=completed_at,
            status=status,
            ingest_id=ingest_result.ingest_id if ingest_result else None,
            iocs_inserted=ingest_result.iocs_inserted if ingest_result else 0,
            iocs_updated=ingest_result.iocs_updated if ingest_result else 0,
            iocs_skipped=ingest_result.iocs_skipped if ingest_result else 0,
            errors=errors[:20],
            org_id=entry.org_id,
            metadata={
                "triggered_by": triggered_by,
                "interval_seconds": entry.interval_seconds,
                "consecutive_failures_before": entry.consecutive_failures,
            },
        )

        with self._lock:
            entry.last_run_at = completed_at
            entry.last_status = status
            entry.last_ingest_id = ingest_result.ingest_id if ingest_result else None
            entry.consecutive_failures = entry.consecutive_failures + 1 if is_failure else 0
            entry.schedule_next(jitter_seconds=self._jitter_seconds)

            self._run_history.append(record)
            if len(self._run_history) > _MAX_RUN_HISTORY:
                self._run_history = self._run_history[-_MAX_RUN_HISTORY:]
            self._total_runs += 1
            if is_failure:
                self._total_failures += 1

        self._persist_run_record(record, ingest_result)

        if entry.consecutive_failures > 0:
            logger.warning(
                "threat_feed_scheduler.consecutive_failures source=%s count=%d",
                entry.source,
                entry.consecutive_failures,
            )

        logger.info(
            "threat_feed_scheduler.run.done run_id=%s source=%s status=%s inserted=%d updated=%d errors=%d",
            run_id,
            entry.source,
            status,
            record.iocs_inserted,
            record.iocs_updated,
            len(errors),
        )

        return record

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _persist_run_record(
        self,
        record: SchedulerRunRecord,
        ingest_result: FeedIngestResult | None,
    ) -> None:
        """
        Persist the scheduler run to feed_ingest_log via IOCStore.
        Uses the FeedIngestResult from run_feed_ingestion when available —
        IOCStore.persist_ingest_result is the single write path to that table.
        When no FeedIngestResult is available (exception path), constructs a
        minimal FAILED FeedIngestResult so the table always has a record.
        """
        try:
            from app.services.ioc_store import get_ioc_store  # noqa: PLC0415

            if ingest_result is not None:
                get_ioc_store().persist_ingest_result(ingest_result)
            else:
                synthetic = FeedIngestResult(
                    ingest_id=f"{_INGEST_ID_PREFIX}{uuid4().hex[:20]}",
                    source=record.source,
                    status=IngestStatusEnum.FAILED,
                    iocs_parsed=0,
                    iocs_inserted=0,
                    iocs_updated=0,
                    iocs_skipped=0,
                    errors=record.errors[:20],
                    started_at=record.started_at,
                    completed_at=record.completed_at,
                    org_id=record.org_id,
                    metadata={
                        "run_id": record.run_id,
                        "triggered_by": record.triggered_by,
                        "scheduler_synthetic": True,
                    },
                )
                get_ioc_store().persist_ingest_result(synthetic)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "threat_feed_scheduler._persist_run_record.error run_id=%s: %s",
                record.run_id,
                exc,
            )

    # ------------------------------------------------------------------
    # Public control API
    # ------------------------------------------------------------------

    def force_run(
        self,
        source: ThreatFeedSourceEnum,
        *,
        org_id: str | None = None,
    ) -> SchedulerRunRecord:
        """
        Trigger an immediate out-of-band ingest for the given source.
        Does not reset the regular schedule interval.
        """
        with self._lock:
            entry = self._entries.get(source)

        if entry is None:
            now = _utcnow_iso()
            return SchedulerRunRecord(
                run_id=f"sched-{uuid4().hex[:16]}",
                source=str(source.value if hasattr(source, "value") else source),
                triggered_by="force",
                started_at=now,
                completed_at=now,
                status=IngestStatusEnum.FAILED,
                ingest_id=None,
                iocs_inserted=0,
                iocs_updated=0,
                iocs_skipped=0,
                errors=[f"source not registered in scheduler: {source}"],
                org_id=org_id,
                metadata={},
            )

        scoped_entry = FeedScheduleEntry(
            source=entry.source,
            interval_seconds=entry.interval_seconds,
            enabled=True,
            org_id=org_id if org_id is not None else entry.org_id,
            custom_url=entry.custom_url,
        )
        scoped_entry.schedule_immediate()
        return self._run_entry(scoped_entry, triggered_by="force")

    def set_interval(
        self,
        source: ThreatFeedSourceEnum,
        interval_seconds: int,
    ) -> bool:
        if interval_seconds < 60:
            logger.warning(
                "threat_feed_scheduler.set_interval: interval %ds < 60s minimum for source=%s",
                interval_seconds,
                source,
            )
            return False
        with self._lock:
            entry = self._entries.get(source)
            if entry is None:
                return False
            entry.interval_seconds = interval_seconds
        logger.info(
            "threat_feed_scheduler.set_interval source=%s interval=%ds",
            source,
            interval_seconds,
        )
        return True

    def set_enabled(
        self,
        source: ThreatFeedSourceEnum,
        enabled: bool,
    ) -> bool:
        with self._lock:
            entry = self._entries.get(source)
            if entry is None:
                return False
            entry.enabled = enabled
        logger.info(
            "threat_feed_scheduler.set_enabled source=%s enabled=%s",
            source,
            enabled,
        )
        return True

    def get_status(self) -> SchedulerStatus:
        with self._lock:
            entries_snapshot = [
                {
                    "source": str(e.source.value if hasattr(e.source, "value") else e.source),
                    "interval_seconds": e.interval_seconds,
                    "enabled": e.enabled,
                    "org_id": e.org_id,
                    "last_run_at": e.last_run_at,
                    "last_ingest_id": e.last_ingest_id,
                    "last_status": e.last_status,
                    "consecutive_failures": e.consecutive_failures,
                    "next_run_in_seconds": max(
                        0.0,
                        round(e._next_run_epoch - time.monotonic(), 1),
                    ),
                }
                for e in self._entries.values()
            ]
            recent = [r.to_dict() for r in self._run_history[-20:]]
            total_runs = self._total_runs
            total_failures = self._total_failures
            started_at = self._started_at

        return SchedulerStatus(
            running=self.is_running,
            schedule_entries=entries_snapshot,
            recent_runs=recent,
            total_runs=total_runs,
            total_failures=total_failures,
            prune_enabled=self._prune_enabled,
            prune_interval_seconds=self._prune_interval_seconds,
            started_at=started_at,
        )

    def get_run_history(
        self,
        *,
        source: str | None = None,
        limit: int = 50,
    ) -> list[SchedulerRunRecord]:
        with self._lock:
            items = list(self._run_history)
        if source is not None:
            items = [r for r in items if r.source == source]
        return items[-limit:]


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_SCHEDULER: ThreatFeedScheduler | None = None
_SCHEDULER_LOCK = threading.Lock()


def get_threat_feed_scheduler() -> ThreatFeedScheduler:
    """Return the module-level ThreatFeedScheduler singleton (lazy init)."""
    global _SCHEDULER
    if _SCHEDULER is None:
        with _SCHEDULER_LOCK:
            if _SCHEDULER is None:
                _SCHEDULER = ThreatFeedScheduler()
    return _SCHEDULER


def start_scheduler() -> None:
    """Start the background scheduler. Safe to call multiple times."""
    get_threat_feed_scheduler().start()


def stop_scheduler(*, timeout_seconds: float = 15.0) -> None:
    """Stop the background scheduler. Safe to call if not running."""
    get_threat_feed_scheduler().stop(timeout_seconds=timeout_seconds)


def force_feed_run(
    source: ThreatFeedSourceEnum,
    *,
    org_id: str | None = None,
) -> SchedulerRunRecord:
    """Trigger an immediate out-of-band ingest. Callable from routers."""
    return get_threat_feed_scheduler().force_run(source, org_id=org_id)


__all__ = [
    "FeedScheduleEntry",
    "SchedulerRunRecord",
    "SchedulerStatus",
    "ThreatFeedScheduler",
    "force_feed_run",
    "get_threat_feed_scheduler",
    "start_scheduler",
    "stop_scheduler",
]
