from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import logging
import threading
from typing import Any

from app.core.logging import get_logger

_logger: logging.Logger = get_logger("ironclaw.supabase_adapter")

_SUPABASE_TABLE_OBSERVATIONS = "ironclaw_agent_observations"
_SUPABASE_TABLE_BASELINES = "ironclaw_agent_baselines"
_SUPABASE_TABLE_DRIFT_REPORTS = "ironclaw_drift_reports"
_SUPABASE_TABLE_ALERTS = "ironclaw_alerts"
_SUPABASE_TABLE_AUDIT_LOGS = "ironclaw_audit_logs"

KNOWN_TABLES = frozenset(
    {
        _SUPABASE_TABLE_OBSERVATIONS,
        _SUPABASE_TABLE_BASELINES,
        _SUPABASE_TABLE_DRIFT_REPORTS,
        _SUPABASE_TABLE_ALERTS,
        _SUPABASE_TABLE_AUDIT_LOGS,
    }
)


@dataclass(slots=True)
class SupabaseResult:
    success: bool
    data: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    count: int = 0

    @property
    def first(self) -> dict[str, Any] | None:
        return self.data[0] if self.data else None


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


class SupabaseAdapter:
    """
    Thread-safe Supabase persistence adapter for IronClaw.

    Wraps the supabase-py client with a clean internal result shape,
    graceful degradation on unavailability, and structured logging.

    All write operations are best-effort: in-memory state is always
    the primary source of truth. A Supabase failure never raises
    into the calling service.
    """

    def __init__(
        self,
        supabase_url: str,
        supabase_key: str,
        *,
        timeout: float = 10.0,
    ) -> None:
        self._url = supabase_url.strip()
        self._key = supabase_key.strip()
        self._timeout = timeout
        self._client: Any = None
        self._lock = threading.Lock()
        self._available: bool = False
        self._init_error: str | None = None
        self._initialize()

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def _initialize(self) -> None:
        try:
            from supabase import Client, create_client  # type: ignore[import-untyped]

            client: Client = create_client(self._url, self._key)
            self._client = client
            self._available = True
            _logger.info(
                "supabase_adapter_initialized",
                extra={
                    "event": "supabase_adapter_initialized",
                    "supabase_url": self._url,
                },
            )
        except ImportError:
            self._available = False
            self._init_error = "supabase package not installed"
            _logger.warning(
                "supabase_unavailable",
                extra={
                    "event": "supabase_unavailable",
                    "reason": self._init_error,
                },
            )
        except Exception as exc:
            self._available = False
            self._init_error = str(exc)
            _logger.error(
                "supabase_init_failed",
                extra={
                    "event": "supabase_init_failed",
                    "error": self._init_error,
                },
                exc_info=True,
            )

    # ------------------------------------------------------------------
    # Public availability
    # ------------------------------------------------------------------

    @property
    def available(self) -> bool:
        return self._available

    def health(self) -> dict[str, Any]:
        return {
            "available": self._available,
            "supabase_url": self._url if self._available else None,
            "init_error": self._init_error,
            "checked_at": _utc_now(),
        }

    # ------------------------------------------------------------------
    # Core CRUD operations
    # ------------------------------------------------------------------

    def insert(
        self,
        table: str,
        record: dict[str, Any],
        *,
        client_id: str | None = None,
    ) -> SupabaseResult:
        if not self._available:
            return SupabaseResult(success=False, error=self._init_error or "adapter_unavailable")
        payload = dict(record)
        if client_id is not None:
            payload.setdefault("client_id", client_id)
        return self._execute("insert", table, payload=payload)

    def upsert(
        self,
        table: str,
        record: dict[str, Any],
        *,
        on_conflict: str = "id",
        client_id: str | None = None,
    ) -> SupabaseResult:
        if not self._available:
            return SupabaseResult(success=False, error=self._init_error or "adapter_unavailable")
        payload = dict(record)
        if client_id is not None:
            payload.setdefault("client_id", client_id)
        return self._execute("upsert", table, payload=payload, on_conflict=on_conflict)

    def select(
        self,
        table: str,
        *,
        filters: dict[str, Any] | None = None,
        columns: str = "*",
        limit: int | None = None,
        order_by: str | None = None,
        order_desc: bool = False,
        client_id: str | None = None,
    ) -> SupabaseResult:
        if not self._available:
            return SupabaseResult(success=False, error=self._init_error or "adapter_unavailable")
        return self._execute(
            "select",
            table,
            filters=filters,
            columns=columns,
            limit=limit,
            order_by=order_by,
            order_desc=order_desc,
            client_id=client_id,
        )

    def update(
        self,
        table: str,
        record: dict[str, Any],
        *,
        filters: dict[str, Any],
        client_id: str | None = None,
    ) -> SupabaseResult:
        if not self._available:
            return SupabaseResult(success=False, error=self._init_error or "adapter_unavailable")
        payload = dict(record)
        if client_id is not None:
            payload.setdefault("client_id", client_id)
        return self._execute("update", table, payload=payload, filters=filters, client_id=client_id)

    def delete(
        self,
        table: str,
        *,
        filters: dict[str, Any],
        client_id: str | None = None,
    ) -> SupabaseResult:
        if not self._available:
            return SupabaseResult(success=False, error=self._init_error or "adapter_unavailable")
        return self._execute("delete", table, filters=filters, client_id=client_id)

    # ------------------------------------------------------------------
    # IronClaw domain operations
    # ------------------------------------------------------------------

    def persist_observation(self, record: dict[str, Any]) -> SupabaseResult:
        return self.upsert(
            _SUPABASE_TABLE_OBSERVATIONS,
            record,
            on_conflict="observation_id",
            client_id=record.get("client_id"),
        )

    def persist_baseline(self, record: dict[str, Any]) -> SupabaseResult:
        return self.upsert(
            _SUPABASE_TABLE_BASELINES,
            record,
            on_conflict="agent_id",
            client_id=record.get("client_id"),
        )

    def persist_drift_report(self, record: dict[str, Any]) -> SupabaseResult:
        return self.upsert(
            _SUPABASE_TABLE_DRIFT_REPORTS,
            record,
            on_conflict="report_id",
            client_id=record.get("client_id"),
        )

    def persist_alert(self, record: dict[str, Any]) -> SupabaseResult:
        return self.upsert(
            _SUPABASE_TABLE_ALERTS,
            record,
            on_conflict="alert_id",
            client_id=record.get("client_id"),
        )

    def persist_audit_log(self, record: dict[str, Any]) -> SupabaseResult:
        return self.insert(
            _SUPABASE_TABLE_AUDIT_LOGS,
            record,
            client_id=record.get("client_id"),
        )

    def fetch_baselines(
        self,
        *,
        client_id: str | None = None,
        status: str | None = None,
        limit: int | None = None,
    ) -> SupabaseResult:
        filters: dict[str, Any] = {}
        if status is not None:
            filters["status"] = status
        return self.select(
            _SUPABASE_TABLE_BASELINES,
            filters=filters,
            limit=limit,
            order_by="updated_at",
            order_desc=True,
            client_id=client_id,
        )

    def fetch_observations(
        self,
        agent_id: str,
        *,
        client_id: str | None = None,
        session_id: str | None = None,
        limit: int | None = None,
    ) -> SupabaseResult:
        filters: dict[str, Any] = {"agent_id": agent_id}
        if session_id is not None:
            filters["session_id"] = session_id
        return self.select(
            _SUPABASE_TABLE_OBSERVATIONS,
            filters=filters,
            limit=limit,
            order_by="timestamp",
            order_desc=True,
            client_id=client_id,
        )

    def fetch_alerts(
        self,
        *,
        client_id: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        limit: int | None = None,
    ) -> SupabaseResult:
        filters: dict[str, Any] = {}
        if status is not None:
            filters["status"] = status
        if severity is not None:
            filters["severity"] = severity
        return self.select(
            _SUPABASE_TABLE_ALERTS,
            filters=filters,
            limit=limit,
            order_by="created_at",
            order_desc=True,
            client_id=client_id,
        )

    def fetch_audit_logs(
        self,
        *,
        client_id: str | None = None,
        agent_id: str | None = None,
        limit: int | None = None,
    ) -> SupabaseResult:
        filters: dict[str, Any] = {}
        if agent_id is not None:
            filters["agent_id"] = agent_id
        return self.select(
            _SUPABASE_TABLE_AUDIT_LOGS,
            filters=filters,
            limit=limit,
            order_by="created_at",
            order_desc=True,
            client_id=client_id,
        )

    def delete_agent_data(self, agent_id: str, *, client_id: str | None = None) -> bool:
        filters: dict[str, Any] = {"agent_id": agent_id}
        r1 = self.delete(_SUPABASE_TABLE_OBSERVATIONS, filters=filters, client_id=client_id)
        r2 = self.delete(_SUPABASE_TABLE_BASELINES, filters={"agent_id": agent_id}, client_id=client_id)
        if not r1.success or not r2.success:
            _logger.warning(
                "supabase_delete_agent_partial_failure",
                extra={
                    "event": "supabase_delete_agent_partial_failure",
                    "agent_id": agent_id,
                    "observations_ok": r1.success,
                    "baselines_ok": r2.success,
                },
            )
        return r1.success and r2.success

    # ------------------------------------------------------------------
    # Internal execution engine
    # ------------------------------------------------------------------

    def _execute(
        self,
        operation: str,
        table: str,
        *,
        payload: dict[str, Any] | None = None,
        filters: dict[str, Any] | None = None,
        columns: str = "*",
        limit: int | None = None,
        order_by: str | None = None,
        order_desc: bool = False,
        on_conflict: str | None = None,
        client_id: str | None = None,
    ) -> SupabaseResult:
        with self._lock:
            try:
                q = self._client.table(table)

                if operation == "insert":
                    q = q.insert(payload)
                elif operation == "upsert":
                    if on_conflict:
                        q = q.upsert(payload, on_conflict=on_conflict)
                    else:
                        q = q.upsert(payload)
                elif operation == "select":
                    q = q.select(columns)
                    if client_id is not None:
                        q = q.eq("client_id", client_id)
                    if filters:
                        for key, value in filters.items():
                            q = q.eq(key, value)
                    if order_by:
                        q = q.order(order_by, desc=order_desc)
                    if limit is not None:
                        q = q.limit(limit)
                elif operation == "update":
                    q = q.update(payload)
                    if client_id is not None:
                        q = q.eq("client_id", client_id)
                    if filters:
                        for key, value in filters.items():
                            q = q.eq(key, value)
                elif operation == "delete":
                    q = q.delete()
                    if client_id is not None:
                        q = q.eq("client_id", client_id)
                    if filters:
                        for key, value in filters.items():
                            q = q.eq(key, value)
                else:
                    return SupabaseResult(success=False, error=f"unknown_operation:{operation}")

                response = q.execute()
                data: list[dict[str, Any]] = response.data if response.data else []
                return SupabaseResult(success=True, data=data, count=len(data))

            except Exception as exc:
                error_msg = str(exc)
                _logger.error(
                    "supabase_operation_failed",
                    extra={
                        "event": "supabase_operation_failed",
                        "operation": operation,
                        "table": table,
                        "error": error_msg,
                    },
                    exc_info=True,
                )
                return SupabaseResult(success=False, error=error_msg)


# ---------------------------------------------------------------------------
# Module-level singleton — lazy, thread-safe
# ---------------------------------------------------------------------------

_adapter_instance: SupabaseAdapter | None = None
_adapter_lock = threading.Lock()


def get_supabase_adapter() -> SupabaseAdapter | None:
    """
    Return the module-level SupabaseAdapter singleton, or None if
    SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY are not configured.

    Importing services should call this and check .available before
    any persistence operation.
    """
    global _adapter_instance
    if _adapter_instance is not None:
        return _adapter_instance
    with _adapter_lock:
        if _adapter_instance is not None:
            return _adapter_instance
        try:
            from app.core.settings import get_settings

            settings = get_settings()
            url: str | None = getattr(settings, "supabase_url", None)
            key: str | None = getattr(settings, "supabase_service_role_key", None)
        except Exception:
            url = None
            key = None

        import os

        url = url or os.getenv("SUPABASE_URL", "").strip() or None
        key = key or os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip() or None

        if not url or not key:
            _logger.info(
                "supabase_adapter_not_configured",
                extra={
                    "event": "supabase_adapter_not_configured",
                    "reason": "SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY not set",
                },
            )
            return None

        _adapter_instance = SupabaseAdapter(url, key)
        return _adapter_instance


def reset_supabase_adapter() -> None:
    """Reset the singleton — intended for testing only."""
    global _adapter_instance
    with _adapter_lock:
        _adapter_instance = None
