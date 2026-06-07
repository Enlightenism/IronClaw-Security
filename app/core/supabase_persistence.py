from __future__ import annotations

from datetime import UTC, datetime
import logging
from typing import Any

from app.core.logging import get_logger
from app.core.supabase import get_supabase_service_client
from app.supabaseclient import SupabaseAPIError, SupabaseClientError

_logger: logging.Logger = get_logger("ironclaw.persistence")


# ---------------------------------------------------------------------------
# Single source of truth for persistence table names used by this adapter.
# Never hardcode table strings outside this module.
# ---------------------------------------------------------------------------
_T_SCAN_HISTORY = "scan_history"
_T_AUDIT_EVENTS = "audit_events"
_T_TELEMETRY = "telemetry_events"
_T_QUARANTINE = "quarantine_items"
_T_REVIEW_QUEUE = "review_queue"
_T_IOCS = "iocs"
_T_THREAT_DETECTIONS = "threat_detections"
_T_POLICY_SETS = "policy_sets"
_T_POLICY_RULES = "policy_rules"
_T_POLICY_SET_MEMBERSHIPS = "policy_set_memberships"
_T_TOOL_CALL_LOG = "tool_call_log"
_T_SANDBOX_EXECUTION_LOG = "sandbox_execution_log"
_T_AGENT_TRUST_PROFILES = "agent_trust_profiles"
_T_TRUST_EVENTS = "trust_events"


# ---------------------------------------------------------------------------
# PersistenceError — the only error type this module raises to callers.
# All SupabaseAPIError / SupabaseClientError are caught here and re-raised
# as PersistenceError. No caller outside this module should import or catch
# Supabase-specific exceptions directly.
# ---------------------------------------------------------------------------


class PersistenceError(RuntimeError):
    """Raised when any Supabase persistence operation fails."""

    def __init__(self, operation: str, message: str, *, cause: BaseException | None = None) -> None:
        super().__init__(f"[{operation}] {message}")
        self.operation = operation
        self.cause = cause


def _now_utc() -> str:
    return datetime.now(UTC).isoformat()


def _wrap(operation: str, exc: BaseException) -> PersistenceError:
    _logger.error(
        "persistence_error",
        extra={"operation": operation, "error": str(exc)},
        exc_info=exc,
    )
    return PersistenceError(operation, str(exc), cause=exc)


# ---------------------------------------------------------------------------
# Scan History
# ---------------------------------------------------------------------------


def upsert_scan(record: dict[str, Any]) -> dict[str, Any]:
    """Upsert a scan record into scan_history.

    ``record`` must include ``scan_id`` (used as the conflict key).
    Returns the upserted row.
    """
    operation = "upsert_scan"
    try:
        client = get_supabase_service_client()
        resp = client.table(_T_SCAN_HISTORY).upsert(record, on_conflict="scan_id", returning="representation").execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else record
        if isinstance(data, dict):
            return data
        return record
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


def get_scan_by_id(scan_id: str) -> dict[str, Any] | None:
    """Return the scan_history row for ``scan_id``, or None if not found."""
    operation = "get_scan_by_id"
    try:
        client = get_supabase_service_client()
        resp = client.table(_T_SCAN_HISTORY).select("*").eq("scan_id", scan_id).maybe_single().execute()
        data = resp.data
        if isinstance(data, dict):
            return data
        if isinstance(data, list):
            return data[0] if data else None
        return None
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


def list_scans(
    *,
    agent_id: str | None = None,
    verdict: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Return scan_history rows ordered by created_at desc.

    Optionally filtered by ``agent_id`` and/or ``verdict``.
    """
    operation = "list_scans"
    try:
        client = get_supabase_service_client()
        q = client.table(_T_SCAN_HISTORY).select("*")
        if agent_id:
            q = q.eq("agent_id", agent_id)
        if verdict:
            q = q.eq("verdict", verdict)
        q = q.order("created_at", desc=True).range(offset, offset + limit - 1)
        resp = q.execute()
        data = resp.data
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Audit Events
# ---------------------------------------------------------------------------


def upsert_audit_event(record: dict[str, Any]) -> dict[str, Any]:
    """Insert or upsert an audit_event row.

    ``record`` should include ``event_id`` for idempotent upserts.
    If ``event_id`` is absent, a plain insert is performed.
    """
    operation = "upsert_audit_event"
    try:
        client = get_supabase_service_client()
        if "created_at" not in record:
            record = {**record, "created_at": _now_utc()}
        if "event_id" in record:
            resp = client.table(_T_AUDIT_EVENTS).upsert(record, on_conflict="event_id", returning="representation").execute()
        else:
            resp = client.table(_T_AUDIT_EVENTS).insert(record, returning="representation").execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else record
        if isinstance(data, dict):
            return data
        return record
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------


def upsert_telemetry(record: dict[str, Any]) -> dict[str, Any]:
    """Upsert a telemetry_events row.

    ``record`` must include ``telemetry_id`` as the conflict key.
    """
    operation = "upsert_telemetry"
    try:
        client = get_supabase_service_client()
        if "recorded_at" not in record:
            record = {**record, "recorded_at": _now_utc()}
        resp = client.table(_T_TELEMETRY).upsert(record, on_conflict="telemetry_id", returning="representation").execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else record
        if isinstance(data, dict):
            return data
        return record
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Quarantine
# ---------------------------------------------------------------------------


def upsert_quarantine_item(record: dict[str, Any]) -> dict[str, Any]:
    """Upsert a quarantine_items row.

    ``record`` must include ``quarantine_id`` as the conflict key.
    """
    operation = "upsert_quarantine_item"
    try:
        client = get_supabase_service_client()
        if "quarantined_at" not in record:
            record = {**record, "quarantined_at": _now_utc()}
        resp = client.table(_T_QUARANTINE).upsert(record, on_conflict="quarantine_id", returning="representation").execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else record
        if isinstance(data, dict):
            return data
        return record
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Review Queue
# ---------------------------------------------------------------------------


def get_review_queue(
    *,
    status: str | None = None,
    agent_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Return review_queue rows ordered by created_at asc.

    Optionally filtered by ``status`` (e.g. ``"pending"``) and/or ``agent_id``.
    """
    operation = "get_review_queue"
    try:
        client = get_supabase_service_client()
        q = client.table(_T_REVIEW_QUEUE).select("*")
        if status:
            q = q.eq("status", status)
        if agent_id:
            q = q.eq("agent_id", agent_id)
        q = q.order("created_at", desc=False).range(offset, offset + limit - 1)
        resp = q.execute()
        data = resp.data
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# IOCs (Indicators of Compromise)
# ---------------------------------------------------------------------------


def upsert_ioc(record: dict[str, Any]) -> dict[str, Any]:
    """Upsert an iocs row.

    ``record`` must include ``ioc_id`` as the conflict key.
    """
    operation = "upsert_ioc"
    try:
        client = get_supabase_service_client()
        if "detected_at" not in record:
            record = {**record, "detected_at": _now_utc()}
        resp = client.table(_T_IOCS).upsert(record, on_conflict="ioc_id", returning="representation").execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else record
        if isinstance(data, dict):
            return data
        return record
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Threat Detections
# ---------------------------------------------------------------------------


def upsert_threat_detection(record: dict[str, Any]) -> dict[str, Any]:
    """Upsert a threat_detections row.

    ``record`` must include ``detection_id`` as the conflict key.
    """
    operation = "upsert_threat_detection"
    try:
        client = get_supabase_service_client()
        if "detected_at" not in record:
            record = {**record, "detected_at": _now_utc()}
        resp = client.table(_T_THREAT_DETECTIONS).upsert(record, on_conflict="detection_id", returning="representation").execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else record
        if isinstance(data, dict):
            return data
        return record
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Policy Sets
# ---------------------------------------------------------------------------


def get_policy_set(set_key: str) -> dict[str, Any] | None:
    """Return the policy_sets row for ``set_key`` with its member rules.

    Returns a dict with keys ``policy_set`` (the set row) and ``rules``
    (list of policy_rules rows that belong to the set), or None if the set
    does not exist.
    """
    operation = "get_policy_set"
    if not set_key or not set_key.strip():
        raise PersistenceError(operation, "set_key is required")
    try:
        client = get_supabase_service_client()

        set_resp = client.table(_T_POLICY_SETS).select("*").eq("set_key", set_key).maybe_single().execute()
        set_data = set_resp.data
        if not set_data:
            return None

        policy_set_id: str | None = None
        if isinstance(set_data, dict):
            policy_set_id = set_data.get("id") or set_data.get("policy_set_id")

        rules: list[dict[str, Any]] = []
        if policy_set_id:
            membership_resp = client.table(_T_POLICY_SET_MEMBERSHIPS).select("policy_rule_id").eq("policy_set_id", str(policy_set_id)).execute()
            memberships = membership_resp.data or []
            if isinstance(memberships, dict):
                memberships = [memberships]

            rule_ids: list[str] = [str(m["policy_rule_id"]) for m in memberships if isinstance(m, dict) and m.get("policy_rule_id")]

            if rule_ids:
                rules_resp = client.table(_T_POLICY_RULES).select("*").in_("id", rule_ids).execute()
                raw_rules = rules_resp.data or []
                rules = raw_rules if isinstance(raw_rules, list) else [raw_rules]

        return {"policy_set": set_data, "rules": rules}
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Tool Call Log
# ---------------------------------------------------------------------------


def log_tool_call(record: dict[str, Any]) -> dict[str, Any]:
    """Insert a tool_call_log row.

    ``record`` should include ``tool_call_id``, ``tool_name``, ``agent_id``,
    ``verdict``, and ``payload`` (serializable dict). If ``tool_call_id`` is
    present it is used as the upsert conflict key; otherwise a plain insert
    is performed.
    """
    operation = "log_tool_call"
    try:
        client = get_supabase_service_client()
        if "called_at" not in record:
            record = {**record, "called_at": _now_utc()}
        if "tool_call_id" in record:
            resp = client.table(_T_TOOL_CALL_LOG).upsert(record, on_conflict="tool_call_id", returning="representation").execute()
        else:
            resp = client.table(_T_TOOL_CALL_LOG).insert(record, returning="representation").execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else record
        if isinstance(data, dict):
            return data
        return record
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Sandbox Execution Log
# ---------------------------------------------------------------------------


def log_sandbox_execution(record: dict[str, Any]) -> dict[str, Any]:
    """Insert a sandbox_execution_log row.

    ``record`` should include ``execution_id``, ``agent_id``, ``sandbox_type``,
    ``verdict``, ``exit_code``, and ``stdout``/``stderr`` (truncated strings).
    If ``execution_id`` is present it is used as the upsert conflict key;
    otherwise a plain insert is performed.
    """
    operation = "log_sandbox_execution"
    try:
        client = get_supabase_service_client()
        if "executed_at" not in record:
            record = {**record, "executed_at": _now_utc()}
        if "execution_id" in record:
            resp = client.table(_T_SANDBOX_EXECUTION_LOG).upsert(record, on_conflict="execution_id", returning="representation").execute()
        else:
            resp = client.table(_T_SANDBOX_EXECUTION_LOG).insert(record, returning="representation").execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else record
        if isinstance(data, dict):
            return data
        return record
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Agent Trust Profiles
# ---------------------------------------------------------------------------


def get_agent_trust_profile(agent_id: str) -> dict[str, Any] | None:
    """Return the agent_trust_profiles row for ``agent_id``, or None if not found.

    Callers that need a TrustProfile dataclass should use trust_engine.get_trust()
    directly. This function exists so the rest of the system can optionally read
    raw trust profile rows through the canonical persistence adapter — e.g. for
    admin inspection, test fixtures, or cross-service reads — without importing
    trust_engine internals.
    """
    operation = "get_agent_trust_profile"
    if not agent_id or not agent_id.strip():
        raise PersistenceError(operation, "agent_id is required")
    try:
        client = get_supabase_service_client()
        resp = client.table(_T_AGENT_TRUST_PROFILES).select("*").eq("agent_id", agent_id.strip()).maybe_single().execute()
        data = resp.data
        if isinstance(data, dict) and data:
            return data
        if isinstance(data, list):
            return data[0] if data else None
        return None
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


def upsert_agent_trust_profile(record: dict[str, Any]) -> dict[str, Any]:
    """Upsert an agent_trust_profiles row.

    ``record`` must include ``agent_id`` as the conflict key.

    Note: trust_engine.py is the authoritative mutation path for trust profiles
    during live scoring. This function exists for seeding, test setup, admin
    overrides, and cross-service writes that bypass the trust engine's cache.
    Callers that go through this path should call trust_engine.invalidate_cache()
    for the affected agent_id after writing.
    """
    operation = "upsert_agent_trust_profile"
    if not record.get("agent_id"):
        raise PersistenceError(operation, "record must include agent_id")
    try:
        client = get_supabase_service_client()
        if "updated_at" not in record:
            record = {**record, "updated_at": _now_utc()}
        resp = client.table(_T_AGENT_TRUST_PROFILES).upsert(record, on_conflict="agent_id", returning="representation").execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else record
        if isinstance(data, dict):
            return data
        return record
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Trust Events
# ---------------------------------------------------------------------------


def insert_trust_event(record: dict[str, Any]) -> dict[str, Any]:
    """Insert a trust_events row.

    ``record`` must include ``event_id``, ``agent_id``, and ``event_type``.
    If ``event_id`` is present it is used as the upsert conflict key to make
    the call idempotent; otherwise a plain insert is performed.

    Note: trust_engine.record_event() is the authoritative mutation path for
    trust events during live scoring. This function exists for replay, test
    fixtures, and administrative back-fills that need to write event rows
    directly through the canonical persistence adapter.
    """
    operation = "insert_trust_event"
    if not record.get("agent_id"):
        raise PersistenceError(operation, "record must include agent_id")
    if not record.get("event_type"):
        raise PersistenceError(operation, "record must include event_type")
    try:
        client = get_supabase_service_client()
        if "recorded_at" not in record:
            record = {**record, "recorded_at": _now_utc()}
        if "event_id" in record:
            resp = client.table(_T_TRUST_EVENTS).upsert(record, on_conflict="event_id", returning="representation").execute()
        else:
            resp = client.table(_T_TRUST_EVENTS).insert(record, returning="representation").execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else record
        if isinstance(data, dict):
            return data
        return record
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


def list_trust_events(
    agent_id: str,
    *,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Return trust_events rows for ``agent_id`` ordered by recorded_at desc.

    Mirrors trust_engine.list_trust_events() but routes through the canonical
    persistence adapter so callers that already depend on supabase_persistence
    do not need to import the trust engine for read-only event listing.
    """
    operation = "list_trust_events"
    if not agent_id or not agent_id.strip():
        raise PersistenceError(operation, "agent_id is required")
    try:
        client = get_supabase_service_client()
        resp = client.table(_T_TRUST_EVENTS).select("*").eq("agent_id", agent_id.strip()).order("recorded_at", desc=True).range(offset, offset + limit - 1).execute()
        data = resp.data
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------

__all__ = [
    "PersistenceError",
    "upsert_scan",
    "get_scan_by_id",
    "list_scans",
    "upsert_audit_event",
    "upsert_telemetry",
    "upsert_quarantine_item",
    "get_review_queue",
    "upsert_ioc",
    "upsert_threat_detection",
    "get_policy_set",
    "log_tool_call",
    "log_sandbox_execution",
    "get_agent_trust_profile",
    "upsert_agent_trust_profile",
    "insert_trust_event",
    "list_trust_events",
]
