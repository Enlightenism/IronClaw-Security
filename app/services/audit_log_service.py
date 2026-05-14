from __future__ import annotations

from pathlib import Path
from typing import Any

from app.orchestrator.security_audit_log import (
    SecurityAuditEvent,
    SecurityAuditLog,
    initialize_security_audit_log,
    read_security_audit_events,
)

_active_audit_log: SecurityAuditLog | None = None
_DEFAULT_AUDIT_LOG_PATH = Path("output/security-events.jsonl")


def get_audit_log() -> SecurityAuditLog:
    """Return the active SecurityAuditLog instance.

    Falls back to initialize_security_audit_log with the default path if one is
    not already configured by the orchestrator.
    """
    global _active_audit_log
    if _active_audit_log is None:
        _DEFAULT_AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        _active_audit_log = initialize_security_audit_log(str(_DEFAULT_AUDIT_LOG_PATH))
    return _active_audit_log


def set_audit_log(log: SecurityAuditLog) -> SecurityAuditLog:
    """Install a SecurityAuditLog instance as the active singleton.

    This is primarily used by the orchestrator and tests.
    """
    global _active_audit_log
    _active_audit_log = log
    return _active_audit_log


def reset_audit_log() -> SecurityAuditLog:
    """Reset the active audit log to a fresh instance with the default path.

    This also clears the persisted default audit log file so tests start from a
    clean state.
    """
    global _active_audit_log
    _DEFAULT_AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _DEFAULT_AUDIT_LOG_PATH.write_text("", encoding="utf-8")
    _active_audit_log = initialize_security_audit_log(str(_DEFAULT_AUDIT_LOG_PATH))
    return _active_audit_log


def _load_events() -> list[SecurityAuditEvent]:
    log = get_audit_log()
    return read_security_audit_events(log)


def list_audit_events(limit: int | None = 100) -> list[dict[str, Any]]:
    """Return recent audit events as plain dicts, newest-first.

    If limit is None, all available events are returned.
    """
    events = _load_events()
    events_as_dicts = [event.to_dict() for event in reversed(events)]

    if limit is None:
        return events_as_dicts

    safe_limit = max(1, int(limit))
    return events_as_dicts[:safe_limit]


def list_audit_events_for_session(
    session_id: str,
    limit: int | None = 100,
) -> list[dict[str, Any]]:
    """Return recent events filtered by session_id, newest-first."""
    normalized_session_id = session_id.strip()
    events = list_audit_events(limit=None)
    filtered = [e for e in events if e.get("session_id") == normalized_session_id]

    if limit is None:
        return filtered

    safe_limit = max(1, int(limit))
    return filtered[:safe_limit]


def list_audit_events_for_actor(
    actor_id: str,
    limit: int | None = 100,
) -> list[dict[str, Any]]:
    """Return recent events filtered by actor_id, newest-first."""
    normalized_actor_id = actor_id.strip()
    events = list_audit_events(limit=None)
    filtered = [e for e in events if e.get("actor_id") == normalized_actor_id or e.get("client_id") == normalized_actor_id]

    if limit is None:
        return filtered

    safe_limit = max(1, int(limit))
    return filtered[:safe_limit]


def list_audit_events_for_request(
    request_id: str,
) -> list[dict[str, Any]]:
    """Return all events associated with a specific request_id."""
    normalized_request_id = request_id.strip()
    events = list_audit_events(limit=None)
    return [e for e in events if e.get("request_id") == normalized_request_id]


def list_audit_events_for_trace(
    trace_id: str,
) -> list[dict[str, Any]]:
    """Return all events associated with a specific trace_id."""
    normalized_trace_id = trace_id.strip()
    events = list_audit_events(limit=None)
    return [e for e in events if e.get("trace_id") == normalized_trace_id]
