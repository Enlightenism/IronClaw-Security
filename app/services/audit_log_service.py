from __future__ import annotations

from pathlib import Path
from typing import Any

from app.orchestrator.security_audit_log import (
    SecurityAuditEvent,
    SecurityAuditLog,
    initialize_security_audit_log,
    read_security_audit_events,
)
from app.schemas.audit import (
    AuditEventCreate,
    AuditEventType,
    AuditOutcome,
    AuditSeverity,
    AuditTargetType,
)

_active_audit_log: SecurityAuditLog | None = None
_DEFAULT_AUDIT_LOG_PATH = Path("output/security-events.jsonl")


# ---------------------------------------------------------------------------
# Singleton management
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_events() -> list[SecurityAuditEvent]:
    log = get_audit_log()
    return read_security_audit_events(log)


# ---------------------------------------------------------------------------
# Legacy dict → AuditEventCreate bridge
# ---------------------------------------------------------------------------

_VERDICT_TO_OUTCOME: dict[str, AuditOutcome] = {
    "allow": AuditOutcome.ALLOWED,
    "execution_allowed": AuditOutcome.ALLOWED,
    "warn": AuditOutcome.WARNED,
    "execution_warned": AuditOutcome.WARNED,
    "quarantine": AuditOutcome.BLOCKED,
    "execution_quarantined": AuditOutcome.BLOCKED,
    "block": AuditOutcome.BLOCKED,
    "execution_blocked": AuditOutcome.BLOCKED,
    "review_requested": AuditOutcome.PENDING,
    "review_completed": AuditOutcome.SUCCESS,
    "supervisor_escalation": AuditOutcome.PENDING,
    "policy_decision": AuditOutcome.UNKNOWN,
}

_ACTION_TYPE_TO_TARGET_TYPE: dict[str, AuditTargetType] = {
    "tool_call": AuditTargetType.TOOL_CALL,
    "prompt": AuditTargetType.PROMPT,
    "action": AuditTargetType.ACTION,
    "policy": AuditTargetType.POLICY,
    "session": AuditTargetType.SESSION,
    "agent": AuditTargetType.AGENT,
    "data": AuditTargetType.DATA_RECORD,
    "scan": AuditTargetType.SCAN,
}

_VERDICT_TO_EVENT_TYPE: dict[str, AuditEventType] = {
    "allow": AuditEventType.ACTION_EXECUTED,
    "execution_allowed": AuditEventType.ACTION_EXECUTED,
    "warn": AuditEventType.ACTION_DECISION_MADE,
    "execution_warned": AuditEventType.ACTION_DECISION_MADE,
    "quarantine": AuditEventType.ACTION_BLOCKED,
    "execution_quarantined": AuditEventType.ACTION_BLOCKED,
    "block": AuditEventType.ACTION_BLOCKED,
    "execution_blocked": AuditEventType.ACTION_BLOCKED,
    "review_requested": AuditEventType.REVIEW_ITEM_CREATED,
    "review_completed": AuditEventType.REVIEW_DECISION_MADE,
    "supervisor_escalation": AuditEventType.REVIEW_ESCALATED,
    "policy_decision": AuditEventType.POLICY_EVALUATED,
}


def _legacy_event_to_schema(event: SecurityAuditEvent) -> AuditEventCreate:
    """Bridge a SecurityAuditEvent (legacy dataclass) to AuditEventCreate (schema).

    This is a single-source bridge. No caller should duplicate this mapping.
    """
    verdict_key = (event.verdict or "").strip().lower()
    event_type_key = (event.event_type or "").strip().lower()

    resolved_event_type = _VERDICT_TO_EVENT_TYPE.get(verdict_key) or _VERDICT_TO_EVENT_TYPE.get(event_type_key) or AuditEventType.UNKNOWN

    outcome = _VERDICT_TO_OUTCOME.get(verdict_key) or _VERDICT_TO_OUTCOME.get(event_type_key) or AuditOutcome.UNKNOWN

    action_type_key = (event.action_type or "").strip().lower()
    target_type = _ACTION_TYPE_TO_TARGET_TYPE.get(action_type_key, AuditTargetType.UNKNOWN)

    risk = max(0, min(100, int(event.risk_score or 0)))
    severity = AuditSeverity.CRITICAL if risk >= 80 else AuditSeverity.HIGH if risk >= 60 else AuditSeverity.MEDIUM if risk >= 40 else AuditSeverity.LOW if risk >= 20 else AuditSeverity.INFO

    meta: dict[str, Any] = dict(event.metadata or {})

    return AuditEventCreate(
        event_type=resolved_event_type,
        actor=event.actor_id or "system",
        actor_type=meta.get("actor_type"),
        target_type=target_type,
        target_id=event.target or None,
        action=f"{event.action_type}: {event.target}" if event.action_type and event.target else (event.action_type or event.target or "unknown"),
        outcome=outcome,
        severity=severity,
        org_id=meta.get("org_id"),
        session_id=event.session_id,
        request_id=event.request_id,
        risk_score=risk,
        categories=meta.get("categories") if isinstance(meta.get("categories"), list) else [],
        tags=meta.get("tags") if isinstance(meta.get("tags"), list) else [],
        reasoning=event.reason or None,
        metadata=meta,
        created_at=None,
    )


# ---------------------------------------------------------------------------
# Public query API — returns raw dicts (legacy contract preserved)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Schema-aligned query API — returns AuditEventCreate (bridge output)
# ---------------------------------------------------------------------------


def list_audit_events_as_schema(limit: int | None = 100) -> list[AuditEventCreate]:
    """Return recent audit events as AuditEventCreate models, newest-first.

    This is the schema-aligned surface for internal consumers that need
    AuditEventCreate instead of raw dicts.
    """
    raw_events = _load_events()
    converted = [_legacy_event_to_schema(e) for e in reversed(raw_events)]

    if limit is None:
        return converted

    safe_limit = max(1, int(limit))
    return converted[:safe_limit]


def list_audit_events_for_session_as_schema(
    session_id: str,
    limit: int | None = 100,
) -> list[AuditEventCreate]:
    """Return schema-aligned events filtered by session_id, newest-first."""
    normalized = session_id.strip()
    raw_events = _load_events()
    filtered = [_legacy_event_to_schema(e) for e in reversed(raw_events) if e.session_id == normalized]

    if limit is None:
        return filtered

    safe_limit = max(1, int(limit))
    return filtered[:safe_limit]


def get_audit_event_as_schema(event_id: str) -> AuditEventCreate | None:
    """Return a single event by event_id as AuditEventCreate, or None if not found."""
    raw_events = _load_events()
    for e in raw_events:
        if e.event_id == event_id.strip():
            return _legacy_event_to_schema(e)
    return None
