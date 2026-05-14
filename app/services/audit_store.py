from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from threading import Lock
from typing import Any
from uuid import uuid4


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(slots=True)
class AuditEventRecord:
    event_id: str
    event_type: str
    severity: str
    created_at: datetime
    actor_id: str | None = None
    session_id: str | None = None
    request_id: str | None = None
    trace_id: str | None = None
    integration_id: str | None = None
    verdict: str | None = None
    summary: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["created_at"] = self.created_at.isoformat().replace("+00:00", "Z")
        return payload


class SecurityAuditEventStore:
    """In-memory store for raw security audit events.

    Distinct from AuditStore (auditstore.py) which is the persistence-backed
    store for structured audit events. This store is for internal IronClaw
    security runtime events with seeded defaults and thread-safe access.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._items: list[AuditEventRecord] = []

    def seed_defaults(self) -> None:
        with self._lock:
            if self._items:
                return

            now = _utcnow()
            self._items.extend(
                [
                    AuditEventRecord(
                        event_id=f"audit-{uuid4().hex[:12]}",
                        event_type="policy_decision",
                        severity="high",
                        created_at=now,
                        actor_id="ironclaw",
                        session_id="session-001",
                        request_id="req-001",
                        trace_id="trace-001",
                        integration_id="claude-router-proxy",
                        verdict="quarantine",
                        summary="Prompt-injection pattern detected and quarantined before execution.",
                        metadata={
                            "category": "prompt-injection",
                            "source": "scan",
                            "matched_rules": ["heuristic_prompt_injection_score"],
                            "seeded": True,
                        },
                    ),
                    AuditEventRecord(
                        event_id=f"audit-{uuid4().hex[:12]}",
                        event_type="tool_guard",
                        severity="critical",
                        created_at=now,
                        actor_id="ironclaw",
                        session_id="session-002",
                        request_id="req-002",
                        trace_id="trace-002",
                        integration_id="secure-runtime",
                        verdict="block",
                        summary="High-risk tool action blocked by runtime guardrails.",
                        metadata={
                            "category": "tool-call",
                            "source": "guard",
                            "tool_name": "filesystem.write",
                            "seeded": True,
                        },
                    ),
                    AuditEventRecord(
                        event_id=f"audit-{uuid4().hex[:12]}",
                        event_type="sandbox_isolation",
                        severity="medium",
                        created_at=now,
                        actor_id="sandbox-review",
                        session_id="session-003",
                        request_id="req-003",
                        trace_id="trace-003",
                        integration_id="sandbox-pipeline",
                        verdict="warn",
                        summary="Suspicious output routed into sandbox-backed review flow.",
                        metadata={
                            "category": "response-review",
                            "source": "sandbox",
                            "seeded": True,
                        },
                    ),
                ],
            )

    def list_events(
        self,
        *,
        actor_id: str | None = None,
        session_id: str | None = None,
        request_id: str | None = None,
        trace_id: str | None = None,
        verdict: str | None = None,
        event_type: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[AuditEventRecord]:
        with self._lock:
            items = list(self._items)

        if actor_id:
            items = [item for item in items if item.actor_id == actor_id]
        if session_id:
            items = [item for item in items if item.session_id == session_id]
        if request_id:
            items = [item for item in items if item.request_id == request_id]
        if trace_id:
            items = [item for item in items if item.trace_id == trace_id]
        if verdict:
            items = [item for item in items if item.verdict == verdict]
        if event_type:
            items = [item for item in items if item.event_type == event_type]
        if severity:
            items = [item for item in items if item.severity == severity]

        return items[:limit]

    def get_by_actor(self, actor_id: str) -> list[AuditEventRecord]:
        return self.list_events(actor_id=actor_id, limit=10_000)

    def get_by_session(self, session_id: str) -> list[AuditEventRecord]:
        return self.list_events(session_id=session_id, limit=10_000)

    def get_by_request(self, request_id: str) -> list[AuditEventRecord]:
        return self.list_events(request_id=request_id, limit=10_000)

    def get_by_trace(self, trace_id: str) -> list[AuditEventRecord]:
        return self.list_events(trace_id=trace_id, limit=10_000)

    def create_event(
        self,
        *,
        event_type: str,
        severity: str,
        summary: str,
        actor_id: str | None = None,
        session_id: str | None = None,
        request_id: str | None = None,
        trace_id: str | None = None,
        integration_id: str | None = None,
        verdict: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEventRecord:
        if not event_type or not event_type.strip():
            raise ValueError("event_type is required")
        if not severity or not severity.strip():
            raise ValueError("severity is required")
        if not summary or not summary.strip():
            raise ValueError("summary is required")

        event = AuditEventRecord(
            event_id=f"audit-{uuid4().hex[:12]}",
            event_type=event_type.strip(),
            severity=severity.strip(),
            created_at=_utcnow(),
            actor_id=actor_id,
            session_id=session_id,
            request_id=request_id,
            trace_id=trace_id,
            integration_id=integration_id,
            verdict=verdict,
            summary=summary.strip(),
            metadata=dict(metadata or {}),
        )

        with self._lock:
            self._items.append(event)

        return event

    def get_event(self, event_id: str) -> AuditEventRecord | None:
        normalized = event_id.strip() if event_id else ""
        if not normalized:
            raise ValueError("event_id is required")
        with self._lock:
            for item in self._items:
                if item.event_id == normalized:
                    return item
        return None

    def delete_event(self, event_id: str) -> AuditEventRecord | None:
        normalized = event_id.strip() if event_id else ""
        if not normalized:
            raise ValueError("event_id is required")
        with self._lock:
            for i, item in enumerate(self._items):
                if item.event_id == normalized:
                    return self._items.pop(i)
        return None

    def count(self) -> int:
        with self._lock:
            return len(self._items)

    def summarize(self) -> dict[str, Any]:
        with self._lock:
            items = list(self._items)

        by_event_type: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        by_verdict: dict[str, int] = {}

        for item in items:
            by_event_type[item.event_type] = by_event_type.get(item.event_type, 0) + 1
            by_severity[item.severity] = by_severity.get(item.severity, 0) + 1
            verdict_key = item.verdict or "none"
            by_verdict[verdict_key] = by_verdict.get(verdict_key, 0) + 1

        return {
            "total": len(items),
            "by_event_type": by_event_type,
            "by_severity": by_severity,
            "by_verdict": by_verdict,
        }

    def reset(self) -> None:
        with self._lock:
            self._items.clear()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_SECURITY_AUDIT_STORE = SecurityAuditEventStore()
_SECURITY_AUDIT_STORE.seed_defaults()


def get_security_audit_store() -> SecurityAuditEventStore:
    """Return the module-level SecurityAuditEventStore singleton."""
    return _SECURITY_AUDIT_STORE


def reset_security_audit_store() -> None:
    """Reset the singleton store and re-seed defaults. Used by tests."""
    _SECURITY_AUDIT_STORE.reset()
    _SECURITY_AUDIT_STORE.seed_defaults()


# ---------------------------------------------------------------------------
# Back-compat shims — remove once all consumers are updated
# ---------------------------------------------------------------------------

#: Deprecated alias. Import SecurityAuditEventStore directly.
AuditStore = SecurityAuditEventStore

_AUDIT_STORE = _SECURITY_AUDIT_STORE


def get_audit_store() -> SecurityAuditEventStore:
    """Deprecated. Use get_security_audit_store()."""
    return _SECURITY_AUDIT_STORE


def reset_audit_store() -> None:
    """Deprecated. Use reset_security_audit_store()."""
    reset_security_audit_store()
