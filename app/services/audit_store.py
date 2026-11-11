from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import logging
import os
from threading import Lock
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)

#: Reason codes that describe infrastructure or system failures, not detected attacks.
SYSTEM_ERROR_REASON_CODES = frozenset(
    {
        "broker_unconfigured",
        "broker_unreachable",
        "broker_error",
        "broker_busy",
        "invalid_response",
        "invalid_output",
        "timeout",
        "docker_unavailable",
        "scanner_error",
        "scanner_image_not_ready",
        "output_too_large",
        "return_scan_error",
        "usage_metering_unavailable",
        "billing_owner_unresolved",
        "protection_units_unavailable",
        "install_gate_error",
        "invalid_request",
        "action_not_allowed",
        "network_not_allowed",
        "read_only_required",
    }
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _is_seeded(record: AuditEventRecord) -> bool:
    return bool(record.metadata.get("seeded"))


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

    def __init__(
        self,
        *,
        durable_writer: Callable[[AuditEventRecord], None] | None = None,
        durable_loader: Callable[[], list[AuditEventRecord]] | None = None,
    ) -> None:
        self._lock = Lock()
        self._items: list[AuditEventRecord] = []
        self._durable_writer = durable_writer
        self._durable_loader = durable_loader
        self._hydrated = durable_loader is None

    def _hydrate(self) -> None:
        if self._hydrated or self._durable_loader is None:
            return
        try:
            durable_items = self._durable_loader()
        except Exception:
            logger.warning("security audit store: durable history unavailable; will retry", exc_info=True)
            return
        with self._lock:
            if self._hydrated:
                return
            known_ids = {item.event_id for item in self._items}
            # Durable history predates anything recorded in this process, so it is placed first.
            self._items[:0] = [item for item in durable_items if item.event_id not in known_ids]
            self._hydrated = True

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
                        verdict="block",
                        summary="Prompt-injection pattern detected and blocked before execution.",
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
                        verdict="block",
                        summary="Suspicious output blocked and routed into sandbox-backed review flow.",
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
        limit: int | None = 100,
        include_seeded: bool = True,
        newest_first: bool = False,
        predicate: Callable[[AuditEventRecord], bool] | None = None,
    ) -> list[AuditEventRecord]:
        self._hydrate()
        with self._lock:
            items = list(self._items)
        if newest_first:
            items.reverse()

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
        if not include_seeded:
            items = [item for item in items if not _is_seeded(item)]
        # Applied before the limit so one tenant's volume cannot push another tenant's events out of the window.
        if predicate is not None:
            items = [item for item in items if predicate(item)]

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

        if self._durable_writer is not None and (event.verdict or "").lower() == "block":
            try:
                self._durable_writer(event)
            except Exception:
                logger.warning("security audit store: failed to persist block event %s", event.event_id, exc_info=True)

        return event

    def get_event(self, event_id: str) -> AuditEventRecord | None:
        self._hydrate()
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
        self._hydrate()
        with self._lock:
            return len(self._items)

    def summarize(self, *, include_seeded: bool = True) -> dict[str, Any]:
        self._hydrate()
        with self._lock:
            items = list(self._items)
        if not include_seeded:
            items = [item for item in items if not _is_seeded(item)]

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


def _durable_storage_enabled() -> bool:
    persistence_mode = os.environ.get("IRONCLAW_PERSISTENCE_MODE", "").strip().lower()
    environment_name = (os.environ.get("IRONCLAW_ENV") or os.environ.get("APP_ENV") or os.environ.get("ENVIRONMENT", "")).strip().lower()
    return persistence_mode == "supabase" or environment_name in {"prod", "production"}


def _event_to_row(event: AuditEventRecord) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "severity": event.severity,
        "verdict": event.verdict,
        "summary": event.summary,
        "actor_id": event.actor_id,
        "session_id": event.session_id,
        "request_id": event.request_id,
        "trace_id": event.trace_id,
        "integration_id": event.integration_id,
        "metadata": event.metadata,
        "created_at": event.created_at.isoformat(),
    }


def _row_to_event(row: dict[str, Any]) -> AuditEventRecord:
    created_at = datetime.fromisoformat(str(row["created_at"]).replace("Z", "+00:00"))
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    metadata = row.get("metadata")
    return AuditEventRecord(
        event_id=str(row["event_id"]),
        event_type=str(row["event_type"]),
        severity=str(row["severity"]),
        created_at=created_at,
        actor_id=row.get("actor_id"),
        session_id=row.get("session_id"),
        request_id=row.get("request_id"),
        trace_id=row.get("trace_id"),
        integration_id=row.get("integration_id"),
        verdict=row.get("verdict"),
        summary=str(row.get("summary") or ""),
        metadata=dict(metadata) if isinstance(metadata, dict) else {},
    )


def _persist_block_event(event: AuditEventRecord) -> None:
    from app.core.supabase_persistence import insert_security_audit_event

    insert_security_audit_event(_event_to_row(event))


def _load_block_events() -> list[AuditEventRecord]:
    from app.core.supabase_persistence import list_security_audit_events

    return [_row_to_event(row) for row in list_security_audit_events()]


def _build_security_audit_store() -> SecurityAuditEventStore:
    if _durable_storage_enabled():
        store = SecurityAuditEventStore(durable_writer=_persist_block_event, durable_loader=_load_block_events)
    else:
        store = SecurityAuditEventStore()
    store.seed_defaults()
    return store


_SECURITY_AUDIT_STORE = _build_security_audit_store()


def get_security_audit_store() -> SecurityAuditEventStore:
    """Return the module-level SecurityAuditEventStore singleton."""
    return _SECURITY_AUDIT_STORE


def reset_security_audit_store() -> None:
    """Reset the singleton store and re-seed defaults. Used by tests."""
    _SECURITY_AUDIT_STORE.reset()
    _SECURITY_AUDIT_STORE.seed_defaults()


def _gate_severity(verdict: str) -> str:
    if verdict == "allow":
        return "low"
    if verdict == "error":
        return "medium"
    return "high"


def record_gate_audit_event(
    *,
    gate: str,
    verdict: str,
    platform: str,
    reason_codes: Sequence[str],
    owner_key: str | None,
    decision_id: str | None = None,
    session_id: str | None = None,
    agent_id: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> AuditEventRecord | None:
    """Audit one return or install gate decision: allow, block, or error.

    A block whose reasons are all system failures is recorded as ``error`` so it is never reported as an attack.
    Best-effort and bounded: metadata holds only identifiers and reason codes, never raw agent content.
    """
    codes = sorted({str(code) for code in reason_codes})
    resolved_verdict = verdict
    if verdict != "allow" and codes and all(code in SYSTEM_ERROR_REASON_CODES for code in codes):
        resolved_verdict = "error"
    try:
        return _SECURITY_AUDIT_STORE.create_event(
            event_type=f"{gate}_gate_decision",
            severity=_gate_severity(resolved_verdict),
            summary=f"{gate} gate {resolved_verdict} for {platform}",
            session_id=session_id,
            integration_id=platform,
            verdict=resolved_verdict,
            metadata={
                "gate": gate,
                "platform": platform,
                "owner_key": owner_key,
                "decision_id": decision_id,
                "agent_id": agent_id,
                "reason_codes": codes,
                **dict(details or {}),
            },
        )
    except Exception:
        logger.exception("runtime gate audit write failed", extra={"gate": gate, "platform": platform})
        return None


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
