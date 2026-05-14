from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

AuditEventType = Literal[
    "policy_decision",
    "execution_allowed",
    "execution_warned",
    "execution_quarantined",
    "execution_blocked",
    "review_requested",
    "review_completed",
    "supervisor_escalation",
]


@dataclass(frozen=True)
class SecurityAuditEvent:
    event_id: str
    event_type: AuditEventType
    actor_id: str
    action_type: str
    target: str
    verdict: str
    risk_score: int
    reason: str
    session_id: str | None = None
    file_path: str | None = None
    trace_id: str | None = None
    request_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityAuditLog:
    log_path: str
    event_count: int = 0
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def initialize_security_audit_log(
    log_path: str = "security-events.jsonl",
) -> SecurityAuditLog:
    path = Path(log_path)
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    event_count = _count_events(path)
    now = datetime.now(UTC).isoformat()
    return SecurityAuditLog(
        log_path=str(path),
        event_count=event_count,
        created_at=now,
        updated_at=now,
    )


def append_security_audit_event(
    audit_log: SecurityAuditLog,
    event: SecurityAuditEvent,
) -> SecurityAuditLog:
    path = Path(audit_log.log_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")

    return SecurityAuditLog(
        log_path=audit_log.log_path,
        event_count=audit_log.event_count + 1,
        created_at=audit_log.created_at,
        updated_at=datetime.now(UTC).isoformat(),
    )


def record_policy_decision(
    audit_log: SecurityAuditLog,
    *,
    actor_id: str,
    action_type: str,
    target: str,
    verdict: str,
    risk_score: int,
    reason: str,
    session_id: str | None = None,
    file_path: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityAuditLog:
    meta = dict(metadata or {})

    event_type = _event_type_for_verdict(verdict)
    event = SecurityAuditEvent(
        event_id=_build_event_id(),
        event_type=event_type,
        actor_id=actor_id,
        action_type=action_type,
        target=target,
        verdict=verdict,
        risk_score=risk_score,
        reason=reason,
        session_id=session_id or meta.get("session_id"),
        file_path=file_path or meta.get("file_path"),
        trace_id=meta.get("trace_id"),
        request_id=meta.get("request_id"),
        metadata=meta,
    )
    return append_security_audit_event(audit_log, event)


def read_security_audit_events(audit_log: SecurityAuditLog) -> list[SecurityAuditEvent]:
    path = Path(audit_log.log_path)
    if not path.exists():
        return []

    events: list[SecurityAuditEvent] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            events.append(
                SecurityAuditEvent(
                    event_id=payload["event_id"],
                    event_type=payload["event_type"],
                    actor_id=payload["actor_id"],
                    action_type=payload["action_type"],
                    target=payload["target"],
                    verdict=payload["verdict"],
                    risk_score=payload["risk_score"],
                    reason=payload["reason"],
                    session_id=payload.get("session_id"),
                    file_path=payload.get("file_path"),
                    trace_id=payload.get("trace_id"),
                    request_id=payload.get("request_id"),
                    metadata=payload.get("metadata", {}),
                    created_at=payload.get(
                        "created_at",
                        datetime.now(UTC).isoformat(),
                    ),
                ),
            )
    return events


def summarize_security_audit_log(audit_log: SecurityAuditLog) -> dict[str, Any]:
    events = read_security_audit_events(audit_log)
    return {
        "log_path": audit_log.log_path,
        "event_count": len(events),
        "policy_decision_count": sum(1 for event in events if event.event_type == "policy_decision"),
        "execution_allowed_count": sum(1 for event in events if event.event_type == "execution_allowed"),
        "execution_warned_count": sum(1 for event in events if event.event_type == "execution_warned"),
        "execution_quarantined_count": sum(1 for event in events if event.event_type == "execution_quarantined"),
        "execution_blocked_count": sum(1 for event in events if event.event_type == "execution_blocked"),
        "review_requested_count": sum(1 for event in events if event.event_type == "review_requested"),
        "review_completed_count": sum(1 for event in events if event.event_type == "review_completed"),
        "supervisor_escalation_count": sum(1 for event in events if event.event_type == "supervisor_escalation"),
        "latest_event_at": max((event.created_at for event in events), default=None),
        "updated_at": audit_log.updated_at,
    }


def record_review_requested(
    audit_log: SecurityAuditLog,
    *,
    actor_id: str,
    action_type: str,
    target: str,
    verdict: str,
    risk_score: int,
    reason: str,
    session_id: str | None = None,
    file_path: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityAuditLog:
    return _record_explicit_event(
        audit_log,
        event_type="review_requested",
        actor_id=actor_id,
        action_type=action_type,
        target=target,
        verdict=verdict,
        risk_score=risk_score,
        reason=reason,
        session_id=session_id,
        file_path=file_path,
        metadata=metadata,
    )


def record_review_completed(
    audit_log: SecurityAuditLog,
    *,
    actor_id: str,
    action_type: str,
    target: str,
    verdict: str,
    risk_score: int,
    reason: str,
    session_id: str | None = None,
    file_path: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityAuditLog:
    return _record_explicit_event(
        audit_log,
        event_type="review_completed",
        actor_id=actor_id,
        action_type=action_type,
        target=target,
        verdict=verdict,
        risk_score=risk_score,
        reason=reason,
        session_id=session_id,
        file_path=file_path,
        metadata=metadata,
    )


def record_supervisor_escalation(
    audit_log: SecurityAuditLog,
    *,
    actor_id: str,
    action_type: str,
    target: str,
    verdict: str,
    risk_score: int,
    reason: str,
    session_id: str | None = None,
    file_path: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityAuditLog:
    return _record_explicit_event(
        audit_log,
        event_type="supervisor_escalation",
        actor_id=actor_id,
        action_type=action_type,
        target=target,
        verdict=verdict,
        risk_score=risk_score,
        reason=reason,
        session_id=session_id,
        file_path=file_path,
        metadata=metadata,
    )


def _record_explicit_event(
    audit_log: SecurityAuditLog,
    *,
    event_type: AuditEventType,
    actor_id: str,
    action_type: str,
    target: str,
    verdict: str,
    risk_score: int,
    reason: str,
    session_id: str | None = None,
    file_path: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityAuditLog:
    meta = dict(metadata or {})
    event = SecurityAuditEvent(
        event_id=_build_event_id(),
        event_type=event_type,
        actor_id=actor_id,
        action_type=action_type,
        target=target,
        verdict=verdict,
        risk_score=risk_score,
        reason=reason,
        session_id=session_id or meta.get("session_id"),
        file_path=file_path or meta.get("file_path"),
        trace_id=meta.get("trace_id"),
        request_id=meta.get("request_id"),
        metadata=meta,
    )
    return append_security_audit_event(audit_log, event)


def _count_events(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8") as handle:
        return sum(1 for line in handle if line.strip())


def _event_type_for_verdict(verdict: str) -> AuditEventType:
    normalized = (verdict or "").strip().lower()
    if normalized == "allow":
        return "execution_allowed"
    if normalized == "warn":
        return "execution_warned"
    if normalized == "quarantine":
        return "execution_quarantined"
    if normalized == "block":
        return "execution_blocked"
    return "policy_decision"


def _build_event_id() -> str:
    now = datetime.now(UTC)
    return f"audit-{now.strftime('%Y%m%d%H%M%S%f')}"


if __name__ == "__main__":
    audit_log = initialize_security_audit_log("output/security-events.jsonl")
    audit_log = record_policy_decision(
        audit_log,
        actor_id="agent-security-01",
        action_type="tool_call",
        target="shell",
        verdict="block",
        risk_score=98,
        reason="Blocked attempt to reveal system prompt and export credentials.",
        session_id="sess-001",
        file_path="app/orchestrator/policy_enforcer.py",
        metadata={
            "source": "policy_enforcer",
            "category": "prompt-injection",
            "trace_id": "trace-demo",
            "request_id": "req-demo",
        },
    )
    print(
        json.dumps(
            summarize_security_audit_log(audit_log),
            ensure_ascii=False,
            indent=2,
        ),
    )
