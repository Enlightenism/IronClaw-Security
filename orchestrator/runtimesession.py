from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4


class RuntimeSessionStatus(str, Enum):
    CREATED = "created"
    ACTIVE = "active"
    PAUSED = "paused"
    NEEDS_REVIEW = "needs_review"
    QUARANTINED = "quarantined"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(slots=True)
class RuntimeSessionEvent:
    event_id: str
    kind: str
    message: str
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "kind": self.kind,
            "message": self.message,
            "created_at": self.created_at,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class RuntimeSession:
    session_id: str
    request_id: str
    status: RuntimeSessionStatus = RuntimeSessionStatus.CREATED
    actor_id: str | None = None
    agent_id: str | None = None
    execution_id: str | None = None
    policy_id: str | None = None
    sandbox_id: str | None = None
    review_id: str | None = None
    quarantine_id: str | None = None
    checkpoint_id: str | None = None
    risk_score: int = 0
    trust_score: int | None = None
    allowed_tools: list[str] = field(default_factory=list)
    blocked_tools: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    events: list[RuntimeSessionEvent] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    completed_at: str | None = None

    def add_event(self, kind: str, message: str, metadata: Mapping[str, Any] | None = None) -> RuntimeSessionEvent:
        event = RuntimeSessionEvent(
            event_id=f"evt-{uuid4().hex}",
            kind=kind,
            message=message,
            metadata=dict(metadata or {}),
        )
        self.events.append(event)
        self.updated_at = datetime.now(UTC).isoformat()
        return event

    def activate(self) -> None:
        self.status = RuntimeSessionStatus.ACTIVE
        self.add_event("activated", "Runtime session activated.")

    def pause(self, reason: str = "Paused by supervisor.") -> None:
        self.status = RuntimeSessionStatus.PAUSED
        self.add_event("paused", reason)

    def mark_needs_review(self, review_id: str | None = None, reason: str = "Human review required.") -> None:
        self.status = RuntimeSessionStatus.NEEDS_REVIEW
        self.review_id = review_id
        self.add_event("needs_review", reason, {"review_id": review_id})

    def quarantine(self, quarantine_id: str | None = None, reason: str = "Session quarantined.") -> None:
        self.status = RuntimeSessionStatus.QUARANTINED
        self.quarantine_id = quarantine_id
        self.add_event("quarantined", reason, {"quarantine_id": quarantine_id})

    def block(self, reason: str = "Session blocked.") -> None:
        self.status = RuntimeSessionStatus.BLOCKED
        self.add_event("blocked", reason)

    def fail(self, reason: str = "Session failed.") -> None:
        self.status = RuntimeSessionStatus.FAILED
        self.add_event("failed", reason)

    def complete(self, reason: str = "Session completed.") -> None:
        self.status = RuntimeSessionStatus.COMPLETED
        self.completed_at = datetime.now(UTC).isoformat()
        self.add_event("completed", reason)

    def attach_checkpoint(self, checkpoint_id: str) -> None:
        self.checkpoint_id = checkpoint_id
        self.add_event(
            "checkpoint_attached",
            "Checkpoint attached to runtime session.",
            {"checkpoint_id": checkpoint_id},
        )

    def apply_supervisor_decision(self, decision: Mapping[str, Any]) -> None:
        status = str(decision.get("status", "")).lower()
        self.execution_id = self.execution_id or self._optional_str(decision.get("execution_id"))
        self.review_id = self.review_id or self._optional_str(decision.get("review_id"))

        if status == "approved":
            self.activate()
            return
        if status == "conditional":
            self.activate()
            self.add_event(
                "conditional_controls",
                "Conditional safeguards applied to runtime session.",
                {
                    "sandbox_required": bool(decision.get("sandbox_required")),
                    "redaction_required": bool(decision.get("redaction_required")),
                },
            )
            return
        if status == "needs_review":
            self.mark_needs_review(
                review_id=self._optional_str(decision.get("review_id")),
                reason="Supervisor routed runtime session into review.",
            )
            return
        if status == "quarantined":
            self.quarantine(
                quarantine_id=self._optional_str(decision.get("quarantine_id")),
                reason="Supervisor quarantined runtime session.",
            )
            return
        if status == "blocked":
            self.block("Supervisor blocked runtime session.")
            return

        self.fail("Unknown supervisor decision status received.")

    def merge_context(self, context: Mapping[str, Any] | None) -> None:
        payload = dict(context or {})
        self.actor_id = self.actor_id or self._optional_str(payload.get("actor_id"))
        self.agent_id = self.agent_id or self._optional_str(payload.get("agent_id"))
        self.execution_id = self.execution_id or self._optional_str(payload.get("execution_id"))
        self.policy_id = self.policy_id or self._optional_str(payload.get("policy_id"))
        self.sandbox_id = self.sandbox_id or self._optional_str(payload.get("sandbox_id"))
        self.risk_score = int(payload.get("risk_score", self.risk_score) or 0)

        trust_score = payload.get("trust_score")
        if trust_score is not None:
            self.trust_score = int(trust_score)

        self.allowed_tools = self._normalize_str_list(payload.get("allowed_tools"), fallback=self.allowed_tools)
        self.blocked_tools = self._normalize_str_list(payload.get("blocked_tools"), fallback=self.blocked_tools)
        self.tags = self._normalize_str_list(payload.get("tags"), fallback=self.tags)

        extra_metadata = payload.get("metadata")
        if isinstance(extra_metadata, Mapping):
            self.metadata.update(dict(extra_metadata))

        self.add_event(
            "context_merged",
            "Runtime session merged new context.",
            {
                "risk_score": self.risk_score,
                "allowed_tools": list(self.allowed_tools),
                "blocked_tools": list(self.blocked_tools),
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "request_id": self.request_id,
            "status": self.status.value,
            "actor_id": self.actor_id,
            "agent_id": self.agent_id,
            "execution_id": self.execution_id,
            "policy_id": self.policy_id,
            "sandbox_id": self.sandbox_id,
            "review_id": self.review_id,
            "quarantine_id": self.quarantine_id,
            "checkpoint_id": self.checkpoint_id,
            "risk_score": self.risk_score,
            "trust_score": self.trust_score,
            "allowed_tools": list(self.allowed_tools),
            "blocked_tools": list(self.blocked_tools),
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
            "events": [event.to_dict() for event in self.events],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "completed_at": self.completed_at,
        }

    @staticmethod
    def _optional_str(value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @staticmethod
    def _normalize_str_list(value: Any, *, fallback: list[str] | None = None) -> list[str]:
        if value is None:
            return list(fallback or [])
        if isinstance(value, str):
            items = [part.strip() for part in value.split(",")]
            return [item for item in items if item]
        if isinstance(value, list | tuple | set):
            normalized = [str(item).strip() for item in value]
            return [item for item in normalized if item]
        return list(fallback or [])


class RuntimeSessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, RuntimeSession] = {}

    def create(self, payload: Mapping[str, Any] | None) -> RuntimeSession:
        data = dict(payload or {})
        session = RuntimeSession(
            session_id=str(data.get("session_id") or f"rts-{uuid4().hex}"),
            request_id=str(data.get("request_id") or f"req-{uuid4().hex}"),
            actor_id=RuntimeSession._optional_str(data.get("actor_id")),
            agent_id=RuntimeSession._optional_str(data.get("agent_id")),
            execution_id=RuntimeSession._optional_str(data.get("execution_id")),
            policy_id=RuntimeSession._optional_str(data.get("policy_id")),
            sandbox_id=RuntimeSession._optional_str(data.get("sandbox_id")),
            risk_score=int(data.get("risk_score", 0) or 0),
            trust_score=int(data["trust_score"]) if data.get("trust_score") is not None else None,
            allowed_tools=RuntimeSession._normalize_str_list(data.get("allowed_tools")),
            blocked_tools=RuntimeSession._normalize_str_list(data.get("blocked_tools")),
            tags=RuntimeSession._normalize_str_list(data.get("tags")),
            metadata=dict(data.get("metadata") or {}),
        )
        session.add_event("created", "Runtime session created.")
        self._sessions[session.session_id] = session
        return session

    def get(self, session_id: str) -> RuntimeSession | None:
        return self._sessions.get(session_id)

    def require(self, session_id: str) -> RuntimeSession:
        session = self.get(session_id)
        if session is None:
            raise KeyError(f"Runtime session not found: {session_id}")
        return session

    def upsert_from_supervisor(
        self,
        payload: Mapping[str, Any] | None,
        supervisor_decision: Mapping[str, Any],
    ) -> RuntimeSession:
        base = dict(payload or {})
        session_id = base.get("session_id")
        session = self.get(str(session_id)) if session_id else None

        if session is None:
            base["request_id"] = supervisor_decision.get("request_id") or base.get("request_id")
            session = self.create(base)

        session.merge_context(base)
        session.apply_supervisor_decision(supervisor_decision)
        self._sessions[session.session_id] = session
        return session

    def list(self) -> list[RuntimeSession]:
        return list(self._sessions.values())


class RuntimeSessionManager:
    def __init__(
        self,
        store: RuntimeSessionStore | None = None,
        *,
        sink: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        self.store = store or RuntimeSessionStore()
        self.sink = sink

    def start(self, payload: Mapping[str, Any] | None) -> RuntimeSession:
        session = self.store.create(payload)
        self._emit("runtime.session.started", session)
        return session

    def apply_supervisor_decision(
        self,
        payload: Mapping[str, Any] | None,
        supervisor_decision: Mapping[str, Any],
    ) -> RuntimeSession:
        session = self.store.upsert_from_supervisor(payload, supervisor_decision)
        self._emit("runtime.session.updated", session)
        return session

    def complete(self, session_id: str, reason: str = "Runtime session completed.") -> RuntimeSession:
        session = self.store.require(session_id)
        session.complete(reason)
        self._emit("runtime.session.completed", session)
        return session

    def fail(self, session_id: str, reason: str = "Runtime session failed.") -> RuntimeSession:
        session = self.store.require(session_id)
        session.fail(reason)
        self._emit("runtime.session.failed", session)
        return session

    def get(self, session_id: str) -> RuntimeSession | None:
        return self.store.get(session_id)

    def list(self) -> list[RuntimeSession]:
        return self.store.list()

    def _emit(self, event_name: str, session: RuntimeSession) -> None:
        if self.sink is not None:
            self.sink(
                {
                    "event": event_name,
                    "session": session.to_dict(),
                    "timestamp": datetime.now(UTC).isoformat(),
                },
            )


def create_runtime_session(payload: Mapping[str, Any] | None) -> RuntimeSession:
    return RuntimeSessionManager().start(payload)


def create_runtime_session_dict(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    return create_runtime_session(payload).to_dict()


__all__ = [
    "RuntimeSession",
    "RuntimeSessionEvent",
    "RuntimeSessionManager",
    "RuntimeSessionStatus",
    "RuntimeSessionStore",
    "create_runtime_session",
    "create_runtime_session_dict",
]
