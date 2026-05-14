from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


def _normalize(value: str | None) -> str:
    return (value or "").strip()


@dataclass(slots=True)
class _HistoryEvent:
    eventtype: str
    message: str
    status: str
    createdat: str = field(default_factory=_utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "eventtype": self.eventtype,
            "message": self.message,
            "status": self.status,
            "createdat": self.createdat,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class _History:
    historyid: str
    sessionid: str
    status: str
    generatedat: str
    entries: list[dict[str, Any]] = field(default_factory=list)

    # --- public surface ---

    def append_event(
        self,
        *,
        event_type: str,
        message: str = "",
        status: str = "ok",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalized = _normalize(event_type)
        if not normalized:
            raise ValueError("event_type is required and must not be blank")

        event = _HistoryEvent(
            eventtype=normalized,
            message=_normalize(message),
            status=_normalize(status) or "ok",
            metadata=dict(metadata or {}),
        )
        entry = event.as_dict()
        self.entries.append(entry)
        return entry

    def as_dict(self) -> dict[str, Any]:
        return {
            "historyid": self.historyid,
            "sessionid": self.sessionid,
            "status": self.status,
            "generatedat": self.generatedat,
            "entries": [dict(e) for e in self.entries],
        }


def build_history(
    *,
    session_id: str | None = None,
    history_id: str | None = None,
    status: str = "active",
) -> _History:
    resolved_session_id = _normalize(session_id) or _new_id("session")
    resolved_history_id = _normalize(history_id) or _new_id("history")
    normalized_status = _normalize(status) or "active"

    return _History(
        historyid=resolved_history_id,
        sessionid=resolved_session_id,
        status=normalized_status,
        generatedat=_utc_now(),
        entries=[],
    )
