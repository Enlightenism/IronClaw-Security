from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import RLock
from typing import Any

__all__ = [
    "UsageTelemetryEvent",
    "UsageTelemetrySummary",
    "UsageMeteringService",
    "get_usage_metering_service",
]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _normalize_owner_key(owner_key: str) -> str:
    normalized = str(owner_key).strip().lower()
    if not normalized:
        raise ValueError("owner_key must not be empty")
    return normalized


def _normalize_key_id(key_id: str | None) -> str | None:
    if key_id is None:
        return None
    normalized = str(key_id).strip()
    return normalized or None


@dataclass(slots=True)
class UsageTelemetryEvent:
    event_id: str
    owner_key: str
    key_id: str | None
    action: str
    blocked_attacks: int = 0
    allowed_actions: int = 0
    denied_prompts: int = 0
    prompt_injection_attempts: int = 0
    units_consumed: int = 0
    recorded_at: datetime = field(default_factory=_utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "owner_key": self.owner_key,
            "key_id": self.key_id,
            "action": self.action,
            "blocked_attacks": self.blocked_attacks,
            "allowed_actions": self.allowed_actions,
            "denied_prompts": self.denied_prompts,
            "prompt_injection_attempts": self.prompt_injection_attempts,
            "units_consumed": self.units_consumed,
            "recorded_at": self.recorded_at.isoformat().replace("+00:00", "Z"),
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class UsageTelemetrySummary:
    owner_key: str
    key_id: str | None = None
    total_allowed_actions: int = 0
    total_denied_prompts: int = 0
    total_prompt_injection_attempts: int = 0
    total_blocked_attacks: int = 0
    total_units_consumed: int = 0
    last_seen_at: datetime | None = None
    action_usage: dict[str, dict[str, int]] = field(default_factory=dict)

    def _touch_action(self, action: str) -> dict[str, int]:
        bucket = self.action_usage.setdefault(
            action,
            {
                "count": 0,
                "allowed_actions": 0,
                "denied_prompts": 0,
                "prompt_injection_attempts": 0,
                "blocked_attacks": 0,
                "units_consumed": 0,
            },
        )
        return bucket

    def add_event(self, event: UsageTelemetryEvent) -> None:
        self.total_allowed_actions += int(event.allowed_actions)
        self.total_denied_prompts += int(event.denied_prompts)
        self.total_prompt_injection_attempts += int(event.prompt_injection_attempts)
        self.total_blocked_attacks += int(event.blocked_attacks)
        self.total_units_consumed += int(event.units_consumed)
        self.last_seen_at = max(self.last_seen_at or event.recorded_at, event.recorded_at)

        bucket = self._touch_action(event.action)
        bucket["count"] += 1
        bucket["allowed_actions"] += int(event.allowed_actions)
        bucket["denied_prompts"] += int(event.denied_prompts)
        bucket["prompt_injection_attempts"] += int(event.prompt_injection_attempts)
        bucket["blocked_attacks"] += int(event.blocked_attacks)
        bucket["units_consumed"] += int(event.units_consumed)

    def as_dict(self) -> dict[str, Any]:
        return {
            "owner_key": self.owner_key,
            "key_id": self.key_id,
            "total_allowed_actions": self.total_allowed_actions,
            "total_denied_prompts": self.total_denied_prompts,
            "total_prompt_injection_attempts": self.total_prompt_injection_attempts,
            "total_blocked_attacks": self.total_blocked_attacks,
            "total_units_consumed": self.total_units_consumed,
            "last_seen_at": self.last_seen_at.isoformat().replace("+00:00", "Z") if self.last_seen_at else None,
            "action_usage": {k: dict(v) for k, v in sorted(self.action_usage.items())},
        }


class UsageMeteringService:
    """Telemetry store that matches the dashboard's owner/key usage schema.

    Each event is associated with an owner_key and, when available, a key_id so
    the dashboard can show per-user and per-key usage without duplication.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._events: list[UsageTelemetryEvent] = []
        self._owner_summaries: dict[str, UsageTelemetrySummary] = {}
        self._key_summaries: dict[tuple[str, str], UsageTelemetrySummary] = {}

    def _build_event(
        self,
        *,
        owner_key: str,
        key_id: str | None,
        action: str,
        blocked_attacks: int = 0,
        allowed: bool = False,
        denied_prompt: bool = False,
        prompt_injection_attempt: bool = False,
        units_consumed: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> UsageTelemetryEvent:
        normalized_owner = _normalize_owner_key(owner_key)
        normalized_key = _normalize_key_id(key_id)
        normalized_action = str(action).strip() or "unknown"

        event = UsageTelemetryEvent(
            event_id=f"usage_{datetime.now(UTC).strftime('%Y%m%d%H%M%S%f')}_{abs(hash((normalized_owner, normalized_key or '', normalized_action))) % 1_000_000:06d}",
            owner_key=normalized_owner,
            key_id=normalized_key,
            action=normalized_action,
            blocked_attacks=max(0, int(blocked_attacks)),
            allowed_actions=1 if allowed else 0,
            denied_prompts=1 if denied_prompt else 0,
            prompt_injection_attempts=1 if prompt_injection_attempt else 0,
            units_consumed=max(0, int(units_consumed)),
            metadata=dict(metadata or {}),
        )
        return event

    def record_action_event(
        self,
        *,
        owner_key: str,
        key_id: str | None = None,
        action: str,
        blocked_attacks: int = 0,
        allowed: bool = False,
        denied_prompt: bool = False,
        prompt_injection_attempt: bool = False,
        units_consumed: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> UsageTelemetryEvent:
        event = self._build_event(
            owner_key=owner_key,
            key_id=key_id,
            action=action,
            blocked_attacks=blocked_attacks,
            allowed=allowed,
            denied_prompt=denied_prompt,
            prompt_injection_attempt=prompt_injection_attempt,
            units_consumed=units_consumed,
            metadata=metadata,
        )

        with self._lock:
            self._events.append(event)

            owner_summary = self._owner_summaries.setdefault(
                event.owner_key,
                UsageTelemetrySummary(owner_key=event.owner_key),
            )
            owner_summary.add_event(event)

            if event.key_id is not None:
                key_summary = self._key_summaries.setdefault(
                    (event.owner_key, event.key_id),
                    UsageTelemetrySummary(owner_key=event.owner_key, key_id=event.key_id),
                )
                key_summary.add_event(event)

        return event

    def record_event(
        self,
        *,
        owner_key: str,
        key_id: str | None = None,
        action: str,
        blocked_attacks: int = 0,
        allowed: bool = False,
        denied_prompt: bool = False,
        prompt_injection_attempt: bool = False,
        units_consumed: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> UsageTelemetryEvent:
        return self.record_action_event(
            owner_key=owner_key,
            key_id=key_id,
            action=action,
            blocked_attacks=blocked_attacks,
            allowed=allowed,
            denied_prompt=denied_prompt,
            prompt_injection_attempt=prompt_injection_attempt,
            units_consumed=units_consumed,
            metadata=metadata,
        )

    def get_owner_summary(self, owner_key: str) -> dict[str, Any]:
        normalized_owner = _normalize_owner_key(owner_key)
        with self._lock:
            summary = self._owner_summaries.get(normalized_owner)
            if summary is None:
                return UsageTelemetrySummary(owner_key=normalized_owner).as_dict()
            return summary.as_dict()

    def get_key_summary(self, owner_key: str, key_id: str) -> dict[str, Any]:
        normalized_owner = _normalize_owner_key(owner_key)
        normalized_key = _normalize_key_id(key_id)
        if normalized_key is None:
            raise ValueError("key_id must not be empty")

        with self._lock:
            summary = self._key_summaries.get((normalized_owner, normalized_key))
            if summary is None:
                return UsageTelemetrySummary(owner_key=normalized_owner, key_id=normalized_key).as_dict()
            return summary.as_dict()

    def list_events(self, *, limit: int = 100, owner_key: str | None = None, key_id: str | None = None) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 1000))
        with self._lock:
            events = self._events
            if owner_key is not None:
                normalized_owner = _normalize_owner_key(owner_key)
                events = [event for event in events if event.owner_key == normalized_owner]
            if key_id is not None:
                normalized_key = _normalize_key_id(key_id)
                events = [event for event in events if event.key_id == normalized_key]
            return [event.as_dict() for event in events[-safe_limit:]]

    def recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.list_events(limit=limit)

    def as_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "total_events": len(self._events),
                "owners": {k: v.as_dict() for k, v in sorted(self._owner_summaries.items())},
                "keys": {f"{owner}|{key}": v.as_dict() for (owner, key), v in sorted(self._key_summaries.items())},
            }


_usage_metering_service = UsageMeteringService()


def get_usage_metering_service() -> UsageMeteringService:
    return _usage_metering_service
