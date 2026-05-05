from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import Lock
from typing import Any


@dataclass
class UsageEvent:
    timestamp: datetime
    api_key_id: str
    route: str
    method: str
    status_code: int
    units: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class UsageSummary:
    api_key_id: str
    total_requests: int = 0
    total_units: int = 0
    last_seen_at: datetime | None = None
    routes: dict[str, int] = field(default_factory=dict)


class UsageMeteringRegistry:
    """
    In-memory metering registry for local-first revenue experiments.

    Tracks:
    - total requests per API key
    - total billable units per API key
    - route distribution
    - last seen timestamp

    This contract is intentionally simple so it can later be replaced by
    a database-backed or streaming implementation without changing route logic.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._events: list[UsageEvent] = []
        self._summaries: dict[str, UsageSummary] = {}

    def record_event(
        self,
        *,
        api_key_id: str,
        route: str,
        method: str,
        status_code: int,
        units: int = 1,
        metadata: dict[str, Any] | None = None,
    ) -> UsageEvent:
        now = datetime.now(UTC)
        event = UsageEvent(
            timestamp=now,
            api_key_id=api_key_id,
            route=route,
            method=method.upper(),
            status_code=status_code,
            units=max(1, int(units)),
            metadata=metadata or {},
        )

        with self._lock:
            self._events.append(event)

            summary = self._summaries.get(api_key_id)
            if summary is None:
                summary = UsageSummary(api_key_id=api_key_id)
                self._summaries[api_key_id] = summary

            summary.total_requests += 1
            summary.total_units += event.units
            summary.last_seen_at = now
            summary.routes[route] = summary.routes.get(route, 0) + 1

        return event

    def get_summary(self, api_key_id: str) -> UsageSummary:
        with self._lock:
            summary = self._summaries.get(api_key_id)
            if summary is None:
                return UsageSummary(api_key_id=api_key_id)
            return UsageSummary(
                api_key_id=summary.api_key_id,
                total_requests=summary.total_requests,
                total_units=summary.total_units,
                last_seen_at=summary.last_seen_at,
                routes=dict(summary.routes),
            )

    def list_summaries(self) -> list[UsageSummary]:
        with self._lock:
            return [
                UsageSummary(
                    api_key_id=summary.api_key_id,
                    total_requests=summary.total_requests,
                    total_units=summary.total_units,
                    last_seen_at=summary.last_seen_at,
                    routes=dict(summary.routes),
                )
                for summary in self._summaries.values()
            ]

    def recent_events(self, limit: int = 100) -> list[UsageEvent]:
        safe_limit = max(1, min(int(limit), 500))
        with self._lock:
            return list(self._events[-safe_limit:])


_usage_metering_registry = UsageMeteringRegistry()


def get_usage_metering_registry() -> UsageMeteringRegistry:
    return _usage_metering_registry