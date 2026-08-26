from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import Lock
from typing import Any


def _normalize_api_key_id(api_key_id: str) -> str:
    normalized = str(api_key_id).strip()
    if not normalized:
        raise ValueError("api_key_id must not be empty")
    return normalized


def _normalize_route(route: str) -> str:
    normalized = str(route).strip()
    if not normalized:
        raise ValueError("route must not be empty")
    return normalized


def _normalize_method(method: str) -> str:
    normalized = str(method).strip().upper()
    return normalized or "GET"


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
    """In-memory metering registry for local-first revenue experiments.

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
        normalized_api_key_id = _normalize_api_key_id(api_key_id)
        normalized_route = _normalize_route(route)
        normalized_method = _normalize_method(method)

        try:
            normalized_status_code = int(status_code)
        except (TypeError, ValueError) as exc:
            raise TypeError("status_code must be int-compatible") from exc

        normalized_units = max(1, int(units))
        now = datetime.now(UTC)
        event = UsageEvent(
            timestamp=now,
            api_key_id=normalized_api_key_id,
            route=normalized_route,
            method=normalized_method,
            status_code=normalized_status_code,
            units=normalized_units,
            metadata=dict(metadata or {}),
        )

        with self._lock:
            self._events.append(event)

            summary = self._summaries.get(normalized_api_key_id)
            if summary is None:
                summary = UsageSummary(api_key_id=normalized_api_key_id)
                self._summaries[normalized_api_key_id] = summary

            summary.total_requests += 1
            summary.total_units += event.units
            summary.last_seen_at = now
            summary.routes[normalized_route] = summary.routes.get(normalized_route, 0) + 1

        return event

    def get_summary(self, api_key_id: str) -> UsageSummary:
        normalized_api_key_id = _normalize_api_key_id(api_key_id)

        with self._lock:
            summary = self._summaries.get(normalized_api_key_id)
            if summary is None:
                return UsageSummary(api_key_id=normalized_api_key_id)
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
