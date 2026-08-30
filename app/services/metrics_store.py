from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import RLock
from typing import Any

__all__ = [
    "IntegrationLatencySummary",
    "IntegrationThroughputSummary",
    "MetricsStore",
    "get_integration_latency_summary",
    "get_integration_throughput_summary",
]


@dataclass(frozen=True, slots=True)
class IntegrationLatencySummary:
    integration_id: str
    p50_ms: float
    p95_ms: float
    p99_ms: float
    sample_count: int = 0


@dataclass(frozen=True, slots=True)
class IntegrationThroughputSummary:
    integration_id: str
    requests_1m: int = 0
    requests_1h: int = 0
    requests_24h: int = 0
    errors_1m: int = 0
    errors_1h: int = 0
    errors_24h: int = 0
    window_seconds: int = 3600


class MetricsStore:
    """In-memory metrics registry for integration dashboards and observability views."""

    _instance: MetricsStore | None = None
    _lock = RLock()

    def __init__(self) -> None:
        self._events: dict[str, list[dict[str, Any]]] = defaultdict(list)

    @classmethod
    def current(cls) -> MetricsStore:
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @classmethod
    def reset(cls) -> None:
        with cls._lock:
            cls._instance = None

    def record(
        self,
        integration_id: str,
        *,
        requests: int = 0,
        errors: int = 0,
        latency_ms: float | None = None,
        occurred_at: datetime | None = None,
    ) -> None:
        timestamp = occurred_at or datetime.now(UTC)
        self._events[str(integration_id)].append(
            {
                "integration_id": str(integration_id),
                "requests": max(0, int(requests)),
                "errors": max(0, int(errors)),
                "latency_ms": float(latency_ms) if latency_ms is not None else 0.0,
                "occurred_at": timestamp,
            }
        )

    def _window_events(self, integration_id: str, seconds: int) -> list[dict[str, Any]]:
        now = datetime.now(UTC)
        cutoff = now - timedelta(seconds=seconds)
        events = self._events.get(str(integration_id), [])
        return [event for event in events if event["occurred_at"] >= cutoff]

    def get_integration_latency_summary(self, integration_id: str) -> IntegrationLatencySummary:
        values = [float(event["latency_ms"]) for event in self._events.get(str(integration_id), []) if event.get("latency_ms") is not None]
        if not values:
            return IntegrationLatencySummary(integration_id=str(integration_id), p50_ms=0.0, p95_ms=0.0, p99_ms=0.0, sample_count=0)

        ordered = sorted(values)
        sample_count = len(ordered)

        def percentile(p: float) -> float:
            if sample_count == 0:
                return 0.0
            index = max(0, min(sample_count - 1, int((sample_count * p) - 0.5)))
            return ordered[index]

        return IntegrationLatencySummary(
            integration_id=str(integration_id),
            p50_ms=percentile(0.50),
            p95_ms=percentile(0.95),
            p99_ms=percentile(0.99),
            sample_count=sample_count,
        )

    def get_integration_throughput_summary(self, integration_id: str) -> IntegrationThroughputSummary:
        key = str(integration_id)
        events = self._events.get(key, [])
        if not events:
            return IntegrationThroughputSummary(
                integration_id=key,
                requests_1m=0,
                requests_1h=0,
                requests_24h=0,
                errors_1m=0,
                errors_1h=0,
                errors_24h=0,
                window_seconds=3600,
            )

        now = datetime.now(UTC)
        windows = {
            60: now - timedelta(seconds=60),
            3600: now - timedelta(seconds=3600),
            86400: now - timedelta(seconds=86400),
        }

        requests_1m = 0
        requests_1h = 0
        requests_24h = 0
        errors_1m = 0
        errors_1h = 0
        errors_24h = 0

        for event in events:
            occurred_at = event["occurred_at"]
            requests = int(event["requests"])
            errors = int(event["errors"])

            if occurred_at >= windows[60]:
                requests_1m += requests
                errors_1m += errors
            if occurred_at >= windows[3600]:
                requests_1h += requests
                errors_1h += errors
            if occurred_at >= windows[86400]:
                requests_24h += requests
                errors_24h += errors

        return IntegrationThroughputSummary(
            integration_id=key,
            requests_1m=requests_1m,
            requests_1h=requests_1h,
            requests_24h=requests_24h,
            errors_1m=errors_1m,
            errors_1h=errors_1h,
            errors_24h=errors_24h,
            window_seconds=3600,
        )


def get_integration_latency_summary(store: MetricsStore, integration_id: str) -> IntegrationLatencySummary:
    return store.get_integration_latency_summary(integration_id)


def get_integration_throughput_summary(store: MetricsStore, integration_id: str) -> IntegrationThroughputSummary:
    return store.get_integration_throughput_summary(integration_id)
