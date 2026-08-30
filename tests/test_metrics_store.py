from __future__ import annotations

from datetime import UTC, datetime

from app.services.metrics_store import (
    MetricsStore,
    get_integration_latency_summary,
    get_integration_throughput_summary,
)


def test_metrics_store_current_and_summary_helpers() -> None:
    MetricsStore.reset()
    store = MetricsStore.current()
    now = datetime.now(UTC)

    store.record(
        "integration-abc",
        requests=12,
        errors=2,
        latency_ms=250.0,
        occurred_at=now,
    )

    latency = get_integration_latency_summary(store, "integration-abc")
    throughput = get_integration_throughput_summary(store, "integration-abc")

    assert latency.integration_id == "integration-abc"
    assert latency.p50_ms == 250.0
    assert latency.p95_ms == 250.0
    assert throughput.requests_1h == 12
    assert throughput.errors_1h == 2
    assert throughput.window_seconds == 3600
