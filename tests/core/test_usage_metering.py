from __future__ import annotations

import pytest

from app.core.usage_metering import UsageMeteringRegistry


@pytest.fixture()
def registry() -> UsageMeteringRegistry:
    return UsageMeteringRegistry()


def test_record_event_tracks_units_and_route(registry: UsageMeteringRegistry) -> None:
    event = registry.record_event(
        api_key_id=" key-123 ",
        route="/guard",
        method="post",
        status_code=200,
        units=3,
        metadata={"request_id": "req-1"},
    )

    assert event.api_key_id == "key-123"
    assert event.route == "/guard"
    assert event.method == "POST"
    assert event.status_code == 200
    assert event.units == 3
    assert event.metadata["request_id"] == "req-1"

    summary = registry.get_summary("key-123")
    assert summary.total_requests == 1
    assert summary.total_units == 3
    assert summary.routes == {"/guard": 1}
    assert summary.last_seen_at is not None


def test_record_event_keeps_distinct_api_keys_separate(registry: UsageMeteringRegistry) -> None:
    registry.record_event(api_key_id="key-a", route="/scan", method="get", status_code=200, units=2)
    registry.record_event(api_key_id="key-b", route="/scan", method="get", status_code=200, units=5)

    summary_a = registry.get_summary("key-a")
    summary_b = registry.get_summary("key-b")

    assert summary_a.total_requests == 1
    assert summary_a.total_units == 2
    assert summary_b.total_requests == 1
    assert summary_b.total_units == 5


def test_list_summaries_returns_all_keys(registry: UsageMeteringRegistry) -> None:
    registry.record_event(api_key_id="alpha", route="/guard", method="get", status_code=200, units=1)
    registry.record_event(api_key_id="beta", route="/scan", method="post", status_code=401, units=4)

    summaries = registry.list_summaries()

    assert len(summaries) == 2
    ids = {summary.api_key_id for summary in summaries}
    assert ids == {"alpha", "beta"}


def test_recent_events_honors_limit(registry: UsageMeteringRegistry) -> None:
    registry.record_event(api_key_id="key-x", route="/guard", method="get", status_code=200, units=1)
    registry.record_event(api_key_id="key-x", route="/scan", method="get", status_code=200, units=2)
    registry.record_event(api_key_id="key-x", route="/verify", method="get", status_code=200, units=3)

    events = registry.recent_events(limit=2)

    assert len(events) == 2
    assert events[0].route == "/scan"
    assert events[1].route == "/verify"


def test_get_summary_for_unknown_key_returns_empty_summary(registry: UsageMeteringRegistry) -> None:
    summary = registry.get_summary("missing-key")

    assert summary.api_key_id == "missing-key"
    assert summary.total_requests == 0
    assert summary.total_units == 0
    assert summary.routes == {}
    assert summary.last_seen_at is None


def test_record_event_rejects_blank_api_key_and_route() -> None:
    registry = UsageMeteringRegistry()

    with pytest.raises(ValueError):
        registry.record_event(api_key_id="   ", route="/guard", method="get", status_code=200)

    with pytest.raises(ValueError):
        registry.record_event(api_key_id="key-1", route="   ", method="get", status_code=200)


def test_record_event_coerces_non_positive_units_to_one() -> None:
    registry = UsageMeteringRegistry()

    event = registry.record_event(api_key_id="key-1", route="/guard", method="get", status_code=200, units=0)

    assert event.units == 1
    assert registry.get_summary("key-1").total_units == 1
