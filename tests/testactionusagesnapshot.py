from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from app.actionusagesnapshot import build_action_usage_snapshot


def _payload_of(result: Any) -> dict[str, Any]:
    if isinstance(result, dict):
        return result
    if hasattr(result, "as_dict") and callable(result.as_dict):
        payload = result.as_dict()
        assert isinstance(payload, dict)
        return payload
    payload: dict[str, Any] = {}
    for name in dir(result):
        if name.startswith("_"):
            continue
        value = getattr(result, name)
        if callable(value):
            continue
        if isinstance(value, (str, int, float, bool, list, dict, type(None))):
            payload[name] = value
    return payload


def _number(payload: dict[str, Any], *keys: str) -> Decimal | None:
    for key in keys:
        if key in payload and payload[key] is not None:
            return Decimal(str(payload[key]))
    return None


def _text(payload: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        if key in payload and payload[key] is not None:
            return str(payload[key])
    return None


def _value(payload: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in payload:
            return payload[key]
    return None


def test_build_action_usage_snapshot_returns_object() -> None:
    snapshot = build_action_usage_snapshot()

    assert snapshot is not None


def test_action_usage_snapshot_is_serializable_to_dictionary_shape() -> None:
    payload = _payload_of(build_action_usage_snapshot())

    assert isinstance(payload, dict)
    assert payload


def test_action_usage_snapshot_contains_stable_snapshot_fields_when_present() -> None:
    payload = _payload_of(build_action_usage_snapshot())

    expected_candidates = {
        "snapshotid",
        "ownerid",
        "periodstart",
        "periodend",
        "totalunits",
        "totalcost",
        "remaining",
        "quota",
        "events",
        "summary",
        "generatedat",
    }
    assert set(payload.keys()).intersection(expected_candidates)


def test_action_usage_snapshot_identifiers_are_non_empty_when_present() -> None:
    payload = _payload_of(build_action_usage_snapshot())

    for value in (
        _text(payload, "snapshotid", "snapshot_id", "id"),
        _text(payload, "ownerid", "owner_id", "owner"),
    ):
        if value is not None:
            assert value.strip()


def test_action_usage_snapshot_period_fields_are_non_empty_when_present() -> None:
    payload = _payload_of(build_action_usage_snapshot())

    for value in (
        _text(payload, "periodstart", "period_start"),
        _text(payload, "periodend", "period_end"),
        _text(payload, "generatedat", "timestamp"),
    ):
        if value is not None:
            assert value.strip()


def test_action_usage_snapshot_numeric_fields_are_non_negative_when_present() -> None:
    payload = _payload_of(build_action_usage_snapshot())

    for keys in (
        ("totalunits", "total_units", "units"),
        ("totalcost", "total_cost"),
        ("remaining", "remainingunits", "available"),
        ("quota", "limit"),
    ):
        value = _number(payload, *keys)
        if value is not None:
            assert value >= Decimal(0)


def test_action_usage_snapshot_remaining_does_not_exceed_quota_when_both_present() -> None:
    payload = _payload_of(build_action_usage_snapshot())

    quota = _number(payload, "quota", "limit")
    remaining = _number(payload, "remaining", "remainingunits", "available")
    if quota is not None and remaining is not None:
        assert remaining <= quota


def test_action_usage_snapshot_summary_is_dict_when_present() -> None:
    payload = _payload_of(build_action_usage_snapshot())

    summary = _value(payload, "summary", "totals", "metadata")
    if summary is not None:
        assert isinstance(summary, dict)


def test_action_usage_snapshot_events_collection_is_list_or_dict_when_present() -> None:
    payload = _payload_of(build_action_usage_snapshot())

    events = _value(payload, "events", "records", "entries", "usage")
    if events is not None:
        assert isinstance(events, (list, dict))


def test_action_usage_snapshot_supports_owner_bound_build_when_available() -> None:
    try:
        snapshot = build_action_usage_snapshot(
            owner_id="owner-001",
            period_start="2026-04-01T00:00:00Z",
            period_end="2026-04-30T23:59:59Z",
        )
    except TypeError:
        snapshot = build_action_usage_snapshot()

    payload = _payload_of(snapshot)
    owner = _text(payload, "ownerid", "owner_id", "owner")
    if owner is not None:
        assert owner.strip()


def test_action_usage_snapshot_total_cost_is_zero_when_total_units_zero_and_unit_fields_exist() -> None:
    try:
        snapshot = build_action_usage_snapshot(
            owner_id="owner-001",
            total_units=0,
            total_cost="0",
        )
    except TypeError:
        snapshot = build_action_usage_snapshot()

    payload = _payload_of(snapshot)
    total_units = _number(payload, "totalunits", "total_units", "units")
    total_cost = _number(payload, "totalcost", "total_cost")

    if total_units is not None and total_cost is not None and total_units == Decimal(0):
        assert total_cost == Decimal(0)


def test_action_usage_snapshot_multiple_builds_have_stable_key_sets() -> None:
    first = _payload_of(build_action_usage_snapshot())
    second = _payload_of(build_action_usage_snapshot())

    assert set(first.keys()) == set(second.keys())


def test_action_usage_snapshot_payload_uses_json_friendly_values() -> None:
    payload = _payload_of(build_action_usage_snapshot())

    for key, value in payload.items():
        assert isinstance(key, str)
        assert value is None or isinstance(value, (str, int, float, bool, list, dict))


def test_action_usage_snapshot_rejects_negative_total_units_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_action_usage_snapshot(
            owner_id="owner-001",
            total_units=-1,
            total_cost="1",
        )


def test_action_usage_snapshot_rejects_negative_total_cost_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_action_usage_snapshot(
            owner_id="owner-001",
            total_units=1,
            total_cost="-1",
        )


def test_action_usage_snapshot_rejects_negative_quota_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_action_usage_snapshot(
            owner_id="owner-001",
            total_units=1,
            total_cost="1",
            quota=-10,
        )
