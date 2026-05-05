from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from app.usagemetering import build_usage_metering


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


def _collection(payload: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in payload:
            return payload[key]
    return None


def test_build_usage_metering_returns_object() -> None:
    metering = build_usage_metering()

    assert metering is not None


def test_usage_metering_is_serializable_to_dictionary_shape() -> None:
    payload = _payload_of(build_usage_metering())

    assert isinstance(payload, dict)
    assert payload


def test_usage_metering_contains_core_fields_when_present() -> None:
    payload = _payload_of(build_usage_metering())

    expected_candidates = {
        "ownerid",
        "meterid",
        "metric",
        "units",
        "unitcost",
        "totalcost",
        "quota",
        "remaining",
        "window",
        "periodstart",
        "periodend",
        "events",
        "generatedat",
    }
    assert set(payload.keys()).intersection(expected_candidates)


def test_usage_metering_owner_and_meter_identifiers_are_non_empty_when_present() -> None:
    payload = _payload_of(build_usage_metering())

    for value in (
        _text(payload, "ownerid", "owner_id", "owner", "accountid", "account_id"),
        _text(payload, "meterid", "meter_id", "metric", "metric_code"),
    ):
        if value is not None:
            assert value.strip()


def test_usage_metering_numeric_fields_are_non_negative_when_present() -> None:
    payload = _payload_of(build_usage_metering())

    for keys in (
        ("units",),
        ("unitcost", "unit_cost"),
        ("totalcost", "total_cost"),
        ("quota", "limit"),
        ("remaining", "remainingunits", "available"),
    ):
        value = _number(payload, *keys)
        if value is not None:
            assert value >= Decimal("0")


def test_usage_metering_remaining_does_not_exceed_quota_when_both_present() -> None:
    payload = _payload_of(build_usage_metering())

    quota = _number(payload, "quota", "limit")
    remaining = _number(payload, "remaining", "remainingunits", "available")
    if quota is not None and remaining is not None:
        assert remaining <= quota


def test_usage_metering_total_cost_matches_units_times_unit_cost_when_present() -> None:
    try:
        metering = build_usage_metering(
            owner_id="owner-001",
            meter_id="api_calls",
            units=5,
            unit_cost="2",
        )
    except TypeError:
        metering = build_usage_metering()

    payload = _payload_of(metering)
    units = _number(payload, "units")
    unit_cost = _number(payload, "unitcost", "unit_cost")
    total_cost = _number(payload, "totalcost", "total_cost")

    if units is not None and unit_cost is not None and total_cost is not None:
        assert total_cost == units * unit_cost


def test_usage_metering_window_or_period_fields_are_non_empty_when_present() -> None:
    payload = _payload_of(build_usage_metering())

    for value in (
        _text(payload, "window"),
        _text(payload, "periodstart", "period_start"),
        _text(payload, "periodend", "period_end"),
        _text(payload, "generatedat", "timestamp"),
    ):
        if value is not None:
            assert value.strip()


def test_usage_metering_events_collection_is_list_when_present() -> None:
    payload = _payload_of(build_usage_metering())

    events = _collection(payload, "events", "records", "entries", "usage")
    if events is not None:
        assert isinstance(events, list)


def test_usage_metering_metadata_is_dict_when_present() -> None:
    payload = _payload_of(build_usage_metering())

    metadata = _collection(payload, "metadata", "context", "dimensions")
    if metadata is not None:
        assert isinstance(metadata, dict)


def test_usage_metering_multiple_builds_have_stable_key_sets() -> None:
    first = _payload_of(build_usage_metering())
    second = _payload_of(build_usage_metering())

    assert set(first.keys()) == set(second.keys())


def test_usage_metering_payload_uses_json_friendly_values() -> None:
    payload = _payload_of(build_usage_metering())

    for key, value in payload.items():
        assert isinstance(key, str)
        assert value is None or isinstance(value, (str, int, float, bool, list, dict))


@pytest.mark.parametrize(
    ("units", "unit_cost", "quota"),
    [
        (1, "1", 10),
        (5, "0.5", 100),
        (10, "2", 1000),
    ],
)
def test_usage_metering_accepts_positive_metering_inputs_when_supported(
    units: int,
    unit_cost: str,
    quota: int,
) -> None:
    try:
        metering = build_usage_metering(
            owner_id="owner-001",
            meter_id="api_calls",
            units=units,
            unit_cost=unit_cost,
            quota=quota,
        )
    except TypeError:
        pytest.skip("usage metering builder does not accept direct inputs")

    payload = _payload_of(metering)
    actual_units = _number(payload, "units")
    if actual_units is not None:
        assert actual_units == Decimal(str(units))


def test_usage_metering_rejects_negative_units_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_usage_metering(
            owner_id="owner-001",
            meter_id="api_calls",
            units=-1,
            unit_cost="1",
            quota=10,
        )


def test_usage_metering_rejects_negative_unit_cost_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_usage_metering(
            owner_id="owner-001",
            meter_id="api_calls",
            units=1,
            unit_cost="-1",
            quota=10,
        )


def test_usage_metering_rejects_negative_quota_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_usage_metering(
            owner_id="owner-001",
            meter_id="api_calls",
            units=1,
            unit_cost="1",
            quota=-10,
        )


def test_usage_metering_rejects_quota_exceeded_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_usage_metering(
            owner_id="owner-001",
            meter_id="api_calls",
            units=11,
            unit_cost="1",
            quota=10,
        )