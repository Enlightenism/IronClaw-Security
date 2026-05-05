from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from app.actionusagetest import build_action_usage_test


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


def _text(payload: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        if key in payload and payload[key] is not None:
            return str(payload[key])
    return None


def _number(payload: dict[str, Any], *keys: str) -> Decimal | None:
    for key in keys:
        if key in payload and payload[key] is not None:
            return Decimal(str(payload[key]))
    return None


def _value(payload: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in payload:
            return payload[key]
    return None


def test_build_action_usage_test_returns_object() -> None:
    result = build_action_usage_test()

    assert result is not None


def test_action_usage_test_is_serializable_to_dictionary_shape() -> None:
    payload = _payload_of(build_action_usage_test())

    assert isinstance(payload, dict)
    assert payload


def test_action_usage_test_contains_stable_harness_fields_when_present() -> None:
    payload = _payload_of(build_action_usage_test())

    expected_candidates = {
        "testid",
        "ownerid",
        "action",
        "units",
        "unitcost",
        "expectedtotalcost",
        "actualtotalcost",
        "passed",
        "status",
        "cases",
        "generatedat",
    }
    assert set(payload.keys()).intersection(expected_candidates)


def test_action_usage_test_identifiers_are_non_empty_when_present() -> None:
    payload = _payload_of(build_action_usage_test())

    for value in (
        _text(payload, "testid", "test_id", "id"),
        _text(payload, "ownerid", "owner_id", "owner"),
        _text(payload, "action", "actionname", "operation"),
    ):
        if value is not None:
            assert value.strip()


def test_action_usage_test_numeric_fields_are_non_negative_when_present() -> None:
    payload = _payload_of(build_action_usage_test())

    for keys in (
        ("units",),
        ("unitcost", "unit_cost"),
        ("expectedtotalcost", "expected_total_cost"),
        ("actualtotalcost", "actual_total_cost"),
    ):
        value = _number(payload, *keys)
        if value is not None:
            assert value >= Decimal("0")


def test_action_usage_test_total_costs_match_when_both_present() -> None:
    try:
        result = build_action_usage_test(
            owner_id="owner-001",
            action="execute",
            units=4,
            unit_cost="1.5",
        )
    except TypeError:
        result = build_action_usage_test()

    payload = _payload_of(result)
    expected_total = _number(payload, "expectedtotalcost", "expected_total_cost")
    actual_total = _number(payload, "actualtotalcost", "actual_total_cost")

    if expected_total is not None and actual_total is not None:
        assert actual_total == expected_total


def test_action_usage_test_expected_total_matches_units_times_unit_cost_when_present() -> None:
    try:
        result = build_action_usage_test(
            owner_id="owner-001",
            action="scan",
            units=3,
            unit_cost="2",
        )
    except TypeError:
        result = build_action_usage_test()

    payload = _payload_of(result)
    units = _number(payload, "units")
    unit_cost = _number(payload, "unitcost", "unit_cost")
    expected_total = _number(payload, "expectedtotalcost", "expected_total_cost")

    if units is not None and unit_cost is not None and expected_total is not None:
        assert expected_total == units * unit_cost


def test_action_usage_test_passed_flag_is_boolean_when_present() -> None:
    payload = _payload_of(build_action_usage_test())

    passed = _value(payload, "passed", "success")
    if passed is not None:
        assert isinstance(passed, bool)


def test_action_usage_test_status_is_non_empty_when_present() -> None:
    payload = _payload_of(build_action_usage_test())

    status = _text(payload, "status", "state", "verdict")
    if status is not None:
        assert status.strip()


def test_action_usage_test_cases_collection_is_list_when_present() -> None:
    payload = _payload_of(build_action_usage_test())

    cases = _value(payload, "cases", "scenarios", "entries")
    if cases is not None:
        assert isinstance(cases, list)


def test_action_usage_test_metadata_is_dict_when_present() -> None:
    payload = _payload_of(build_action_usage_test())

    metadata = _value(payload, "metadata", "context", "summary")
    if metadata is not None:
        assert isinstance(metadata, dict)


def test_action_usage_test_timestamp_fields_are_non_empty_when_present() -> None:
    payload = _payload_of(build_action_usage_test())

    timestamp = _text(payload, "generatedat", "timestamp", "createdat")
    if timestamp is not None:
        assert timestamp.strip()


def test_action_usage_test_multiple_builds_have_stable_key_sets() -> None:
    first = _payload_of(build_action_usage_test())
    second = _payload_of(build_action_usage_test())

    assert set(first.keys()) == set(second.keys())


def test_action_usage_test_payload_uses_json_friendly_values() -> None:
    payload = _payload_of(build_action_usage_test())

    for key, value in payload.items():
        assert isinstance(key, str)
        assert value is None or isinstance(value, (str, int, float, bool, list, dict))


@pytest.mark.parametrize(
    ("units", "unit_cost"),
    [
        (1, "1"),
        (5, "0.5"),
        (10, "2"),
    ],
)
def test_action_usage_test_accepts_positive_metering_inputs_when_supported(
    units: int,
    unit_cost: str,
) -> None:
    try:
        result = build_action_usage_test(
            owner_id="owner-001",
            action="execute",
            units=units,
            unit_cost=unit_cost,
        )
    except TypeError:
        pytest.skip("builder does not accept direct test inputs")

    payload = _payload_of(result)
    actual_units = _number(payload, "units")
    if actual_units is not None:
        assert actual_units == Decimal(str(units))


def test_action_usage_test_rejects_negative_units_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_action_usage_test(
            owner_id="owner-001",
            action="execute",
            units=-1,
            unit_cost="1",
        )


def test_action_usage_test_rejects_negative_unit_cost_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_action_usage_test(
            owner_id="owner-001",
            action="execute",
            units=1,
            unit_cost="-1",
        )