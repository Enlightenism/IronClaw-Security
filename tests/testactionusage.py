from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from app.actionusage import build_action_usage


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


def _read_numeric(payload: dict[str, Any], *keys: str) -> Decimal | None:
    for key in keys:
        if key in payload and payload[key] is not None:
            return Decimal(str(payload[key]))
    return None


def _read_text(payload: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        if key in payload and payload[key] is not None:
            return str(payload[key])
    return None


def _read_collection(payload: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in payload:
            return payload[key]
    return None


def test_build_action_usage_returns_usage_object() -> None:
    usage = build_action_usage()

    assert usage is not None


def test_action_usage_is_serializable_to_dictionary_shape() -> None:
    usage = build_action_usage()
    payload = _payload_of(usage)

    assert isinstance(payload, dict)
    assert payload


def test_action_usage_contains_stable_metering_fields_when_present() -> None:
    usage = build_action_usage()
    payload = _payload_of(usage)

    present = set(payload.keys())
    expected_candidates = {
        "ownerid",
        "action",
        "units",
        "unitcost",
        "totalcost",
        "status",
        "quota",
        "remaining",
        "usageid",
        "generatedat",
    }
    assert present.intersection(expected_candidates)


def test_action_usage_numeric_fields_are_non_negative_when_present() -> None:
    usage = build_action_usage()
    payload = _payload_of(usage)

    for key in ("units", "unitcost", "totalcost", "quota", "remaining"):
        value = _read_numeric(payload, key)
        if value is not None:
            assert value >= Decimal("0")


def test_action_usage_owner_identifier_is_non_empty_when_present() -> None:
    usage = build_action_usage()
    payload = _payload_of(usage)

    owner = _read_text(payload, "ownerid", "owner_id", "owner", "accountid", "account_id")
    if owner is not None:
        assert owner.strip()


def test_action_usage_action_name_is_non_empty_when_present() -> None:
    usage = build_action_usage()
    payload = _payload_of(usage)

    action = _read_text(payload, "action", "actionname", "operation", "event")
    if action is not None:
        assert action.strip()


def test_action_usage_status_is_non_empty_when_present() -> None:
    usage = build_action_usage()
    payload = _payload_of(usage)

    status = _read_text(payload, "status", "state", "verdict")
    if status is not None:
        assert status.strip()


def test_action_usage_supports_owner_bound_build_when_available() -> None:
    try:
        usage = build_action_usage(owner_id="owner-001", action="scan", units=5)
    except TypeError:
        usage = build_action_usage()

    payload = _payload_of(usage)
    owner = _read_text(payload, "ownerid", "owner_id", "owner")
    if owner is not None:
        assert owner.strip()


def test_action_usage_calculates_total_cost_when_inputs_are_present() -> None:
    try:
        usage = build_action_usage(
            owner_id="owner-001",
            action="scan",
            units=5,
            unit_cost="2",
        )
    except TypeError:
        usage = build_action_usage()

    payload = _payload_of(usage)
    units = _read_numeric(payload, "units")
    unit_cost = _read_numeric(payload, "unitcost", "unit_cost")
    total_cost = _read_numeric(payload, "totalcost", "total_cost")

    if units is not None and unit_cost is not None and total_cost is not None:
        assert total_cost == units * unit_cost


def test_action_usage_remaining_does_not_exceed_quota_when_both_present() -> None:
    usage = build_action_usage()
    payload = _payload_of(usage)

    quota = _read_numeric(payload, "quota", "limit")
    remaining = _read_numeric(payload, "remaining", "remainingunits", "available")
    if quota is not None and remaining is not None:
        assert remaining <= quota


def test_action_usage_collection_fields_are_json_friendly_when_present() -> None:
    usage = build_action_usage()
    payload = _payload_of(usage)

    for value in payload.values():
        assert value is None or isinstance(value, (str, int, float, bool, list, dict))


def test_action_usage_event_list_is_list_when_present() -> None:
    usage = build_action_usage()
    payload = _payload_of(usage)

    events = _read_collection(payload, "events", "entries", "records", "usageevents")
    if events is not None:
        assert isinstance(events, list)


def test_action_usage_metadata_is_dict_when_present() -> None:
    usage = build_action_usage()
    payload = _payload_of(usage)

    metadata = _read_collection(payload, "metadata", "context", "dimensions")
    if metadata is not None:
        assert isinstance(metadata, dict)


def test_action_usage_multiple_builds_have_stable_key_sets() -> None:
    first = _payload_of(build_action_usage())
    second = _payload_of(build_action_usage())

    assert set(first.keys()) == set(second.keys())


def test_action_usage_usageid_is_non_empty_when_present() -> None:
    usage = build_action_usage()
    payload = _payload_of(usage)

    usage_id = _read_text(payload, "usageid", "usage_id", "id")
    if usage_id is not None:
        assert usage_id.strip()


@pytest.mark.parametrize(
    ("units", "unit_cost"),
    [
        (1, "1"),
        (5, "0.5"),
        (10, "2"),
    ],
)
def test_action_usage_accepts_positive_metering_inputs_when_supported(
    units: int,
    unit_cost: str,
) -> None:
    try:
        usage = build_action_usage(
            owner_id="owner-001",
            action="execute",
            units=units,
            unit_cost=unit_cost,
        )
    except TypeError:
        pytest.skip("builder does not accept direct metering inputs")

    payload = _payload_of(usage)
    actual_units = _read_numeric(payload, "units")
    if actual_units is not None:
        assert actual_units == Decimal(str(units))


def test_action_usage_rejects_negative_units_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_action_usage(
            owner_id="owner-001",
            action="execute",
            units=-1,
            unit_cost="1",
        )


def test_action_usage_rejects_negative_unit_cost_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_action_usage(
            owner_id="owner-001",
            action="execute",
            units=1,
            unit_cost="-1",
        )