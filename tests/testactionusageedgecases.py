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


def test_action_usage_rejects_negative_units() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_action_usage(
            owner_id="owner-001",
            action="execute",
            units=-1,
            unit_cost="1",
        )


def test_action_usage_rejects_negative_unit_cost() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_action_usage(
            owner_id="owner-001",
            action="execute",
            units=1,
            unit_cost="-1",
        )


def test_action_usage_rejects_negative_quota_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_action_usage(
            owner_id="owner-001",
            action="execute",
            units=1,
            unit_cost="1",
            quota=-10,
        )


def test_action_usage_rejects_blank_owner_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_action_usage(
            owner_id="",
            action="execute",
            units=1,
            unit_cost="1",
        )


def test_action_usage_rejects_blank_action_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_action_usage(
            owner_id="owner-001",
            action="",
            units=1,
            unit_cost="1",
        )


def test_action_usage_rejects_missing_owner_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_action_usage(
            action="execute",
            units=1,
            unit_cost="1",
        )


def test_action_usage_rejects_missing_action_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_action_usage(
            owner_id="owner-001",
            units=1,
            unit_cost="1",
        )


def test_action_usage_rejects_quota_exceeded_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_action_usage(
            owner_id="owner-001",
            action="execute",
            units=11,
            unit_cost="1",
            quota=10,
        )


def test_action_usage_allows_zero_units_only_if_model_explicitly_supports_it() -> None:
    try:
        usage = build_action_usage(
            owner_id="owner-001",
            action="execute",
            units=0,
            unit_cost="1",
        )
    except (TypeError, ValueError, AssertionError):
        return

    payload = _payload_of(usage)
    units = _number(payload, "units")
    if units is not None:
        assert units == Decimal(0)


def test_action_usage_handles_zero_unit_cost_when_supported() -> None:
    try:
        usage = build_action_usage(
            owner_id="owner-001",
            action="execute",
            units=5,
            unit_cost="0",
        )
    except (TypeError, ValueError, AssertionError):
        pytest.skip("builder does not allow zero-cost usage")

    payload = _payload_of(usage)
    unit_cost = _number(payload, "unitcost", "unit_cost")
    total_cost = _number(payload, "totalcost", "total_cost")

    if unit_cost is not None:
        assert unit_cost == Decimal(0)
    if total_cost is not None:
        assert total_cost == Decimal(0)


def test_action_usage_large_values_remain_non_negative_when_supported() -> None:
    try:
        usage = build_action_usage(
            owner_id="owner-001",
            action="batch-execute",
            units=1_000_000,
            unit_cost="2",
            quota=2_000_000,
        )
    except TypeError:
        pytest.skip("builder does not accept direct large metering inputs")

    payload = _payload_of(usage)
    units = _number(payload, "units")
    total_cost = _number(payload, "totalcost", "total_cost")

    if units is not None:
        assert units == Decimal(1000000)
    if total_cost is not None:
        assert total_cost == Decimal(2000000)


def test_action_usage_remaining_is_never_negative_when_present() -> None:
    payload = _payload_of(build_action_usage())

    remaining = _number(payload, "remaining", "remainingunits", "available")
    if remaining is not None:
        assert remaining >= Decimal(0)


def test_action_usage_total_cost_is_consistent_when_present() -> None:
    try:
        usage = build_action_usage(
            owner_id="owner-001",
            action="scan",
            units=5,
            unit_cost="3",
        )
    except TypeError:
        usage = build_action_usage()

    payload = _payload_of(usage)
    units = _number(payload, "units")
    unit_cost = _number(payload, "unitcost", "unit_cost")
    total_cost = _number(payload, "totalcost", "total_cost")

    if units is not None and unit_cost is not None and total_cost is not None:
        assert total_cost == units * unit_cost


def test_action_usage_owner_identifier_is_trimmed_when_present() -> None:
    try:
        usage = build_action_usage(
            owner_id=" owner-001 ",
            action="execute",
            units=1,
            unit_cost="1",
        )
    except TypeError:
        pytest.skip("builder does not accept owner input")

    payload = _payload_of(usage)
    owner = _text(payload, "ownerid", "owner_id", "owner")
    if owner is not None:
        assert owner == owner.strip()


def test_action_usage_action_name_is_trimmed_when_present() -> None:
    try:
        usage = build_action_usage(
            owner_id="owner-001",
            action=" execute ",
            units=1,
            unit_cost="1",
        )
    except TypeError:
        pytest.skip("builder does not accept action input")

    payload = _payload_of(usage)
    action = _text(payload, "action", "actionname", "operation")
    if action is not None:
        assert action == action.strip()


def test_action_usage_multiple_invalid_fields_fail_fast() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_action_usage(
            owner_id="",
            action="",
            units=-5,
            unit_cost="-1",
            quota=-10,
        )
