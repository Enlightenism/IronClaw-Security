from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from app.ownerusageaccounting import build_owner_usage_accounting


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


def _call_method_if_present(target: Any, names: tuple[str, ...], *args: Any, **kwargs: Any) -> Any:
    for name in names:
        if hasattr(target, name):
            method = getattr(target, name)
            if callable(method):
                return method(*args, **kwargs)
    raise AssertionError(f"missing expected method from candidates: {names}")


def test_build_owner_usage_accounting_returns_object() -> None:
    accounting = build_owner_usage_accounting()

    assert accounting is not None


def test_owner_usage_accounting_is_serializable_to_dictionary_shape() -> None:
    payload = _payload_of(build_owner_usage_accounting())

    assert isinstance(payload, dict)
    assert payload


def test_owner_usage_accounting_contains_core_fields_when_present() -> None:
    payload = _payload_of(build_owner_usage_accounting())

    expected_candidates = {
        "accountingid",
        "accounting_id",
        "ownerid",
        "owner_id",
        "usage",
        "units",
        "totalunits",
        "total_units",
        "unitcost",
        "unit_cost",
        "totalcost",
        "total_cost",
        "quota",
        "limit",
        "remaining",
        "available",
        "events",
        "records",
        "entries",
        "summary",
        "generatedat",
        "generated_at",
        "createdat",
        "created_at",
    }
    assert set(payload.keys()).intersection(expected_candidates)


def test_owner_usage_accounting_identifiers_are_non_empty_when_present() -> None:
    payload = _payload_of(build_owner_usage_accounting())

    for value in (
        _text(payload, "accountingid", "accounting_id", "id"),
        _text(payload, "ownerid", "owner_id", "owner", "accountid", "account_id"),
        _text(payload, "status", "state"),
    ):
        if value is not None:
            assert value.strip()


def test_owner_usage_accounting_numeric_fields_are_non_negative_when_present() -> None:
    payload = _payload_of(build_owner_usage_accounting())

    for keys in (
        ("units", "totalunits", "total_units"),
        ("unitcost", "unit_cost"),
        ("totalcost", "total_cost"),
        ("quota", "limit"),
        ("remaining", "available"),
    ):
        value = _number(payload, *keys)
        if value is not None:
            assert value >= Decimal(0)


def test_owner_usage_accounting_remaining_does_not_exceed_quota_when_both_present() -> None:
    payload = _payload_of(build_owner_usage_accounting())

    quota = _number(payload, "quota", "limit")
    remaining = _number(payload, "remaining", "available")
    if quota is not None and remaining is not None:
        assert remaining <= quota


def test_owner_usage_accounting_total_cost_matches_units_times_unit_cost_when_present() -> None:
    try:
        accounting = build_owner_usage_accounting(
            owner_id="owner-001",
            units=5,
            unit_cost="2",
        )
    except TypeError:
        accounting = build_owner_usage_accounting()

    payload = _payload_of(accounting)
    units = _number(payload, "units", "totalunits", "total_units")
    unit_cost = _number(payload, "unitcost", "unit_cost")
    total_cost = _number(payload, "totalcost", "total_cost")

    if units is not None and unit_cost is not None and total_cost is not None:
        assert total_cost == units * unit_cost


def test_owner_usage_accounting_supports_owner_bound_build_when_available() -> None:
    try:
        accounting = build_owner_usage_accounting(
            owner_id="owner-001",
            units=3,
            unit_cost="1",
            quota=10,
        )
    except TypeError:
        accounting = build_owner_usage_accounting()

    payload = _payload_of(accounting)
    owner = _text(payload, "ownerid", "owner_id", "owner")
    if owner is not None:
        assert owner.strip()


def test_owner_usage_accounting_events_collection_is_list_or_dict_when_present() -> None:
    payload = _payload_of(build_owner_usage_accounting())

    events = _value(
        payload,
        "events",
        "records",
        "entries",
        "usage",
        "usagerecords",
        "usage_events",
    )
    if events is not None:
        assert isinstance(events, (list, dict))


def test_owner_usage_accounting_summary_is_dict_when_present() -> None:
    payload = _payload_of(build_owner_usage_accounting())

    summary = _value(payload, "summary", "totals", "metadata")
    if summary is not None:
        assert isinstance(summary, dict)


def test_owner_usage_accounting_owner_specificity_is_stable_when_supported() -> None:
    try:
        first = build_owner_usage_accounting(
            owner_id="owner-001",
            units=1,
            unit_cost="1",
        )
        second = build_owner_usage_accounting(
            owner_id="owner-002",
            units=1,
            unit_cost="1",
        )
    except TypeError:
        pytest.skip("builder does not accept direct owner-bound inputs")

    first_payload = _payload_of(first)
    second_payload = _payload_of(second)

    first_owner = _text(first_payload, "ownerid", "owner_id", "owner")
    second_owner = _text(second_payload, "ownerid", "owner_id", "owner")

    if first_owner is not None and second_owner is not None:
        assert first_owner != second_owner


def test_owner_usage_accounting_rejects_blank_owner_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_owner_usage_accounting(
            owner_id="",
            units=1,
            unit_cost="1",
        )


def test_owner_usage_accounting_rejects_negative_units_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_owner_usage_accounting(
            owner_id="owner-001",
            units=-1,
            unit_cost="1",
        )


def test_owner_usage_accounting_rejects_negative_unit_cost_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_owner_usage_accounting(
            owner_id="owner-001",
            units=1,
            unit_cost="-1",
        )


def test_owner_usage_accounting_rejects_negative_quota_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_owner_usage_accounting(
            owner_id="owner-001",
            units=1,
            unit_cost="1",
            quota=-1,
        )


def test_owner_usage_accounting_rejects_remaining_greater_than_quota_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_owner_usage_accounting(
            owner_id="owner-001",
            units=1,
            unit_cost="1",
            quota=10,
            remaining=11,
        )


def test_owner_usage_accounting_record_method_tracks_owner_when_supported() -> None:
    accounting = build_owner_usage_accounting()

    record_methods = ("record_usage", "add_usage", "track_usage", "meter_usage")
    if not any(hasattr(accounting, name) and callable(getattr(accounting, name)) for name in record_methods):
        pytest.skip("owner usage accounting record method not implemented")

    try:
        result = _call_method_if_present(
            accounting,
            record_methods,
            owner_id="owner-001",
            units=2,
            unit_cost="3",
        )
    except TypeError:
        result = _call_method_if_present(accounting, record_methods, "owner-001", 2, "3")

    if result is not None:
        payload = _payload_of(result)
        owner = _text(payload, "ownerid", "owner_id", "owner")
        units = _number(payload, "units", "totalunits", "total_units")
        if owner is not None:
            assert owner == "owner-001"
        if units is not None:
            assert units == Decimal(2)


def test_owner_usage_accounting_record_method_distinguishes_owners_when_supported() -> None:
    accounting = build_owner_usage_accounting()

    record_methods = ("record_usage", "add_usage", "track_usage", "meter_usage")
    if not any(hasattr(accounting, name) and callable(getattr(accounting, name)) for name in record_methods):
        pytest.skip("owner usage accounting record method not implemented")

    try:
        first = _call_method_if_present(
            accounting,
            record_methods,
            owner_id="owner-001",
            units=1,
            unit_cost="1",
        )
        second = _call_method_if_present(
            accounting,
            record_methods,
            owner_id="owner-002",
            units=1,
            unit_cost="1",
        )
    except TypeError:
        first = _call_method_if_present(accounting, record_methods, "owner-001", 1, "1")
        second = _call_method_if_present(accounting, record_methods, "owner-002", 1, "1")

    first_owner = _text(_payload_of(first), "ownerid", "owner_id", "owner") if first is not None else None
    second_owner = _text(_payload_of(second), "ownerid", "owner_id", "owner") if second is not None else None

    if first_owner is not None and second_owner is not None:
        assert first_owner != second_owner


def test_owner_usage_accounting_payload_uses_json_friendly_values() -> None:
    payload = _payload_of(build_owner_usage_accounting())

    for key, value in payload.items():
        assert isinstance(key, str)
        assert value is None or isinstance(value, (str, int, float, bool, list, dict))


def test_owner_usage_accounting_multiple_builds_have_stable_key_sets() -> None:
    first = _payload_of(build_owner_usage_accounting())
    second = _payload_of(build_owner_usage_accounting())

    assert set(first.keys()) == set(second.keys())
