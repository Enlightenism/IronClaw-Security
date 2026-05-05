from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from app.usagereports import build_usage_reports


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


def _items_of(result: Any) -> list[Any]:
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        for key in ("items", "summaries", "reports", "events", "data"):
            value = result.get(key)
            if isinstance(value, list):
                return value
        return [result]
    if hasattr(result, "__iter__") and not isinstance(result, (str, bytes)):
        try:
            return list(result)
        except TypeError:
            pass
    return [result]


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


def test_build_usage_reports_returns_object() -> None:
    reports = build_usage_reports()

    assert reports is not None


def test_usage_reports_is_serializable_to_supported_shape() -> None:
    reports = build_usage_reports()

    assert isinstance(reports, (dict, list)) or hasattr(reports, "as_dict") or hasattr(reports, "__iter__")


def test_usage_reports_contains_at_least_one_record() -> None:
    items = _items_of(build_usage_reports())

    assert isinstance(items, list)
    assert items


def test_each_usage_report_has_dictionary_shape_when_serialized() -> None:
    items = _items_of(build_usage_reports())

    for item in items:
        payload = _payload_of(item)
        assert isinstance(payload, dict)
        assert payload


def test_usage_reports_contains_core_fields_when_present() -> None:
    items = _items_of(build_usage_reports())
    expected_candidates = {
        "apikeyid",
        "api_key_id",
        "ownerkey",
        "owner_key",
        "totalrequests",
        "total_requests",
        "totalunits",
        "total_units",
        "lastseenat",
        "last_seen_at",
        "routes",
        "status",
        "timestamp",
    }

    payload = _payload_of(items[0])
    assert set(payload.keys()).intersection(expected_candidates)


def test_usage_reports_identifiers_are_non_empty_when_present() -> None:
    items = _items_of(build_usage_reports())

    for item in items:
        payload = _payload_of(item)
        for value in (
            _text(payload, "apikeyid", "api_key_id", "id"),
            _text(payload, "ownerkey", "owner_key", "ownerid", "owner_id"),
            _text(payload, "status", "state"),
            _text(payload, "timestamp", "generatedat", "generated_at"),
        ):
            if value is not None:
                assert value.strip()


def test_usage_reports_numeric_fields_are_non_negative_when_present() -> None:
    items = _items_of(build_usage_reports())

    for item in items:
        payload = _payload_of(item)
        for keys in (
            ("totalrequests", "total_requests"),
            ("totalunits", "total_units"),
            ("averageunitsperrequest", "average_units_per_request"),
            ("units",),
            ("requests",),
        ):
            value = _number(payload, *keys)
            if value is not None:
                assert value >= Decimal("0")


def test_usage_reports_routes_are_list_or_dict_when_present() -> None:
    items = _items_of(build_usage_reports())

    for item in items:
        payload = _payload_of(item)
        routes = _value(payload, "routes", "samples", "events", "history")
        if routes is not None:
            assert isinstance(routes, (list, dict))


def test_usage_reports_average_is_consistent_with_totals_when_present() -> None:
    items = _items_of(build_usage_reports())

    for item in items:
        payload = _payload_of(item)
        total_requests = _number(payload, "totalrequests", "total_requests")
        total_units = _number(payload, "totalunits", "total_units")
        average = _number(payload, "averageunitsperrequest", "average_units_per_request")

        if total_requests is not None and total_units is not None and average is not None:
            if total_requests == 0:
                assert average == Decimal("0")
            else:
                assert average == total_units / total_requests


def test_usage_reports_support_owner_bound_build_when_available() -> None:
    try:
        reports = build_usage_reports(owner_key="owner-001")
    except TypeError:
        reports = build_usage_reports()

    items = _items_of(reports)
    assert items


def test_usage_reports_support_limit_parameter_when_available() -> None:
    try:
        reports = build_usage_reports(limit=5)
    except TypeError:
        reports = build_usage_reports()

    items = _items_of(reports)
    assert len(items) >= 1


def test_usage_reports_rejects_blank_owner_key_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_usage_reports(owner_key="")


def test_usage_reports_rejects_invalid_limit_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_usage_reports(limit=0)


def test_usage_reports_list_events_method_returns_collection_when_supported() -> None:
    reports = build_usage_reports()

    event_methods = ("list_events", "events", "usage_events", "get_events")
    if not any(hasattr(reports, name) and callable(getattr(reports, name)) for name in event_methods):
        pytest.skip("usage event listing method not implemented")

    result = _call_method_if_present(reports, event_methods)
    items = _items_of(result)

    assert isinstance(items, list)
    assert items


def test_usage_reports_lookup_by_api_key_returns_matching_record_when_supported() -> None:
    reports = build_usage_reports()

    lookup_methods = ("get_by_api_key", "find_by_api_key", "report_for_key", "lookup")
    if not any(hasattr(reports, name) and callable(getattr(reports, name)) for name in lookup_methods):
        pytest.skip("usage report lookup method not implemented")

    items = _items_of(reports)
    sample_payload = _payload_of(items[0])
    api_key_id = _text(sample_payload, "apikeyid", "api_key_id", "id")
    if api_key_id is None:
        pytest.skip("no api key identifier available")

    result = _call_method_if_present(reports, lookup_methods, api_key_id)
    payload = _payload_of(result)
    matched = _text(payload, "apikeyid", "api_key_id", "id")

    assert matched == api_key_id


def test_usage_reports_payload_uses_json_friendly_values() -> None:
    items = _items_of(build_usage_reports())

    for item in items:
        payload = _payload_of(item)
        for key, value in payload.items():
            assert isinstance(key, str)
            assert value is None or isinstance(value, (str, int, float, bool, list, dict))


def test_usage_reports_multiple_builds_have_stable_top_level_shape() -> None:
    first = _items_of(build_usage_reports())
    second = _items_of(build_usage_reports())

    assert isinstance(first, list)
    assert isinstance(second, list)
    assert bool(first) == bool(second)

    if first and second:
        assert set(_payload_of(first[0]).keys()) == set(_payload_of(second[0]).keys())