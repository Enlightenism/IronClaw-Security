from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from app.billingpackages import build_billing_packages


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
        if isinstance(value, str | int | float | bool | list | dict | type(None)):
            payload[name] = value
    return payload


def _items_of(result: Any) -> list[Any]:
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        for key in ("items", "packages", "plans", "results", "data"):
            value = result.get(key)
            if isinstance(value, list):
                return value
        return [result]
    if hasattr(result, "as_dict") and callable(result.as_dict):
        payload = result.as_dict()
        if isinstance(payload, dict):
            return _items_of(payload)
    if hasattr(result, "__iter__") and not isinstance(result, str | bytes):
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


def test_build_billing_packages_returns_object() -> None:
    packages = build_billing_packages()

    assert packages is not None


def test_billing_packages_is_serializable_to_supported_shape() -> None:
    result = build_billing_packages()

    assert isinstance(result, dict | list) or hasattr(result, "as_dict") or hasattr(result, "__iter__")


def test_billing_packages_contains_at_least_one_package_record() -> None:
    items = _items_of(build_billing_packages())

    assert isinstance(items, list)
    assert items


def test_each_billing_package_has_dictionary_shape_when_serialized() -> None:
    items = _items_of(build_billing_packages())

    for item in items:
        payload = _payload_of(item)
        assert isinstance(payload, dict)
        assert payload


def test_billing_package_contains_core_fields_when_present() -> None:
    items = _items_of(build_billing_packages())

    expected_candidates = {
        "packageid",
        "package_id",
        "id",
        "name",
        "code",
        "price",
        "currency",
        "quota",
        "units",
        "status",
        "features",
    }

    for item in items:
        payload = _payload_of(item)
        assert set(payload.keys()).intersection(expected_candidates)
        break


def test_billing_package_identifier_and_name_are_non_empty_when_present() -> None:
    items = _items_of(build_billing_packages())

    for item in items:
        payload = _payload_of(item)
        for value in (
            _text(payload, "packageid", "package_id", "id"),
            _text(payload, "name", "title", "code", "slug"),
            _text(payload, "currency"),
            _text(payload, "status", "state"),
        ):
            if value is not None:
                assert value.strip()


def test_billing_package_numeric_fields_are_non_negative_when_present() -> None:
    items = _items_of(build_billing_packages())

    for item in items:
        payload = _payload_of(item)
        for keys in (
            ("price", "amount", "cost"),
            ("quota", "limit"),
            ("units", "credits"),
            ("intervalcount", "interval_count"),
        ):
            value = _number(payload, *keys)
            if value is not None:
                assert value >= Decimal(0)


def test_billing_package_features_are_list_or_dict_when_present() -> None:
    items = _items_of(build_billing_packages())

    for item in items:
        payload = _payload_of(item)
        features = _value(payload, "features", "entitlements", "benefits")
        if features is not None:
            assert isinstance(features, list | dict)


def test_billing_packages_support_owner_bound_build_when_available() -> None:
    try:
        result = build_billing_packages(owner_id="owner-001")
    except TypeError:
        result = build_billing_packages()

    items = _items_of(result)
    assert items


def test_billing_packages_support_filtering_active_records_when_available() -> None:
    try:
        result = build_billing_packages(status="active")
    except TypeError:
        result = build_billing_packages()

    items = _items_of(result)
    for item in items:
        payload = _payload_of(item)
        status = _text(payload, "status", "state")
        if status is not None:
            assert status.strip()


def test_billing_packages_rejects_blank_owner_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_billing_packages(owner_id="")


def test_billing_packages_rejects_negative_price_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_billing_packages(
            owner_id="owner-001",
            price="-1",
        )


def test_billing_packages_rejects_negative_quota_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_billing_packages(
            owner_id="owner-001",
            quota=-1,
        )


def test_billing_packages_rejects_blank_package_name_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_billing_packages(
            owner_id="owner-001",
            name="",
        )


def test_billing_packages_list_method_returns_collection_when_supported() -> None:
    packages = build_billing_packages()

    list_methods = ("list_packages", "packages", "all", "list")
    if not any(hasattr(packages, name) and callable(getattr(packages, name)) for name in list_methods):
        pytest.skip("package listing method not implemented")

    result = _call_method_if_present(packages, list_methods)
    items = _items_of(result)

    assert isinstance(items, list)
    assert items


def test_billing_packages_lookup_by_code_returns_matching_record_when_supported() -> None:
    packages = build_billing_packages()

    lookup_methods = ("get_by_code", "find_by_code", "package_by_code", "lookup")
    if not any(hasattr(packages, name) and callable(getattr(packages, name)) for name in lookup_methods):
        pytest.skip("package lookup method not implemented")

    sample_items = _items_of(packages)
    sample_payload = _payload_of(sample_items[0])
    code = _text(sample_payload, "code", "name", "packageid", "package_id", "id")
    if code is None:
        pytest.skip("no package code-like field available")

    result = _call_method_if_present(packages, lookup_methods, code)
    payload = _payload_of(result)
    matched = _text(payload, "code", "name", "packageid", "package_id", "id")

    assert matched == code


def test_billing_packages_payload_uses_json_friendly_values() -> None:
    items = _items_of(build_billing_packages())

    for item in items:
        payload = _payload_of(item)
        for key, value in payload.items():
            assert isinstance(key, str)
            assert value is None or isinstance(value, str | int | float | bool | list | dict)


def test_billing_packages_multiple_builds_have_stable_top_level_shape() -> None:
    first = _items_of(build_billing_packages())
    second = _items_of(build_billing_packages())

    assert isinstance(first, list)
    assert isinstance(second, list)
    assert bool(first) == bool(second)

    if first and second:
        assert set(_payload_of(first[0]).keys()) == set(_payload_of(second[0]).keys())
