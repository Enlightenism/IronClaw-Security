from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from app.corebilling import build_core_billing


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


def test_build_core_billing_returns_object() -> None:
    core = build_core_billing()

    assert core is not None


def test_core_billing_is_serializable_to_dictionary_shape() -> None:
    payload = _payload_of(build_core_billing())

    assert isinstance(payload, dict)
    assert payload


def test_core_billing_contains_core_fields_when_present() -> None:
    payload = _payload_of(build_core_billing())

    expected_candidates = {
        "billingid",
        "ownerid",
        "wallet",
        "ledger",
        "packages",
        "usage",
        "quota",
        "remaining",
        "status",
        "generatedat",
    }
    assert set(payload.keys()).intersection(expected_candidates)


def test_core_billing_identifiers_are_non_empty_when_present() -> None:
    payload = _payload_of(build_core_billing())

    for value in (
        _text(payload, "billingid", "billing_id", "id"),
        _text(payload, "ownerid", "owner_id", "owner", "accountid", "account_id"),
        _text(payload, "status", "state"),
    ):
        if value is not None:
            assert value.strip()


def test_core_billing_nested_components_are_dicts_when_present() -> None:
    payload = _payload_of(build_core_billing())

    for value in (
        _value(payload, "wallet"),
        _value(payload, "ledger"),
        _value(payload, "usage"),
        _value(payload, "summary"),
    ):
        if value is not None:
            assert isinstance(value, dict)


def test_core_billing_collections_are_list_or_dict_when_present() -> None:
    payload = _payload_of(build_core_billing())

    for value in (
        _value(payload, "packages", "plans", "catalog"),
        _value(payload, "purchases", "orders", "entitlements"),
        _value(payload, "events", "records"),
    ):
        if value is not None:
            assert isinstance(value, list | dict)


def test_core_billing_numeric_fields_are_non_negative_when_present() -> None:
    payload = _payload_of(build_core_billing())

    for keys in (
        ("balance",),
        ("quota", "limit"),
        ("remaining", "remainingunits", "available"),
        ("units",),
        ("totalcost", "total_cost"),
    ):
        value = _number(payload, *keys)
        if value is not None:
            assert value >= Decimal(0)


def test_core_billing_remaining_does_not_exceed_quota_when_both_present() -> None:
    payload = _payload_of(build_core_billing())

    quota = _number(payload, "quota", "limit")
    remaining = _number(payload, "remaining", "remainingunits", "available")
    if quota is not None and remaining is not None:
        assert remaining <= quota


def test_core_billing_supports_owner_bound_build_when_available() -> None:
    try:
        core = build_core_billing(owner_id="owner-001")
    except TypeError:
        core = build_core_billing()

    payload = _payload_of(core)
    owner = _text(payload, "ownerid", "owner_id", "owner")
    if owner is not None:
        assert owner.strip()


def test_core_billing_purchase_enforcement_flow_when_supported() -> None:
    core = build_core_billing()

    purchase_methods = ("purchase_package", "purchase", "buy_package", "grant_package")
    if not any(hasattr(core, name) and callable(getattr(core, name)) for name in purchase_methods):
        pytest.skip("core billing purchase method not implemented")

    try:
        result = _call_method_if_present(
            core,
            purchase_methods,
            owner_id="owner-001",
            package_id="starter",
            quantity=1,
        )
    except TypeError:
        result = _call_method_if_present(core, purchase_methods, "owner-001", "starter", 1)

    if result is not None:
        payload = _payload_of(result)
        package_id = _text(payload, "packageid", "package_id", "planid", "plan_id")
        if package_id is not None:
            assert package_id.strip()


def test_core_billing_usage_recording_flow_when_supported() -> None:
    core = build_core_billing()

    usage_methods = ("record_usage", "meter_usage", "charge_usage", "consume_units")
    if not any(hasattr(core, name) and callable(getattr(core, name)) for name in usage_methods):
        pytest.skip("core billing usage method not implemented")

    try:
        result = _call_method_if_present(
            core,
            usage_methods,
            owner_id="owner-001",
            action="execute",
            units=5,
            unit_cost="2",
        )
    except TypeError:
        result = _call_method_if_present(core, usage_methods, "owner-001", "execute", 5, "2")

    if result is not None:
        payload = _payload_of(result)
        units = _number(payload, "units")
        if units is not None:
            assert units == Decimal(5)


def test_core_billing_rejects_negative_usage_when_supported() -> None:
    core = build_core_billing()

    usage_methods = ("record_usage", "meter_usage", "charge_usage", "consume_units")
    if not any(hasattr(core, name) and callable(getattr(core, name)) for name in usage_methods):
        pytest.skip("core billing usage method not implemented")

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            _call_method_if_present(
                core,
                usage_methods,
                owner_id="owner-001",
                action="execute",
                units=-1,
                unit_cost="1",
            )
        except TypeError:
            _call_method_if_present(core, usage_methods, "owner-001", "execute", -1, "1")


def test_core_billing_rejects_blank_purchase_fields_when_supported() -> None:
    core = build_core_billing()

    purchase_methods = ("purchase_package", "purchase", "buy_package", "grant_package")
    if not any(hasattr(core, name) and callable(getattr(core, name)) for name in purchase_methods):
        pytest.skip("core billing purchase method not implemented")

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            _call_method_if_present(
                core,
                purchase_methods,
                owner_id="",
                package_id="",
                quantity=0,
            )
        except TypeError:
            _call_method_if_present(core, purchase_methods, "", "", 0)


def test_core_billing_json_values_are_serialization_friendly() -> None:
    payload = _payload_of(build_core_billing())

    for key, value in payload.items():
        assert isinstance(key, str)
        assert value is None or isinstance(value, str | int | float | bool | list | dict)


def test_core_billing_multiple_builds_have_stable_key_sets() -> None:
    first = _payload_of(build_core_billing())
    second = _payload_of(build_core_billing())

    assert set(first.keys()) == set(second.keys())
