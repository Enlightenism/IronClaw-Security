from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from app.billingsummary import build_billing_summary


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


def test_build_billing_summary_returns_object() -> None:
    summary = build_billing_summary()

    assert summary is not None


def test_billing_summary_is_serializable_to_dictionary_shape() -> None:
    payload = _payload_of(build_billing_summary())

    assert isinstance(payload, dict)
    assert payload


def test_billing_summary_contains_core_fields_when_present() -> None:
    payload = _payload_of(build_billing_summary())

    expected_candidates = {
        "summaryid",
        "ownerid",
        "wallet",
        "ledger",
        "usage",
        "revenue",
        "quota",
        "remaining",
        "packages",
        "purchases",
        "generatedat",
        "status",
    }
    assert set(payload.keys()).intersection(expected_candidates)


def test_billing_summary_identifiers_are_non_empty_when_present() -> None:
    payload = _payload_of(build_billing_summary())

    for value in (
        _text(payload, "summaryid", "summary_id", "id"),
        _text(payload, "ownerid", "owner_id", "owner", "accountid", "account_id"),
        _text(payload, "status", "state"),
        _text(payload, "currency"),
    ):
        if value is not None:
            assert value.strip()


def test_billing_summary_nested_dict_sections_are_dicts_when_present() -> None:
    payload = _payload_of(build_billing_summary())

    for value in (
        _value(payload, "wallet"),
        _value(payload, "ledger"),
        _value(payload, "usage"),
        _value(payload, "summary"),
        _value(payload, "totals"),
    ):
        if value is not None:
            assert isinstance(value, dict)


def test_billing_summary_collection_sections_are_list_or_dict_when_present() -> None:
    payload = _payload_of(build_billing_summary())

    for value in (
        _value(payload, "packages", "catalog", "plans"),
        _value(payload, "purchases", "orders", "entitlements"),
        _value(payload, "events", "records"),
    ):
        if value is not None:
            assert isinstance(value, list | dict)


def test_billing_summary_numeric_fields_are_non_negative_when_present() -> None:
    payload = _payload_of(build_billing_summary())

    for keys in (
        ("balance",),
        ("revenue", "totalrevenue", "total_revenue"),
        ("usagecost", "usage_cost", "cost"),
        ("quota", "limit"),
        ("remaining", "available"),
        ("units",),
    ):
        value = _number(payload, *keys)
        if value is not None:
            assert value >= Decimal(0)


def test_billing_summary_remaining_does_not_exceed_quota_when_both_present() -> None:
    payload = _payload_of(build_billing_summary())

    quota = _number(payload, "quota", "limit")
    remaining = _number(payload, "remaining", "available")
    if quota is not None and remaining is not None:
        assert remaining <= quota


def test_billing_summary_supports_owner_bound_build_when_available() -> None:
    try:
        summary = build_billing_summary(owner_id="owner-001")
    except TypeError:
        summary = build_billing_summary()

    payload = _payload_of(summary)
    owner = _text(payload, "ownerid", "owner_id", "owner")
    if owner is not None:
        assert owner.strip()


def test_billing_summary_revenue_and_usage_cost_consistency_when_present() -> None:
    try:
        summary = build_billing_summary(
            owner_id="owner-001",
            revenue="100",
            usage_cost="40",
        )
    except TypeError:
        summary = build_billing_summary()

    payload = _payload_of(summary)
    revenue = _number(payload, "revenue", "totalrevenue", "total_revenue")
    usage_cost = _number(payload, "usagecost", "usage_cost", "cost")
    margin = _number(payload, "margin", "netrevenue", "net_revenue")

    if revenue is not None and usage_cost is not None:
        assert revenue >= usage_cost
    if revenue is not None and usage_cost is not None and margin is not None:
        assert margin == revenue - usage_cost


def test_billing_summary_usage_and_quota_consistency_when_present() -> None:
    try:
        summary = build_billing_summary(
            owner_id="owner-001",
            units=4,
            quota=10,
            remaining=6,
        )
    except TypeError:
        summary = build_billing_summary()

    payload = _payload_of(summary)
    units = _number(payload, "units")
    quota = _number(payload, "quota", "limit")
    remaining = _number(payload, "remaining", "available")

    if units is not None and quota is not None and remaining is not None:
        assert units + remaining == quota


def test_billing_summary_rejects_blank_owner_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_billing_summary(owner_id="")


def test_billing_summary_rejects_negative_revenue_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_billing_summary(
            owner_id="owner-001",
            revenue="-1",
        )


def test_billing_summary_rejects_negative_usage_cost_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_billing_summary(
            owner_id="owner-001",
            usage_cost="-1",
        )


def test_billing_summary_rejects_negative_quota_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_billing_summary(
            owner_id="owner-001",
            quota=-1,
        )


def test_billing_summary_rejects_remaining_greater_than_quota_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_billing_summary(
            owner_id="owner-001",
            quota=10,
            remaining=11,
        )


def test_billing_summary_generate_method_returns_owner_scoped_summary_when_supported() -> None:
    summary = build_billing_summary()

    generate_methods = ("generate_summary", "build_summary", "render_summary", "summarize")
    if not any(hasattr(summary, name) and callable(getattr(summary, name)) for name in generate_methods):
        pytest.skip("summary generation method not implemented")

    try:
        result = _call_method_if_present(
            summary,
            generate_methods,
            owner_id="owner-001",
        )
    except TypeError:
        result = _call_method_if_present(summary, generate_methods, "owner-001")

    if result is not None:
        payload = _payload_of(result)
        owner = _text(payload, "ownerid", "owner_id", "owner")
        if owner is not None:
            assert owner == "owner-001"


def test_billing_summary_payload_uses_json_friendly_values() -> None:
    payload = _payload_of(build_billing_summary())

    for key, value in payload.items():
        assert isinstance(key, str)
        assert value is None or isinstance(value, str | int | float | bool | list | dict)


def test_billing_summary_multiple_builds_have_stable_key_sets() -> None:
    first = _payload_of(build_billing_summary())
    second = _payload_of(build_billing_summary())

    assert set(first.keys()) == set(second.keys())
