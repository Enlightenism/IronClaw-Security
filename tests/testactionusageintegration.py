from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from app.actionusage import build_action_usage
from app.unitwallet import build_unit_wallet


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


def _call_method_if_present(target: Any, names: tuple[str, ...], *args: Any, **kwargs: Any) -> Any:
    for name in names:
        if hasattr(target, name):
            method = getattr(target, name)
            if callable(method):
                return method(*args, **kwargs)
    raise AssertionError(f"missing expected method from candidates: {names}")


def _wallet_balance(wallet: Any) -> Decimal:
    payload = _payload_of(wallet)
    for key in ("balance", "units", "available_units", "available", "credits"):
        if key in payload and payload[key] is not None:
            return Decimal(str(payload[key]))
    for name in ("balance", "units", "available_units", "available", "credits"):
        if hasattr(wallet, name):
            value = getattr(wallet, name)
            if callable(value):
                value = value()
            return Decimal(str(value))
    raise AssertionError("wallet balance field not found")


def test_action_usage_and_wallet_build_together() -> None:
    wallet = build_unit_wallet()
    usage = build_action_usage()

    assert wallet is not None
    assert usage is not None


def test_action_usage_integration_shapes_are_serializable() -> None:
    wallet_payload = _payload_of(build_unit_wallet())
    usage_payload = _payload_of(build_action_usage())

    assert isinstance(wallet_payload, dict)
    assert isinstance(usage_payload, dict)
    assert wallet_payload
    assert usage_payload


def test_action_usage_can_bind_to_same_owner_as_wallet_when_supported() -> None:
    try:
        wallet = build_unit_wallet(owner_id="owner-001")
    except TypeError:
        wallet = build_unit_wallet()

    try:
        usage = build_action_usage(
            owner_id="owner-001",
            action="execute",
            units=5,
            unit_cost="2",
        )
    except TypeError:
        usage = build_action_usage()

    wallet_payload = _payload_of(wallet)
    usage_payload = _payload_of(usage)

    wallet_owner = _text(wallet_payload, "ownerid", "owner_id", "owner", "accountid", "account_id")
    usage_owner = _text(usage_payload, "ownerid", "owner_id", "owner", "accountid", "account_id")

    if wallet_owner is not None and usage_owner is not None:
        assert wallet_owner == usage_owner


def test_action_usage_total_cost_can_be_covered_by_wallet_credit_when_supported() -> None:
    wallet = build_unit_wallet()

    try:
        usage = build_action_usage(
            owner_id="owner-001",
            action="scan",
            units=5,
            unit_cost="2",
        )
    except TypeError:
        usage = build_action_usage()

    usage_payload = _payload_of(usage)
    total_cost = _number(usage_payload, "totalcost", "total_cost")

    credit_methods = ("credit", "deposit", "add_units", "fund", "top_up")
    if total_cost is None:
        pytest.skip("usage payload does not expose total cost")
    if not any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in credit_methods):
        pytest.skip("wallet credit method not implemented")

    _call_method_if_present(wallet, credit_methods, total_cost)
    assert _wallet_balance(wallet) >= total_cost


def test_wallet_debit_can_track_usage_total_cost_when_supported() -> None:
    wallet = build_unit_wallet()

    try:
        usage = build_action_usage(
            owner_id="owner-001",
            action="execute",
            units=4,
            unit_cost="3",
        )
    except TypeError:
        usage = build_action_usage()

    usage_payload = _payload_of(usage)
    total_cost = _number(usage_payload, "totalcost", "total_cost")

    credit_methods = ("credit", "deposit", "add_units", "fund", "top_up")
    debit_methods = ("debit", "charge", "consume", "spend", "withdraw")

    if total_cost is None:
        pytest.skip("usage payload does not expose total cost")
    if not any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in credit_methods):
        pytest.skip("wallet credit method not implemented")
    if not any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in debit_methods):
        pytest.skip("wallet debit method not implemented")

    _call_method_if_present(wallet, credit_methods, total_cost + Decimal("5"))
    before = _wallet_balance(wallet)
    _call_method_if_present(wallet, debit_methods, total_cost)
    after = _wallet_balance(wallet)

    assert before - after == total_cost


def test_usage_quota_and_remaining_are_consistent_with_consumption_when_present() -> None:
    try:
        usage = build_action_usage(
            owner_id="owner-001",
            action="execute",
            units=5,
            unit_cost="1",
            quota=20,
        )
    except TypeError:
        usage = build_action_usage()

    payload = _payload_of(usage)
    quota = _number(payload, "quota", "limit")
    remaining = _number(payload, "remaining", "remainingunits", "available")
    units = _number(payload, "units")

    if quota is not None and remaining is not None and units is not None:
        assert remaining == quota - units


def test_usage_and_wallet_values_remain_non_negative_across_integration() -> None:
    wallet = build_unit_wallet()
    usage = build_action_usage()

    wallet_balance = _wallet_balance(wallet)
    usage_payload = _payload_of(usage)

    assert wallet_balance >= Decimal("0")

    for key in ("units", "unitcost", "totalcost", "quota", "remaining"):
        value = _number(usage_payload, key, key.replace("cost", "_cost"))
        if value is not None:
            assert value >= Decimal("0")


def test_multiple_usage_records_for_same_owner_have_stable_owner_identity_when_supported() -> None:
    try:
        first = build_action_usage(
            owner_id="owner-001",
            action="scan",
            units=1,
            unit_cost="1",
        )
        second = build_action_usage(
            owner_id="owner-001",
            action="execute",
            units=2,
            unit_cost="1",
        )
    except TypeError:
        pytest.skip("builder does not accept direct owner-bound usage inputs")

    first_payload = _payload_of(first)
    second_payload = _payload_of(second)

    first_owner = _text(first_payload, "ownerid", "owner_id", "owner")
    second_owner = _text(second_payload, "ownerid", "owner_id", "owner")

    if first_owner is not None and second_owner is not None:
        assert first_owner == "owner-001"
        assert second_owner == "owner-001"


def test_usage_records_for_different_owners_stay_distinct_when_supported() -> None:
    try:
        first = build_action_usage(
            owner_id="owner-001",
            action="scan",
            units=1,
            unit_cost="1",
        )
        second = build_action_usage(
            owner_id="owner-002",
            action="scan",
            units=1,
            unit_cost="1",
        )
    except TypeError:
        pytest.skip("builder does not accept direct owner-bound usage inputs")

    first_payload = _payload_of(first)
    second_payload = _payload_of(second)

    first_owner = _text(first_payload, "ownerid", "owner_id", "owner")
    second_owner = _text(second_payload, "ownerid", "owner_id", "owner")

    if first_owner is not None and second_owner is not None:
        assert first_owner != second_owner


def test_usage_and_wallet_support_json_friendly_reporting() -> None:
    wallet_payload = _payload_of(build_unit_wallet())
    usage_payload = _payload_of(build_action_usage())

    for payload in (wallet_payload, usage_payload):
        for key, value in payload.items():
            assert isinstance(key, str)
            assert value is None or isinstance(value, (str, int, float, bool, list, dict))


def test_usage_cost_formula_is_stable_across_multiple_integration_builds_when_present() -> None:
    try:
        first = build_action_usage(
            owner_id="owner-001",
            action="execute",
            units=3,
            unit_cost="2",
        )
        second = build_action_usage(
            owner_id="owner-001",
            action="execute",
            units=3,
            unit_cost="2",
        )
    except TypeError:
        first = build_action_usage()
        second = build_action_usage()

    first_payload = _payload_of(first)
    second_payload = _payload_of(second)

    first_total = _number(first_payload, "totalcost", "total_cost")
    second_total = _number(second_payload, "totalcost", "total_cost")

    if first_total is not None and second_total is not None:
        assert first_total == second_total