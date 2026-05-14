from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from app.billingwallet import build_billing_wallet


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


def test_build_billing_wallet_returns_object() -> None:
    wallet = build_billing_wallet()

    assert wallet is not None


def test_billing_wallet_is_serializable_to_dictionary_shape() -> None:
    payload = _payload_of(build_billing_wallet())

    assert isinstance(payload, dict)
    assert payload


def test_billing_wallet_contains_core_fields_when_present() -> None:
    payload = _payload_of(build_billing_wallet())

    expected_candidates = {
        "walletid",
        "ownerid",
        "balance",
        "available",
        "reserved",
        "currency",
        "status",
        "ledger",
        "generatedat",
    }
    assert set(payload.keys()).intersection(expected_candidates)


def test_billing_wallet_identifiers_are_non_empty_when_present() -> None:
    payload = _payload_of(build_billing_wallet())

    for value in (
        _text(payload, "walletid", "wallet_id", "id"),
        _text(payload, "ownerid", "owner_id", "owner", "accountid", "account_id"),
        _text(payload, "currency"),
        _text(payload, "status", "state"),
    ):
        if value is not None:
            assert value.strip()


def test_billing_wallet_numeric_fields_are_non_negative_when_present() -> None:
    payload = _payload_of(build_billing_wallet())

    for keys in (
        ("balance",),
        ("available", "availablebalance", "available_balance"),
        ("reserved", "held", "pending"),
        ("quota", "limit"),
    ):
        value = _number(payload, *keys)
        if value is not None:
            assert value >= Decimal(0)


def test_billing_wallet_available_and_reserved_do_not_exceed_balance_when_present() -> None:
    payload = _payload_of(build_billing_wallet())

    balance = _number(payload, "balance")
    available = _number(payload, "available", "availablebalance", "available_balance")
    reserved = _number(payload, "reserved", "held", "pending")

    if balance is not None and available is not None:
        assert available <= balance
    if balance is not None and reserved is not None:
        assert reserved <= balance
    if balance is not None and available is not None and reserved is not None:
        assert available + reserved <= balance


def test_billing_wallet_nested_ledger_is_dict_when_present() -> None:
    payload = _payload_of(build_billing_wallet())

    ledger = _value(payload, "ledger")
    if ledger is not None:
        assert isinstance(ledger, dict)


def test_billing_wallet_supports_owner_bound_build_when_available() -> None:
    try:
        wallet = build_billing_wallet(owner_id="owner-001")
    except TypeError:
        wallet = build_billing_wallet()

    payload = _payload_of(wallet)
    owner = _text(payload, "ownerid", "owner_id", "owner")
    if owner is not None:
        assert owner.strip()


def test_billing_wallet_credit_increases_balance_when_supported() -> None:
    wallet = build_billing_wallet()

    credit_methods = ("credit", "deposit", "add_funds", "fund", "top_up")
    if not any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in credit_methods):
        pytest.skip("billing wallet credit method not implemented")

    before = _number(_payload_of(wallet), "balance") or Decimal(0)
    _call_method_if_present(wallet, credit_methods, Decimal(10))
    after = _number(_payload_of(wallet), "balance") or Decimal(0)

    assert after - before == Decimal(10)


def test_billing_wallet_debit_decreases_balance_when_supported() -> None:
    wallet = build_billing_wallet()

    credit_methods = ("credit", "deposit", "add_funds", "fund", "top_up")
    debit_methods = ("debit", "charge", "spend", "withdraw", "consume")

    if not any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in debit_methods):
        pytest.skip("billing wallet debit method not implemented")

    if any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in credit_methods):
        _call_method_if_present(wallet, credit_methods, Decimal(20))

    before = _number(_payload_of(wallet), "balance") or Decimal(0)
    _call_method_if_present(wallet, debit_methods, Decimal(5))
    after = _number(_payload_of(wallet), "balance") or Decimal(0)

    assert before - after == Decimal(5)


def test_billing_wallet_reserve_and_release_flow_when_supported() -> None:
    wallet = build_billing_wallet()

    credit_methods = ("credit", "deposit", "add_funds", "fund", "top_up")
    reserve_methods = ("reserve", "hold", "authorize")
    release_methods = ("release", "unreserve", "void_hold")

    has_reserve = any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in reserve_methods)
    has_release = any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in release_methods)

    if not (has_reserve and has_release):
        pytest.skip("billing wallet reserve/release methods not implemented")

    if any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in credit_methods):
        _call_method_if_present(wallet, credit_methods, Decimal(20))

    before_payload = _payload_of(wallet)
    before_available = _number(before_payload, "available", "availablebalance", "available_balance")
    token = _call_method_if_present(wallet, reserve_methods, Decimal(5))
    middle_payload = _payload_of(wallet)
    middle_reserved = _number(middle_payload, "reserved", "held", "pending")
    _call_method_if_present(wallet, release_methods, token if token is not None else Decimal(5))
    after_payload = _payload_of(wallet)
    after_reserved = _number(after_payload, "reserved", "held", "pending")

    if before_available is not None:
        current_available = _number(middle_payload, "available", "availablebalance", "available_balance")
        if current_available is not None:
            assert current_available <= before_available
    if middle_reserved is not None:
        assert middle_reserved >= Decimal(0)
    if after_reserved is not None:
        assert after_reserved >= Decimal(0)


def test_billing_wallet_rejects_negative_credit_when_supported() -> None:
    wallet = build_billing_wallet()

    credit_methods = ("credit", "deposit", "add_funds", "fund", "top_up")
    if not any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in credit_methods):
        pytest.skip("billing wallet credit method not implemented")

    with pytest.raises((ValueError, AssertionError)):
        _call_method_if_present(wallet, credit_methods, Decimal(-1))


def test_billing_wallet_rejects_negative_debit_when_supported() -> None:
    wallet = build_billing_wallet()

    debit_methods = ("debit", "charge", "spend", "withdraw", "consume")
    if not any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in debit_methods):
        pytest.skip("billing wallet debit method not implemented")

    with pytest.raises((ValueError, AssertionError)):
        _call_method_if_present(wallet, debit_methods, Decimal(-1))


def test_billing_wallet_prevents_overdraft_when_supported() -> None:
    wallet = build_billing_wallet()

    debit_methods = ("debit", "charge", "spend", "withdraw", "consume")
    if not any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in debit_methods):
        pytest.skip("billing wallet debit method not implemented")

    balance = _number(_payload_of(wallet), "balance") or Decimal(0)

    with pytest.raises((ValueError, AssertionError)):
        _call_method_if_present(wallet, debit_methods, balance + Decimal(1))


def test_billing_wallet_payload_uses_json_friendly_values() -> None:
    payload = _payload_of(build_billing_wallet())

    for key, value in payload.items():
        assert isinstance(key, str)
        assert value is None or isinstance(value, str | int | float | bool | list | dict)


def test_billing_wallet_multiple_builds_have_stable_key_sets() -> None:
    first = _payload_of(build_billing_wallet())
    second = _payload_of(build_billing_wallet())

    assert set(first.keys()) == set(second.keys())
