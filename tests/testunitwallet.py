from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from app.unitwallet import build_unit_wallet


def _balance_of(wallet: Any) -> Decimal:
    # Prefer payload view when available for consistency
    if hasattr(wallet, "as_dict") and callable(wallet.as_dict):
        payload = wallet.as_dict()
        for name in ("balance", "units", "available_units", "available", "credits"):
            if name in payload and payload[name] is not None:
                return Decimal(str(payload[name]))

    for name in ("balance", "units", "available_units", "available", "credits"):
        if isinstance(wallet, dict) and name in wallet:
            return Decimal(str(wallet[name]))
        if hasattr(wallet, name):
            value = getattr(wallet, name)
            if callable(value):
                value = value()
            return Decimal(str(value))

    if hasattr(wallet, "as_dict") and callable(wallet.as_dict):
        payload = wallet.as_dict()
        for name in ("balance", "units", "available_units", "available", "credits"):
            if name in payload:
                return Decimal(str(payload[name]))

    raise AssertionError("wallet balance field not found")


def _owner_of(wallet: Any) -> str | None:
    for name in ("owner_id", "ownerid", "owner", "account_id", "accountid"):
        if hasattr(wallet, name):
            value = getattr(wallet, name)
            if callable(value):
                value = value()
            return None if value is None else str(value)
        if isinstance(wallet, dict) and name in wallet:
            value = wallet[name]
            return None if value is None else str(value)
    if hasattr(wallet, "as_dict") and callable(wallet.as_dict):
        payload = wallet.as_dict()
        for name in ("owner_id", "ownerid", "owner", "account_id", "accountid"):
            if name in payload:
                value = payload[name]
                return None if value is None else str(value)
    return None


def _status_of(wallet: Any) -> str | None:
    for name in ("status", "state"):
        if hasattr(wallet, name):
            value = getattr(wallet, name)
            if callable(value):
                value = value()
            return None if value is None else str(value)
        if isinstance(wallet, dict) and name in wallet:
            return str(wallet[name])
    if hasattr(wallet, "as_dict") and callable(wallet.as_dict):
        payload = wallet.as_dict()
        for name in ("status", "state"):
            if name in payload:
                return str(payload[name])
    return None


def _payload_of(wallet: Any) -> dict[str, Any]:
    if isinstance(wallet, dict):
        return wallet
    if hasattr(wallet, "as_dict") and callable(wallet.as_dict):
        payload = wallet.as_dict()
        assert isinstance(payload, dict)
        return payload
    result: dict[str, Any] = {}
    for name in dir(wallet):
        if name.startswith("_"):
            continue
        value = getattr(wallet, name)
        if callable(value):
            continue
        if isinstance(value, (str, int, float, bool, list, dict, type(None))):
            result[name] = value
    return result


def _call_method_if_present(wallet: Any, method_names: tuple[str, ...], *args: Any, **kwargs: Any) -> Any:
    for name in method_names:
        if hasattr(wallet, name):
            method = getattr(wallet, name)
            if callable(method):
                return method(*args, **kwargs)
    raise AssertionError(f"missing expected method from candidates: {method_names}")


def test_build_unit_wallet_returns_wallet_object() -> None:
    wallet = build_unit_wallet()

    assert wallet is not None


def test_wallet_exposes_stable_serializable_shape() -> None:
    wallet = build_unit_wallet()
    payload = _payload_of(wallet)

    assert isinstance(payload, dict)
    assert payload


def test_wallet_balance_is_numeric_and_non_negative() -> None:
    wallet = build_unit_wallet()

    balance = _balance_of(wallet)
    assert balance >= Decimal("0")


def test_wallet_owner_can_be_bound_when_supported() -> None:
    try:
        wallet = build_unit_wallet(owner_id="owner-001")
    except TypeError:
        wallet = build_unit_wallet()

    owner = _owner_of(wallet)
    if owner is not None:
        assert owner.strip()


def test_wallet_status_is_string_when_present() -> None:
    wallet = build_unit_wallet()
    status = _status_of(wallet)

    if status is not None:
        assert status.strip()


def test_wallet_as_dict_is_stable_when_available() -> None:
    wallet = build_unit_wallet()

    if hasattr(wallet, "as_dict") and callable(wallet.as_dict):
        first = wallet.as_dict()
        second = wallet.as_dict()
        assert isinstance(first, dict)
        assert isinstance(second, dict)
        assert set(first.keys()) == set(second.keys())


def test_wallet_credit_increases_balance_when_credit_method_exists() -> None:
    wallet = build_unit_wallet()

    credit_methods = ("credit", "deposit", "add_units", "fund", "top_up")
    if not any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in credit_methods):
        pytest.skip("wallet credit method not implemented")

    before = _balance_of(wallet)
    _call_method_if_present(wallet, credit_methods, Decimal("25"))
    after = _balance_of(wallet)

    assert after >= before
    assert after - before == Decimal("25")


def test_wallet_debit_decreases_balance_when_debit_method_exists() -> None:
    wallet = build_unit_wallet()

    credit_methods = ("credit", "deposit", "add_units", "fund", "top_up")
    debit_methods = ("debit", "charge", "consume", "spend", "withdraw")

    if not any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in debit_methods):
        pytest.skip("wallet debit method not implemented")

    if any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in credit_methods):
        _call_method_if_present(wallet, credit_methods, Decimal("30"))

    before = _balance_of(wallet)
    _call_method_if_present(wallet, debit_methods, Decimal("10"))
    after = _balance_of(wallet)

    assert after <= before
    assert before - after == Decimal("10")


def test_wallet_rejects_negative_credit_when_credit_method_exists() -> None:
    wallet = build_unit_wallet()

    credit_methods = ("credit", "deposit", "add_units", "fund", "top_up")
    if not any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in credit_methods):
        pytest.skip("wallet credit method not implemented")

    with pytest.raises((TypeError, ValueError, AssertionError)):
        _call_method_if_present(wallet, credit_methods, Decimal("-1"))


def test_wallet_rejects_negative_debit_when_debit_method_exists() -> None:
    wallet = build_unit_wallet()

    debit_methods = ("debit", "charge", "consume", "spend", "withdraw")
    if not any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in debit_methods):
        pytest.skip("wallet debit method not implemented")

    with pytest.raises((TypeError, ValueError, AssertionError)):
        _call_method_if_present(wallet, debit_methods, Decimal("-1"))


def test_wallet_prevents_overdraft_when_debit_method_exists() -> None:
    wallet = build_unit_wallet()

    debit_methods = ("debit", "charge", "consume", "spend", "withdraw")
    if not any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in debit_methods):
        pytest.skip("wallet debit method not implemented")

    current = _balance_of(wallet)

    with pytest.raises((TypeError, ValueError, AssertionError)):
        _call_method_if_present(wallet, debit_methods, current + Decimal("1"))


def test_wallet_supports_reserve_and_release_when_available() -> None:
    wallet = build_unit_wallet()

    reserve_methods = ("reserve", "hold", "authorize")
    release_methods = ("release", "unreserve", "void_hold")

    has_reserve = any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in reserve_methods)
    has_release = any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in release_methods)

    if not (has_reserve and has_release):
        pytest.skip("wallet reserve/release methods not implemented")

    credit_methods = ("credit", "deposit", "add_units", "fund", "top_up")
    if any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in credit_methods):
        _call_method_if_present(wallet, credit_methods, Decimal("20"))

    before = _balance_of(wallet)
    token = _call_method_if_present(wallet, reserve_methods, Decimal("5"))
    middle = _balance_of(wallet)
    _call_method_if_present(wallet, release_methods, token if token is not None else Decimal("5"))
    after = _balance_of(wallet)

    assert middle <= before
    assert after >= middle


def test_wallet_payload_uses_json_friendly_values() -> None:
    wallet = build_unit_wallet()
    payload = _payload_of(wallet)

    for key, value in payload.items():
        assert isinstance(key, str)
        assert value is None or isinstance(value, (str, int, float, bool, list, dict))


def test_wallet_multiple_instances_are_independent() -> None:
    first = build_unit_wallet()
    second = build_unit_wallet()

    assert first is not second

    credit_methods = ("credit", "deposit", "add_units", "fund", "top_up")
    if any(hasattr(first, name) and callable(getattr(first, name)) for name in credit_methods):
        before_first = _balance_of(first)
        before_second = _balance_of(second)
        _call_method_if_present(first, credit_methods, Decimal("7"))
        after_first = _balance_of(first)
        after_second = _balance_of(second)

        assert after_first - before_first == Decimal("7")
        assert after_second == before_second


def test_wallet_instances_can_be_bound_to_distinct_owners_when_supported() -> None:
    try:
        first = build_unit_wallet(owner_id="owner-001")
        second = build_unit_wallet(owner_id="owner-002")
    except TypeError:
        pytest.skip("wallet builder does not accept owner-bound inputs")

    first_owner = _owner_of(first)
    second_owner = _owner_of(second)

    if first_owner is not None and second_owner is not None:
        assert first_owner != second_owner