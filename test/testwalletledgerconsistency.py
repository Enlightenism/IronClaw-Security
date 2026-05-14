from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from app.unitledger import build_unit_ledger

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


def _wallet_balance_of(wallet: Any) -> Decimal:
    payload = _payload_of(wallet)
    for key in ("balance", "units", "available_units", "available", "credits"):
        value = _number(payload, key)
        if value is not None:
            return value
    raise AssertionError("wallet balance field not found")


def _ledger_balance_of(ledger: Any) -> Decimal | None:
    payload = _payload_of(ledger)
    return _number(payload, "balance", "units", "available", "credits", "available_units")


def _entries_of(ledger: Any) -> list[Any] | None:
    payload = _payload_of(ledger)
    for key in ("entries", "records", "transactions", "journal"):
        if key in payload:
            value = payload[key]
            if value is not None:
                assert isinstance(value, list)
                return value
    for name in ("entries", "records", "transactions", "journal"):
        if hasattr(ledger, name):
            value = getattr(ledger, name)
            if callable(value):
                value = value()
            if value is not None:
                assert isinstance(value, list)
                return value
    return None


def _entry_amount(entry: dict[str, Any]) -> Decimal | None:
    return _number(entry, "amount", "units", "value")


def _entry_direction(entry: dict[str, Any]) -> str | None:
    return _text(entry, "direction", "kind", "type")


def _sum_entries(entries: list[Any]) -> Decimal:
    total = Decimal(0)
    for raw in entries:
        if not isinstance(raw, dict):
            continue
        amount = _entry_amount(raw)
        if amount is None:
            continue
        direction = (_entry_direction(raw) or "").strip().lower()
        if direction in {"credit", "deposit", "add", "fund", "top_up", "increase"}:
            total += amount
        elif direction in {"debit", "charge", "consume", "spend", "withdraw", "decrease"}:
            total -= amount
    return total


def _call_method_if_present(target: Any, names: tuple[str, ...], *args: Any, **kwargs: Any) -> Any:
    for name in names:
        if hasattr(target, name):
            method = getattr(target, name)
            if callable(method):
                return method(*args, **kwargs)
    raise AssertionError(f"missing expected method from candidates: {names}")


def test_wallet_and_ledger_build_objects() -> None:
    wallet = build_unit_wallet()
    ledger = build_unit_ledger()

    assert wallet is not None
    assert ledger is not None


def test_wallet_and_ledger_payloads_are_serializable() -> None:
    wallet_payload = _payload_of(build_unit_wallet())
    ledger_payload = _payload_of(build_unit_ledger())

    assert isinstance(wallet_payload, dict)
    assert isinstance(ledger_payload, dict)
    assert wallet_payload
    assert ledger_payload


def test_wallet_and_ledger_owner_match_when_built_for_same_owner() -> None:
    try:
        wallet = build_unit_wallet(owner_id="owner-001")
        ledger = build_unit_ledger(owner_id="owner-001")
    except TypeError:
        pytest.skip("builders do not accept owner-bound inputs")

    wallet_owner = _text(_payload_of(wallet), "ownerid", "owner_id", "owner", "accountid", "account_id")
    ledger_owner = _text(_payload_of(ledger), "ownerid", "owner_id", "owner", "accountid", "account_id")

    if wallet_owner is not None and ledger_owner is not None:
        assert wallet_owner == ledger_owner == "owner-001"


def test_wallet_and_ledger_distinguish_different_owners_when_supported() -> None:
    try:
        first_wallet = build_unit_wallet(owner_id="owner-001")
        second_wallet = build_unit_wallet(owner_id="owner-002")
        first_ledger = build_unit_ledger(owner_id="owner-001")
        second_ledger = build_unit_ledger(owner_id="owner-002")
    except TypeError:
        pytest.skip("builders do not accept owner-bound inputs")

    fw_owner = _text(_payload_of(first_wallet), "ownerid", "owner_id", "owner", "accountid", "account_id")
    sw_owner = _text(_payload_of(second_wallet), "ownerid", "owner_id", "owner", "accountid", "account_id")
    fl_owner = _text(_payload_of(first_ledger), "ownerid", "owner_id", "owner", "accountid", "account_id")
    sl_owner = _text(_payload_of(second_ledger), "ownerid", "owner_id", "owner", "accountid", "account_id")

    if fw_owner is not None and sw_owner is not None:
        assert fw_owner != sw_owner
    if fl_owner is not None and sl_owner is not None:
        assert fl_owner != sl_owner


def test_wallet_and_ledger_balances_are_non_negative_when_present() -> None:
    wallet_balance = _wallet_balance_of(build_unit_wallet())
    ledger_balance = _ledger_balance_of(build_unit_ledger())

    assert wallet_balance >= Decimal(0)
    if ledger_balance is not None:
        assert ledger_balance >= Decimal(0)


def test_wallet_and_ledger_initial_balances_match_when_built_for_same_owner() -> None:
    try:
        wallet = build_unit_wallet(owner_id="owner-001")
        ledger = build_unit_ledger(owner_id="owner-001")
    except TypeError:
        wallet = build_unit_wallet()
        ledger = build_unit_ledger()

    wallet_balance = _wallet_balance_of(wallet)
    ledger_balance = _ledger_balance_of(ledger)

    if ledger_balance is not None:
        assert wallet_balance == ledger_balance


def test_wallet_credit_and_ledger_credit_stay_consistent_when_supported() -> None:
    try:
        wallet = build_unit_wallet(owner_id="owner-001")
        ledger = build_unit_ledger(owner_id="owner-001")
    except TypeError:
        wallet = build_unit_wallet()
        ledger = build_unit_ledger()

    wallet_credit_methods = ("credit", "deposit", "add_units", "fund", "top_up")
    ledger_credit_methods = ("post_credit", "credit", "add_entry", "record_credit")

    if not any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in wallet_credit_methods):
        pytest.skip("wallet credit method not implemented")
    if not any(hasattr(ledger, name) and callable(getattr(ledger, name)) for name in ledger_credit_methods):
        pytest.skip("ledger credit posting method not implemented")

    wallet_before = _wallet_balance_of(wallet)
    ledger_before = _ledger_balance_of(ledger) or Decimal(0)
    entries_before = list(_entries_of(ledger) or [])

    _call_method_if_present(wallet, wallet_credit_methods, Decimal(10))
    _call_method_if_present(
        ledger,
        ledger_credit_methods,
        amount=Decimal(10),
        reference_id="wallet-ledger-credit-001",
    )

    wallet_after = _wallet_balance_of(wallet)
    ledger_after = _ledger_balance_of(ledger) or Decimal(0)
    entries_after = list(_entries_of(ledger) or [])

    assert wallet_after - wallet_before == Decimal(10)
    assert ledger_after - ledger_before == Decimal(10)
    assert wallet_after == ledger_after
    assert len(entries_after) >= len(entries_before)


def test_wallet_debit_and_ledger_debit_stay_consistent_when_supported() -> None:
    try:
        wallet = build_unit_wallet(owner_id="owner-001")
        ledger = build_unit_ledger(owner_id="owner-001")
    except TypeError:
        wallet = build_unit_wallet()
        ledger = build_unit_ledger()

    wallet_credit_methods = ("credit", "deposit", "add_units", "fund", "top_up")
    wallet_debit_methods = ("debit", "charge", "consume", "spend", "withdraw")
    ledger_credit_methods = ("post_credit", "credit", "add_entry", "record_credit")
    ledger_debit_methods = ("post_debit", "debit", "record_debit")

    if not any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in wallet_debit_methods):
        pytest.skip("wallet debit method not implemented")
    if not any(hasattr(ledger, name) and callable(getattr(ledger, name)) for name in ledger_debit_methods):
        pytest.skip("ledger debit posting method not implemented")

    if any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in wallet_credit_methods):
        _call_method_if_present(wallet, wallet_credit_methods, Decimal(20))
    if any(hasattr(ledger, name) and callable(getattr(ledger, name)) for name in ledger_credit_methods):
        _call_method_if_present(
            ledger,
            ledger_credit_methods,
            amount=Decimal(20),
            reference_id="wallet-ledger-fund-001",
        )

    wallet_before = _wallet_balance_of(wallet)
    ledger_before = _ledger_balance_of(ledger) or Decimal(0)

    _call_method_if_present(wallet, wallet_debit_methods, Decimal(5))
    _call_method_if_present(
        ledger,
        ledger_debit_methods,
        amount=Decimal(5),
        reference_id="wallet-ledger-debit-001",
    )

    wallet_after = _wallet_balance_of(wallet)
    ledger_after = _ledger_balance_of(ledger) or Decimal(0)

    assert wallet_before - wallet_after == Decimal(5)
    assert ledger_before - ledger_after == Decimal(5)
    assert wallet_after == ledger_after


def test_ledger_entry_sum_matches_ledger_balance_when_entries_are_directional() -> None:
    ledger = build_unit_ledger()
    entries = _entries_of(ledger)
    ledger_balance = _ledger_balance_of(ledger)

    if entries is None or ledger_balance is None:
        pytest.skip("ledger does not expose balance and entries together")

    if not entries:
        assert ledger_balance == Decimal(0)
        return

    has_directional_amounts = any(isinstance(entry, dict) and _entry_amount(entry) is not None and _entry_direction(entry) is not None for entry in entries)
    if not has_directional_amounts:
        pytest.skip("ledger entries do not expose directional amounts")

    assert _sum_entries(entries) == ledger_balance


def test_wallet_and_ledger_reject_overdraft_consistently_when_supported() -> None:
    try:
        wallet = build_unit_wallet(owner_id="owner-001")
        ledger = build_unit_ledger(owner_id="owner-001")
    except TypeError:
        wallet = build_unit_wallet()
        ledger = build_unit_ledger()

    wallet_debit_methods = ("debit", "charge", "consume", "spend", "withdraw")
    ledger_debit_methods = ("post_debit", "debit", "record_debit")

    if not any(hasattr(wallet, name) and callable(getattr(wallet, name)) for name in wallet_debit_methods):
        pytest.skip("wallet debit method not implemented")
    if not any(hasattr(ledger, name) and callable(getattr(ledger, name)) for name in ledger_debit_methods):
        pytest.skip("ledger debit posting method not implemented")

    wallet_balance = _wallet_balance_of(wallet)
    ledger_balance = _ledger_balance_of(ledger) or Decimal(0)
    attempt = max(wallet_balance, ledger_balance) + Decimal(1)

    with pytest.raises((TypeError, ValueError, AssertionError)):
        _call_method_if_present(wallet, wallet_debit_methods, attempt)

    with pytest.raises((TypeError, ValueError, AssertionError)):
        _call_method_if_present(
            ledger,
            ledger_debit_methods,
            amount=attempt,
            reference_id="wallet-ledger-overdraft-001",
        )


def test_wallet_and_ledger_payloads_use_json_friendly_values() -> None:
    for payload in (_payload_of(build_unit_wallet()), _payload_of(build_unit_ledger())):
        for key, value in payload.items():
            assert isinstance(key, str)
            assert value is None or isinstance(value, str | int | float | bool | list | dict)
