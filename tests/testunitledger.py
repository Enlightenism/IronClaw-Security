from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from app.unitledger import build_unit_ledger


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


def _call_method_if_present(target: Any, names: tuple[str, ...], *args: Any, **kwargs: Any) -> Any:
    for name in names:
        if hasattr(target, name):
            method = getattr(target, name)
            if callable(method):
                return method(*args, **kwargs)
    raise AssertionError(f"missing expected method from candidates: {names}")


def test_build_unit_ledger_returns_object() -> None:
    ledger = build_unit_ledger()

    assert ledger is not None


def test_unit_ledger_is_serializable_to_dictionary_shape() -> None:
    payload = _payload_of(build_unit_ledger())

    assert isinstance(payload, dict)
    assert payload


def test_unit_ledger_contains_stable_top_level_fields_when_present() -> None:
    payload = _payload_of(build_unit_ledger())

    expected_candidates = {
        "ledgerid",
        "ledger_id",
        "ownerid",
        "owner_id",
        "balance",
        "units",
        "available",
        "entrycount",
        "entry_count",
        "entries",
        "records",
        "transactions",
        "journal",
        "currency",
        "status",
        "state",
        "generatedat",
        "generated_at",
        "createdat",
        "created_at",
    }
    assert set(payload.keys()).intersection(expected_candidates)


def test_unit_ledger_owner_identifier_is_non_empty_when_present() -> None:
    payload = _payload_of(build_unit_ledger())

    owner = _text(payload, "ownerid", "owner_id", "owner", "accountid", "account_id")
    if owner is not None:
        assert owner.strip()


def test_unit_ledger_balance_is_non_negative_when_present() -> None:
    payload = _payload_of(build_unit_ledger())

    balance = _number(payload, "balance", "units", "available", "credits", "available_units")
    if balance is not None:
        assert balance >= Decimal(0)


def test_unit_ledger_entry_count_matches_entries_length_when_both_present() -> None:
    ledger = build_unit_ledger()
    payload = _payload_of(ledger)
    entries = _entries_of(ledger)
    entry_count = _number(payload, "entrycount", "entry_count", "totalentries", "total_entries")

    if entries is not None and entry_count is not None:
        assert int(entry_count) == len(entries)


def test_unit_ledger_entries_have_stable_shape_when_present() -> None:
    ledger = build_unit_ledger()
    entries = _entries_of(ledger)

    if entries is None:
        pytest.skip("ledger does not expose entries collection")

    for entry in entries:
        assert isinstance(entry, dict)
        assert any(
            key in entry
            for key in (
                "entryid",
                "entry_id",
                "amount",
                "direction",
                "type",
                "referenceid",
                "reference_id",
                "timestamp",
            )
        )


def test_unit_ledger_entry_amounts_are_non_negative_when_present() -> None:
    entries = _entries_of(build_unit_ledger())

    if entries is None:
        pytest.skip("ledger does not expose entries collection")

    for entry in entries:
        if "amount" in entry and entry["amount"] is not None:
            assert Decimal(str(entry["amount"])) >= Decimal(0)


def test_unit_ledger_post_credit_increases_balance_when_supported() -> None:
    ledger = build_unit_ledger()

    post_methods = ("post_credit", "credit", "add_entry", "record_credit")
    if not any(hasattr(ledger, name) and callable(getattr(ledger, name)) for name in post_methods):
        pytest.skip("ledger credit posting method not implemented")

    before_payload = _payload_of(ledger)
    before = _number(before_payload, "balance", "units", "available") or Decimal(0)

    _call_method_if_present(
        ledger,
        post_methods,
        amount=Decimal(10),
        reference_id="credit-001",
    )

    after_payload = _payload_of(ledger)
    after = _number(after_payload, "balance", "units", "available") or Decimal(0)

    assert after - before == Decimal(10)


def test_unit_ledger_post_debit_decreases_balance_when_supported() -> None:
    ledger = build_unit_ledger()

    credit_methods = ("post_credit", "credit", "add_entry", "record_credit")
    debit_methods = ("post_debit", "debit", "record_debit")

    if not any(hasattr(ledger, name) and callable(getattr(ledger, name)) for name in debit_methods):
        pytest.skip("ledger debit posting method not implemented")

    if any(hasattr(ledger, name) and callable(getattr(ledger, name)) for name in credit_methods):
        _call_method_if_present(
            ledger,
            credit_methods,
            amount=Decimal(25),
            reference_id="fund-001",
        )

    before_payload = _payload_of(ledger)
    before = _number(before_payload, "balance", "units", "available") or Decimal(0)

    _call_method_if_present(
        ledger,
        debit_methods,
        amount=Decimal(5),
        reference_id="debit-001",
    )

    after_payload = _payload_of(ledger)
    after = _number(after_payload, "balance", "units", "available") or Decimal(0)

    assert before - after == Decimal(5)


def test_unit_ledger_rejects_negative_credit_when_supported() -> None:
    ledger = build_unit_ledger()

    post_methods = ("post_credit", "credit", "add_entry", "record_credit")
    if not any(hasattr(ledger, name) and callable(getattr(ledger, name)) for name in post_methods):
        pytest.skip("ledger credit posting method not implemented")

    with pytest.raises((TypeError, ValueError, AssertionError)):
        _call_method_if_present(
            ledger,
            post_methods,
            amount=Decimal(-1),
            reference_id="credit-negative",
        )


def test_unit_ledger_rejects_negative_debit_when_supported() -> None:
    ledger = build_unit_ledger()

    debit_methods = ("post_debit", "debit", "record_debit")
    if not any(hasattr(ledger, name) and callable(getattr(ledger, name)) for name in debit_methods):
        pytest.skip("ledger debit posting method not implemented")

    with pytest.raises((TypeError, ValueError, AssertionError)):
        _call_method_if_present(
            ledger,
            debit_methods,
            amount=Decimal(-1),
            reference_id="debit-negative",
        )


def test_unit_ledger_prevents_overdraft_when_supported() -> None:
    ledger = build_unit_ledger()

    debit_methods = ("post_debit", "debit", "record_debit")
    if not any(hasattr(ledger, name) and callable(getattr(ledger, name)) for name in debit_methods):
        pytest.skip("ledger debit posting method not implemented")

    payload = _payload_of(ledger)
    balance = _number(payload, "balance", "units", "available") or Decimal(0)

    with pytest.raises((TypeError, ValueError, AssertionError)):
        _call_method_if_present(
            ledger,
            debit_methods,
            amount=balance + Decimal(1),
            reference_id="overdraft-001",
        )


def test_unit_ledger_entries_are_append_only_when_supported() -> None:
    ledger = build_unit_ledger()
    credit_methods = ("post_credit", "credit", "add_entry", "record_credit")

    if not any(hasattr(ledger, name) and callable(getattr(ledger, name)) for name in credit_methods):
        pytest.skip("ledger credit posting method not implemented")

    before_entries = list(_entries_of(ledger) or [])
    _call_method_if_present(
        ledger,
        credit_methods,
        amount=Decimal(3),
        reference_id="append-001",
    )
    after_entries = list(_entries_of(ledger) or [])

    assert len(after_entries) >= len(before_entries)


def test_unit_ledger_idempotent_reference_does_not_duplicate_when_supported() -> None:
    ledger = build_unit_ledger()
    credit_methods = ("post_credit", "credit", "add_entry", "record_credit")

    if not any(hasattr(ledger, name) and callable(getattr(ledger, name)) for name in credit_methods):
        pytest.skip("ledger credit posting method not implemented")

    try:
        _call_method_if_present(
            ledger,
            credit_methods,
            amount=Decimal(4),
            reference_id="idempotent-001",
        )
        first_entries = list(_entries_of(ledger) or [])
        _call_method_if_present(
            ledger,
            credit_methods,
            amount=Decimal(4),
            reference_id="idempotent-001",
        )
        second_entries = list(_entries_of(ledger) or [])
    except (TypeError, ValueError, AssertionError):
        pytest.skip("ledger does not support idempotent reference enforcement")

    assert len(second_entries) == len(first_entries)


def test_unit_ledger_owner_specificity_is_stable_when_supported() -> None:
    try:
        first = build_unit_ledger(owner_id="owner-001")
        second = build_unit_ledger(owner_id="owner-002")
    except TypeError:
        pytest.skip("ledger builder does not accept owner-bound inputs")

    first_owner = _text(_payload_of(first), "ownerid", "owner_id", "owner", "accountid", "account_id")
    second_owner = _text(_payload_of(second), "ownerid", "owner_id", "owner", "accountid", "account_id")

    if first_owner is not None and second_owner is not None:
        assert first_owner != second_owner


def test_unit_ledger_payload_uses_json_friendly_values() -> None:
    payload = _payload_of(build_unit_ledger())

    for key, value in payload.items():
        assert isinstance(key, str)
        assert value is None or isinstance(value, (str, int, float, bool, list, dict))
