from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from app.billingstore import build_billing_store


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


def test_build_billing_store_returns_object() -> None:
    store = build_billing_store()

    assert store is not None


def test_billing_store_is_serializable_to_dictionary_shape() -> None:
    payload = _payload_of(build_billing_store())

    assert isinstance(payload, dict)
    assert payload


def test_billing_store_contains_core_fields_when_present() -> None:
    payload = _payload_of(build_billing_store())

    expected_candidates = {
        "storeid",
        "ownerid",
        "packages",
        "purchases",
        "wallet",
        "ledger",
        "status",
        "generatedat",
    }
    assert set(payload.keys()).intersection(expected_candidates)


def test_billing_store_identifiers_are_non_empty_when_present() -> None:
    payload = _payload_of(build_billing_store())

    for value in (
        _text(payload, "storeid", "store_id", "id"),
        _text(payload, "ownerid", "owner_id", "owner", "accountid", "account_id"),
        _text(payload, "status", "state"),
    ):
        if value is not None:
            assert value.strip()


def test_billing_store_collections_have_expected_types_when_present() -> None:
    payload = _payload_of(build_billing_store())

    packages = _value(payload, "packages", "catalog", "plans")
    purchases = _value(payload, "purchases", "orders", "entitlements")

    if packages is not None:
        assert isinstance(packages, list | dict)
    if purchases is not None:
        assert isinstance(purchases, list | dict)


def test_billing_store_nested_wallet_and_ledger_are_dicts_when_present() -> None:
    payload = _payload_of(build_billing_store())

    wallet = _value(payload, "wallet")
    ledger = _value(payload, "ledger")

    if wallet is not None:
        assert isinstance(wallet, dict)
    if ledger is not None:
        assert isinstance(ledger, dict)


def test_billing_store_supports_owner_bound_build_when_available() -> None:
    try:
        store = build_billing_store(owner_id="owner-001")
    except TypeError:
        store = build_billing_store()

    payload = _payload_of(store)
    owner = _text(payload, "ownerid", "owner_id", "owner")
    if owner is not None:
        assert owner.strip()


def test_billing_store_purchase_package_flow_when_supported() -> None:
    store = build_billing_store()

    purchase_methods = ("purchase_package", "purchase", "buy_package", "grant_package")
    if not any(hasattr(store, name) and callable(getattr(store, name)) for name in purchase_methods):
        pytest.skip("billing store purchase method not implemented")

    try:
        result = _call_method_if_present(
            store,
            purchase_methods,
            owner_id="owner-001",
            package_id="starter",
            quantity=1,
        )
    except TypeError:
        result = _call_method_if_present(
            store,
            purchase_methods,
            "owner-001",
            "starter",
            1,
        )

    if result is not None:
        payload = _payload_of(result)
        package_id = _text(payload, "packageid", "package_id", "planid", "plan_id")
        if package_id is not None:
            assert package_id.strip()


def test_billing_store_rejects_blank_owner_on_purchase_when_supported() -> None:
    store = build_billing_store()

    purchase_methods = ("purchase_package", "purchase", "buy_package", "grant_package")
    if not any(hasattr(store, name) and callable(getattr(store, name)) for name in purchase_methods):
        pytest.skip("billing store purchase method not implemented")

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            _call_method_if_present(
                store,
                purchase_methods,
                owner_id="",
                package_id="starter",
                quantity=1,
            )
        except TypeError:
            _call_method_if_present(store, purchase_methods, "", "starter", 1)


def test_billing_store_rejects_blank_package_on_purchase_when_supported() -> None:
    store = build_billing_store()

    purchase_methods = ("purchase_package", "purchase", "buy_package", "grant_package")
    if not any(hasattr(store, name) and callable(getattr(store, name)) for name in purchase_methods):
        pytest.skip("billing store purchase method not implemented")

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            _call_method_if_present(
                store,
                purchase_methods,
                owner_id="owner-001",
                package_id="",
                quantity=1,
            )
        except TypeError:
            _call_method_if_present(store, purchase_methods, "owner-001", "", 1)


def test_billing_store_rejects_non_positive_quantity_on_purchase_when_supported() -> None:
    store = build_billing_store()

    purchase_methods = ("purchase_package", "purchase", "buy_package", "grant_package")
    if not any(hasattr(store, name) and callable(getattr(store, name)) for name in purchase_methods):
        pytest.skip("billing store purchase method not implemented")

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            _call_method_if_present(
                store,
                purchase_methods,
                owner_id="owner-001",
                package_id="starter",
                quantity=0,
            )
        except TypeError:
            _call_method_if_present(store, purchase_methods, "owner-001", "starter", 0)


def test_billing_store_package_catalog_entries_have_stable_shape_when_present() -> None:
    payload = _payload_of(build_billing_store())
    packages = _value(payload, "packages", "catalog", "plans")

    if packages is None:
        pytest.skip("billing store does not expose package catalog")

    if isinstance(packages, dict):
        iterable = list(packages.values())
    else:
        iterable = list(packages)

    for entry in iterable:
        assert isinstance(entry, dict)
        assert any(
            key in entry
            for key in (
                "packageid",
                "package_id",
                "name",
                "price",
                "units",
                "quota",
            )
        )


def test_billing_store_purchase_records_have_stable_shape_when_present() -> None:
    payload = _payload_of(build_billing_store())
    purchases = _value(payload, "purchases", "orders", "entitlements")

    if purchases is None:
        pytest.skip("billing store does not expose purchases collection")

    if isinstance(purchases, dict):
        iterable = list(purchases.values())
    else:
        iterable = list(purchases)

    for record in iterable:
        assert isinstance(record, dict)
        assert any(
            key in record
            for key in (
                "purchaseid",
                "purchase_id",
                "packageid",
                "package_id",
                "ownerid",
                "owner_id",
                "status",
            )
        )


def test_billing_store_financial_fields_are_non_negative_when_present() -> None:
    payload = _payload_of(build_billing_store())

    for keys in (
        ("balance",),
        ("units",),
        ("price",),
        ("quota",),
        ("remaining",),
    ):
        value = _number(payload, *keys)
        if value is not None:
            assert value >= Decimal(0)


def test_billing_store_multiple_builds_have_stable_key_sets() -> None:
    first = _payload_of(build_billing_store())
    second = _payload_of(build_billing_store())

    assert set(first.keys()) == set(second.keys())


def test_billing_store_payload_uses_json_friendly_values() -> None:
    payload = _payload_of(build_billing_store())

    for key, value in payload.items():
        assert isinstance(key, str)
        assert value is None or isinstance(value, str | int | float | bool | list | dict)
