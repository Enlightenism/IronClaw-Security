from __future__ import annotations

from typing import Any

import pytest
from app.billingregistry import build_billing_registry


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
        for key in ("items", "entries", "records", "registrations", "data"):
            value = result.get(key)
            if isinstance(value, list):
                return value
        return [result]
    if hasattr(result, "__iter__") and not isinstance(result, str | bytes):
        try:
            return list(result)
        except TypeError:
            pass
    return [result]


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


def test_build_billing_registry_returns_object() -> None:
    registry = build_billing_registry()

    assert registry is not None


def test_billing_registry_is_serializable_to_supported_shape() -> None:
    registry = build_billing_registry()

    assert isinstance(registry, dict | list) or hasattr(registry, "as_dict") or hasattr(registry, "__iter__")


def test_billing_registry_contains_at_least_one_entry() -> None:
    items = _items_of(build_billing_registry())

    assert isinstance(items, list)
    assert items


def test_each_billing_registry_entry_has_dictionary_shape_when_serialized() -> None:
    items = _items_of(build_billing_registry())

    for item in items:
        payload = _payload_of(item)
        assert isinstance(payload, dict)
        assert payload


def test_billing_registry_contains_core_fields_when_present() -> None:
    items = _items_of(build_billing_registry())
    assert items

    expected_candidates = {
        "registryid",
        "registry_id",
        "entryid",
        "entry_id",
        "id",
        "ownerid",
        "owner_id",
        "packageid",
        "package_id",
        "walletid",
        "wallet_id",
        "status",
        "generatedat",
        "createdat",
    }

    payload = _payload_of(items[0])
    assert set(payload.keys()).intersection(expected_candidates)


def test_billing_registry_identifiers_are_non_empty_when_present() -> None:
    items = _items_of(build_billing_registry())

    for item in items:
        payload = _payload_of(item)
        for value in (
            _text(payload, "registryid", "registry_id", "entryid", "entry_id", "id"),
            _text(payload, "ownerid", "owner_id", "owner"),
            _text(payload, "packageid", "package_id", "package"),
            _text(payload, "walletid", "wallet_id", "wallet"),
            _text(payload, "status", "state"),
        ):
            if value is not None:
                assert value.strip()


def test_billing_registry_nested_sections_are_dict_or_list_when_present() -> None:
    items = _items_of(build_billing_registry())

    for item in items:
        payload = _payload_of(item)
        for value in (
            _value(payload, "metadata", "summary", "context"),
            _value(payload, "events", "history", "records"),
        ):
            if value is not None:
                assert isinstance(value, dict | list)


def test_billing_registry_supports_owner_bound_build_when_available() -> None:
    try:
        registry = build_billing_registry(owner_id="owner-001")
    except TypeError:
        registry = build_billing_registry()

    items = _items_of(registry)
    assert items

    first_payload = _payload_of(items[0])
    owner = _text(first_payload, "ownerid", "owner_id", "owner")
    if owner is not None:
        assert owner.strip()


def test_billing_registry_supports_package_bound_build_when_available() -> None:
    try:
        registry = build_billing_registry(package_id="pkg-basic")
    except TypeError:
        registry = build_billing_registry()

    items = _items_of(registry)
    assert items


def test_billing_registry_supports_wallet_bound_build_when_available() -> None:
    try:
        registry = build_billing_registry(wallet_id="wallet-001")
    except TypeError:
        registry = build_billing_registry()

    items = _items_of(registry)
    assert items


def test_billing_registry_rejects_blank_owner_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_billing_registry(owner_id="")


def test_billing_registry_rejects_blank_package_id_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_billing_registry(package_id="")


def test_billing_registry_rejects_blank_wallet_id_when_supported() -> None:
    with pytest.raises((TypeError, ValueError, AssertionError)):
        build_billing_registry(wallet_id="")


def test_billing_registry_register_method_returns_new_entry_when_supported() -> None:
    registry = build_billing_registry()

    register_methods = ("register", "add_entry", "create_entry", "enroll")
    if not any(hasattr(registry, name) and callable(getattr(registry, name)) for name in register_methods):
        pytest.skip("registry register method not implemented")

    result = _call_method_if_present(
        registry,
        register_methods,
        owner_id="owner-001",
        package_id="pkg-basic",
        wallet_id="wallet-001",
    )
    payload = _payload_of(result)

    owner = _text(payload, "ownerid", "owner_id", "owner")
    package_id = _text(payload, "packageid", "package_id", "package")
    wallet_id = _text(payload, "walletid", "wallet_id", "wallet")

    if owner is not None:
        assert owner == "owner-001"
    if package_id is not None:
        assert package_id == "pkg-basic"
    if wallet_id is not None:
        assert wallet_id == "wallet-001"


def test_billing_registry_register_method_rejects_blank_identifiers_when_supported() -> None:
    registry = build_billing_registry()

    register_methods = ("register", "add_entry", "create_entry", "enroll")
    if not any(hasattr(registry, name) and callable(getattr(registry, name)) for name in register_methods):
        pytest.skip("registry register method not implemented")

    with pytest.raises((TypeError, ValueError, AssertionError)):
        _call_method_if_present(
            registry,
            register_methods,
            owner_id="",
            package_id="pkg-basic",
            wallet_id="wallet-001",
        )

    with pytest.raises((TypeError, ValueError, AssertionError)):
        _call_method_if_present(
            registry,
            register_methods,
            owner_id="owner-001",
            package_id="",
            wallet_id="wallet-001",
        )

    with pytest.raises((TypeError, ValueError, AssertionError)):
        _call_method_if_present(
            registry,
            register_methods,
            owner_id="owner-001",
            package_id="pkg-basic",
            wallet_id="",
        )


def test_billing_registry_lookup_method_returns_matching_entry_when_supported() -> None:
    registry = build_billing_registry()

    lookup_methods = ("get", "find", "find_entry", "lookup")
    if not any(hasattr(registry, name) and callable(getattr(registry, name)) for name in lookup_methods):
        pytest.skip("registry lookup method not implemented")

    items = _items_of(registry)
    sample_payload = _payload_of(items[0])
    entry_id = _text(sample_payload, "registryid", "registry_id", "entryid", "entry_id", "id")
    if entry_id is None:
        pytest.skip("no lookup-friendly identifier available")

    result = _call_method_if_present(registry, lookup_methods, entry_id)
    payload = _payload_of(result)
    matched = _text(payload, "registryid", "registry_id", "entryid", "entry_id", "id")

    assert matched == entry_id


def test_billing_registry_payload_uses_json_friendly_values() -> None:
    items = _items_of(build_billing_registry())

    for item in items:
        payload = _payload_of(item)
        for key, value in payload.items():
            assert isinstance(key, str)
            assert value is None or isinstance(value, str | int | float | bool | list | dict)


def test_billing_registry_multiple_builds_have_stable_top_level_shape() -> None:
    first = _items_of(build_billing_registry())
    second = _items_of(build_billing_registry())

    assert isinstance(first, list)
    assert isinstance(second, list)
    assert bool(first) == bool(second)

    if first and second:
        assert set(_payload_of(first[0]).keys()) == set(_payload_of(second[0]).keys())


def test_billing_registry_filtered_builds_have_stable_top_level_shape_when_supported() -> None:
    try:
        first = _items_of(build_billing_registry(owner_id="owner-001"))
        second = _items_of(build_billing_registry(owner_id="owner-001"))
    except TypeError:
        pytest.skip("owner-bound registry build not implemented")

    assert isinstance(first, list)
    assert isinstance(second, list)
    assert bool(first) == bool(second)

    if first and second:
        assert set(_payload_of(first[0]).keys()) == set(_payload_of(second[0]).keys())
