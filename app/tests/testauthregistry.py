from __future__ import annotations

from app.core.apikeys import APIKeyRecord, get_api_key_registry


def _clear_registry() -> None:
    registry = get_api_key_registry()
    for attr_name in ("clear", "reset"):
        method = getattr(registry, attr_name, None)
        if callable(method):
            method()
            return
    keys_by_id = getattr(registry, "_keys_by_id", None)
    if isinstance(keys_by_id, dict):
        keys_by_id.clear()
    api_keys_to_id = getattr(registry, "_api_keys_to_id", None)
    if isinstance(api_keys_to_id, dict):
        api_keys_to_id.clear()


def _register_api_key(*, key_id: str, api_key: str) -> None:
    registry = get_api_key_registry()
    for attr_name in ("register_api_key", "add_api_key", "upsert_api_key"):
        method = getattr(registry, attr_name, None)
        if callable(method):
            try:
                method(key_id=key_id, api_key=api_key)
                return
            except TypeError:
                try:
                    method(id=key_id, api_key=api_key)
                    return
                except TypeError:
                    pass
    raise AssertionError("API key registry does not expose a supported registration method")


def test_get_api_key_registry_returns_singleton_instance() -> None:
    _clear_registry()

    first = get_api_key_registry()
    second = get_api_key_registry()

    assert first is second


def test_registry_resolves_registered_api_key_to_record() -> None:
    _clear_registry()
    _register_api_key(key_id="ops-key", api_key="secret-ops")

    registry = get_api_key_registry()
    record = registry.resolve_api_key("secret-ops")

    assert isinstance(record, APIKeyRecord)
    assert getattr(record, "id", None) == "ops-key"


def test_registry_returns_none_for_unknown_api_key() -> None:
    _clear_registry()
    _register_api_key(key_id="ops-key", api_key="secret-ops")

    registry = get_api_key_registry()

    assert registry.resolve_api_key("unknown-key") is None


def test_registry_clear_removes_registered_keys() -> None:
    _clear_registry()
    _register_api_key(key_id="ops-key", api_key="secret-ops")

    registry = get_api_key_registry()
    assert registry.resolve_api_key("secret-ops") is not None

    _clear_registry()

    assert registry.resolve_api_key("secret-ops") is None


def test_registry_supports_multiple_distinct_keys() -> None:
    _clear_registry()
    _register_api_key(key_id="ops-key", api_key="secret-ops")
    _register_api_key(key_id="admin-key", api_key="secret-admin")

    registry = get_api_key_registry()
    ops_record = registry.resolve_api_key("secret-ops")
    admin_record = registry.resolve_api_key("secret-admin")

    assert isinstance(ops_record, APIKeyRecord)
    assert isinstance(admin_record, APIKeyRecord)
    assert getattr(ops_record, "id", None) == "ops-key"
    assert getattr(admin_record, "id", None) == "admin-key"


def test_registry_latest_registration_wins_for_same_api_key_value() -> None:
    _clear_registry()
    _register_api_key(key_id="first-key", api_key="shared-secret")
    _register_api_key(key_id="second-key", api_key="shared-secret")

    registry = get_api_key_registry()
    record = registry.resolve_api_key("shared-secret")

    assert isinstance(record, APIKeyRecord)
    assert getattr(record, "id", None) == "second-key"
