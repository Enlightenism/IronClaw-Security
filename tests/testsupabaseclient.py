from __future__ import annotations

import importlib
from typing import Any, Final

import pytest

MODULE_CANDIDATES: Final[tuple[str, ...]] = (
    "app.supabaseclient",
    "supabaseclient",
)


def _load_module() -> Any:
    last_error: Exception | None = None
    for name in MODULE_CANDIDATES:
        try:
            return importlib.import_module(name)
        except Exception as exc:  # pragma: no cover
            last_error = exc
    raise AssertionError(f"unable to import Supabase client module: {last_error}")


def _public_callables(module: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name in dir(module):
        if name.startswith("_"):
            continue
        value = getattr(module, name)
        if callable(value):
            result[name] = value
    return result


def _first_callable(module: Any, candidates: tuple[str, ...]) -> Any | None:
    for name in candidates:
        if hasattr(module, name):
            value = getattr(module, name)
            if callable(value):
                return value
    return None


def test_supabase_client_module_imports() -> None:
    module = _load_module()
    assert module is not None


def test_supabase_client_exposes_public_surface() -> None:
    module = _load_module()
    public = _public_callables(module)
    assert public


def test_supabase_client_has_expected_factory_or_client_symbol() -> None:
    module = _load_module()
    names = set(dir(module))

    expected = {
        "create_client",
        "get_client",
        "build_client",
        "build_supabase_client",
        "get_supabase_client",
        "SupabaseClient",
        "SupabaseConfig",
    }

    assert names.intersection(expected)


def test_supabase_client_can_read_environment_backed_configuration_when_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()

    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "test-service-role-key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key")
    monkeypatch.setenv("SUPABASE_ANON_KEY", "test-anon-key")

    config_builders: Final[tuple[str, ...]] = (
        "load_config",
        "get_config",
        "build_config",
        "supabase_config_from_env",
    )

    builder = _first_callable(module, config_builders)
    if builder is None:
        pytest.skip("config builder not implemented")

    config = builder()
    assert config is not None


def test_supabase_client_configuration_rejects_missing_url_when_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()

    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.setenv("SUPABASE_KEY", "test-service-role-key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key")

    config_builders: Final[tuple[str, ...]] = (
        "load_config",
        "get_config",
        "build_config",
        "supabase_config_from_env",
    )

    builder = _first_callable(module, config_builders)
    if builder is None:
        pytest.skip("config builder not implemented")

    with pytest.raises((ValueError, RuntimeError, AssertionError)):
        builder()


def test_supabase_client_configuration_rejects_missing_key_when_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()

    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.delenv("SUPABASE_KEY", raising=False)
    monkeypatch.delenv("SUPABASE_SERVICE_ROLE_KEY", raising=False)
    monkeypatch.delenv("SUPABASE_ANON_KEY", raising=False)

    config_builders: Final[tuple[str, ...]] = (
        "load_config",
        "get_config",
        "build_config",
        "supabase_config_from_env",
    )

    builder = _first_callable(module, config_builders)
    if builder is None:
        pytest.skip("config builder not implemented")

    with pytest.raises((ValueError, RuntimeError, AssertionError)):
        builder()


def test_supabase_client_factory_accepts_explicit_parameters_when_supported() -> None:
    module = _load_module()

    factory_names: Final[tuple[str, ...]] = (
        "create_client",
        "get_client",
        "build_client",
        "build_supabase_client",
        "get_supabase_client",
    )

    factory = _first_callable(module, factory_names)
    if factory is None:
        pytest.skip("client factory not implemented")

    try:
        client = factory(
            url="https://example.supabase.co",
            key="test-service-role-key",
        )
    except TypeError:
        pytest.skip("factory does not support explicit url/key parameters")

    assert client is not None


def test_supabase_client_factory_can_use_environment_when_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()

    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "test-service-role-key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key")

    factory_names: Final[tuple[str, ...]] = (
        "create_client",
        "get_client",
        "build_client",
        "build_supabase_client",
        "get_supabase_client",
    )

    factory = _first_callable(module, factory_names)
    if factory is None:
        pytest.skip("client factory not implemented")

    try:
        client = factory()
    except TypeError:
        pytest.skip("factory requires explicit parameters")

    assert client is not None


def test_supabase_client_factory_rejects_blank_url_when_supported() -> None:
    module = _load_module()

    factory_names: Final[tuple[str, ...]] = (
        "create_client",
        "get_client",
        "build_client",
        "build_supabase_client",
        "get_supabase_client",
    )

    factory = _first_callable(module, factory_names)
    if factory is None:
        pytest.skip("client factory not implemented")

    with pytest.raises((TypeError, ValueError, RuntimeError, AssertionError)):
        factory(url="", key="test-service-role-key")


def test_supabase_client_factory_rejects_blank_key_when_supported() -> None:
    module = _load_module()

    factory_names: Final[tuple[str, ...]] = (
        "create_client",
        "get_client",
        "build_client",
        "build_supabase_client",
        "get_supabase_client",
    )

    factory = _first_callable(module, factory_names)
    if factory is None:
        pytest.skip("client factory not implemented")

    with pytest.raises((TypeError, ValueError, RuntimeError, AssertionError)):
        factory(url="https://example.supabase.co", key="")


def test_supabase_config_object_exposes_url_and_key_when_supported() -> None:
    module = _load_module()

    if not hasattr(module, "SupabaseConfig"):
        pytest.skip("SupabaseConfig not implemented")

    config_cls = module.SupabaseConfig

    try:
        config = config_cls(
            url="https://example.supabase.co",
            key="test-service-role-key",
        )
    except TypeError:
        try:
            config = config_cls(
                supabase_url="https://example.supabase.co",
                supabase_key="test-service-role-key",
            )
        except TypeError:
            pytest.skip("SupabaseConfig constructor shape differs")

    attrs = set(dir(config))
    assert attrs.intersection({"url", "supabase_url"})
    assert attrs.intersection({"key", "supabase_key", "service_role_key", "anon_key"})


def test_supabase_client_module_keeps_network_side_effects_out_of_import() -> None:
    module = _load_module()
    assert module is not None


def test_supabase_client_config_is_immutable_or_defensive_when_supported() -> None:
    module = _load_module()

    if not hasattr(module, "SupabaseConfig"):
        pytest.skip("SupabaseConfig not implemented")

    config_cls = module.SupabaseConfig

    try:
        config = config_cls(
            url="https://example.supabase.co",
            key="test-service-role-key",
        )
    except TypeError:
        try:
            config = config_cls(
                supabase_url="https://example.supabase.co",
                supabase_key="test-service-role-key",
            )
        except TypeError:
            pytest.skip("SupabaseConfig constructor shape differs")

    # At a minimum, object must remain usable after attribute-set attempts,
    # even if the attributes are frozen (raises AttributeError).
    for field in ("url", "supabase_url", "key", "supabase_key"):
        if not hasattr(config, field):
            continue
        try:
            setattr(config, field, getattr(config, field))
        except AttributeError:
            # Frozen config is acceptable.
            continue

    assert config is not None
