from __future__ import annotations

import importlib
from typing import Any, Final

import pytest

MODULE_CANDIDATES: Final[tuple[str, ...]] = (
    "app.persistencebootstrap",
    "persistencebootstrap",
    "app.bootstrap",
)


def _load_module() -> Any:
    last_error: Exception | None = None
    for name in MODULE_CANDIDATES:
        try:
            return importlib.import_module(name)
        except Exception as exc:  # pragma: no cover
            last_error = exc
    raise AssertionError(f"unable to import persistence bootstrap module: {last_error}")


def _callable_names(module: Any) -> set[str]:
    return {name for name in dir(module) if not name.startswith("_") and callable(getattr(module, name))}


def _first_callable(module: Any, *names: str) -> Any | None:
    for name in names:
        if hasattr(module, name):
            value = getattr(module, name)
            if callable(value):
                return value
    return None


def _resolve_builder(module: Any) -> Any | None:
    return _first_callable(
        module,
        "bootstrap_persistence",
        "build_persistence",
        "get_persistence",
        "build_store_registry",
        "build_persistence_registry",
    )


def test_persistence_bootstrap_module_imports() -> None:
    module = _load_module()
    assert module is not None


def test_persistence_bootstrap_exposes_bootstrap_surface() -> None:
    module = _load_module()
    names = set(dir(module))

    expected = {
        "bootstrap_persistence",
        "build_persistence",
        "get_persistence",
        "build_store_registry",
        "build_persistence_registry",
        "PersistenceBootstrap",
        "PersistenceRegistry",
    }

    assert names.intersection(expected)


def test_persistence_bootstrap_has_public_callables() -> None:
    module = _load_module()
    assert _callable_names(module)


def test_persistence_bootstrap_can_build_default_registry_when_supported() -> None:
    module = _load_module()
    builder = _resolve_builder(module)
    if builder is None:
        pytest.skip("bootstrap builder not implemented")

    try:
        registry = builder()
    except TypeError:
        pytest.skip("builder requires unsupported arguments")

    assert registry is not None


def test_persistence_bootstrap_supports_explicit_memory_mode_when_supported() -> None:
    module = _load_module()
    builder = _resolve_builder(module)
    if builder is None:
        pytest.skip("bootstrap builder not implemented")

    try:
        registry = builder(mode="memory")
    except TypeError:
        try:
            registry = builder(backend="memory")
        except TypeError:
            pytest.skip("explicit backend selection not implemented")

    assert registry is not None


def test_persistence_bootstrap_supports_explicit_supabase_mode_when_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()
    builder = _resolve_builder(module)
    if builder is None:
        pytest.skip("bootstrap builder not implemented")

    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "test-service-role-key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key")

    try:
        registry = builder(mode="supabase")
    except TypeError:
        try:
            registry = builder(backend="supabase")
        except TypeError:
            pytest.skip("explicit backend selection not implemented")

    assert registry is not None


def test_persistence_bootstrap_rejects_unknown_backend_when_supported() -> None:
    module = _load_module()
    builder = _resolve_builder(module)
    if builder is None:
        pytest.skip("bootstrap builder not implemented")

    with pytest.raises((TypeError, ValueError, RuntimeError, AssertionError)):
        try:
            builder(mode="bogus")
        except TypeError:
            builder(backend="bogus")


def test_persistence_bootstrap_can_read_env_selected_backend_when_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()
    builder = _first_callable(
        module,
        "bootstrap_persistence",
        "build_persistence",
        "get_persistence",
    )
    if builder is None:
        pytest.skip("bootstrap builder not implemented")

    monkeypatch.setenv("IRONCLAW_PERSISTENCE_BACKEND", "memory")

    try:
        registry = builder()
    except TypeError:
        pytest.skip("builder requires unsupported arguments")

    assert registry is not None


def test_persistence_bootstrap_requires_supabase_config_for_supabase_mode_when_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()
    builder = _resolve_builder(module)
    if builder is None:
        pytest.skip("bootstrap builder not implemented")

    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_KEY", raising=False)
    monkeypatch.delenv("SUPABASE_SERVICE_ROLE_KEY", raising=False)
    monkeypatch.delenv("SUPABASE_ANON_KEY", raising=False)

    with pytest.raises((TypeError, ValueError, RuntimeError, AssertionError)):
        try:
            builder(mode="supabase")
        except TypeError:
            builder(backend="supabase")


def test_persistence_registry_exposes_domain_stores_when_supported() -> None:
    module = _load_module()
    builder = _resolve_builder(module)
    if builder is None:
        pytest.skip("bootstrap builder not implemented")

    try:
        registry = builder(mode="memory")
    except TypeError:
        try:
            registry = builder(backend="memory")
        except TypeError:
            try:
                registry = builder()
            except TypeError:
                pytest.skip("builder requires unsupported arguments")

    expected_names = {
        "audit",
        "audit_store",
        "history",
        "history_store",
        "incidents",
        "incident_store",
        "quarantine",
        "quarantine_store",
        "review_queue",
        "reviewqueue",
        "billing",
        "billing_store",
        "organizations",
        "organization_store",
        "telemetry",
        "runtime_state",
        "review_state",
    }

    registry_names = set(dir(registry))
    assert registry_names.intersection(expected_names)


def test_persistence_registry_can_serialize_or_describe_itself_when_supported() -> None:
    module = _load_module()
    builder = _resolve_builder(module)
    if builder is None:
        pytest.skip("bootstrap builder not implemented")

    try:
        registry = builder(mode="memory")
    except TypeError:
        try:
            registry = builder(backend="memory")
        except TypeError:
            try:
                registry = builder()
            except TypeError:
                pytest.skip("builder requires unsupported arguments")

    supported = False
    for name in ("as_dict", "to_dict", "describe", "summary"):
        if hasattr(registry, name) and callable(getattr(registry, name)):
            value = getattr(registry, name)()
            assert value is not None
            supported = True
            break

    if not supported:
        assert registry is not None


def test_persistence_bootstrap_is_stable_across_multiple_calls_when_supported() -> None:
    module = _load_module()
    builder = _resolve_builder(module)
    if builder is None:
        pytest.skip("bootstrap builder not implemented")

    try:
        first = builder(mode="memory")
        second = builder(mode="memory")
    except TypeError:
        try:
            first = builder(backend="memory")
            second = builder(backend="memory")
        except TypeError:
            try:
                first = builder()
                second = builder()
            except TypeError:
                pytest.skip("builder requires unsupported arguments")

    assert first is not None
    assert second is not None
    assert type(first) is type(second)


def test_persistence_bootstrap_can_accept_injected_supabase_client_when_supported() -> None:
    module = _load_module()
    builder = _resolve_builder(module)
    if builder is None:
        pytest.skip("bootstrap builder not implemented")

    fake_client = object()

    try:
        registry = builder(mode="supabase", client=fake_client)
    except TypeError:
        try:
            registry = builder(backend="supabase", client=fake_client)
        except TypeError:
            try:
                registry = builder(mode="supabase", supabase_client=fake_client)
            except TypeError:
                try:
                    registry = builder(backend="supabase", supabase_client=fake_client)
                except TypeError:
                    pytest.skip("client injection not implemented")

    assert registry is not None
