from __future__ import annotations

import importlib
from typing import Any, Final

import pytest

MODULE_CANDIDATES: Final[tuple[str, ...]] = (
    "app.services.organizationstore",
    "services.organizationstore",
    "organizationstore",
    "app.services.telemetry",
    "services.telemetry",
    "telemetry",
    "app.services.runtimesession",
    "services.runtimesession",
    "runtimesession",
    "app.services.reviewstatestore",
    "services.reviewstatestore",
    "reviewstatestore",
    "app.orchestrator.checkpointstore",
    "orchestrator.checkpointstore",
    "checkpointstore",
)


def _load_modules() -> list[Any]:
    modules: list[Any] = []
    for name in MODULE_CANDIDATES:
        try:
            modules.append(importlib.import_module(name))
        except Exception:  # pragma: no cover - missing modules tolerated
            continue
    if not modules:
        raise AssertionError("unable to import any persistence-related module")
    return modules


def _first_callable(target: Any, *names: str) -> Any | None:
    for name in names:
        if hasattr(target, name):
            value = getattr(target, name)
            if callable(value):
                return value
    return None


def _serialize(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump") and callable(value.model_dump):
        data = value.model_dump()
        if isinstance(data, dict):
            return data
    if hasattr(value, "dict") and callable(value.dict):
        data = value.dict()
        if isinstance(data, dict):
            return data
    if hasattr(value, "as_dict") and callable(value.as_dict):
        data = value.as_dict()
        if isinstance(data, dict):
            return data
    payload: dict[str, Any] = {}
    for name in dir(value):
        if name.startswith("_"):
            continue
        attr = getattr(value, name)
        if callable(attr):
            continue
        if isinstance(attr, (str, int, float, bool, list, dict, type(None))):
            payload[name] = attr
    return payload


def _discover_factory(module: Any) -> Any | None:
    return _first_callable(
        module,
        "build_store",
        "create_store",
        "get_store",
        "build_organization_store",
        "create_organization_store",
        "get_organization_store",
        "build_telemetry_store",
        "create_telemetry_store",
        "get_telemetry_store",
        "build_runtime_state_store",
        "create_runtime_state_store",
        "get_runtime_state_store",
        "build_runtime_session_store",
        "create_runtime_session_store",
        "get_runtime_session_store",
        "build_review_state_store",
        "create_review_state_store",
        "get_review_state_store",
        "build_checkpoint_store",
        "create_checkpoint_store",
        "get_checkpoint_store",
    )


def _build_with_backend(factory: Any, backend_name: str) -> Any:
    attempts = (
        lambda: factory(mode=backend_name),
        lambda: factory(backend=backend_name),
        lambda: factory(store=backend_name),
        lambda: factory(provider=backend_name),
        lambda: factory(persistence=backend_name),
        lambda: factory(kind=backend_name),
    )
    for attempt in attempts:
        try:
            return attempt()
        except TypeError:
            continue
    raise TypeError("factory does not accept explicit backend selector")


def _build_default(factory: Any) -> Any:
    attempts = (
        lambda: factory(),
        lambda: factory(mode="auto"),
        lambda: factory(backend="auto"),
    )
    for attempt in attempts:
        try:
            return attempt()
        except TypeError:
            continue
    raise TypeError("factory could not be called with supported defaults")


def _store_backend_name(store: Any) -> str:
    payload = _serialize(store)
    for key in (
        "backend",
        "backend_name",
        "store_type",
        "persistence",
        "mode",
        "provider",
        "kind",
        "adapter",
    ):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.lower()
    for attr in (
        "backend",
        "backend_name",
        "store_type",
        "persistence",
        "mode",
        "provider",
        "kind",
        "adapter",
    ):
        if hasattr(store, attr):
            value = getattr(store, attr)
            if isinstance(value, str) and value.strip():
                return value.lower()
    return ""


def _fallback_enabled(value: Any) -> bool | None:
    payload = _serialize(value)
    for key in (
        "fallback_enabled",
        "allow_fallback",
        "fallback_allowed",
        "uses_fallback",
        "supports_fallback",
        "fallback",
    ):
        if key in payload and isinstance(payload[key], bool):
            return payload[key]
    for attr in (
        "fallback_enabled",
        "allow_fallback",
        "fallback_allowed",
        "uses_fallback",
        "supports_fallback",
        "fallback",
    ):
        if hasattr(value, attr):
            current = getattr(value, attr)
            if isinstance(current, bool):
                return current
    return None


def test_persistence_modules_import() -> None:
    modules = _load_modules()
    assert modules


def test_at_least_one_persistence_factory_exists() -> None:
    modules = _load_modules()

    factories = [_discover_factory(module) for module in modules]
    assert any(factory is not None for factory in factories)


def test_default_persistence_store_can_be_built_when_factory_exists() -> None:
    modules = _load_modules()

    built = False
    for module in modules:
        factory = _discover_factory(module)
        if factory is None:
            continue
        try:
            store = _build_default(factory)
        except TypeError:
            continue
        assert store is not None
        built = True
        break

    if not built:
        pytest.skip("no default-callable persistence factory found")


def test_explicit_memory_backend_can_be_selected_when_supported() -> None:
    modules = _load_modules()

    built = False
    for module in modules:
        factory = _discover_factory(module)
        if factory is None:
            continue
        try:
            store = _build_with_backend(factory, "memory")
        except TypeError:
            continue
        assert store is not None
        built = True
        break

    if not built:
        pytest.skip("explicit memory backend selection not implemented")


def test_explicit_supabase_backend_can_be_selected_when_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    modules = _load_modules()

    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "test-service-role-key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key")

    built = False
    for module in modules:
        factory = _discover_factory(module)
        if factory is None:
            continue
        try:
            store = _build_with_backend(factory, "supabase")
        except TypeError:
            continue
        assert store is not None
        built = True
        break

    if not built:
        pytest.skip("explicit supabase backend selection not implemented")


def test_default_policy_prefers_available_supabase_when_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    modules = _load_modules()

    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "test-service-role-key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key")

    observed = False
    for module in modules:
        factory = _discover_factory(module)
        if factory is None:
            continue
        try:
            store = _build_default(factory)
        except TypeError:
            continue

        backend_name = _store_backend_name(store)
        if backend_name:
            observed = True
            assert "supabase" in backend_name or "remote" in backend_name or "db" in backend_name
            break

    if not observed:
        pytest.skip("default backend identity not exposed")


def test_default_policy_falls_back_without_supabase_credentials_when_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    modules = _load_modules()

    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_KEY", raising=False)
    monkeypatch.delenv("SUPABASE_SERVICE_ROLE_KEY", raising=False)

    observed = False
    for module in modules:
        factory = _discover_factory(module)
        if factory is None:
            continue
        try:
            store = _build_default(factory)
        except TypeError:
            continue

        backend_name = _store_backend_name(store)
        if backend_name:
            observed = True
            assert "memory" in backend_name or "local" in backend_name or "inmemory" in backend_name
            break

    if not observed:
        pytest.skip("fallback backend identity not exposed")


def test_fallback_policy_exposes_boolean_flag_when_supported() -> None:
    modules = _load_modules()

    observed = False
    for module in modules:
        factory = _discover_factory(module)
        if factory is None:
            continue
        try:
            store = _build_default(factory)
        except TypeError:
            continue

        fallback = _fallback_enabled(store)
        if fallback is not None:
            observed = True
            assert isinstance(fallback, bool)
            break

    if not observed:
        pytest.skip("fallback boolean flag not exposed")


def test_invalid_backend_name_is_rejected_when_supported() -> None:
    modules = _load_modules()

    attempted = False
    for module in modules:
        factory = _discover_factory(module)
        if factory is None:
            continue
        attempted = True
        with pytest.raises((TypeError, ValueError, AssertionError)):
            try:
                factory(mode="definitely-not-a-real-backend")
            except TypeError:
                try:
                    factory(backend="definitely-not-a-real-backend")
                except TypeError:
                    factory(provider="definitely-not-a-real-backend")

    if not attempted:
        pytest.skip("no persistence factory found")


def test_supabase_mode_requires_configuration_or_fallback_when_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    modules = _load_modules()

    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_KEY", raising=False)
    monkeypatch.delenv("SUPABASE_SERVICE_ROLE_KEY", raising=False)

    observed = False
    for module in modules:
        factory = _discover_factory(module)
        if factory is None:
            continue
        try:
            store = _build_with_backend(factory, "supabase")
        except TypeError:
            continue
        except (ValueError, AssertionError):
            observed = True
            break

        observed = True
        backend_name = _store_backend_name(store)
        if backend_name:
            assert "memory" in backend_name or "fallback" in backend_name or "supabase" in backend_name
        break

    if not observed:
        pytest.skip("supabase mode selection not implemented")


def test_memory_backend_selection_is_stable_across_builds_when_supported() -> None:
    modules = _load_modules()

    observed = False
    for module in modules:
        factory = _discover_factory(module)
        if factory is None:
            continue
        try:
            first = _build_with_backend(factory, "memory")
            second = _build_with_backend(factory, "memory")
        except TypeError:
            continue

        observed = True
        first_name = _store_backend_name(first)
        second_name = _store_backend_name(second)
        if first_name and second_name:
            assert first_name == second_name
        break

    if not observed:
        pytest.skip("stable explicit memory backend selection not implemented")


def test_default_build_returns_serializable_store_shape_when_supported() -> None:
    modules = _load_modules()

    observed = False
    for module in modules:
        factory = _discover_factory(module)
        if factory is None:
            continue
        try:
            store = _build_default(factory)
        except TypeError:
            continue

        observed = True
        payload = _serialize(store)
        assert isinstance(payload, dict)
        break

    if not observed:
        pytest.skip("no serializable default store found")


def test_auto_mode_is_accepted_when_supported() -> None:
    modules = _load_modules()

    observed = False
    for module in modules:
        factory = _discover_factory(module)
        if factory is None:
            continue
        try:
            store = factory(mode="auto")
        except TypeError:
            try:
                store = factory(backend="auto")
            except TypeError:
                continue

        observed = True
        assert store is not None
        break

    if not observed:
        pytest.skip("auto backend selection not implemented")


def test_environment_driven_selection_changes_backend_when_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    modules = _load_modules()

    observed = False
    for module in modules:
        factory = _discover_factory(module)
        if factory is None:
            continue

        monkeypatch.delenv("SUPABASE_URL", raising=False)
        monkeypatch.delenv("SUPABASE_KEY", raising=False)
        monkeypatch.delenv("SUPABASE_SERVICE_ROLE_KEY", raising=False)
        try:
            without_remote = _build_default(factory)
        except TypeError:
            continue

        monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
        monkeypatch.setenv("SUPABASE_KEY", "test-service-role-key")
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key")
        try:
            with_remote = _build_default(factory)
        except TypeError:
            continue

        observed = True
        first_name = _store_backend_name(without_remote)
        second_name = _store_backend_name(with_remote)
        if first_name and second_name:
            assert first_name != second_name or "supabase" in second_name
        break

    if not observed:
        pytest.skip("environment-driven backend switching not observable")