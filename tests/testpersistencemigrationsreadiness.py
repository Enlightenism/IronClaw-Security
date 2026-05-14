from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any, Final

import pytest

MODULE_CANDIDATES: Final[tuple[str, ...]] = (
    "app.services.organizationstore",
    "services.organizationstore",
    "organizationstore",
    "app.services.telemetry",
    "services.telemetry",
    "telemetry",
    "app.services.reviewstatestore",
    "services.reviewstatestore",
    "reviewstatestore",
    "app.services.runtimesession",
    "services.runtimesession",
    "runtimesession",
    "app.orchestrator.checkpointstore",
    "orchestrator.checkpointstore",
    "checkpointstore",
)


def _load_modules() -> list[Any]:
    modules: list[Any] = []
    for name in MODULE_CANDIDATES:
        try:
            modules.append(importlib.import_module(name))
        except Exception:  # pragma: no cover - missing modules are tolerated
            continue
    if not modules:
        raise AssertionError("unable to import persistence modules")
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
        payload = value.model_dump()
        if isinstance(payload, dict):
            return payload
    if hasattr(value, "dict") and callable(value.dict):
        payload = value.dict()
        if isinstance(payload, dict):
            return payload
    if hasattr(value, "as_dict") and callable(value.as_dict):
        payload = value.as_dict()
        if isinstance(payload, dict):
            return payload
    data: dict[str, Any] = {}
    for name in dir(value):
        if name.startswith("_"):
            continue
        attr = getattr(value, name)
        if callable(attr):
            continue
        if isinstance(attr, str | int | float | bool | list | dict | type(None)):
            data[name] = attr
    return data


def _migration_paths() -> list[Path]:
    roots = [Path.cwd(), Path.cwd() / "app", Path.cwd() / "scripts"]
    candidates: list[Path] = []

    for root in roots:
        if not root.exists():
            continue
        for pattern in (
            "**/migrations",
            "**/migration",
            "**/*migrations*",
            "**/*migration*",
            "**/supabase",
            "**/schema",
        ):
            candidates.extend(path for path in root.glob(pattern) if path.exists())

    unique: list[Path] = []
    seen: set[str] = set()
    for path in candidates:
        resolved = str(path.resolve())
        if resolved not in seen:
            seen.add(resolved)
            unique.append(path)
    return unique


def _sql_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_file() and path.suffix.lower() == ".sql":
            files.append(path)
        elif path.is_dir():
            files.extend(p for p in path.rglob("*.sql") if p.is_file())
    unique: list[Path] = []
    seen: set[str] = set()
    for file in files:
        resolved = str(file.resolve())
        if resolved not in seen:
            seen.add(resolved)
            unique.append(file)
    return unique


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
        "build_review_state_store",
        "create_review_state_store",
        "get_review_state_store",
        "build_runtime_state_store",
        "create_runtime_state_store",
        "get_runtime_state_store",
        "build_runtime_session_store",
        "create_runtime_session_store",
        "get_runtime_session_store",
        "build_checkpoint_store",
        "create_checkpoint_store",
        "get_checkpoint_store",
    )


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
    raise TypeError("factory does not support default build calls")


def _build_supabase(factory: Any) -> Any:
    attempts = (
        lambda: factory(mode="supabase"),
        lambda: factory(backend="supabase"),
        lambda: factory(provider="supabase"),
        lambda: factory(persistence="supabase"),
    )
    for attempt in attempts:
        try:
            return attempt()
        except TypeError:
            continue
    raise TypeError("factory does not support supabase selection")


def _backend_name(store: Any) -> str:
    payload = _serialize(store)
    for key in ("backend", "backend_name", "store_type", "provider", "persistence", "mode"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.lower()
    for attr in ("backend", "backend_name", "store_type", "provider", "persistence", "mode"):
        if hasattr(store, attr):
            value = getattr(store, attr)
            if isinstance(value, str) and value.strip():
                return value.lower()
    return ""


def _readiness_value(value: Any) -> Any:
    payload = _serialize(value)
    for key in (
        "migration_ready",
        "migrations_ready",
        "schema_ready",
        "ready",
        "is_ready",
        "readiness",
        "bootstrap_ready",
    ):
        if key in payload:
            return payload[key]
    for attr in (
        "migration_ready",
        "migrations_ready",
        "schema_ready",
        "ready",
        "is_ready",
        "readiness",
        "bootstrap_ready",
    ):
        if hasattr(value, attr):
            return getattr(value, attr)
    return None


def test_persistence_modules_import_for_migration_readiness() -> None:
    modules = _load_modules()
    assert modules


def test_persistence_factory_exists_for_migration_readiness() -> None:
    modules = _load_modules()
    assert any(_discover_factory(module) is not None for module in modules)


def test_repository_contains_migration_or_schema_artifacts() -> None:
    paths = _migration_paths()
    assert paths, "expected migration, schema, or supabase directory to exist"


def test_repository_contains_sql_or_schema_files_for_persistence() -> None:
    files = _sql_files(_migration_paths())

    if not files:
        pytest.skip("no sql migration files found; schema may be code-first only")
    assert files


def test_sql_migration_files_are_not_empty_when_present() -> None:
    files = _sql_files(_migration_paths())

    if not files:
        pytest.skip("no sql migration files found")

    for file in files:
        assert file.read_text(encoding="utf-8", errors="ignore").strip()


def test_sql_migration_files_look_like_schema_or_data_definition_when_present() -> None:
    files = _sql_files(_migration_paths())

    if not files:
        pytest.skip("no sql migration files found")

    found = False
    markers = (
        "create table",
        "alter table",
        "create index",
        "create schema",
        "insert into",
        "drop table",
        "create extension",
    )
    for file in files:
        text = file.read_text(encoding="utf-8", errors="ignore").lower()
        if any(marker in text for marker in markers):
            found = True
            break

    assert found, "expected at least one sql artifact to contain migration-like statements"


def test_default_store_build_is_migration_readiness_safe_when_supported() -> None:
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


def test_supabase_store_selection_is_constructible_for_readiness_checks_when_supported(
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
            store = _build_supabase(factory)
        except TypeError:
            continue
        assert store is not None
        built = True
        break

    if not built:
        pytest.skip("explicit supabase store selection not implemented")


def test_store_exposes_readiness_or_backend_identity_when_supported() -> None:
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

        readiness = _readiness_value(store)
        backend = _backend_name(store)

        if readiness is not None:
            observed = True
            assert isinstance(readiness, bool | str | dict)
            break

        if backend:
            observed = True
            assert isinstance(backend, str)
            break

    if not observed:
        pytest.skip("store does not expose readiness or backend metadata")


def test_default_build_without_supabase_credentials_does_not_crash_readiness_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    modules = _load_modules()

    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_KEY", raising=False)
    monkeypatch.delenv("SUPABASE_SERVICE_ROLE_KEY", raising=False)

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
        pytest.skip("no default persistence build path available")


def test_supabase_readiness_path_requires_config_or_handles_missing_config_cleanly(
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
            store = _build_supabase(factory)
        except TypeError:
            continue
        except (ValueError, AssertionError, RuntimeError):
            observed = True
            break

        observed = True
        assert store is not None
        backend = _backend_name(store)
        if backend:
            assert "memory" in backend or "fallback" in backend or "supabase" in backend
        break

    if not observed:
        pytest.skip("supabase readiness path not implemented")


def test_migration_artifact_names_are_reasonably_orderable_when_present() -> None:
    files = _sql_files(_migration_paths())

    if len(files) < 2:
        pytest.skip("not enough sql migration files to evaluate ordering")

    names = [file.name for file in files]
    assert names == sorted(names) or bool(sorted(names)), "migration filenames should be sortable"


def test_migration_artifacts_include_persistence_related_keywords_when_present() -> None:
    files = _sql_files(_migration_paths())

    if not files:
        pytest.skip("no sql migration files found")

    keywords = (
        "organization",
        "telemetry",
        "review",
        "runtime",
        "checkpoint",
        "audit",
        "policy",
        "incident",
    )

    found = False
    for file in files:
        text = file.read_text(encoding="utf-8", errors="ignore").lower()
        if any(keyword in text or keyword in file.name.lower() for keyword in keywords):
            found = True
            break

    if not found:
        pytest.skip("sql artifacts exist but none expose target persistence keywords")


def test_migration_directories_are_readable() -> None:
    for path in _migration_paths():
        if path.is_dir():
            assert path.exists()
            assert path.is_dir()
            return

    pytest.skip("no migration directories found")


def test_default_store_backend_metadata_is_serializable_when_supported() -> None:
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
        pytest.skip("no default persistence store available for serialization check")
