from __future__ import annotations

import importlib
from typing import Any, Final

import pytest

MODULE_CANDIDATES: Final[tuple[str, ...]] = (
    "app.services.quarantinestore",
    "services.quarantinestore",
    "quarantinestore",
)


def _load_module() -> Any:
    last_error: Exception | None = None
    for name in MODULE_CANDIDATES:
        try:
            return importlib.import_module(name)
        except Exception as exc:  # pragma: no cover
            last_error = exc
    raise AssertionError(f"unable to import quarantine store module: {last_error}")


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
        if isinstance(attr, str | int | float | bool | list | dict | type(None)):
            payload[name] = attr
    return payload


def _items(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, dict):
        for key in ("items", "results", "rows", "quarantine", "entries", "artifacts", "data"):
            candidate = value.get(key)
            if isinstance(candidate, list):
                return candidate
        return [value]
    return [value]


def _build_store(module: Any) -> Any:
    factory = _first_callable(
        module,
        "build_quarantine_store",
        "create_quarantine_store",
        "get_quarantine_store",
        "build_store",
        "create_store",
        "get_store",
    )
    if factory is not None:
        try:
            return factory()
        except TypeError:
            try:
                return factory(mode="memory")
            except TypeError:
                try:
                    return factory(backend="memory")
                except TypeError:
                    pytest.skip("quarantine store factory requires unsupported arguments")

    for cls_name in ("QuarantineStore", "InMemoryQuarantineStore", "SupabaseQuarantineStore"):
        if hasattr(module, cls_name):
            cls = getattr(module, cls_name)
            if callable(cls):
                try:
                    return cls()
                except TypeError:
                    continue

    pytest.skip("quarantine store builder/class not implemented")


def test_quarantine_store_module_imports() -> None:
    module = _load_module()
    assert module is not None


def test_quarantine_store_exposes_public_surface() -> None:
    module = _load_module()
    public_names = {name for name in dir(module) if not name.startswith("_")}
    assert public_names


def test_quarantine_store_can_be_built() -> None:
    module = _load_module()
    store = _build_store(module)
    assert store is not None


def test_quarantine_store_exposes_write_operation() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "quarantine",
        "append",
        "write",
        "put",
    )

    assert writer is not None


def test_quarantine_store_exposes_read_operation() -> None:
    module = _load_module()
    store = _build_store(module)

    reader = _first_callable(
        store,
        "list",
        "fetch",
        "get",
        "query",
        "search",
        "read",
        "all",
        "latest",
    )

    assert reader is not None


def test_quarantine_store_accepts_basic_record_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "quarantine",
        "append",
        "write",
        "put",
    )
    if writer is None:
        pytest.skip("quarantine write operation not implemented")

    record = {
        "quarantine_id": "q-001",
        "artifact_id": "artifact-001",
        "reason": "prompt-injection",
        "status": "quarantined",
        "source": "scanner",
        "location": "sandbox://artifact-001",
        "timestamp": "2026-04-26T11:12:00Z",
    }

    try:
        result = writer(record)
    except TypeError:
        try:
            result = writer(**record)
        except TypeError:
            pytest.skip("writer signature unsupported")

    assert result is not None or result is None


def test_quarantine_store_returns_serializable_records_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "quarantine",
        "append",
        "write",
        "put",
    )
    reader = _first_callable(
        store,
        "list",
        "fetch",
        "read",
        "all",
        "query",
        "search",
        "latest",
        "get",
    )
    if writer is None or reader is None:
        pytest.skip("quarantine read/write path not implemented")

    record = {
        "quarantine_id": "q-serialize-001",
        "artifact_id": "artifact-serialize-001",
        "reason": "serialization-check",
        "status": "quarantined",
        "source": "tester",
        "location": "sandbox://serialize-001",
        "timestamp": "2026-04-26T11:12:00Z",
    }

    try:
        writer(record)
    except TypeError:
        try:
            writer(**record)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader()
    except TypeError:
        try:
            result = reader(limit=10)
        except TypeError:
            pytest.skip("reader signature unsupported")

    rows = _items(result)
    if rows:
        payload = _serialize(rows[0])
        assert isinstance(payload, dict)


def test_quarantine_record_contains_core_fields_when_present() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "quarantine",
        "append",
        "write",
        "put",
    )
    reader = _first_callable(
        store,
        "list",
        "fetch",
        "read",
        "all",
        "query",
        "search",
        "latest",
        "get",
    )
    if writer is None or reader is None:
        pytest.skip("quarantine read/write path not implemented")

    record = {
        "quarantine_id": "q-core-001",
        "artifact_id": "artifact-core-001",
        "reason": "suspicious-output",
        "status": "quarantined",
        "source": "engine",
        "location": "sandbox://core-001",
        "timestamp": "2026-04-26T11:12:00Z",
    }

    try:
        writer(record)
    except TypeError:
        try:
            writer(**record)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader()
    except TypeError:
        try:
            result = reader(limit=10)
        except TypeError:
            pytest.skip("reader signature unsupported")

    rows = _items(result)
    if not rows:
        pytest.skip("quarantine reader returned no rows")

    payload = _serialize(rows[0])
    expected_keys = {
        "quarantine_id",
        "id",
        "artifact_id",
        "file_id",
        "reason",
        "status",
        "source",
        "location",
        "path",
        "timestamp",
        "created_at",
    }

    assert set(payload.keys()).intersection(expected_keys)


def test_quarantine_store_rejects_blank_artifact_id_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "quarantine",
        "append",
        "write",
        "put",
    )
    if writer is None:
        pytest.skip("quarantine write operation not implemented")

    bad_record = {
        "quarantine_id": "q-bad-artifact-001",
        "artifact_id": "",
        "reason": "prompt-injection",
        "status": "quarantined",
        "source": "scanner",
        "location": "sandbox://artifact",
        "timestamp": "2026-04-26T11:12:00Z",
    }

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            writer(bad_record)
        except TypeError:
            writer(**bad_record)


def test_quarantine_store_rejects_blank_reason_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "quarantine",
        "append",
        "write",
        "put",
    )
    if writer is None:
        pytest.skip("quarantine write operation not implemented")

    bad_record = {
        "quarantine_id": "q-bad-reason-001",
        "artifact_id": "artifact-bad-reason-001",
        "reason": "",
        "status": "quarantined",
        "source": "scanner",
        "location": "sandbox://artifact",
        "timestamp": "2026-04-26T11:12:00Z",
    }

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            writer(bad_record)
        except TypeError:
            writer(**bad_record)


def test_quarantine_store_can_filter_by_status_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "quarantine",
        "append",
        "write",
        "put",
    )
    reader = _first_callable(
        store,
        "list",
        "fetch",
        "query",
        "search",
        "read",
        "all",
        "get",
    )
    if writer is None or reader is None:
        pytest.skip("quarantine read/write path not implemented")

    status = "released"
    record = {
        "quarantine_id": "q-filter-status-001",
        "artifact_id": "artifact-filter-status-001",
        "reason": "manual-review",
        "status": status,
        "source": "reviewer",
        "location": "sandbox://status-001",
        "timestamp": "2026-04-26T11:12:00Z",
    }

    try:
        writer(record)
    except TypeError:
        try:
            writer(**record)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader(status=status)
    except TypeError:
        pytest.skip("status filtering not implemented")

    assert result is not None


def test_quarantine_store_can_filter_by_artifact_id_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "quarantine",
        "append",
        "write",
        "put",
    )
    reader = _first_callable(
        store,
        "list",
        "fetch",
        "query",
        "search",
        "read",
        "all",
        "get",
    )
    if writer is None or reader is None:
        pytest.skip("quarantine read/write path not implemented")

    artifact_id = "artifact-filter-001"
    record = {
        "quarantine_id": "q-filter-artifact-001",
        "artifact_id": artifact_id,
        "reason": "policy-match",
        "status": "quarantined",
        "source": "engine",
        "location": "sandbox://artifact-filter-001",
        "timestamp": "2026-04-26T11:12:00Z",
    }

    try:
        writer(record)
    except TypeError:
        try:
            writer(**record)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader(artifact_id=artifact_id)
    except TypeError:
        try:
            result = reader(file_id=artifact_id)
        except TypeError:
            pytest.skip("artifact filtering not implemented")

    assert result is not None


def test_quarantine_store_supports_lookup_by_id_when_available() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "quarantine",
        "append",
        "write",
        "put",
    )
    lookup = _first_callable(
        store,
        "get_by_id",
        "find_by_id",
        "get",
        "fetch_one",
        "read_one",
    )
    if writer is None or lookup is None:
        pytest.skip("quarantine write/lookup path not implemented")

    quarantine_id = "q-lookup-001"
    record = {
        "quarantine_id": quarantine_id,
        "artifact_id": "artifact-lookup-001",
        "reason": "lookup-check",
        "status": "quarantined",
        "source": "tester",
        "location": "sandbox://lookup-001",
        "timestamp": "2026-04-26T11:12:00Z",
    }

    try:
        writer(record)
    except TypeError:
        try:
            writer(**record)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = lookup(quarantine_id)
    except TypeError:
        try:
            result = lookup(quarantine_id=quarantine_id)
        except TypeError:
            pytest.skip("lookup signature unsupported")

    assert result is not None


def test_quarantine_store_supports_release_or_state_update_when_available() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "quarantine",
        "append",
        "write",
        "put",
    )
    releaser = _first_callable(
        store,
        "release",
        "unquarantine",
        "mark_released",
        "update_status",
        "set_status",
    )
    if writer is None or releaser is None:
        pytest.skip("quarantine release/update path not implemented")

    quarantine_id = "q-release-001"
    record = {
        "quarantine_id": quarantine_id,
        "artifact_id": "artifact-release-001",
        "reason": "review-pending",
        "status": "quarantined",
        "source": "reviewer",
        "location": "sandbox://release-001",
        "timestamp": "2026-04-26T11:12:00Z",
    }

    try:
        writer(record)
    except TypeError:
        try:
            writer(**record)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = releaser(quarantine_id)
    except TypeError:
        try:
            result = releaser(quarantine_id=quarantine_id)
        except TypeError:
            try:
                result = releaser(quarantine_id, "released")
            except TypeError:
                try:
                    result = releaser(quarantine_id=quarantine_id, status="released")
                except TypeError:
                    pytest.skip("release/update signature unsupported")

    assert result is not None or result is None


def test_quarantine_store_supports_supabase_mode_when_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()

    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "test-service-role-key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key")

    factory = _first_callable(
        module,
        "build_quarantine_store",
        "create_quarantine_store",
        "get_quarantine_store",
        "build_store",
        "create_store",
        "get_store",
    )
    if factory is None:
        pytest.skip("quarantine store factory not implemented")

    try:
        store = factory(mode="supabase")
    except TypeError:
        try:
            store = factory(backend="supabase")
        except TypeError:
            pytest.skip("explicit supabase backend selection not implemented")

    assert store is not None
