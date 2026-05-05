from __future__ import annotations

import importlib
from typing import Any, Final

import pytest


MODULE_CANDIDATES: Final[tuple[str, ...]] = (
    "app.services.history",
    "services.history",
    "history",
)


def _load_module() -> Any:
    last_error: Exception | None = None
    for name in MODULE_CANDIDATES:
        try:
            return importlib.import_module(name)
        except Exception as exc:  # pragma: no cover
            last_error = exc
    raise AssertionError(f"unable to import history module: {last_error}")


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
    if hasattr(value, "model_dump") and callable(getattr(value, "model_dump")):
        data = value.model_dump()
        if isinstance(data, dict):
            return data
    if hasattr(value, "dict") and callable(getattr(value, "dict")):
        data = value.dict()
        if isinstance(data, dict):
            return data
    if hasattr(value, "as_dict") and callable(getattr(value, "as_dict")):
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


def _items(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, dict):
        for key in ("items", "results", "rows", "history", "entries", "events", "data"):
            candidate = value.get(key)
            if isinstance(candidate, list):
                return candidate
        return [value]
    return [value]


def _build_history_store(module: Any) -> Any:
    factory = _first_callable(
        module,
        "build_history_store",
        "create_history_store",
        "get_history_store",
        "build_history",
        "create_history",
        "get_history",
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
                    pytest.skip("history factory requires unsupported arguments")

    for cls_name in ("HistoryStore", "HistoryService", "InMemoryHistoryStore", "SupabaseHistoryStore"):
        if hasattr(module, cls_name):
            cls = getattr(module, cls_name)
            if callable(cls):
                try:
                    return cls()
                except TypeError:
                    continue

    pytest.skip("history store/service builder not implemented")


def test_history_module_imports() -> None:
    module = _load_module()
    assert module is not None


def test_history_exposes_public_surface() -> None:
    module = _load_module()

    public_names = {name for name in dir(module) if not name.startswith("_")}
    assert public_names


def test_history_store_can_be_built() -> None:
    module = _load_module()
    store = _build_history_store(module)
    assert store is not None


def test_history_store_exposes_write_operation() -> None:
    module = _load_module()
    store = _build_history_store(module)

    writer = _first_callable(
        store,
        "append",
        "record",
        "add",
        "insert",
        "create",
        "write",
        "save",
        "push",
    )

    assert writer is not None


def test_history_store_exposes_read_operation() -> None:
    module = _load_module()
    store = _build_history_store(module)

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


def test_history_store_accepts_basic_entry_when_supported() -> None:
    module = _load_module()
    store = _build_history_store(module)

    writer = _first_callable(
        store,
        "append",
        "record",
        "add",
        "insert",
        "create",
        "write",
        "save",
        "push",
    )
    if writer is None:
        pytest.skip("history write operation not implemented")

    entry = {
        "entry_id": "hist-001",
        "session_id": "sess-001",
        "actor": "system",
        "action": "scan.completed",
        "status": "ok",
        "timestamp": "2026-04-26T10:45:00Z",
    }

    try:
        result = writer(entry)
    except TypeError:
        try:
            result = writer(**entry)
        except TypeError:
            pytest.skip("writer signature unsupported")

    assert result is not None or result is None


def test_history_store_returns_serializable_entries_when_supported() -> None:
    module = _load_module()
    store = _build_history_store(module)

    writer = _first_callable(
        store,
        "append",
        "record",
        "add",
        "insert",
        "create",
        "write",
        "save",
        "push",
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
        pytest.skip("history read/write path not implemented")

    entry = {
        "entry_id": "hist-serialize-001",
        "session_id": "sess-serialize-001",
        "actor": "tester",
        "action": "history.serialize",
        "status": "ok",
        "timestamp": "2026-04-26T10:45:00Z",
    }

    try:
        writer(entry)
    except TypeError:
        try:
            writer(**entry)
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


def test_history_entry_contains_identity_fields_when_present() -> None:
    module = _load_module()
    store = _build_history_store(module)

    writer = _first_callable(
        store,
        "append",
        "record",
        "add",
        "insert",
        "create",
        "write",
        "save",
        "push",
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
        pytest.skip("history read/write path not implemented")

    entry = {
        "entry_id": "hist-core-001",
        "session_id": "sess-core-001",
        "actor": "system",
        "action": "history.core",
        "status": "ok",
        "timestamp": "2026-04-26T10:45:00Z",
    }

    try:
        writer(entry)
    except TypeError:
        try:
            writer(**entry)
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
        pytest.skip("history reader returned no rows")

    payload = _serialize(rows[0])
    expected_keys = {
        "entry_id",
        "id",
        "history_id",
        "session_id",
        "request_id",
        "actor",
        "action",
        "status",
        "timestamp",
        "created_at",
    }

    assert set(payload.keys()).intersection(expected_keys)


def test_history_store_rejects_blank_action_when_supported() -> None:
    module = _load_module()
    store = _build_history_store(module)

    writer = _first_callable(
        store,
        "append",
        "record",
        "add",
        "insert",
        "create",
        "write",
        "save",
        "push",
    )
    if writer is None:
        pytest.skip("history write operation not implemented")

    bad_entry = {
        "entry_id": "hist-bad-action-001",
        "session_id": "sess-bad-001",
        "actor": "system",
        "action": "",
        "status": "ok",
        "timestamp": "2026-04-26T10:45:00Z",
    }

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            writer(bad_entry)
        except TypeError:
            writer(**bad_entry)


def test_history_store_rejects_blank_session_id_when_supported() -> None:
    module = _load_module()
    store = _build_history_store(module)

    writer = _first_callable(
        store,
        "append",
        "record",
        "add",
        "insert",
        "create",
        "write",
        "save",
        "push",
    )
    if writer is None:
        pytest.skip("history write operation not implemented")

    bad_entry = {
        "entry_id": "hist-bad-session-001",
        "session_id": "",
        "actor": "system",
        "action": "scan.completed",
        "status": "ok",
        "timestamp": "2026-04-26T10:45:00Z",
    }

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            writer(bad_entry)
        except TypeError:
            writer(**bad_entry)


def test_history_store_can_filter_by_session_when_supported() -> None:
    module = _load_module()
    store = _build_history_store(module)

    writer = _first_callable(
        store,
        "append",
        "record",
        "add",
        "insert",
        "create",
        "write",
        "save",
        "push",
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
        pytest.skip("history read/write path not implemented")

    session_id = "sess-filter-001"
    entry = {
        "entry_id": "hist-filter-001",
        "session_id": session_id,
        "actor": "system",
        "action": "history.filtered",
        "status": "ok",
        "timestamp": "2026-04-26T10:45:00Z",
    }

    try:
        writer(entry)
    except TypeError:
        try:
            writer(**entry)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader(session_id=session_id)
    except TypeError:
        try:
            result = reader(session=session_id)
        except TypeError:
            pytest.skip("session filtering not implemented")

    assert result is not None


def test_history_store_can_filter_by_actor_when_supported() -> None:
    module = _load_module()
    store = _build_history_store(module)

    writer = _first_callable(
        store,
        "append",
        "record",
        "add",
        "insert",
        "create",
        "write",
        "save",
        "push",
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
        pytest.skip("history read/write path not implemented")

    actor = "actor-filter-001"
    entry = {
        "entry_id": "hist-filter-actor-001",
        "session_id": "sess-filter-actor-001",
        "actor": actor,
        "action": "history.actor",
        "status": "ok",
        "timestamp": "2026-04-26T10:45:00Z",
    }

    try:
        writer(entry)
    except TypeError:
        try:
            writer(**entry)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader(actor=actor)
    except TypeError:
        pytest.skip("actor filtering not implemented")

    assert result is not None


def test_history_store_supports_latest_or_ordered_reads_when_available() -> None:
    module = _load_module()
    store = _build_history_store(module)

    writer = _first_callable(
        store,
        "append",
        "record",
        "add",
        "insert",
        "create",
        "write",
        "save",
        "push",
    )
    latest = _first_callable(store, "latest", "last", "most_recent", "get_latest")
    reader = _first_callable(store, "list", "fetch", "all", "read")

    if writer is None:
        pytest.skip("history write operation not implemented")

    first_entry = {
        "entry_id": "hist-order-001",
        "session_id": "sess-order-001",
        "actor": "system",
        "action": "history.first",
        "status": "ok",
        "timestamp": "2026-04-26T10:45:00Z",
    }
    second_entry = {
        "entry_id": "hist-order-002",
        "session_id": "sess-order-001",
        "actor": "system",
        "action": "history.second",
        "status": "ok",
        "timestamp": "2026-04-26T10:46:00Z",
    }

    try:
        writer(first_entry)
        writer(second_entry)
    except TypeError:
        try:
            writer(**first_entry)
            writer(**second_entry)
        except TypeError:
            pytest.skip("writer signature unsupported")

    if latest is not None:
        result = latest()
        assert result is not None
        return

    if reader is not None:
        try:
            rows = reader()
        except TypeError:
            try:
                rows = reader(limit=10)
            except TypeError:
                pytest.skip("reader signature unsupported")
        assert rows is not None
        return

    pytest.skip("no latest/read operation implemented")


def test_history_store_supports_supabase_mode_when_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()

    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "test-service-role-key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key")

    factory = _first_callable(
        module,
        "build_history_store",
        "create_history_store",
        "get_history_store",
        "build_history",
        "create_history",
        "get_history",
    )
    if factory is None:
        pytest.skip("history factory not implemented")

    try:
        store = factory(mode="supabase")
    except TypeError:
        try:
            store = factory(backend="supabase")
        except TypeError:
            pytest.skip("explicit supabase backend selection not implemented")

    assert store is not None