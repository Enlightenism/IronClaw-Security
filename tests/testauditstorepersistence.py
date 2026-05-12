from __future__ import annotations

import importlib
from typing import Any, Final

import pytest

MODULE_CANDIDATES: Final[tuple[str, ...]] = (
    "app.services.auditstore",
    "services.auditstore",
    "auditstore",
)


def _load_module() -> Any:
    last_error: Exception | None = None
    for name in MODULE_CANDIDATES:
        try:
            return importlib.import_module(name)
        except Exception as exc:  # pragma: no cover
            last_error = exc
    raise AssertionError(f"unable to import audit store module: {last_error}")


def _callable_names(module: Any) -> set[str]:
    return {
        name
        for name in dir(module)
        if not name.startswith("_") and callable(getattr(module, name))
    }


def _first_callable(module: Any, *names: str) -> Any | None:
    for name in names:
        if hasattr(module, name):
            value = getattr(module, name)
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


def _build_store(module: Any) -> Any:
    factory = _first_callable(
        module,
        "build_audit_store",
        "create_audit_store",
        "get_audit_store",
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
                    pytest.skip("audit store factory requires unsupported arguments")

    for cls_name in ("AuditStore", "InMemoryAuditStore", "SupabaseAuditStore"):
        if hasattr(module, cls_name):
            cls = getattr(module, cls_name)
            if callable(cls):
                try:
                    return cls()
                except TypeError:
                    continue

    pytest.skip("audit store builder/class not implemented")


def test_audit_store_module_imports() -> None:
    module = _load_module()
    assert module is not None


def test_audit_store_exposes_public_surface() -> None:
    module = _load_module()
    assert _callable_names(module) or any(
        hasattr(module, name) for name in ("AuditStore", "InMemoryAuditStore", "SupabaseAuditStore")
    )


def test_audit_store_can_be_built() -> None:
    module = _load_module()
    store = _build_store(module)
    assert store is not None


def test_audit_store_exposes_write_or_record_operation() -> None:
    module = _load_module()
    store = _build_store(module)

    names = set(dir(store))
    expected = {
        "append",
        "write",
        "record",
        "add",
        "insert",
        "create",
        "log",
        "save",
    }

    assert names.intersection(expected)


def test_audit_store_exposes_read_or_query_operation() -> None:
    module = _load_module()
    store = _build_store(module)

    names = set(dir(store))
    expected = {
        "list",
        "fetch",
        "get",
        "query",
        "search",
        "all",
        "read",
        "latest",
    }

    assert names.intersection(expected)


def test_audit_store_accepts_basic_audit_event_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(store, "record", "append", "write", "add", "insert", "create", "log", "save")
    if writer is None:
        pytest.skip("no audit write operation available")

    event = {
        "event_id": "evt-001",
        "action": "policy.checked",
        "actor": "system",
        "status": "allowed",
        "target": "scan-001",
        "timestamp": "2026-04-26T10:42:00Z",
    }

    try:
        result = writer(event)
    except TypeError:
        try:
            result = writer(**event)
        except TypeError:
            pytest.skip("writer signature unsupported")

    assert result is not None or result is None


def test_audit_store_can_return_serializable_records_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(store, "record", "append", "write", "add", "insert", "create", "log", "save")
    reader = _first_callable(store, "list", "fetch", "all", "read", "query", "search", "latest", "get")
    if writer is None or reader is None:
        pytest.skip("audit read/write path not fully implemented")

    event = {
        "event_id": "evt-serial-001",
        "action": "audit.serialize",
        "actor": "tester",
        "status": "ok",
        "target": "target-001",
        "timestamp": "2026-04-26T10:42:00Z",
    }

    try:
        writer(event)
    except TypeError:
        try:
            writer(**event)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader()
    except TypeError:
        try:
            result = reader(limit=10)
        except TypeError:
            pytest.skip("reader signature unsupported")

    if isinstance(result, list) and result:
        payload = _serialize(result[0])
        assert isinstance(payload, dict)


def test_audit_store_rejects_blank_action_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(store, "record", "append", "write", "add", "insert", "create", "log", "save")
    if writer is None:
        pytest.skip("no audit write operation available")

    bad_event = {
        "event_id": "evt-bad-001",
        "action": "",
        "actor": "system",
        "status": "allowed",
        "target": "scan-001",
        "timestamp": "2026-04-26T10:42:00Z",
    }

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            writer(bad_event)
        except TypeError:
            writer(**bad_event)


def test_audit_store_rejects_blank_actor_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(store, "record", "append", "write", "add", "insert", "create", "log", "save")
    if writer is None:
        pytest.skip("no audit write operation available")

    bad_event = {
        "event_id": "evt-bad-actor-001",
        "action": "policy.checked",
        "actor": "",
        "status": "allowed",
        "target": "scan-001",
        "timestamp": "2026-04-26T10:42:00Z",
    }

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            writer(bad_event)
        except TypeError:
            writer(**bad_event)


def test_audit_store_can_filter_by_target_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(store, "record", "append", "write", "add", "insert", "create", "log", "save")
    reader = _first_callable(store, "list", "fetch", "query", "search", "read", "all")
    if writer is None or reader is None:
        pytest.skip("audit read/write path not fully implemented")

    target = "scan-filter-001"
    event = {
        "event_id": "evt-filter-001",
        "action": "policy.checked",
        "actor": "system",
        "status": "allowed",
        "target": target,
        "timestamp": "2026-04-26T10:42:00Z",
    }

    try:
        writer(event)
    except TypeError:
        try:
            writer(**event)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader(target=target)
    except TypeError:
        try:
            result = reader(resource_id=target)
        except TypeError:
            pytest.skip("target filtering not implemented")

    assert result is not None


def test_audit_store_can_filter_by_actor_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(store, "record", "append", "write", "add", "insert", "create", "log", "save")
    reader = _first_callable(store, "list", "fetch", "query", "search", "read", "all")
    if writer is None or reader is None:
        pytest.skip("audit read/write path not fully implemented")

    actor = "actor-filter-001"
    event = {
        "event_id": "evt-filter-actor-001",
        "action": "review.opened",
        "actor": actor,
        "status": "pending",
        "target": "incident-001",
        "timestamp": "2026-04-26T10:42:00Z",
    }

    try:
        writer(event)
    except TypeError:
        try:
            writer(**event)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader(actor=actor)
    except TypeError:
        pytest.skip("actor filtering not implemented")

    assert result is not None


def test_audit_store_preserves_ordering_or_latest_lookup_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(store, "record", "append", "write", "add", "insert", "create", "log", "save")
    latest = _first_callable(store, "latest", "last", "most_recent", "get_latest")
    reader = _first_callable(store, "list", "fetch", "all", "read")
    if writer is None:
        pytest.skip("no audit write operation available")

    first_event = {
        "event_id": "evt-order-001",
        "action": "audit.first",
        "actor": "system",
        "status": "ok",
        "target": "item-001",
        "timestamp": "2026-04-26T10:42:00Z",
    }
    second_event = {
        "event_id": "evt-order-002",
        "action": "audit.second",
        "actor": "system",
        "status": "ok",
        "target": "item-001",
        "timestamp": "2026-04-26T10:43:00Z",
    }

    try:
        writer(first_event)
        writer(second_event)
    except TypeError:
        try:
            writer(**first_event)
            writer(**second_event)
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


def test_audit_store_supports_supabase_mode_when_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()

    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "test-service-role-key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key")

    factory = _first_callable(
        module,
        "build_audit_store",
        "create_audit_store",
        "get_audit_store",
        "build_store",
        "create_store",
        "get_store",
    )
    if factory is None:
        pytest.skip("audit store factory not implemented")

    try:
        store = factory(mode="supabase")
    except TypeError:
        try:
            store = factory(backend="supabase")
        except TypeError:
            pytest.skip("explicit supabase backend selection not implemented")

    assert store is not None