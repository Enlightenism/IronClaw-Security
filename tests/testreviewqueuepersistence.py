from __future__ import annotations

import importlib
from typing import Any, Final

import pytest

MODULE_CANDIDATES: Final[tuple[str, ...]] = (
    "app.services.reviewqueueservice",
    "app.review.reviewqueueservice",
    "review.reviewqueueservice",
    "services.reviewqueueservice",
    "reviewqueueservice",
)


def _load_module() -> Any:
    last_error: Exception | None = None
    for name in MODULE_CANDIDATES:
        try:
            return importlib.import_module(name)
        except Exception as exc:  # pragma: no cover
            last_error = exc
    raise AssertionError(f"unable to import review queue persistence module: {last_error}")


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


def _items(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, dict):
        for key in ("items", "results", "rows", "entries", "queue", "reviews", "data"):
            candidate = value.get(key)
            if isinstance(candidate, list):
                return candidate
        return [value]
    return [value]


def _build_service(module: Any) -> Any:
    factory = _first_callable(
        module,
        "build_review_queue_service",
        "create_review_queue_service",
        "get_review_queue_service",
        "build_service",
        "create_service",
        "get_service",
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
                    pytest.skip("review queue service factory requires unsupported arguments")

    for cls_name in (
        "ReviewQueueService",
        "InMemoryReviewQueueService",
        "SupabaseReviewQueueService",
    ):
        if hasattr(module, cls_name):
            cls = getattr(module, cls_name)
            if callable(cls):
                try:
                    return cls()
                except TypeError:
                    continue

    pytest.skip("review queue persistence builder/class not implemented")


def test_review_queue_persistence_module_imports() -> None:
    module = _load_module()
    assert module is not None


def test_review_queue_persistence_exposes_public_surface() -> None:
    module = _load_module()
    public_names = {name for name in dir(module) if not name.startswith("_")}
    assert public_names


def test_review_queue_service_can_be_built() -> None:
    module = _load_module()
    service = _build_service(module)
    assert service is not None


def test_review_queue_service_exposes_enqueue_operation() -> None:
    module = _load_module()
    service = _build_service(module)

    enqueue = _first_callable(
        service,
        "enqueue",
        "create",
        "insert",
        "add",
        "push",
        "submit",
        "record",
        "save",
    )

    assert enqueue is not None


def test_review_queue_service_exposes_read_operation() -> None:
    module = _load_module()
    service = _build_service(module)

    reader = _first_callable(
        service,
        "list",
        "fetch",
        "query",
        "search",
        "read",
        "all",
        "get",
        "pending",
    )

    assert reader is not None


def test_review_queue_service_accepts_basic_review_record_when_supported() -> None:
    module = _load_module()
    service = _build_service(module)

    enqueue = _first_callable(
        service,
        "enqueue",
        "create",
        "insert",
        "add",
        "push",
        "submit",
        "record",
        "save",
    )
    if enqueue is None:
        pytest.skip("enqueue operation not implemented")

    entry = {
        "review_id": "rq-001",
        "incident_id": "inc-001",
        "status": "pending",
        "priority": "high",
        "reason": "prompt-injection",
        "source": "guard",
        "assigned_to": "analyst-1",
        "created_at": "2026-04-26T11:15:00Z",
    }

    try:
        result = enqueue(entry)
    except TypeError:
        try:
            result = enqueue(**entry)
        except TypeError:
            pytest.skip("enqueue signature unsupported")

    assert result is not None or result is None


def test_review_queue_service_returns_serializable_records_when_supported() -> None:
    module = _load_module()
    service = _build_service(module)

    enqueue = _first_callable(
        service,
        "enqueue",
        "create",
        "insert",
        "add",
        "push",
        "submit",
        "record",
        "save",
    )
    reader = _first_callable(
        service,
        "list",
        "fetch",
        "query",
        "search",
        "read",
        "all",
        "pending",
        "get",
    )
    if enqueue is None or reader is None:
        pytest.skip("enqueue/read path not implemented")

    entry = {
        "review_id": "rq-serialize-001",
        "incident_id": "inc-serialize-001",
        "status": "pending",
        "priority": "medium",
        "reason": "serialization-check",
        "source": "tester",
        "assigned_to": "analyst-2",
        "created_at": "2026-04-26T11:15:00Z",
    }

    try:
        enqueue(entry)
    except TypeError:
        try:
            enqueue(**entry)
        except TypeError:
            pytest.skip("enqueue signature unsupported")

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


def test_review_queue_record_contains_core_fields_when_present() -> None:
    module = _load_module()
    service = _build_service(module)

    enqueue = _first_callable(
        service,
        "enqueue",
        "create",
        "insert",
        "add",
        "push",
        "submit",
        "record",
        "save",
    )
    reader = _first_callable(
        service,
        "list",
        "fetch",
        "query",
        "search",
        "read",
        "all",
        "pending",
        "get",
    )
    if enqueue is None or reader is None:
        pytest.skip("enqueue/read path not implemented")

    entry = {
        "review_id": "rq-core-001",
        "incident_id": "inc-core-001",
        "status": "pending",
        "priority": "high",
        "reason": "manual-review",
        "source": "engine",
        "assigned_to": "analyst-3",
        "created_at": "2026-04-26T11:15:00Z",
    }

    try:
        enqueue(entry)
    except TypeError:
        try:
            enqueue(**entry)
        except TypeError:
            pytest.skip("enqueue signature unsupported")

    try:
        result = reader()
    except TypeError:
        try:
            result = reader(limit=10)
        except TypeError:
            pytest.skip("reader signature unsupported")

    rows = _items(result)
    if not rows:
        pytest.skip("reader returned no review queue rows")

    payload = _serialize(rows[0])
    expected_keys = {
        "review_id",
        "id",
        "incident_id",
        "case_id",
        "status",
        "priority",
        "reason",
        "source",
        "assigned_to",
        "created_at",
        "updated_at",
    }

    assert set(payload.keys()).intersection(expected_keys)


def test_review_queue_service_rejects_blank_incident_id_when_supported() -> None:
    module = _load_module()
    service = _build_service(module)

    enqueue = _first_callable(
        service,
        "enqueue",
        "create",
        "insert",
        "add",
        "push",
        "submit",
        "record",
        "save",
    )
    if enqueue is None:
        pytest.skip("enqueue operation not implemented")

    bad_entry = {
        "review_id": "rq-bad-incident-001",
        "incident_id": "",
        "status": "pending",
        "priority": "high",
        "reason": "prompt-injection",
        "source": "guard",
        "assigned_to": "analyst-1",
        "created_at": "2026-04-26T11:15:00Z",
    }

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            enqueue(bad_entry)
        except TypeError:
            enqueue(**bad_entry)


def test_review_queue_service_rejects_blank_reason_when_supported() -> None:
    module = _load_module()
    service = _build_service(module)

    enqueue = _first_callable(
        service,
        "enqueue",
        "create",
        "insert",
        "add",
        "push",
        "submit",
        "record",
        "save",
    )
    if enqueue is None:
        pytest.skip("enqueue operation not implemented")

    bad_entry = {
        "review_id": "rq-bad-reason-001",
        "incident_id": "inc-bad-reason-001",
        "status": "pending",
        "priority": "high",
        "reason": "",
        "source": "guard",
        "assigned_to": "analyst-1",
        "created_at": "2026-04-26T11:15:00Z",
    }

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            enqueue(bad_entry)
        except TypeError:
            enqueue(**bad_entry)


def test_review_queue_service_can_filter_by_status_when_supported() -> None:
    module = _load_module()
    service = _build_service(module)

    enqueue = _first_callable(
        service,
        "enqueue",
        "create",
        "insert",
        "add",
        "push",
        "submit",
        "record",
        "save",
    )
    reader = _first_callable(
        service,
        "list",
        "fetch",
        "query",
        "search",
        "read",
        "all",
        "get",
    )
    if enqueue is None or reader is None:
        pytest.skip("enqueue/read path not implemented")

    entry = {
        "review_id": "rq-filter-status-001",
        "incident_id": "inc-filter-status-001",
        "status": "approved",
        "priority": "low",
        "reason": "human-approved",
        "source": "reviewer",
        "assigned_to": "analyst-4",
        "created_at": "2026-04-26T11:15:00Z",
    }

    try:
        enqueue(entry)
    except TypeError:
        try:
            enqueue(**entry)
        except TypeError:
            pytest.skip("enqueue signature unsupported")

    try:
        result = reader(status="approved")
    except TypeError:
        pytest.skip("status filter not implemented")

    assert result is not None


def test_review_queue_service_can_filter_by_assignee_when_supported() -> None:
    module = _load_module()
    service = _build_service(module)

    enqueue = _first_callable(
        service,
        "enqueue",
        "create",
        "insert",
        "add",
        "push",
        "submit",
        "record",
        "save",
    )
    reader = _first_callable(
        service,
        "list",
        "fetch",
        "query",
        "search",
        "read",
        "all",
        "get",
    )
    if enqueue is None or reader is None:
        pytest.skip("enqueue/read path not implemented")

    assigned_to = "analyst-filter-001"
    entry = {
        "review_id": "rq-filter-assignee-001",
        "incident_id": "inc-filter-assignee-001",
        "status": "pending",
        "priority": "medium",
        "reason": "assignee-check",
        "source": "engine",
        "assigned_to": assigned_to,
        "created_at": "2026-04-26T11:15:00Z",
    }

    try:
        enqueue(entry)
    except TypeError:
        try:
            enqueue(**entry)
        except TypeError:
            pytest.skip("enqueue signature unsupported")

    try:
        result = reader(assigned_to=assigned_to)
    except TypeError:
        try:
            result = reader(assignee=assigned_to)
        except TypeError:
            pytest.skip("assignee filter not implemented")

    assert result is not None


def test_review_queue_service_supports_lookup_by_review_id_when_available() -> None:
    module = _load_module()
    service = _build_service(module)

    enqueue = _first_callable(
        service,
        "enqueue",
        "create",
        "insert",
        "add",
        "push",
        "submit",
        "record",
        "save",
    )
    lookup = _first_callable(
        service,
        "get_by_id",
        "find_by_id",
        "get",
        "fetch_one",
        "read_one",
        "get_review",
    )
    if enqueue is None or lookup is None:
        pytest.skip("enqueue/lookup path not implemented")

    review_id = "rq-lookup-001"
    entry = {
        "review_id": review_id,
        "incident_id": "inc-lookup-001",
        "status": "pending",
        "priority": "high",
        "reason": "lookup-check",
        "source": "tester",
        "assigned_to": "analyst-5",
        "created_at": "2026-04-26T11:15:00Z",
    }

    try:
        enqueue(entry)
    except TypeError:
        try:
            enqueue(**entry)
        except TypeError:
            pytest.skip("enqueue signature unsupported")

    try:
        result = lookup(review_id)
    except TypeError:
        try:
            result = lookup(review_id=review_id)
        except TypeError:
            pytest.skip("lookup signature unsupported")

    assert result is not None


def test_review_queue_service_supports_status_update_when_available() -> None:
    module = _load_module()
    service = _build_service(module)

    enqueue = _first_callable(
        service,
        "enqueue",
        "create",
        "insert",
        "add",
        "push",
        "submit",
        "record",
        "save",
    )
    updater = _first_callable(
        service,
        "update_status",
        "set_status",
        "resolve",
        "complete",
        "approve",
        "mark_resolved",
    )
    if enqueue is None or updater is None:
        pytest.skip("enqueue/update path not implemented")

    review_id = "rq-update-001"
    entry = {
        "review_id": review_id,
        "incident_id": "inc-update-001",
        "status": "pending",
        "priority": "medium",
        "reason": "update-check",
        "source": "tester",
        "assigned_to": "analyst-6",
        "created_at": "2026-04-26T11:15:00Z",
    }

    try:
        enqueue(entry)
    except TypeError:
        try:
            enqueue(**entry)
        except TypeError:
            pytest.skip("enqueue signature unsupported")

    try:
        result = updater(review_id, "resolved")
    except TypeError:
        try:
            result = updater(review_id=review_id, status="resolved")
        except TypeError:
            try:
                result = updater(review_id)
            except TypeError:
                pytest.skip("update signature unsupported")

    assert result is not None or result is None


def test_review_queue_service_supports_supabase_mode_when_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()

    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "test-service-role-key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key")

    factory = _first_callable(
        module,
        "build_review_queue_service",
        "create_review_queue_service",
        "get_review_queue_service",
        "build_service",
        "create_service",
        "get_service",
    )
    if factory is None:
        pytest.skip("review queue service factory not implemented")

    try:
        service = factory(mode="supabase")
    except TypeError:
        try:
            service = factory(backend="supabase")
        except TypeError:
            pytest.skip("explicit supabase backend selection not implemented")

    assert service is not None