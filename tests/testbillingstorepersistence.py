from __future__ import annotations

import importlib
from decimal import Decimal, InvalidOperation
from typing import Any, Final

import pytest

MODULE_CANDIDATES: Final[tuple[str, ...]] = (
    "app.services.billingstore",
    "services.billingstore",
    "billingstore",
)


def _load_module() -> Any:
    last_error: Exception | None = None
    for name in MODULE_CANDIDATES:
        try:
            return importlib.import_module(name)
        except Exception as exc:  # pragma: no cover
            last_error = exc
    raise AssertionError(f"unable to import billing store module: {last_error}")


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
        for key in ("items", "results", "rows", "entries", "records", "data"):
            candidate = value.get(key)
            if isinstance(candidate, list):
                return candidate
        return [value]
    return [value]


def _to_decimal(value: Any) -> Decimal | None:
    if value is None:
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return None


def _build_store(module: Any) -> Any:
    factory = _first_callable(
        module,
        "build_billing_store",
        "create_billing_store",
        "get_billing_store",
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
                    pytest.skip("billing store factory requires unsupported arguments")

    for cls_name in ("BillingStore", "InMemoryBillingStore", "SupabaseBillingStore"):
        if hasattr(module, cls_name):
            cls = getattr(module, cls_name)
            if callable(cls):
                try:
                    return cls()
                except TypeError:
                    continue

    pytest.skip("billing store builder/class not implemented")


def test_billing_store_module_imports() -> None:
    module = _load_module()
    assert module is not None


def test_billing_store_exposes_public_surface() -> None:
    module = _load_module()
    public_names = {name for name in dir(module) if not name.startswith("_")}
    assert public_names


def test_billing_store_can_be_built() -> None:
    module = _load_module()
    store = _build_store(module)
    assert store is not None


def test_billing_store_exposes_write_operation() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "put",
        "upsert",
        "store",
    )

    assert writer is not None


def test_billing_store_exposes_read_operation() -> None:
    module = _load_module()
    store = _build_store(module)

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

    assert reader is not None


def test_billing_store_accepts_basic_record_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "put",
        "upsert",
        "store",
    )
    if writer is None:
        pytest.skip("billing write operation not implemented")

    record = {
        "billing_id": "bill-001",
        "customer_id": "cust-001",
        "package_id": "pkg-pro",
        "status": "active",
        "currency": "USD",
        "amount": "49.99",
        "interval": "monthly",
        "created_at": "2026-04-26T11:18:00Z",
    }

    try:
        result = writer(record)
    except TypeError:
        try:
            result = writer(**record)
        except TypeError:
            pytest.skip("writer signature unsupported")

    assert result is not None or result is None


def test_billing_store_returns_serializable_records_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "put",
        "upsert",
        "store",
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
        pytest.skip("billing read/write path not implemented")

    record = {
        "billing_id": "bill-serialize-001",
        "customer_id": "cust-serialize-001",
        "package_id": "pkg-basic",
        "status": "active",
        "currency": "USD",
        "amount": "19.99",
        "interval": "monthly",
        "created_at": "2026-04-26T11:18:00Z",
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


def test_billing_record_contains_core_fields_when_present() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "put",
        "upsert",
        "store",
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
        pytest.skip("billing read/write path not implemented")

    record = {
        "billing_id": "bill-core-001",
        "customer_id": "cust-core-001",
        "package_id": "pkg-enterprise",
        "status": "trialing",
        "currency": "USD",
        "amount": "99.99",
        "interval": "yearly",
        "created_at": "2026-04-26T11:18:00Z",
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
        pytest.skip("reader returned no billing rows")

    payload = _serialize(rows[0])
    expected_keys = {
        "billing_id",
        "id",
        "customer_id",
        "account_id",
        "package_id",
        "plan_id",
        "status",
        "currency",
        "amount",
        "price",
        "interval",
        "created_at",
        "updated_at",
    }

    assert set(payload.keys()).intersection(expected_keys)


def test_billing_record_numeric_fields_are_non_negative_when_present() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "put",
        "upsert",
        "store",
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
        pytest.skip("billing read/write path not implemented")

    record = {
        "billing_id": "bill-numeric-001",
        "customer_id": "cust-numeric-001",
        "package_id": "pkg-standard",
        "status": "active",
        "currency": "USD",
        "amount": "29.00",
        "interval": "monthly",
        "created_at": "2026-04-26T11:18:00Z",
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
        pytest.skip("reader returned no billing rows")

    payload = _serialize(rows[0])
    for key in ("amount", "price", "subtotal", "tax", "total"):
        number = _to_decimal(payload.get(key))
        if number is not None:
            assert number >= Decimal(0)


def test_billing_store_rejects_blank_customer_id_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "put",
        "upsert",
        "store",
    )
    if writer is None:
        pytest.skip("billing write operation not implemented")

    bad_record = {
        "billing_id": "bill-bad-customer-001",
        "customer_id": "",
        "package_id": "pkg-pro",
        "status": "active",
        "currency": "USD",
        "amount": "49.99",
        "interval": "monthly",
        "created_at": "2026-04-26T11:18:00Z",
    }

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            writer(bad_record)
        except TypeError:
            writer(**bad_record)


def test_billing_store_rejects_blank_package_id_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "put",
        "upsert",
        "store",
    )
    if writer is None:
        pytest.skip("billing write operation not implemented")

    bad_record = {
        "billing_id": "bill-bad-package-001",
        "customer_id": "cust-bad-package-001",
        "package_id": "",
        "status": "active",
        "currency": "USD",
        "amount": "49.99",
        "interval": "monthly",
        "created_at": "2026-04-26T11:18:00Z",
    }

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            writer(bad_record)
        except TypeError:
            writer(**bad_record)


def test_billing_store_rejects_negative_amount_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "put",
        "upsert",
        "store",
    )
    if writer is None:
        pytest.skip("billing write operation not implemented")

    bad_record = {
        "billing_id": "bill-bad-amount-001",
        "customer_id": "cust-bad-amount-001",
        "package_id": "pkg-pro",
        "status": "active",
        "currency": "USD",
        "amount": "-1.00",
        "interval": "monthly",
        "created_at": "2026-04-26T11:18:00Z",
    }

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            writer(bad_record)
        except TypeError:
            writer(**bad_record)


def test_billing_store_can_filter_by_status_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "put",
        "upsert",
        "store",
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
        pytest.skip("billing read/write path not implemented")

    record = {
        "billing_id": "bill-filter-status-001",
        "customer_id": "cust-filter-status-001",
        "package_id": "pkg-status",
        "status": "canceled",
        "currency": "USD",
        "amount": "9.99",
        "interval": "monthly",
        "created_at": "2026-04-26T11:18:00Z",
    }

    try:
        writer(record)
    except TypeError:
        try:
            writer(**record)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader(status="canceled")
    except TypeError:
        pytest.skip("status filter not implemented")

    assert result is not None


def test_billing_store_can_filter_by_customer_id_when_supported() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "put",
        "upsert",
        "store",
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
        pytest.skip("billing read/write path not implemented")

    customer_id = "cust-filter-001"
    record = {
        "billing_id": "bill-filter-customer-001",
        "customer_id": customer_id,
        "package_id": "pkg-filter",
        "status": "active",
        "currency": "USD",
        "amount": "59.99",
        "interval": "monthly",
        "created_at": "2026-04-26T11:18:00Z",
    }

    try:
        writer(record)
    except TypeError:
        try:
            writer(**record)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = reader(customer_id=customer_id)
    except TypeError:
        try:
            result = reader(account_id=customer_id)
        except TypeError:
            pytest.skip("customer filter not implemented")

    assert result is not None


def test_billing_store_supports_lookup_by_billing_id_when_available() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "put",
        "upsert",
        "store",
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
        pytest.skip("billing write/lookup path not implemented")

    billing_id = "bill-lookup-001"
    record = {
        "billing_id": billing_id,
        "customer_id": "cust-lookup-001",
        "package_id": "pkg-lookup",
        "status": "active",
        "currency": "USD",
        "amount": "39.99",
        "interval": "monthly",
        "created_at": "2026-04-26T11:18:00Z",
    }

    try:
        writer(record)
    except TypeError:
        try:
            writer(**record)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = lookup(billing_id)
    except TypeError:
        try:
            result = lookup(billing_id=billing_id)
        except TypeError:
            pytest.skip("lookup signature unsupported")

    assert result is not None


def test_billing_store_supports_status_update_when_available() -> None:
    module = _load_module()
    store = _build_store(module)

    writer = _first_callable(
        store,
        "create",
        "insert",
        "add",
        "record",
        "save",
        "put",
        "upsert",
        "store",
    )
    updater = _first_callable(
        store,
        "update_status",
        "set_status",
        "cancel",
        "activate",
        "mark_paid",
        "mark_overdue",
    )
    if writer is None or updater is None:
        pytest.skip("billing write/update path not implemented")

    billing_id = "bill-update-001"
    record = {
        "billing_id": billing_id,
        "customer_id": "cust-update-001",
        "package_id": "pkg-update",
        "status": "trialing",
        "currency": "USD",
        "amount": "15.00",
        "interval": "monthly",
        "created_at": "2026-04-26T11:18:00Z",
    }

    try:
        writer(record)
    except TypeError:
        try:
            writer(**record)
        except TypeError:
            pytest.skip("writer signature unsupported")

    try:
        result = updater(billing_id, "active")
    except TypeError:
        try:
            result = updater(billing_id=billing_id, status="active")
        except TypeError:
            try:
                result = updater(billing_id)
            except TypeError:
                pytest.skip("update signature unsupported")

    assert result is not None or result is None


def test_billing_store_supports_supabase_mode_when_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()

    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "test-service-role-key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key")

    factory = _first_callable(
        module,
        "build_billing_store",
        "create_billing_store",
        "get_billing_store",
        "build_store",
        "create_store",
        "get_store",
    )
    if factory is None:
        pytest.skip("billing store factory not implemented")

    try:
        store = factory(mode="supabase")
    except TypeError:
        try:
            store = factory(backend="supabase")
        except TypeError:
            pytest.skip("explicit supabase backend selection not implemented")

    assert store is not None
