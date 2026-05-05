from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP, getcontext
from typing import Any, Mapping
from uuid import uuid4

from app.persistencebootstrap import build_store


DEFAULT_BILLING_TABLE = "billing_records"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()  # [web:127]


def _normalize_timestamp(value: str | datetime | None) -> str:
    if value is None:
        return _utc_now()
    if isinstance(value, datetime):
        dt = value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
        return dt.isoformat()
    text = str(value).strip()
    return text or _utc_now()


def _string(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _mapping(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, Mapping):  # [web:115][web:116]
        return dict(value)
    if hasattr(value, "model_dump") and callable(value.model_dump):
        dumped = value.model_dump()
        if isinstance(dumped, Mapping):
            return dict(dumped)
    if hasattr(value, "dict") and callable(value.dict):
        dumped = value.dict()
        if isinstance(dumped, Mapping):
            return dict(dumped)
    if hasattr(value, "__dict__"):
        return {
            key: val
            for key, val in vars(value).items()
            if not key.startswith("_") and not callable(val)
        }
    raise TypeError("value is not serializable to dict")


def _listify(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _decimal_text(value: Any, default: str = "0") -> str:
    if value is None or value == "":
        return default
    try:
        amount = Decimal(str(value))  # [web:129][web:130]
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValueError("invalid decimal amount") from exc
    quantized = amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)  # [web:125][web:126]
    return format(quantized, "f")


def _normalize_billing_payload(
    payload: dict[str, Any] | None = None,
    *,
    billing_id: str | None = None,
    owner_id: str | None = None,
    organization_id: str | None = None,
    org_id: str | None = None,
    customer_id: str | None = None,
    package_id: str | None = None,
    package_code: str | None = None,
    package_name: str | None = None,
    plan_id: str | None = None,
    invoice_id: str | None = None,
    purchase_id: str | None = None,
    transaction_id: str | None = None,
    amount: Any = None,
    subtotal: Any = None,
    tax_amount: Any = None,
    total_amount: Any = None,
    currency: str | None = None,
    status: str | None = None,
    billing_type: str | None = None,
    interval: str | None = None,
    units: Any = None,
    quota: Any = None,
    source: str | None = None,
    metadata: dict[str, Any] | None = None,
    line_items: list[Any] | None = None,
    tags: list[Any] | None = None,
    created_at: str | datetime | None = None,
    updated_at: str | datetime | None = None,
    billed_at: str | datetime | None = None,
    paid_at: str | datetime | None = None,
    **extra: Any,
) -> dict[str, Any]:
    source_payload = _mapping(payload)
    source_payload.update({key: value for key, value in extra.items() if value is not None})

    resolved_billing_id = (
        _string(billing_id)
        or _string(source_payload.get("billing_id"))
        or _string(source_payload.get("id"))
        or str(uuid4())
    )

    resolved_owner_id = (
        _string(owner_id)
        or _string(source_payload.get("owner_id"))
        or _string(source_payload.get("account_id"))
    )

    resolved_org = (
        _string(organization_id)
        or _string(org_id)
        or _string(customer_id)
        or _string(source_payload.get("organization_id"))
        or _string(source_payload.get("org_id"))
        or _string(source_payload.get("customer_id"))
    )

    resolved_package_id = (
        _string(package_id)
        or _string(package_code)
        or _string(plan_id)
        or _string(source_payload.get("package_id"))
        or _string(source_payload.get("package_code"))
        or _string(source_payload.get("plan_id"))
    )

    resolved_package_name = (
        _string(package_name)
        or _string(source_payload.get("package_name"))
        or _string(source_payload.get("plan_name"))
        or resolved_package_id
        or "standard"
    )

    resolved_currency = (
        _string(currency)
        or _string(source_payload.get("currency"))
        or "USD"
    ).upper()

    resolved_amount = _decimal_text(
        amount
        if amount is not None
        else source_payload.get("amount", source_payload.get("price"))
    )
    resolved_subtotal = _decimal_text(
        subtotal
        if subtotal is not None
        else source_payload.get("subtotal", resolved_amount)
    )
    resolved_tax_amount = _decimal_text(
        tax_amount
        if tax_amount is not None
        else source_payload.get("tax_amount", source_payload.get("tax", "0"))
    )
    # use Decimal from strings, not floats, for currency-safe math [web:129][web:130]
    resolved_total_amount = _decimal_text(
        total_amount
        if total_amount is not None
        else source_payload.get(
            "total_amount",
            source_payload.get(
                "total",
                Decimal(resolved_subtotal) + Decimal(resolved_tax_amount),
            ),
        )
    )

    resolved_units = int(
        units
        if units is not None
        else source_payload.get("units", source_payload.get("credits", 0))
    )
    resolved_quota = int(
        quota
        if quota is not None
        else source_payload.get("quota", source_payload.get("limit", 0))
    )

    resolved_status = (
        _string(status)
        or _string(source_payload.get("status"))
        or "pending"
    )
    resolved_billing_type = (
        _string(billing_type)
        or _string(source_payload.get("billing_type"))
        or "package_purchase"
    )
    resolved_interval = (
        _string(interval)
        or _string(source_payload.get("interval"))
        or "monthly"
    )
    resolved_source = (
        _string(source)
        or _string(source_payload.get("source"))
        or "ironclaw"
    )

    resolved_created_at = _normalize_timestamp(
        created_at or source_payload.get("created_at") or billed_at or source_payload.get("billed_at")
    )
    resolved_updated_at = _normalize_timestamp(
        updated_at or source_payload.get("updated_at") or resolved_created_at
    )
    resolved_billed_at = _normalize_timestamp(
        billed_at or source_payload.get("billed_at") or resolved_created_at
    )
    resolved_paid_at = (
        _normalize_timestamp(paid_at or source_payload.get("paid_at"))
        if (paid_at is not None or source_payload.get("paid_at") is not None)
        else None
    )

    return {
        "billing_id": resolved_billing_id,
        "id": resolved_billing_id,
        "owner_id": resolved_owner_id or None,
        "organization_id": resolved_org or None,
        "org_id": resolved_org or None,
        "customer_id": resolved_org or None,
        "package_id": resolved_package_id or None,
        "package_code": resolved_package_id or None,
        "package_name": resolved_package_name,
        "plan_id": _string(plan_id) or _string(source_payload.get("plan_id")) or resolved_package_id or None,
        "invoice_id": _string(invoice_id) or _string(source_payload.get("invoice_id")) or None,
        "purchase_id": _string(purchase_id) or _string(source_payload.get("purchase_id")) or None,
        "transaction_id": _string(transaction_id) or _string(source_payload.get("transaction_id")) or None,
        "amount": resolved_amount,
        "subtotal": resolved_subtotal,
        "tax_amount": resolved_tax_amount,
        "total_amount": resolved_total_amount,
        "currency": resolved_currency,
        "status": resolved_status,
        "billing_type": resolved_billing_type,
        "interval": resolved_interval,
        "units": resolved_units,
        "quota": resolved_quota,
        "source": resolved_source,
        "metadata": metadata if isinstance(metadata, dict) else _mapping(source_payload.get("metadata")),
        "line_items": _listify(line_items if line_items is not None else source_payload.get("line_items")),
        "tags": _listify(tags if tags is not None else source_payload.get("tags")),
        "created_at": resolved_created_at,
        "updated_at": resolved_updated_at,
        "billed_at": resolved_billed_at,
        "paid_at": resolved_paid_at,
    }


@dataclass(slots=True)  # [web:121][web:124]
class BillingStore:
    backend: Any = field(default_factory=build_store)
    table_name: str = DEFAULT_BILLING_TABLE

    @property
    def backend_name(self) -> str:
        return str(getattr(self.backend, "backend_name", "memory"))

    def as_dict(self) -> dict[str, Any]:
        return {
            "backend_name": self.backend_name,
            "table_name": self.table_name,
            "ready": True,
        }

    def is_ready(self) -> bool:
        return True

    def healthcheck(self) -> bool:
        health = getattr(self.backend, "healthcheck", None)
        if callable(health):
            return bool(health())
        return True

    def create_record(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        record = _normalize_billing_payload(payload, **kwargs)
        inserted = self.backend.insert(self.table_name, record)
        if isinstance(inserted, list) and inserted:
            return dict(inserted[0])
        if isinstance(inserted, dict):
            return dict(inserted)
        return record

    def create(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        return self.create_record(payload, **kwargs)

    def charge(self, payload: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        return self.create_record(payload, **kwargs)

    def purchase_package(
        self,
        *,
        owner_id: str | None = None,
        organization_id: str | None = None,
        package_id: str | None = None,
        package_name: str | None = None,
        amount: Any = None,
        currency: str = "USD",
        units: int = 0,
        quota: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.create_record(
            owner_id=owner_id,
            organization_id=organization_id,
            package_id=package_id,
            package_name=package_name,
            amount=amount,
            subtotal=amount,
            total_amount=amount,
            currency=currency,
            units=units,
            quota=quota,
            status="active",
            billing_type="package_purchase",
            metadata=metadata or {},
        )

    def list_records(
        self,
        *,
        limit: int = 100,
        filters: dict[str, Any] | None = None,
        owner_id: str | None = None,
        organization_id: str | None = None,
        status: str | None = None,
        package_id: str | None = None,
        invoice_id: str | None = None,
    ) -> list[dict[str, Any]]:
        query_filters: dict[str, Any] = dict(filters or {})
        if owner_id:
            query_filters.setdefault("owner_id", owner_id)
        if organization_id:
            query_filters.setdefault("organization_id", organization_id)
        if status:
            query_filters.setdefault("status", status)
        if package_id:
            query_filters.setdefault("package_id", package_id)
        if invoice_id:
            query_filters.setdefault("invoice_id", invoice_id)

        rows = self.backend.select(
            self.table_name,
            limit=limit,
            filters=query_filters or None,
        )
        items = [dict(row) for row in rows]
        items.sort(
            key=lambda row: _normalize_timestamp(row.get("updated_at") or row.get("created_at")),
            reverse=True,
        )
        return items

    def list(self, **kwargs: Any) -> list[dict[str, Any]]:
        return self.list_records(**kwargs)

    def get_record(self, billing_id: str) -> dict[str, Any] | None:
        if not _string(billing_id):
            raise ValueError("billing_id is required")
        rows = self.backend.select(self.table_name, filters={"billing_id": billing_id}, limit=1)
        if rows:
            return dict(rows[0])
        rows = self.backend.select(self.table_name, filters={"id": billing_id}, limit=1)
        if rows:
            return dict(rows[0])
        return None

    def get(self, billing_id: str) -> dict[str, Any] | None:
        return self.get_record(billing_id)

    def update_record(self, billing_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
        existing = self.get_record(billing_id)
        if existing is None:
            return None

        merged = dict(existing)
        merged.update(_mapping(updates))
        merged["billing_id"] = existing.get("billing_id") or existing.get("id") or billing_id
        merged["id"] = merged["billing_id"]
        merged["updated_at"] = _utc_now()

        if _string(merged.get("status")).lower() in {"paid", "settled"} and not merged.get("paid_at"):
            merged["paid_at"] = merged["updated_at"]

        normalized = _normalize_billing_payload(merged)

        updated = self.backend.update(
            self.table_name,
            normalized,
            filters={"billing_id": billing_id},
        )
        if isinstance(updated, list) and updated:
            return dict(updated[0])

        updated = self.backend.update(
            self.table_name,
            normalized,
            filters={"id": billing_id},
        )
        if isinstance(updated, list) and updated:
            return dict(updated[0])

        return normalized

    def update(self, billing_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
        return self.update_record(billing_id, updates)

    def mark_paid(
        self,
        billing_id: str,
        *,
        transaction_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        updates: dict[str, Any] = {
            "status": "paid",
            "paid_at": _utc_now(),
        }
        if transaction_id is not None:
            updates["transaction_id"] = transaction_id
        if metadata:
            current = self.get_record(billing_id) or {}
            merged_metadata = _mapping(current.get("metadata"))
            merged_metadata.update(metadata)
            updates["metadata"] = merged_metadata
        return self.update_record(billing_id, updates)

    def cancel_record(self, billing_id: str) -> dict[str, Any] | None:
        return self.update_record(billing_id, {"status": "cancelled"})

    def refund_record(
        self,
        billing_id: str,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        updates: dict[str, Any] = {"status": "refunded"}
        if metadata:
            current = self.get_record(billing_id) or {}
            merged_metadata = _mapping(current.get("metadata"))
            merged_metadata.update(metadata)
            updates["metadata"] = merged_metadata
        return self.update_record(billing_id, updates)

    def delete_record(self, billing_id: str) -> dict[str, Any] | None:
        if not _string(billing_id):
            raise ValueError("billing_id is required")

        deleted = self.backend.delete(self.table_name, filters={"billing_id": billing_id})
        if isinstance(deleted, list) and deleted:
            return dict(deleted[0])

        deleted = self.backend.delete(self.table_name, filters={"id": billing_id})
        if isinstance(deleted, list) and deleted:
            return dict(deleted[0])

        return None

    def summarize(
        self,
        *,
        owner_id: str | None = None,
        organization_id: str | None = None,
        limit: int = 1000,
    ) -> dict[str, Any]:
        records = self.list_records(
            limit=limit,
            owner_id=owner_id,
            organization_id=organization_id,
        )

        by_status: dict[str, int] = {}
        by_currency: dict[str, str] = {}
        total_amount = Decimal("0.00")

        for record in records:
            status = _string(record.get("status"), "unknown")
            currency = _string(record.get("currency"), "USD")
            amount = Decimal(str(record.get("total_amount", "0")))  # [web:129]
            by_status[status] = by_status.get(status, 0) + 1
            total_amount += amount
            running = Decimal(by_currency.get(currency, "0.00")) + amount
            by_currency[currency] = format(running.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP), "f")

        return {
            "total_records": len(records),
            "total_amount": format(total_amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP), "f"),
            "by_status": by_status,
            "by_currency": by_currency,
            "backend_name": self.backend_name,
            "table_name": self.table_name,
        }


def build_billing_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_BILLING_TABLE,
    **store_kwargs: Any,
) -> BillingStore:
    resolved_backend = backend if backend is not None else build_store(**store_kwargs)
    return BillingStore(backend=resolved_backend, table_name=table_name)


def create_billing_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_BILLING_TABLE,
    **store_kwargs: Any,
) -> BillingStore:
    return build_billing_store(backend=backend, table_name=table_name, **store_kwargs)


def get_billing_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_BILLING_TABLE,
    **store_kwargs: Any,
) -> BillingStore:
    return build_billing_store(backend=backend, table_name=table_name, **store_kwargs)