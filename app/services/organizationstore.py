from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.persistencebootstrap import build_store

DEFAULT_ORGANIZATION_TABLE = "organizations"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_timestamp(value: str | datetime | None) -> str:
    if value is None:
        return _utc_now()
    if isinstance(value, datetime):
        dt = value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
        return dt.isoformat()
    text = str(value).strip()
    return text or _utc_now()


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    result = str(value).strip()
    return result or default


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    lowered = str(value).strip().lower()
    if lowered in {"1", "true", "yes", "y", "on", "enabled", "active"}:
        return True
    if lowered in {"0", "false", "no", "n", "off", "disabled", "inactive"}:
        return False
    return default


def _as_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, Mapping):
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
            key: item
            for key, item in vars(value).items()
            if not key.startswith("_") and not callable(item)
        }
    raise TypeError("organization payload must be a mapping-like object")


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _slugify(value: str) -> str:
    text = _text(value).lower()
    cleaned: list[str] = []
    previous_dash = False
    for char in text:
        if char.isalnum():
            cleaned.append(char)
            previous_dash = False
            continue
        if not previous_dash:
            cleaned.append("-")
            previous_dash = True
    slug = "".join(cleaned).strip("-")
    return slug or f"org-{uuid4().hex[:8]}"


def _normalize_organization_payload(
    payload: dict[str, Any] | None = None,
    *,
    organization_id: str | None = None,
    org_id: str | None = None,
    owner_id: str | None = None,
    name: str | None = None,
    slug: str | None = None,
    display_name: str | None = None,
    legal_name: str | None = None,
    description: str | None = None,
    industry: str | None = None,
    website_url: str | None = None,
    email_domain: str | None = None,
    contact_email: str | None = None,
    billing_email: str | None = None,
    status: str | None = None,
    tier: str | None = None,
    plan: str | None = None,
    region: str | None = None,
    country: str | None = None,
    timezone: str | None = None,
    seat_limit: Any = None,
    member_count: Any = None,
    tags: list[Any] | None = None,
    metadata: dict[str, Any] | None = None,
    settings: dict[str, Any] | None = None,
    enabled: Any = None,
    archived: Any = None,
    created_at: str | datetime | None = None,
    updated_at: str | datetime | None = None,
    **extra: Any,
) -> dict[str, Any]:
    source = _as_dict(payload)
    source.update({key: value for key, value in extra.items() if value is not None})

    resolved_org_id = (
        _text(organization_id)
        or _text(org_id)
        or _text(source.get("organization_id"))
        or _text(source.get("org_id"))
        or _text(source.get("id"))
        or str(uuid4())
    )

    resolved_name = (
        _text(name)
        or _text(display_name)
        or _text(legal_name)
        or _text(source.get("name"))
        or _text(source.get("display_name"))
        or _text(source.get("legal_name"))
        or f"Organization {resolved_org_id[:8]}"
    )

    resolved_slug = (
        _text(slug)
        or _text(source.get("slug"))
        or _slugify(resolved_name)
    )

    resolved_owner_id = (
        _text(owner_id)
        or _text(source.get("owner_id"))
        or None
    )

    resolved_status = (
        _text(status)
        or _text(source.get("status"))
        or "active"
    )

    resolved_tier = (
        _text(tier)
        or _text(plan)
        or _text(source.get("tier"))
        or _text(source.get("plan"))
        or "standard"
    )

    resolved_created_at = _normalize_timestamp(created_at or source.get("created_at"))
    resolved_updated_at = _normalize_timestamp(
        updated_at or source.get("updated_at") or resolved_created_at
    )

    return {
        "organization_id": resolved_org_id,
        "org_id": resolved_org_id,
        "id": resolved_org_id,
        "owner_id": resolved_owner_id,
        "name": resolved_name,
        "display_name": _text(display_name)
        or _text(source.get("display_name"))
        or resolved_name,
        "legal_name": _text(legal_name)
        or _text(source.get("legal_name"))
        or resolved_name,
        "slug": resolved_slug,
        "description": _text(description) or _text(source.get("description")),
        "industry": _text(industry) or _text(source.get("industry")),
        "website_url": _text(website_url) or _text(source.get("website_url")),
        "email_domain": _text(email_domain) or _text(source.get("email_domain")),
        "contact_email": _text(contact_email) or _text(source.get("contact_email")),
        "billing_email": _text(billing_email) or _text(source.get("billing_email")),
        "status": resolved_status,
        "tier": resolved_tier,
        "plan": resolved_tier,
        "region": _text(region) or _text(source.get("region")),
        "country": _text(country) or _text(source.get("country")),
        "timezone": _text(timezone) or _text(source.get("timezone")) or "UTC",
        "seat_limit": int(
            seat_limit if seat_limit is not None else source.get("seat_limit", 0)
        ),
        "member_count": int(
            member_count if member_count is not None else source.get("member_count", 0)
        ),
        "tags": _as_list(tags if tags is not None else source.get("tags")),
        "metadata": metadata if isinstance(metadata, dict) else _as_dict(
            source.get("metadata")
        ),
        "settings": settings if isinstance(settings, dict) else _as_dict(
            source.get("settings")
        ),
        "enabled": _bool(
            enabled if enabled is not None else source.get("enabled"),
            default=resolved_status.lower() == "active",
        ),
        "archived": _bool(
            archived if archived is not None else source.get("archived"),
            default=resolved_status.lower() == "archived",
        ),
        "created_at": resolved_created_at,
        "updated_at": resolved_updated_at,
    }


@dataclass(slots=True)
class OrganizationRecord:
    organizationid: str
    name: str
    slug: str
    status: str
    createdat: str
    updatedat: str
    owneremail: str
    tier: str
    plan: str
    metadata: dict[str, Any]

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> OrganizationRecord:
        data = dict(row)
        org_id = (
            _text(data.get("organization_id"))
            or _text(data.get("org_id"))
            or _text(data.get("id"))
        )
        created_at = _normalize_timestamp(data.get("created_at"))
        updated_at = _normalize_timestamp(data.get("updated_at") or created_at)
        tier = _text(data.get("tier"), "standard")
        plan = _text(data.get("plan"), tier)
        owner_email = (
            _text(data.get("owner_email"))
            or _text(data.get("contact_email"))
            or _text(data.get("billing_email"))
        )
        return cls(
            organizationid=org_id,
            name=_text(data.get("name")),
            slug=_text(data.get("slug")),
            status=_text(data.get("status"), "active"),
            createdat=created_at,
            updatedat=updated_at,
            owneremail=owner_email,
            tier=tier,
            plan=plan,
            metadata=_as_dict(data.get("metadata")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "organizationid": self.organizationid,
            "name": self.name,
            "slug": self.slug,
            "status": self.status,
            "createdat": self.createdat,
            "updatedat": self.updatedat,
            "owneremail": self.owneremail,
            "tier": self.tier,
            "plan": self.plan,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class OrganizationStore:
    backend: Any = field(default_factory=build_store)
    table_name: str = DEFAULT_ORGANIZATION_TABLE

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
        probe = getattr(self.backend, "healthcheck", None)
        if callable(probe):
            return bool(probe())
        return True

    def create_organization(
        self,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> OrganizationRecord:
        record = _normalize_organization_payload(payload, **kwargs)
        inserted = self.backend.insert(self.table_name, record)
        if isinstance(inserted, list) and inserted:
            row = dict(inserted[0])
        elif isinstance(inserted, dict):
            row = dict(inserted)
        else:
            row = record
        return OrganizationRecord.from_row(row)

    def create(
        self,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> OrganizationRecord:
        return self.create_organization(payload, **kwargs)

    def upsert_organization(
        self,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> OrganizationRecord:
        record = _normalize_organization_payload(payload, **kwargs)
        existing = self.get_organization(record["organization_id"])
        if existing is None:
            return self.create_organization(record)
        updated = self.update_organization(record["organization_id"], record)
        return updated or OrganizationRecord.from_row(record)

    def list_organizations(
        self,
        *,
        limit: int = 100,
        filters: dict[str, Any] | None = None,
        owner_id: str | None = None,
        status: str | None = None,
        tier: str | None = None,
        slug: str | None = None,
    ) -> list[OrganizationRecord]:
        query_filters: dict[str, Any] = dict(filters or {})
        if owner_id:
            query_filters.setdefault("owner_id", owner_id)
        if status:
            query_filters.setdefault("status", status)
        if tier:
            query_filters.setdefault("tier", tier)
        if slug:
            query_filters.setdefault("slug", slug)

        rows = self.backend.select(
            self.table_name,
            filters=query_filters or None,
            limit=limit,
        )
        items = [OrganizationRecord.from_row(row) for row in rows]
        items.sort(
            key=lambda rec: rec.updatedat or rec.createdat,
            reverse=True,
        )
        return items

    def list(self, **kwargs: Any) -> list[OrganizationRecord]:
        return self.list_organizations(**kwargs)

    def get_organization(self, organization_id: str) -> OrganizationRecord | None:
        oid = _text(organization_id)
        if not oid:
            raise ValueError("organization_id is required")

        for key in ("organization_id", "org_id", "id"):
            rows = self.backend.select(self.table_name, filters={key: oid}, limit=1)
            if rows:
                return OrganizationRecord.from_row(rows[0])
        return None

    def get(self, organization_id: str) -> OrganizationRecord | None:
        return self.get_organization(organization_id)

    def get_by_slug(self, slug: str) -> OrganizationRecord | None:
        normalized = _text(slug)
        if not normalized:
            raise ValueError("slug is required")
        rows = self.backend.select(
            self.table_name,
            filters={"slug": normalized},
            limit=1,
        )
        if rows:
            return OrganizationRecord.from_row(rows[0])
        return None

    def update_organization(
        self,
        organization_id: str,
        updates: dict[str, Any],
    ) -> OrganizationRecord | None:
        existing = self.get_organization(organization_id)
        if existing is None:
            return None

        merged = _as_dict(existing.to_dict())
        merged.update(_as_dict(updates))
        merged["organization_id"] = organization_id
        merged["org_id"] = organization_id
        merged["id"] = organization_id
        merged["updated_at"] = _utc_now()

        normalized = _normalize_organization_payload(merged)

        for key in ("organization_id", "org_id", "id"):
            updated = self.backend.update(
                self.table_name,
                normalized,
                filters={key: organization_id},
            )
            if isinstance(updated, list) and updated:
                return OrganizationRecord.from_row(updated[0])

        return OrganizationRecord.from_row(normalized)

    def update(
        self,
        organization_id: str,
        updates: dict[str, Any],
    ) -> OrganizationRecord | None:
        return self.update_organization(organization_id, updates)

    def activate(self, organization_id: str) -> OrganizationRecord | None:
        return self.update_organization(
            organization_id,
            {"status": "active", "enabled": True, "archived": False},
        )

    def suspend(self, organization_id: str) -> OrganizationRecord | None:
        return self.update_organization(
            organization_id,
            {"status": "suspended", "enabled": False},
        )

    def archive(self, organization_id: str) -> OrganizationRecord | None:
        return self.update_organization(
            organization_id,
            {"status": "archived", "enabled": False, "archived": True},
        )

    def delete_organization(self, organization_id: str) -> dict[str, Any] | None:
        oid = _text(organization_id)
        if not oid:
            raise ValueError("organization_id is required")

        for key in ("organization_id", "org_id", "id"):
            deleted = self.backend.delete(self.table_name, filters={key: oid})
            if isinstance(deleted, list) and deleted:
                return dict(deleted[0])
        return None

    def delete(self, organization_id: str) -> dict[str, Any] | None:
        return self.delete_organization(organization_id)

    def exists(self, organization_id: str) -> bool:
        return self.get_organization(organization_id) is not None

    def summarize(
        self,
        *,
        owner_id: str | None = None,
        limit: int = 1000,
    ) -> dict[str, Any]:
        organizations = self.list_organizations(limit=limit, owner_id=owner_id)
        by_status: dict[str, int] = {}
        by_tier: dict[str, int] = {}

        for organization in organizations:
            status = _text(organization.status, "unknown")
            tier = _text(organization.tier, "unknown")
            by_status[status] = by_status.get(status, 0) + 1
            by_tier[tier] = by_tier.get(tier, 0) + 1

        return {
            "total_organizations": len(organizations),
            "by_status": by_status,
            "by_tier": by_tier,
            "backend_name": self.backend_name,
            "table_name": self.table_name,
        }


def build_organization_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_ORGANIZATION_TABLE,
    **store_kwargs: Any,
) -> OrganizationStore:
    resolved_backend = backend if backend is not None else build_store(**store_kwargs)
    return OrganizationStore(backend=resolved_backend, table_name=table_name)


def create_organization_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_ORGANIZATION_TABLE,
    **store_kwargs: Any,
) -> OrganizationStore:
    return build_organization_store(backend=backend, table_name=table_name, **store_kwargs)


def get_organization_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_ORGANIZATION_TABLE,
    **store_kwargs: Any,
) -> OrganizationStore:
    return build_organization_store(backend=backend, table_name=table_name, **store_kwargs)