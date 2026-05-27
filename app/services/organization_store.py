from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from threading import Lock
from typing import Any, Literal
from uuid import uuid4

OrganizationRole = Literal["owner", "admin", "analyst", "viewer"]
OrganizationStatus = Literal["active", "suspended", "invited"]

_SLUG_EXISTS = "slug_exists"
_MEMBER_EXISTS = "member_exists"
_NOT_FOUND = "not_found"


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _normalize_email(value: str) -> str:
    return value.strip().lower()


def _normalize_slug(value: str) -> str:
    return value.strip().lower().replace(" ", "-")


@dataclass(slots=True)
class OrganizationMemberRecord:
    member_id: str
    email: str
    display_name: str
    role: OrganizationRole
    status: OrganizationStatus
    created_at: datetime
    updated_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["created_at"] = self.created_at.isoformat().replace("+00:00", "Z")
        payload["updated_at"] = self.updated_at.isoformat().replace("+00:00", "Z")
        return payload


@dataclass(slots=True)
class OrganizationRecord:
    organization_id: str
    name: str
    slug: str
    status: Literal["active", "suspended"]
    created_at: datetime
    updated_at: datetime
    owner_email: str
    members: list[OrganizationMemberRecord] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Internal/list serialization — uses organization_id (underscored)."""
        return {
            "organization_id": self.organization_id,
            "name": self.name,
            "slug": self.slug,
            "status": self.status,
            "created_at": self.created_at.isoformat().replace("+00:00", "Z"),
            "updated_at": self.updated_at.isoformat().replace("+00:00", "Z"),
            "owner_email": self.owner_email,
            "members": [m.to_dict() for m in self.members],
            "metadata": dict(self.metadata),
        }

    def as_response_dict(self) -> dict[str, Any]:
        """POST/GET-by-ID response serialization — uses organizationid (no underscore)."""
        return {
            "organizationid": self.organization_id,
            "name": self.name,
            "slug": self.slug,
            "status": self.status,
            "created_at": self.created_at.isoformat().replace("+00:00", "Z"),
            "updated_at": self.updated_at.isoformat().replace("+00:00", "Z"),
            "owner_email": self.owner_email,
            "members": [m.to_dict() for m in self.members],
            "metadata": dict(self.metadata),
        }


class OrganizationStore:
    def __init__(self) -> None:
        self._lock = Lock()
        self._items: list[OrganizationRecord] = []

    # ------------------------------------------------------------------
    # Canonical public API
    # ------------------------------------------------------------------

    def create(
        self,
        *,
        name: str,
        slug: str,
        owner_email: str,
        owner_display_name: str,
        metadata: dict[str, Any] | None = None,
    ) -> OrganizationRecord | tuple[Literal["slug_exists"], str]:
        """Create a new organization. Returns the record or ("slug_exists", slug)."""
        normalized_slug = _normalize_slug(slug)
        normalized_owner_email = _normalize_email(owner_email)

        with self._lock:
            if any(item.slug == normalized_slug for item in self._items):
                return (_SLUG_EXISTS, normalized_slug)

            now = _utcnow()
            owner = OrganizationMemberRecord(
                member_id=f"member-{uuid4().hex[:12]}",
                email=normalized_owner_email,
                display_name=owner_display_name.strip(),
                role="owner",
                status="active",
                created_at=now,
                updated_at=now,
                metadata={"source": "organization_create"},
            )
            organization = OrganizationRecord(
                organization_id=f"org-{uuid4().hex[:12]}",
                name=name.strip(),
                slug=normalized_slug,
                status="active",
                created_at=now,
                updated_at=now,
                owner_email=normalized_owner_email,
                members=[owner],
                metadata=dict(metadata or {}),
            )
            self._items.append(organization)
            return organization

    def get_by_id(self, organization_id: str) -> OrganizationRecord | None:
        """Return the organization with the given ID, or None."""
        with self._lock:
            for item in self._items:
                if item.organization_id == organization_id:
                    return item
        return None

    def list_all(self) -> list[OrganizationRecord]:
        """Return a snapshot of all organizations regardless of status."""
        with self._lock:
            return list(self._items)

    def list_by_status(
        self,
        status: Literal["active", "suspended"],
    ) -> list[OrganizationRecord]:
        """Return all organizations matching the given status."""
        with self._lock:
            return [item for item in self._items if item.status == status]

    def add_member(
        self,
        organization_id: str,
        *,
        email: str,
        display_name: str,
        role: OrganizationRole,
        metadata: dict[str, Any] | None = None,
    ) -> OrganizationRecord | tuple[Literal["not_found", "member_exists"], str]:
        normalized_email = _normalize_email(email)

        with self._lock:
            for index, organization in enumerate(self._items):
                if organization.organization_id != organization_id:
                    continue

                if any(m.email == normalized_email for m in organization.members):
                    return (_MEMBER_EXISTS, normalized_email)

                now = _utcnow()
                member = OrganizationMemberRecord(
                    member_id=f"member-{uuid4().hex[:12]}",
                    email=normalized_email,
                    display_name=display_name.strip(),
                    role=role,
                    status="invited",
                    created_at=now,
                    updated_at=now,
                    metadata=dict(metadata or {}),
                )
                updated = OrganizationRecord(
                    organization_id=organization.organization_id,
                    name=organization.name,
                    slug=organization.slug,
                    status=organization.status,
                    created_at=organization.created_at,
                    updated_at=now,
                    owner_email=organization.owner_email,
                    members=[*organization.members, member],
                    metadata=dict(organization.metadata),
                )
                self._items[index] = updated
                return updated

        return (_NOT_FOUND, organization_id)

    def reset(self) -> None:
        with self._lock:
            self._items.clear()

    # ------------------------------------------------------------------
    # Legacy aliases — preserved for backward compatibility
    # ------------------------------------------------------------------

    def list_organizations(
        self,
        *,
        status: Literal["active", "suspended"] | None = None,
    ) -> list[OrganizationRecord]:
        if status is not None:
            return self.list_by_status(status)
        return self.list_all()

    def get_organization(self, organization_id: str) -> OrganizationRecord | None:
        return self.get_by_id(organization_id)

    def create_organization(
        self,
        *,
        name: str,
        slug: str,
        owner_email: str,
        owner_display_name: str,
        metadata: dict[str, Any] | None = None,
    ) -> OrganizationRecord | tuple[Literal["slug_exists"], str]:
        return self.create(
            name=name,
            slug=slug,
            owner_email=owner_email,
            owner_display_name=owner_display_name,
            metadata=metadata,
        )


_ORGANIZATION_STORE = OrganizationStore()


def get_store() -> OrganizationStore:
    """Canonical FastAPI dependency — swap via dependency_overrides in tests."""
    return _ORGANIZATION_STORE


def get_organization_store() -> OrganizationStore:
    """Backward-compatible alias for get_store()."""
    return _ORGANIZATION_STORE


def reset_organization_store() -> None:
    _ORGANIZATION_STORE.reset()
