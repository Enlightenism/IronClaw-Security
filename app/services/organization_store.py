from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from threading import Lock
from typing import Any, Literal
from uuid import uuid4

OrganizationRole = Literal["owner", "admin", "analyst", "viewer"]
OrganizationStatus = Literal["active", "suspended", "invited"]


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
        return {
            "organization_id": self.organization_id,
            "name": self.name,
            "slug": self.slug,
            "status": self.status,
            "created_at": self.created_at.isoformat().replace("+00:00", "Z"),
            "updated_at": self.updated_at.isoformat().replace("+00:00", "Z"),
            "owner_email": self.owner_email,
            "members": [member.to_dict() for member in self.members],
            "metadata": dict(self.metadata),
        }


class OrganizationStore:
    def __init__(self) -> None:
        self._lock = Lock()
        self._items: list[OrganizationRecord] = []

    def list_organizations(
        self,
        *,
        status: Literal["active", "suspended"] | None = None,
    ) -> list[OrganizationRecord]:
        with self._lock:
            items = list(self._items)

        if status is not None:
            items = [item for item in items if item.status == status]

        return items

    def get_organization(self, organization_id: str) -> OrganizationRecord | None:
        with self._lock:
            for item in self._items:
                if item.organization_id == organization_id:
                    return item
        return None

    def create_organization(
        self,
        *,
        name: str,
        slug: str,
        owner_email: str,
        owner_display_name: str,
        metadata: dict[str, Any] | None = None,
    ) -> OrganizationRecord | tuple[Literal["slug_exists"], str]:
        normalized_slug = _normalize_slug(slug)
        normalized_owner_email = _normalize_email(owner_email)

        with self._lock:
            if any(item.slug == normalized_slug for item in self._items):
                return ("slug_exists", normalized_slug)

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

                if any(member.email == normalized_email for member in organization.members):
                    return ("member_exists", normalized_email)

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

        return ("not_found", organization_id)

    def reset(self) -> None:
        with self._lock:
            self._items.clear()


_ORGANIZATION_STORE = OrganizationStore()


def get_organization_store() -> OrganizationStore:
    return _ORGANIZATION_STORE


def reset_organization_store() -> None:
    _ORGANIZATION_STORE.reset()