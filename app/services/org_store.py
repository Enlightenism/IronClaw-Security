from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from app.services.organizationstore import (
    OrganizationStore as CanonicalOrganizationStore,
    get_organization_store,
)

OrgRole = Literal["owner", "admin", "analyst", "viewer"]
OrgMemberStatus = Literal["active", "invited", "suspended"]
OrgStatus = Literal["active", "trialing", "suspended"]


def _parse_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value or "").strip()
    if not text:
        return datetime.now(UTC)
    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return datetime.now(UTC)
    return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    result = str(value).strip()
    return result or default


def _member_status(value: Any) -> OrgMemberStatus:
    normalized = _text(value, "active").lower()
    if normalized in {"active", "invited", "suspended"}:
        return normalized
    return "active"


def _org_status(value: Any) -> OrgStatus:
    normalized = _text(value, "active").lower()
    if normalized in {"active", "trialing", "suspended"}:
        return normalized
    return "active"


@dataclass(slots=True)
class OrgMemberRecord:
    member_id: str
    user_id: str
    email: str
    display_name: str
    role: OrgRole
    status: OrgMemberStatus
    joined_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "member_id": self.member_id,
            "user_id": self.user_id,
            "email": self.email,
            "display_name": self.display_name,
            "role": self.role,
            "status": self.status,
            "joined_at": self.joined_at.isoformat().replace("+00:00", "Z"),
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class OrganizationRecord:
    org_id: str
    name: str
    slug: str
    status: OrgStatus
    created_at: datetime
    updated_at: datetime
    owner_user_id: str
    plan_name: str
    members: list[OrgMemberRecord] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "org_id": self.org_id,
            "name": self.name,
            "slug": self.slug,
            "status": self.status,
            "created_at": self.created_at.isoformat().replace("+00:00", "Z"),
            "updated_at": self.updated_at.isoformat().replace("+00:00", "Z"),
            "owner_user_id": self.owner_user_id,
            "plan_name": self.plan_name,
            "members": [member.to_dict() for member in self.members],
            "metadata": dict(self.metadata),
        }


def _member_from_canonical(payload: dict[str, Any]) -> OrgMemberRecord:
    user_id = (
        _text(payload.get("user_id"))
        or _text(payload.get("owner_user_id"))
        or _text(payload.get("owner_id"))
        or f"user-{_text(payload.get('member_id'), 'unknown')}"
    )
    return OrgMemberRecord(
        member_id=_text(payload.get("member_id")) or f"mbr-{user_id}",
        user_id=user_id,
        email=_text(payload.get("email")),
        display_name=_text(payload.get("display_name")),
        role=_text(payload.get("role"), "viewer"),  # type: ignore[assignment]
        status=_member_status(payload.get("status")),
        joined_at=_parse_datetime(payload.get("joined_at") or payload.get("created_at")),
        metadata=dict(payload.get("metadata") or {}),
    )


def _organization_from_canonical(payload: dict[str, Any]) -> OrganizationRecord:
    owner_user_id = (
        _text(payload.get("owner_user_id"))
        or _text(payload.get("owner_id"))
        or _text(payload.get("owner_email"))
        or "unknown-owner"
    )
    plan_name = _text(payload.get("plan_name")) or _text(payload.get("tier")) or _text(
        payload.get("plan"),
        "standard",
    )
    members = [
        _member_from_canonical(dict(member))
        for member in list(payload.get("members") or [])
    ]
    return OrganizationRecord(
        org_id=(
            _text(payload.get("org_id"))
            or _text(payload.get("organization_id"))
            or _text(payload.get("id"))
        ),
        name=_text(payload.get("name")),
        slug=_text(payload.get("slug")),
        status=_org_status(payload.get("status")),
        created_at=_parse_datetime(payload.get("created_at")),
        updated_at=_parse_datetime(payload.get("updated_at") or payload.get("created_at")),
        owner_user_id=owner_user_id,
        plan_name=plan_name,
        members=members,
        metadata=dict(payload.get("metadata") or {}),
    )


class OrgStore:
    def __init__(self, canonical_store: CanonicalOrganizationStore | None = None) -> None:
        self._canonical_store = canonical_store or get_organization_store()

    def seed_defaults(self) -> None:
        return None

    def list_orgs(self, *, status: OrgStatus | None = None) -> list[OrganizationRecord]:
        items = self._canonical_store.list_organizations(status=status)
        return [_organization_from_canonical(dict(item)) for item in items]

    def get_org(self, org_id: str) -> OrganizationRecord | None:
        item = self._canonical_store.get_organization(org_id)
        if item is None:
            return None
        return _organization_from_canonical(dict(item))

    def create_org(
        self,
        *,
        name: str,
        slug: str,
        owner_user_id: str,
        owner_email: str,
        owner_display_name: str,
        plan_name: str,
        status: OrgStatus = "trialing",
        metadata: dict[str, Any] | None = None,
    ) -> OrganizationRecord:
        created = self._canonical_store.create_organization(
            {
                "name": name,
                "slug": slug,
                "owner_id": owner_user_id,
                "owner_email": owner_email,
                "owner_display_name": owner_display_name,
                "status": status,
                "tier": plan_name,
                "plan": plan_name,
                "metadata": dict(metadata or {}),
                "members": [
                    {
                        "member_id": "",
                        "user_id": owner_user_id,
                        "email": owner_email,
                        "display_name": owner_display_name,
                        "role": "owner",
                        "status": "active",
                        "joined_at": datetime.now(UTC).isoformat(),
                        "metadata": {
                            "seeded": False,
                            "provisioned_as": "owner",
                        },
                    }
                ],
                "member_count": 1,
            }
        )
        return _organization_from_canonical(dict(created))

    def add_member(
        self,
        org_id: str,
        *,
        user_id: str,
        email: str,
        display_name: str,
        role: OrgRole,
        status: OrgMemberStatus = "invited",
        metadata: dict[str, Any] | None = None,
    ) -> OrganizationRecord | None:
        existing = self._canonical_store.get_organization(org_id)
        if existing is None:
            return None

        members = list(existing.get("members") or [])
        members.append(
            {
                "member_id": f"mbr-{_text(user_id) or _text(email)}",
                "user_id": user_id,
                "email": email,
                "display_name": display_name,
                "role": role,
                "status": status,
                "joined_at": datetime.now(UTC).isoformat(),
                "metadata": dict(metadata or {}),
            }
        )

        updated = self._canonical_store.update_organization(
            org_id,
            {
                "members": members,
                "member_count": len(members),
            },
        )
        if updated is None:
            return None
        return _organization_from_canonical(dict(updated))

    def update_member_role(
        self,
        org_id: str,
        member_id: str,
        *,
        role: OrgRole,
        status: OrgMemberStatus | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> OrganizationRecord | None:
        existing = self._canonical_store.get_organization(org_id)
        if existing is None:
            return None

        members = list(existing.get("members") or [])
        updated_any = False
        new_members: list[dict[str, Any]] = []

        for member in members:
            member_dict = dict(member)
            current_member_id = _text(member_dict.get("member_id"))
            if current_member_id != member_id:
                new_members.append(member_dict)
                continue

            updated_any = True
            merged_metadata = dict(member_dict.get("metadata") or {})
            merged_metadata.update(dict(metadata or {}))
            member_dict["role"] = role
            if status is not None:
                member_dict["status"] = status
            member_dict["metadata"] = merged_metadata
            new_members.append(member_dict)

        if not updated_any:
            return None

        updated = self._canonical_store.update_organization(
            org_id,
            {
                "members": new_members,
                "member_count": len(new_members),
            },
        )
        if updated is None:
            return None
        return _organization_from_canonical(dict(updated))

    def update_org_status(
        self,
        org_id: str,
        *,
        status: OrgStatus,
        plan_name: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> OrganizationRecord | None:
        updates: dict[str, Any] = {
            "status": status,
            "metadata": metadata if metadata is not None else None,
        }
        if plan_name is not None:
            updates["tier"] = plan_name
            updates["plan"] = plan_name

        updated = self._canonical_store.update_organization(
            org_id,
            {key: value for key, value in updates.items() if value is not None},
        )
        if updated is None:
            return None
        return _organization_from_canonical(dict(updated))

    def reset(self) -> None:
        return None


_ORG_STORE = OrgStore()


def get_org_store() -> OrgStore:
    return _ORG_STORE


def reset_org_store() -> None:
    global _ORG_STORE
    _ORG_STORE = OrgStore()