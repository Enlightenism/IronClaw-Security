from __future__ import annotations

from datetime import datetime

import pytest

from app.services.org_store import (
    OrganizationRecord,
    OrgStore,
    get_org_store,
    reset_org_store,
)
from app.services.organizationstore import (
    OrganizationStore,
    build_organization_store,
    get_organization_store,
)

# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture()
def fresh_org_store() -> OrgStore:
    """Return a new OrgStore backed by a fresh in-memory canonical store."""
    canonical = get_organization_store()
    return OrgStore(canonical_store=canonical)


@pytest.fixture()
def canonical_store() -> OrganizationStore:
    """Return a fresh canonical OrganizationStore (in-memory)."""
    return build_organization_store()


@pytest.fixture()
def org_with_owner(fresh_org_store: OrgStore) -> OrganizationRecord:
    """Create a standard org with an owner member for reuse across tests."""
    return fresh_org_store.create_org(
        name="IronClaw Ops",
        slug="ironclaw-ops",
        owner_user_id="user-owner-001",
        owner_email="owner@ironclaw.dev",
        owner_display_name="Jesse Owner",
        plan_name="enterprise",
        status="active",
    )


# ===========================================================================
# OrganizationRecord dataclass — OrgStore layer
# ===========================================================================


class TestOrganizationRecordDataclass:
    def test_to_dict_has_required_keys(self, org_with_owner: OrganizationRecord) -> None:
        d = org_with_owner.to_dict()
        required = {
            "org_id",
            "name",
            "slug",
            "status",
            "created_at",
            "updated_at",
            "owner_user_id",
            "plan_name",
            "members",
            "metadata",
        }
        assert required.issubset(set(d.keys()))

    def test_to_dict_timestamps_are_iso_strings(self, org_with_owner: OrganizationRecord) -> None:
        d = org_with_owner.to_dict()
        assert isinstance(d["created_at"], str)
        assert isinstance(d["updated_at"], str)
        assert "T" in d["created_at"]
        assert "T" in d["updated_at"]

    def test_to_dict_members_is_list(self, org_with_owner: OrganizationRecord) -> None:
        d = org_with_owner.to_dict()
        assert isinstance(d["members"], list)

    def test_to_dict_metadata_is_dict(self, org_with_owner: OrganizationRecord) -> None:
        d = org_with_owner.to_dict()
        assert isinstance(d["metadata"], dict)

    def test_org_id_non_empty(self, org_with_owner: OrganizationRecord) -> None:
        assert org_with_owner.org_id
        assert isinstance(org_with_owner.org_id, str)

    def test_name_preserved(self, org_with_owner: OrganizationRecord) -> None:
        assert org_with_owner.name == "IronClaw Ops"

    def test_slug_preserved(self, org_with_owner: OrganizationRecord) -> None:
        assert org_with_owner.slug == "ironclaw-ops"

    def test_status_preserved(self, org_with_owner: OrganizationRecord) -> None:
        assert org_with_owner.status == "active"

    def test_plan_name_preserved(self, org_with_owner: OrganizationRecord) -> None:
        assert org_with_owner.plan_name == "enterprise"

    def test_owner_user_id_preserved(self, org_with_owner: OrganizationRecord) -> None:
        assert org_with_owner.owner_user_id == "user-owner-001"


# ===========================================================================
# OrgMemberRecord dataclass
# ===========================================================================


class TestOrgMemberRecordDataclass:
    def test_to_dict_has_required_keys(self, org_with_owner: OrganizationRecord) -> None:
        assert org_with_owner.members
        member = org_with_owner.members[0]
        d = member.to_dict()
        required = {
            "member_id",
            "user_id",
            "email",
            "display_name",
            "role",
            "status",
            "joined_at",
            "metadata",
        }
        assert required.issubset(set(d.keys()))

    def test_owner_member_role_is_owner(self, org_with_owner: OrganizationRecord) -> None:
        owner_members = [m for m in org_with_owner.members if m.role == "owner"]
        assert len(owner_members) == 1

    def test_owner_member_status_is_active(self, org_with_owner: OrganizationRecord) -> None:
        owner_members = [m for m in org_with_owner.members if m.role == "owner"]
        assert owner_members[0].status == "active"

    def test_owner_member_email(self, org_with_owner: OrganizationRecord) -> None:
        owner_members = [m for m in org_with_owner.members if m.role == "owner"]
        assert owner_members[0].email == "owner@ironclaw.dev"

    def test_joined_at_is_datetime(self, org_with_owner: OrganizationRecord) -> None:
        for member in org_with_owner.members:
            assert isinstance(member.joined_at, datetime)

    def test_metadata_is_dict(self, org_with_owner: OrganizationRecord) -> None:
        for member in org_with_owner.members:
            assert isinstance(member.metadata, dict)

    def test_to_dict_joined_at_is_iso_string(self, org_with_owner: OrganizationRecord) -> None:
        for member in org_with_owner.members:
            d = member.to_dict()
            assert isinstance(d["joined_at"], str)
            assert "T" in d["joined_at"]


# ===========================================================================
# OrgStore — create_org
# ===========================================================================


class TestOrgStoreCreateOrg:
    def test_create_org_returns_organization_record(self, fresh_org_store: OrgStore) -> None:
        result = fresh_org_store.create_org(
            name="Test Org",
            slug="test-org",
            owner_user_id="user-001",
            owner_email="admin@test.dev",
            owner_display_name="Admin User",
            plan_name="pro",
        )
        assert isinstance(result, OrganizationRecord)

    def test_create_org_default_status_is_trialing(self, fresh_org_store: OrgStore) -> None:
        result = fresh_org_store.create_org(
            name="Trialing Org",
            slug="trialing-org",
            owner_user_id="user-002",
            owner_email="trial@test.dev",
            owner_display_name="Trial User",
            plan_name="free",
        )
        assert result.status == "trialing"

    def test_create_org_explicit_active_status(self, fresh_org_store: OrgStore) -> None:
        result = fresh_org_store.create_org(
            name="Active Org",
            slug="active-org",
            owner_user_id="user-003",
            owner_email="active@test.dev",
            owner_display_name="Active User",
            plan_name="enterprise",
            status="active",
        )
        assert result.status == "active"

    def test_create_org_owner_member_added(self, fresh_org_store: OrgStore) -> None:
        result = fresh_org_store.create_org(
            name="Owner Org",
            slug="owner-org",
            owner_user_id="user-004",
            owner_email="owner@test.dev",
            owner_display_name="Owner",
            plan_name="standard",
        )
        assert len(result.members) >= 1
        roles = [m.role for m in result.members]
        assert "owner" in roles

    def test_create_org_with_metadata(self, fresh_org_store: OrgStore) -> None:
        result = fresh_org_store.create_org(
            name="Meta Org",
            slug="meta-org",
            owner_user_id="user-005",
            owner_email="meta@test.dev",
            owner_display_name="Meta User",
            plan_name="pro",
            metadata={"region": "us-west", "tier": "gold"},
        )
        assert isinstance(result.metadata, dict)

    def test_create_org_ids_are_non_empty_strings(self, fresh_org_store: OrgStore) -> None:
        result = fresh_org_store.create_org(
            name="Id Org",
            slug="id-org",
            owner_user_id="user-006",
            owner_email="id@test.dev",
            owner_display_name="Id User",
            plan_name="free",
        )
        assert result.org_id
        assert isinstance(result.org_id, str)


# ===========================================================================
# OrgStore — get_org
# ===========================================================================


class TestOrgStoreGetOrg:
    def test_get_org_returns_organization_record(self, fresh_org_store: OrgStore, org_with_owner: OrganizationRecord) -> None:
        fetched = fresh_org_store.get_org(org_with_owner.org_id)
        assert fetched is not None
        assert isinstance(fetched, OrganizationRecord)

    def test_get_org_id_matches(self, fresh_org_store: OrgStore, org_with_owner: OrganizationRecord) -> None:
        fetched = fresh_org_store.get_org(org_with_owner.org_id)
        assert fetched is not None
        assert fetched.org_id == org_with_owner.org_id

    def test_get_org_missing_returns_none(self, fresh_org_store: OrgStore) -> None:
        result = fresh_org_store.get_org("org-does-not-exist-xyz")
        assert result is None

    def test_get_org_name_intact(self, fresh_org_store: OrgStore, org_with_owner: OrganizationRecord) -> None:
        fetched = fresh_org_store.get_org(org_with_owner.org_id)
        assert fetched is not None
        assert fetched.name == org_with_owner.name

    def test_get_org_plan_name_intact(self, fresh_org_store: OrgStore, org_with_owner: OrganizationRecord) -> None:
        fetched = fresh_org_store.get_org(org_with_owner.org_id)
        assert fetched is not None
        assert fetched.plan_name == org_with_owner.plan_name


# ===========================================================================
# OrgStore — list_orgs
# ===========================================================================


class TestOrgStoreListOrgs:
    def test_list_orgs_returns_list(self, fresh_org_store: OrgStore) -> None:
        result = fresh_org_store.list_orgs()
        assert isinstance(result, list)

    def test_list_orgs_contains_created_org(self, fresh_org_store: OrgStore, org_with_owner: OrganizationRecord) -> None:
        orgs = fresh_org_store.list_orgs()
        ids = [o.org_id for o in orgs]
        assert org_with_owner.org_id in ids

    def test_list_orgs_filter_by_active_status(self, fresh_org_store: OrgStore) -> None:
        fresh_org_store.create_org(
            name="Active Filter Org",
            slug="active-filter-org",
            owner_user_id="user-filter-01",
            owner_email="filter@test.dev",
            owner_display_name="Filter User",
            plan_name="pro",
            status="active",
        )
        orgs = fresh_org_store.list_orgs(status="active")
        for org in orgs:
            assert org.status == "active"

    def test_list_orgs_filter_by_trialing_status(self, fresh_org_store: OrgStore) -> None:
        fresh_org_store.create_org(
            name="Trial Filter Org",
            slug="trial-filter-org",
            owner_user_id="user-filter-02",
            owner_email="trial.filter@test.dev",
            owner_display_name="Trial Filter User",
            plan_name="free",
        )
        orgs = fresh_org_store.list_orgs(status="trialing")
        for org in orgs:
            assert org.status == "trialing"

    def test_list_orgs_all_elements_are_organization_records(self, fresh_org_store: OrgStore, org_with_owner: OrganizationRecord) -> None:
        orgs = fresh_org_store.list_orgs()
        for org in orgs:
            assert isinstance(org, OrganizationRecord)


# ===========================================================================
# OrgStore — add_member
# ===========================================================================


class TestOrgStoreAddMember:
    def test_add_member_returns_updated_record(self, fresh_org_store: OrgStore, org_with_owner: OrganizationRecord) -> None:
        result = fresh_org_store.add_member(
            org_with_owner.org_id,
            user_id="user-analyst-01",
            email="analyst@ironclaw.dev",
            display_name="Analyst One",
            role="analyst",
        )
        assert isinstance(result, OrganizationRecord)

    def test_add_member_increases_member_count(self, fresh_org_store: OrgStore, org_with_owner: OrganizationRecord) -> None:
        before = len(org_with_owner.members)
        result = fresh_org_store.add_member(
            org_with_owner.org_id,
            user_id="user-analyst-02",
            email="analyst2@ironclaw.dev",
            display_name="Analyst Two",
            role="analyst",
        )
        assert result is not None
        assert len(result.members) == before + 1

    def test_add_member_role_preserved(self, fresh_org_store: OrgStore, org_with_owner: OrganizationRecord) -> None:
        result = fresh_org_store.add_member(
            org_with_owner.org_id,
            user_id="user-viewer-01",
            email="viewer@ironclaw.dev",
            display_name="Viewer One",
            role="viewer",
        )
        assert result is not None
        viewers = [m for m in result.members if m.role == "viewer"]
        assert len(viewers) == 1

    def test_add_member_default_status_is_invited(self, fresh_org_store: OrgStore, org_with_owner: OrganizationRecord) -> None:
        result = fresh_org_store.add_member(
            org_with_owner.org_id,
            user_id="user-invited-01",
            email="invited@ironclaw.dev",
            display_name="Invited User",
            role="analyst",
        )
        assert result is not None
        invited = [m for m in result.members if m.email == "invited@ironclaw.dev"]
        assert invited[0].status == "invited"

    def test_add_member_explicit_active_status(self, fresh_org_store: OrgStore, org_with_owner: OrganizationRecord) -> None:
        result = fresh_org_store.add_member(
            org_with_owner.org_id,
            user_id="user-active-member",
            email="activemember@ironclaw.dev",
            display_name="Active Member",
            role="admin",
            status="active",
        )
        assert result is not None
        active = [m for m in result.members if m.email == "activemember@ironclaw.dev"]
        assert active[0].status == "active"

    def test_add_member_to_missing_org_returns_none(self, fresh_org_store: OrgStore) -> None:
        result = fresh_org_store.add_member(
            "org-does-not-exist",
            user_id="user-x",
            email="x@x.com",
            display_name="X",
            role="viewer",
        )
        assert result is None

    def test_add_member_with_metadata(self, fresh_org_store: OrgStore, org_with_owner: OrganizationRecord) -> None:
        result = fresh_org_store.add_member(
            org_with_owner.org_id,
            user_id="user-meta-member",
            email="meta.member@ironclaw.dev",
            display_name="Meta Member",
            role="analyst",
            metadata={"provisioned_by": "test_org_store"},
        )
        assert result is not None
        meta_members = [m for m in result.members if m.email == "meta.member@ironclaw.dev"]
        assert meta_members[0].metadata.get("provisioned_by") == "test_org_store"


# ===========================================================================
# OrgStore — update_member_role
# ===========================================================================


class TestOrgStoreUpdateMemberRole:
    def test_update_member_role_changes_role(self, fresh_org_store: OrgStore, org_with_owner: OrganizationRecord) -> None:
        added = fresh_org_store.add_member(
            org_with_owner.org_id,
            user_id="user-role-change",
            email="role.change@ironclaw.dev",
            display_name="Role Change User",
            role="viewer",
        )
        assert added is not None
        target_member = next((m for m in added.members if m.email == "role.change@ironclaw.dev"), None)
        assert target_member is not None

        updated = fresh_org_store.update_member_role(
            org_with_owner.org_id,
            target_member.member_id,
            role="admin",
        )
        assert updated is not None
        changed = next((m for m in updated.members if m.member_id == target_member.member_id), None)
        assert changed is not None
        assert changed.role == "admin"

    def test_update_member_role_with_status(self, fresh_org_store: OrgStore, org_with_owner: OrganizationRecord) -> None:
        added = fresh_org_store.add_member(
            org_with_owner.org_id,
            user_id="user-status-change",
            email="status.change@ironclaw.dev",
            display_name="Status Change",
            role="analyst",
        )
        assert added is not None
        target = next((m for m in added.members if m.email == "status.change@ironclaw.dev"), None)
        assert target is not None

        updated = fresh_org_store.update_member_role(
            org_with_owner.org_id,
            target.member_id,
            role="analyst",
            status="active",
        )
        assert updated is not None
        changed = next((m for m in updated.members if m.member_id == target.member_id), None)
        assert changed is not None
        assert changed.status == "active"

    def test_update_member_role_missing_member_returns_none(self, fresh_org_store: OrgStore, org_with_owner: OrganizationRecord) -> None:
        result = fresh_org_store.update_member_role(
            org_with_owner.org_id,
            "mbr-does-not-exist",
            role="admin",
        )
        assert result is None

    def test_update_member_role_missing_org_returns_none(self, fresh_org_store: OrgStore) -> None:
        result = fresh_org_store.update_member_role(
            "org-ghost",
            "mbr-ghost",
            role="viewer",
        )
        assert result is None

    def test_update_member_role_merges_metadata(self, fresh_org_store: OrgStore, org_with_owner: OrganizationRecord) -> None:
        added = fresh_org_store.add_member(
            org_with_owner.org_id,
            user_id="user-meta-role",
            email="meta.role@ironclaw.dev",
            display_name="Meta Role",
            role="viewer",
            metadata={"key": "original"},
        )
        assert added is not None
        target = next((m for m in added.members if m.email == "meta.role@ironclaw.dev"), None)
        assert target is not None

        updated = fresh_org_store.update_member_role(
            org_with_owner.org_id,
            target.member_id,
            role="analyst",
            metadata={"added_key": "new_value"},
        )
        assert updated is not None
        changed = next((m for m in updated.members if m.member_id == target.member_id), None)
        assert changed is not None
        assert "added_key" in changed.metadata


# ===========================================================================
# OrgStore — update_org_status
# ===========================================================================


class TestOrgStoreUpdateOrgStatus:
    def test_update_org_status_to_suspended(self, fresh_org_store: OrgStore, org_with_owner: OrganizationRecord) -> None:
        result = fresh_org_store.update_org_status(org_with_owner.org_id, status="suspended")
        assert result is not None
        assert result.status == "suspended"

    def test_update_org_status_to_active(self, fresh_org_store: OrgStore, org_with_owner: OrganizationRecord) -> None:
        fresh_org_store.update_org_status(org_with_owner.org_id, status="suspended")
        result = fresh_org_store.update_org_status(org_with_owner.org_id, status="active")
        assert result is not None
        assert result.status == "active"

    def test_update_org_status_with_plan_name(self, fresh_org_store: OrgStore, org_with_owner: OrganizationRecord) -> None:
        result = fresh_org_store.update_org_status(
            org_with_owner.org_id,
            status="active",
            plan_name="pro",
        )
        assert result is not None
        assert result.plan_name == "pro"

    def test_update_org_status_missing_org_returns_none(self, fresh_org_store: OrgStore) -> None:
        result = fresh_org_store.update_org_status("org-ghost-xyz", status="suspended")
        assert result is None

    def test_update_org_status_with_metadata(self, fresh_org_store: OrgStore, org_with_owner: OrganizationRecord) -> None:
        result = fresh_org_store.update_org_status(
            org_with_owner.org_id,
            status="active",
            metadata={"reason": "reactivated"},
        )
        assert result is not None


# ===========================================================================
# OrgStore — seed_defaults and reset
# ===========================================================================


class TestOrgStoreSeedAndReset:
    def test_seed_defaults_is_no_op(self, fresh_org_store: OrgStore) -> None:
        # seed_defaults is intentionally a no-op on this layer
        result = fresh_org_store.seed_defaults()
        assert result is None

    def test_reset_is_no_op(self, fresh_org_store: OrgStore) -> None:
        result = fresh_org_store.reset()
        assert result is None


# ===========================================================================
# Module-level singleton and factory
# ===========================================================================


class TestOrgStoreSingleton:
    def test_get_org_store_returns_org_store_instance(self) -> None:
        store = get_org_store()
        assert isinstance(store, OrgStore)

    def test_get_org_store_same_object_across_calls(self) -> None:
        s1 = get_org_store()
        s2 = get_org_store()
        assert s1 is s2

    def test_reset_org_store_returns_fresh_instance(self) -> None:
        s1 = get_org_store()
        reset_org_store()
        s2 = get_org_store()
        assert isinstance(s2, OrgStore)
        assert s1 is not s2


# ===========================================================================
# Canonical OrganizationStore (organizationstore.py) — direct coverage
# ===========================================================================


class TestCanonicalOrganizationStoreInit:
    def test_is_ready(self, canonical_store: OrganizationStore) -> None:
        assert canonical_store.is_ready() is True

    def test_as_dict_has_expected_keys(self, canonical_store: OrganizationStore) -> None:
        d = canonical_store.as_dict()
        assert "backend_name" in d
        assert "table_name" in d
        assert "ready" in d
        assert d["ready"] is True

    def test_healthcheck_returns_bool(self, canonical_store: OrganizationStore) -> None:
        assert isinstance(canonical_store.healthcheck(), bool)


class TestCanonicalOrganizationStoreCRUD:
    def test_create_organization_returns_record(self, canonical_store: OrganizationStore) -> None:
        from app.services.organizationstore import OrganizationRecord as CanonRecord

        result = canonical_store.create_organization(
            {
                "name": "Canonical Test Org",
                "slug": "canonical-test-org",
                "owner_id": "user-canonical-01",
                "owner_email": "canonical@test.dev",
                "status": "active",
                "tier": "pro",
            }
        )
        assert isinstance(result, CanonRecord)
        assert result.name == "Canonical Test Org"

    def test_get_organization_by_id(self, canonical_store: OrganizationStore) -> None:
        created = canonical_store.create_organization(
            {
                "name": "Get Org",
                "slug": "get-org",
                "owner_id": "user-get-01",
                "status": "active",
                "tier": "free",
            }
        )
        fetched = canonical_store.get_organization(created.organizationid)
        assert fetched is not None
        assert fetched.organizationid == created.organizationid

    def test_get_organization_missing_returns_none(self, canonical_store: OrganizationStore) -> None:
        result = canonical_store.get_organization("org-not-found-xyz")
        assert result is None

    def test_get_by_slug_returns_record(self, canonical_store: OrganizationStore) -> None:
        canonical_store.create_organization(
            {
                "name": "Slug Org",
                "slug": "unique-slug-test",
                "owner_id": "user-slug-01",
                "status": "active",
                "tier": "standard",
            }
        )
        result = canonical_store.get_by_slug("unique-slug-test")
        assert result is not None
        assert result.slug == "unique-slug-test"

    def test_get_by_slug_missing_returns_none(self, canonical_store: OrganizationStore) -> None:
        result = canonical_store.get_by_slug("slug-not-found-xyz")
        assert result is None

    def test_list_organizations_returns_list(self, canonical_store: OrganizationStore) -> None:
        result = canonical_store.list_organizations()
        assert isinstance(result, list)

    def test_list_organizations_filter_by_status(self, canonical_store: OrganizationStore) -> None:
        canonical_store.create_organization(
            {
                "name": "Active List Org",
                "slug": "active-list-org",
                "owner_id": "user-list-01",
                "status": "active",
                "tier": "pro",
            }
        )
        results = canonical_store.list_organizations(status="active")
        for r in results:
            assert r.status == "active"

    def test_update_organization_changes_status(self, canonical_store: OrganizationStore) -> None:
        created = canonical_store.create_organization(
            {
                "name": "Update Org",
                "slug": "update-org",
                "owner_id": "user-upd-01",
                "status": "trialing",
                "tier": "free",
            }
        )
        updated = canonical_store.update_organization(created.organizationid, {"status": "active"})
        assert updated is not None
        assert updated.status == "active"

    def test_update_organization_missing_returns_none(self, canonical_store: OrganizationStore) -> None:
        result = canonical_store.update_organization("org-ghost-xyz", {"status": "active"})
        assert result is None

    def test_activate_sets_status_active(self, canonical_store: OrganizationStore) -> None:
        created = canonical_store.create_organization(
            {
                "name": "Activate Org",
                "slug": "activate-org",
                "owner_id": "user-act-01",
                "status": "trialing",
                "tier": "free",
            }
        )
        result = canonical_store.activate(created.organizationid)
        assert result is not None
        assert result.status == "active"

    def test_suspend_sets_status_suspended(self, canonical_store: OrganizationStore) -> None:
        created = canonical_store.create_organization(
            {
                "name": "Suspend Org",
                "slug": "suspend-org",
                "owner_id": "user-sus-01",
                "status": "active",
                "tier": "pro",
            }
        )
        result = canonical_store.suspend(created.organizationid)
        assert result is not None
        assert result.status == "suspended"

    def test_exists_returns_true_for_known_org(self, canonical_store: OrganizationStore) -> None:
        created = canonical_store.create_organization(
            {
                "name": "Exists Org",
                "slug": "exists-org",
                "owner_id": "user-ex-01",
                "status": "active",
                "tier": "free",
            }
        )
        assert canonical_store.exists(created.organizationid) is True

    def test_exists_returns_false_for_unknown_org(self, canonical_store: OrganizationStore) -> None:
        assert canonical_store.exists("org-not-here-xyz") is False

    def test_delete_organization_removes_record(self, canonical_store: OrganizationStore) -> None:
        created = canonical_store.create_organization(
            {
                "name": "Delete Org",
                "slug": "delete-org",
                "owner_id": "user-del-01",
                "status": "active",
                "tier": "free",
            }
        )
        canonical_store.delete_organization(created.organizationid)
        assert canonical_store.get_organization(created.organizationid) is None

    def test_to_dict_has_stable_keys(self, canonical_store: OrganizationStore) -> None:
        created = canonical_store.create_organization(
            {
                "name": "Dict Org",
                "slug": "dict-org",
                "owner_id": "user-dict-01",
                "status": "active",
                "tier": "standard",
            }
        )
        d = created.to_dict()
        expected_keys = {
            "organizationid",
            "name",
            "slug",
            "status",
            "createdat",
            "updatedat",
            "owneremail",
            "tier",
            "plan",
            "metadata",
        }
        assert expected_keys == set(d.keys())

    def test_summarize_returns_totals(self, canonical_store: OrganizationStore) -> None:
        canonical_store.create_organization(
            {
                "name": "Summary Org",
                "slug": "summary-org",
                "owner_id": "user-sum-01",
                "status": "active",
                "tier": "pro",
            }
        )
        summary = canonical_store.summarize()
        assert "total_organizations" in summary
        assert "by_status" in summary
        assert "by_tier" in summary
        assert isinstance(summary["total_organizations"], int)

    def test_upsert_creates_when_not_exists(self, canonical_store: OrganizationStore) -> None:
        result = canonical_store.upsert_organization(
            {
                "name": "Upsert New Org",
                "slug": "upsert-new-org",
                "owner_id": "user-ups-01",
                "status": "trialing",
                "tier": "free",
            }
        )
        assert result is not None
        assert result.name == "Upsert New Org"

    def test_create_alias_works(self, canonical_store: OrganizationStore) -> None:
        result = canonical_store.create(
            {
                "name": "Alias Org",
                "slug": "alias-org",
                "owner_id": "user-alias-01",
                "status": "active",
                "tier": "pro",
            }
        )
        assert result is not None
        assert result.name == "Alias Org"


# ===========================================================================
# Cross-layer: OrgStore output feeds back into canonical queries correctly
# ===========================================================================


class TestCrossLayerConsistency:
    def test_org_store_org_id_resolves_in_canonical_store(
        self,
        fresh_org_store: OrgStore,
        org_with_owner: OrganizationRecord,
    ) -> None:
        """OrgStore org_id must resolve cleanly in the canonical OrganizationStore."""
        canonical = get_organization_store()
        result = canonical.get_organization(org_with_owner.org_id)
        assert result is not None

    def test_to_dict_keys_stable_across_two_creates(self, fresh_org_store: OrgStore) -> None:
        r1 = fresh_org_store.create_org(
            name="Stable A",
            slug="stable-a",
            owner_user_id="user-sa-01",
            owner_email="sa@test.dev",
            owner_display_name="SA",
            plan_name="free",
        )
        r2 = fresh_org_store.create_org(
            name="Stable B",
            slug="stable-b",
            owner_user_id="user-sb-01",
            owner_email="sb@test.dev",
            owner_display_name="SB",
            plan_name="enterprise",
        )
        assert set(r1.to_dict().keys()) == set(r2.to_dict().keys())

    def test_member_to_dict_keys_stable_across_two_orgs(self, fresh_org_store: OrgStore) -> None:
        r1 = fresh_org_store.create_org(
            name="Key Org A",
            slug="key-org-a",
            owner_user_id="user-ka-01",
            owner_email="ka@test.dev",
            owner_display_name="KA",
            plan_name="free",
        )
        r2 = fresh_org_store.create_org(
            name="Key Org B",
            slug="key-org-b",
            owner_user_id="user-kb-01",
            owner_email="kb@test.dev",
            owner_display_name="KB",
            plan_name="pro",
        )
        keys_a = set(r1.members[0].to_dict().keys())
        keys_b = set(r2.members[0].to_dict().keys())
        assert keys_a == keys_b
