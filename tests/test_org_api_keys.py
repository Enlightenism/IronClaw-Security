from __future__ import annotations

import pytest

from app.core.apikeys import (
    _API_KEY_PREFIX,
    _ORG_KEY_PREFIX,
    APIKeyRegistry,
    create_org_key,
    generate_org_api_key,
)

_ORG_ID_A = "org-alpha-001"
_ORG_ID_B = "org-beta-002"


@pytest.fixture()
def registry() -> APIKeyRegistry:
    """Fresh isolated registry per test — never touches the global singleton."""
    return APIKeyRegistry()


# ---------------------------------------------------------------------------
# generate_org_api_key — prefix
# ---------------------------------------------------------------------------


class TestGenerateOrgApiKey:
    def test_returns_ic_org_prefix(self):
        key = generate_org_api_key()
        assert key.startswith(_ORG_KEY_PREFIX)

    def test_returns_string(self):
        key = generate_org_api_key()
        assert isinstance(key, str)

    def test_two_calls_produce_unique_keys(self):
        assert generate_org_api_key() != generate_org_api_key()

    def test_prefix_is_longer_than_personal_prefix(self):
        assert len(_ORG_KEY_PREFIX) > len(_API_KEY_PREFIX)


# ---------------------------------------------------------------------------
# create_org_key — prefix, key_type, org_id binding
# ---------------------------------------------------------------------------


class TestCreateOrgKey:
    def test_api_key_uses_ic_org_prefix(self, registry: APIKeyRegistry):
        record = registry.create_key(
            "Org Alpha Key",
            key_type="org",
            org_id=_ORG_ID_A,
            prefix=_ORG_KEY_PREFIX,
        )
        assert record.api_key.startswith(_ORG_KEY_PREFIX)

    def test_key_type_is_org(self, registry: APIKeyRegistry):
        record = registry.create_key(
            "Org Alpha Key",
            key_type="org",
            org_id=_ORG_ID_A,
            prefix=_ORG_KEY_PREFIX,
        )
        assert record.key_type == "org"

    def test_org_id_is_bound_correctly(self, registry: APIKeyRegistry):
        record = registry.create_key(
            "Org Alpha Key",
            key_type="org",
            org_id=_ORG_ID_A,
            prefix=_ORG_KEY_PREFIX,
        )
        assert record.org_id == _ORG_ID_A

    def test_create_org_key_factory_uses_org_prefix(self):
        """create_org_key() module-level factory uses the global registry."""
        record = create_org_key(_ORG_ID_A, "Factory Org Key")
        assert record.api_key.startswith(_ORG_KEY_PREFIX)
        assert record.key_type == "org"
        assert record.org_id == _ORG_ID_A

    def test_create_org_key_factory_key_type_is_org(self):
        record = create_org_key(_ORG_ID_B, "Factory Org Key B")
        assert record.key_type == "org"

    def test_create_org_key_factory_org_id_bound(self):
        record = create_org_key(_ORG_ID_A, "Factory Org Key A2")
        assert record.org_id == _ORG_ID_A

    def test_two_org_keys_different_orgs_have_correct_org_ids(self, registry: APIKeyRegistry):
        rec_a = registry.create_key("Key A", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        rec_b = registry.create_key("Key B", key_type="org", org_id=_ORG_ID_B, prefix=_ORG_KEY_PREFIX)
        assert rec_a.org_id == _ORG_ID_A
        assert rec_b.org_id == _ORG_ID_B

    def test_org_key_is_active_by_default(self, registry: APIKeyRegistry):
        record = registry.create_key(
            "Active Org Key",
            key_type="org",
            org_id=_ORG_ID_A,
            prefix=_ORG_KEY_PREFIX,
        )
        assert record.active is True


# ---------------------------------------------------------------------------
# list_keys_by_org — isolation and correctness
# ---------------------------------------------------------------------------


class TestListKeysByOrg:
    def test_returns_only_keys_for_requested_org(self, registry: APIKeyRegistry):
        registry.create_key("A1", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        registry.create_key("A2", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        registry.create_key("B1", key_type="org", org_id=_ORG_ID_B, prefix=_ORG_KEY_PREFIX)
        result = registry.list_keys_by_org(_ORG_ID_A)
        assert len(result) == 2
        assert all(r.org_id == _ORG_ID_A for r in result)

    def test_does_not_return_other_org_keys(self, registry: APIKeyRegistry):
        registry.create_key("A1", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        registry.create_key("B1", key_type="org", org_id=_ORG_ID_B, prefix=_ORG_KEY_PREFIX)
        result = registry.list_keys_by_org(_ORG_ID_A)
        assert all(r.org_id != _ORG_ID_B for r in result)

    def test_does_not_return_personal_keys(self, registry: APIKeyRegistry):
        registry.create_key("Personal", key_type="personal", org_id=None)
        registry.create_key("Org Key", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        result = registry.list_keys_by_org(_ORG_ID_A)
        assert all(r.key_type == "org" for r in result)

    def test_empty_org_returns_empty_list(self, registry: APIKeyRegistry):
        registry.create_key("Org Key", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        result = registry.list_keys_by_org(_ORG_ID_B)
        assert result == []

    def test_active_only_filters_revoked_org_keys(self, registry: APIKeyRegistry):
        rec = registry.create_key("A1", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        registry.create_key("A2", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        registry.revoke_key(rec.key_id)
        result = registry.list_keys_by_org(_ORG_ID_A, active_only=True)
        assert len(result) == 1
        assert result[0].active is True

    def test_returns_all_including_revoked_when_active_only_false(self, registry: APIKeyRegistry):
        rec = registry.create_key("A1", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        registry.create_key("A2", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        registry.revoke_key(rec.key_id)
        result = registry.list_keys_by_org(_ORG_ID_A, active_only=False)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# public_dict() — key_type and org_id present
# ---------------------------------------------------------------------------


class TestPublicDict:
    def test_org_key_public_dict_contains_key_type(self, registry: APIKeyRegistry):
        record = registry.create_key("Org Key", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        d = record.public_dict()
        assert "key_type" in d

    def test_org_key_public_dict_key_type_is_org(self, registry: APIKeyRegistry):
        record = registry.create_key("Org Key", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        d = record.public_dict()
        assert d["key_type"] == "org"

    def test_org_key_public_dict_contains_org_id(self, registry: APIKeyRegistry):
        record = registry.create_key("Org Key", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        d = record.public_dict()
        assert "org_id" in d

    def test_org_key_public_dict_org_id_is_correct(self, registry: APIKeyRegistry):
        record = registry.create_key("Org Key", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        d = record.public_dict()
        assert d["org_id"] == _ORG_ID_A

    def test_personal_key_public_dict_contains_key_type(self, registry: APIKeyRegistry):
        record = registry.create_key("Personal Key", key_type="personal")
        d = record.public_dict()
        assert "key_type" in d

    def test_personal_key_public_dict_key_type_is_personal(self, registry: APIKeyRegistry):
        record = registry.create_key("Personal Key", key_type="personal")
        d = record.public_dict()
        assert d["key_type"] == "personal"

    def test_personal_key_public_dict_contains_org_id(self, registry: APIKeyRegistry):
        record = registry.create_key("Personal Key", key_type="personal")
        d = record.public_dict()
        assert "org_id" in d

    def test_personal_key_public_dict_org_id_is_none(self, registry: APIKeyRegistry):
        record = registry.create_key("Personal Key", key_type="personal")
        d = record.public_dict()
        assert d["org_id"] is None

    def test_backward_compat_personal_key_no_extra_fields_missing(self, registry: APIKeyRegistry):
        """Existing personal key public_dict() must still expose both new fields with safe defaults."""
        record = registry.create_key("Legacy Personal Key")
        d = record.public_dict()
        assert d.get("key_type") == "personal"
        assert d.get("org_id") is None

    def test_public_dict_does_not_expose_raw_api_key(self, registry: APIKeyRegistry):
        record = registry.create_key("Org Key", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        d = record.public_dict()
        assert "api_key" not in d

    def test_public_dict_exposes_masked_key(self, registry: APIKeyRegistry):
        record = registry.create_key("Org Key", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        d = record.public_dict()
        assert "masked_key" in d
        assert d["masked_key"] == record.masked_key


# ---------------------------------------------------------------------------
# authenticate — org key works normally
# ---------------------------------------------------------------------------


class TestAuthenticateOrgKey:
    def test_org_key_authenticate_returns_record(self, registry: APIKeyRegistry):
        record = registry.create_key("Org Key", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        result = registry.authenticate(record.api_key, touch=False)
        assert result is not None

    def test_org_key_authenticate_returns_correct_key_type(self, registry: APIKeyRegistry):
        record = registry.create_key("Org Key", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        result = registry.authenticate(record.api_key, touch=False)
        assert result is not None
        assert result.key_type == "org"

    def test_org_key_authenticate_returns_correct_org_id(self, registry: APIKeyRegistry):
        record = registry.create_key("Org Key", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        result = registry.authenticate(record.api_key, touch=False)
        assert result is not None
        assert result.org_id == _ORG_ID_A

    def test_org_key_authenticate_touch_true_updates_last_used_at(self, registry: APIKeyRegistry):
        record = registry.create_key("Org Key", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        assert record.last_used_at is None
        result = registry.authenticate(record.api_key, touch=True)
        assert result is not None
        assert result.last_used_at is not None

    def test_shared_org_key_authenticates_multiple_times(self, registry: APIKeyRegistry):
        record = registry.create_key("Shared Org Key", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        for _ in range(5):
            result = registry.authenticate(record.api_key, touch=False)
            assert result is not None
            assert result.key_type == "org"

    def test_revoked_org_key_authenticate_returns_none(self, registry: APIKeyRegistry):
        record = registry.create_key("Org Key", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        registry.revoke_key(record.key_id)
        result = registry.authenticate(record.api_key, touch=False)
        assert result is None

    def test_wrong_key_string_for_org_key_returns_none(self, registry: APIKeyRegistry):
        registry.create_key("Org Key", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        result = registry.authenticate("ic_org_completely_wrong_key", touch=False)
        assert result is None


# ---------------------------------------------------------------------------
# rotate_key — org key preserves ic_org_ prefix
# ---------------------------------------------------------------------------


class TestRotateOrgKey:
    def test_rotated_org_key_preserves_ic_org_prefix(self, registry: APIKeyRegistry):
        record = registry.create_key("Org Key", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        rotated = registry.rotate_key(record.key_id)
        assert rotated is not None
        assert rotated.api_key.startswith(_ORG_KEY_PREFIX)

    def test_rotated_org_key_preserves_key_type(self, registry: APIKeyRegistry):
        record = registry.create_key("Org Key", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        rotated = registry.rotate_key(record.key_id)
        assert rotated is not None
        assert rotated.key_type == "org"

    def test_rotated_org_key_preserves_org_id(self, registry: APIKeyRegistry):
        record = registry.create_key("Org Key", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        rotated = registry.rotate_key(record.key_id)
        assert rotated is not None
        assert rotated.org_id == _ORG_ID_A

    def test_rotated_org_key_is_different_secret(self, registry: APIKeyRegistry):
        record = registry.create_key("Org Key", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        rotated = registry.rotate_key(record.key_id)
        assert rotated is not None
        assert rotated.api_key != record.api_key

    def test_old_org_key_no_longer_authenticates_after_rotation(self, registry: APIKeyRegistry):
        record = registry.create_key("Org Key", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        old_secret = record.api_key
        registry.rotate_key(record.key_id)
        result = registry.authenticate(old_secret, touch=False)
        assert result is None

    def test_new_org_key_authenticates_after_rotation(self, registry: APIKeyRegistry):
        record = registry.create_key("Org Key", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        rotated = registry.rotate_key(record.key_id)
        assert rotated is not None
        result = registry.authenticate(rotated.api_key, touch=False)
        assert result is not None

    def test_personal_key_rotate_preserves_ic_prefix(self, registry: APIKeyRegistry):
        record = registry.create_key("Personal Key", key_type="personal")
        rotated = registry.rotate_key(record.key_id)
        assert rotated is not None
        assert rotated.api_key.startswith(_API_KEY_PREFIX)
        assert not rotated.api_key.startswith(_ORG_KEY_PREFIX)


# ---------------------------------------------------------------------------
# summary() — org_keys count
# ---------------------------------------------------------------------------


class TestSummaryOrgKeys:
    def test_summary_reports_zero_org_keys_for_empty_registry(self, registry: APIKeyRegistry):
        assert registry.summary()["org_keys"] == 0

    def test_summary_reports_zero_org_keys_when_only_personal(self, registry: APIKeyRegistry):
        registry.create_key("P1", key_type="personal")
        registry.create_key("P2", key_type="personal")
        assert registry.summary()["org_keys"] == 0

    def test_summary_reports_correct_org_key_count(self, registry: APIKeyRegistry):
        registry.create_key("Org1", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        registry.create_key("Org2", key_type="org", org_id=_ORG_ID_B, prefix=_ORG_KEY_PREFIX)
        assert registry.summary()["org_keys"] == 2

    def test_summary_org_keys_includes_revoked_org_keys(self, registry: APIKeyRegistry):
        rec = registry.create_key("Org1", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        registry.revoke_key(rec.key_id)
        assert registry.summary()["org_keys"] == 1

    def test_summary_total_includes_both_personal_and_org(self, registry: APIKeyRegistry):
        registry.create_key("P1", key_type="personal")
        registry.create_key("Org1", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        s = registry.summary()
        assert s["total"] == 2
        assert s["org_keys"] == 1

    def test_summary_active_excludes_revoked_keys(self, registry: APIKeyRegistry):
        rec = registry.create_key("Org1", key_type="org", org_id=_ORG_ID_A, prefix=_ORG_KEY_PREFIX)
        registry.create_key("Org2", key_type="org", org_id=_ORG_ID_B, prefix=_ORG_KEY_PREFIX)
        registry.revoke_key(rec.key_id)
        s = registry.summary()
        assert s["active"] == 1
        assert s["revoked"] == 1


# ---------------------------------------------------------------------------
# Personal keys — default key_type and org_id
# ---------------------------------------------------------------------------


class TestPersonalKeyDefaults:
    def test_personal_key_type_defaults_to_personal(self, registry: APIKeyRegistry):
        record = registry.create_key("My Key")
        assert record.key_type == "personal"

    def test_personal_key_org_id_defaults_to_none(self, registry: APIKeyRegistry):
        record = registry.create_key("My Key")
        assert record.org_id is None

    def test_explicit_personal_key_type_is_personal(self, registry: APIKeyRegistry):
        record = registry.create_key("My Key", key_type="personal")
        assert record.key_type == "personal"

    def test_personal_key_api_key_uses_ic_prefix_not_org(self, registry: APIKeyRegistry):
        record = registry.create_key("My Key", key_type="personal")
        assert record.api_key.startswith(_API_KEY_PREFIX)
        assert not record.api_key.startswith(_ORG_KEY_PREFIX)

    def test_personal_key_authenticate_succeeds(self, registry: APIKeyRegistry):
        record = registry.create_key("My Key", key_type="personal")
        result = registry.authenticate(record.api_key, touch=False)
        assert result is not None
        assert result.key_type == "personal"
        assert result.org_id is None
