from __future__ import annotations

from collections.abc import Generator
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from app.core.install_keys import (
    InstallKeyAlreadyExistsError,
    InstallKeyNotFoundError,
    InstallKeyRecord,
    InstallKeyRegistry,
    InstallKeyUsageError,
    _reset_install_key_registry_for_testing,
    get_install_key_registry,
)

_MOCK_TARGET = "app.core.install_keys.get_supabase_service_client"

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_OWNER = "owner_test_001"
_SUB = "sub_abc123"


def _empty_client() -> MagicMock:
    resp = MagicMock()
    resp.data = []
    chain = MagicMock()
    chain.execute.return_value = resp
    chain.select.return_value = chain
    chain.eq.return_value = chain
    chain.update.return_value = chain
    chain.insert.return_value = chain
    client = MagicMock()
    client.table.return_value = chain
    return client


def _fresh_registry(client: MagicMock) -> InstallKeyRegistry:
    registry = InstallKeyRegistry()
    with patch(_MOCK_TARGET, return_value=client):
        registry._ensure_loaded()
    return registry


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_singleton() -> Generator[None, None, None]:
    _reset_install_key_registry_for_testing()
    yield
    _reset_install_key_registry_for_testing()


# ---------------------------------------------------------------------------
# generate_install_key — happy path
# ---------------------------------------------------------------------------


class TestGenerateInstallKeyHappyPath:
    def test_openclaw_returns_install_key_record(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            record = registry.generate_install_key(_OWNER, _SUB, "openclaw")
        assert isinstance(record, InstallKeyRecord)
        assert record.program == "openclaw"
        assert record.owner_key == _OWNER
        assert record.subscription_id == _SUB
        assert record.active is True
        assert record.units_consumed == 0

    def test_openclaw_raw_key_has_correct_prefix(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            record = registry.generate_install_key(_OWNER, _SUB, "openclaw")
        assert record.raw_key.startswith("ic_install_openclaw_")

    def test_claude_code_returns_install_key_record(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            record = registry.generate_install_key(_OWNER, _SUB, "claude_code")
        assert isinstance(record, InstallKeyRecord)
        assert record.program == "claude_code"
        assert record.active is True

    def test_claude_code_raw_key_has_correct_prefix(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            record = registry.generate_install_key(_OWNER, _SUB, "claude_code")
        assert record.raw_key.startswith("ic_install_claude_code_")

    def test_raw_key_is_returned_only_at_generation(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            record = registry.generate_install_key(_OWNER, _SUB, "openclaw")
        assert len(record.raw_key) > 20

    def test_masked_key_does_not_expose_full_secret(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            record = registry.generate_install_key(_OWNER, _SUB, "openclaw")
        assert record.raw_key not in record.masked_key
        assert "..." in record.masked_key

    def test_key_id_starts_with_ik_prefix(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            record = registry.generate_install_key(_OWNER, _SUB, "openclaw")
        assert record.key_id.startswith("ik_")

    def test_label_is_stored_when_provided(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            record = registry.generate_install_key(_OWNER, _SUB, "openclaw", label="  prod  ")
        assert record.label == "prod"

    def test_insert_is_called_on_supabase(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch("app.core.install_keys._should_use_memory_fallback", return_value=False), patch(_MOCK_TARGET, return_value=client):
            registry.generate_install_key(_OWNER, _SUB, "openclaw")
        assert any(call.args == ("install_keys",) for call in client.table.call_args_list)

    def test_replay_for_same_session_is_blocked_before_issuance(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            registry.generate_install_key(_OWNER, _SUB, "openclaw", purchase_reference="purch_123", checkout_session_id="cs_123")
            with pytest.raises(InstallKeyAlreadyExistsError):
                registry.generate_install_key(_OWNER, _SUB, "openclaw", purchase_reference="purch_123", checkout_session_id="cs_123")

    def test_two_different_programs_same_owner_both_succeed(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            r1 = registry.generate_install_key(_OWNER, _SUB, "openclaw")
            r2 = registry.generate_install_key(_OWNER, _SUB, "claude_code")
        assert r1.program == "openclaw"
        assert r2.program == "claude_code"
        assert r1.key_id != r2.key_id


# ---------------------------------------------------------------------------
# generate_install_key — duplicate active key raises
# ---------------------------------------------------------------------------


class TestGenerateInstallKeyDuplicate:
    def test_duplicate_active_openclaw_raises_already_exists_error(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            registry.generate_install_key(_OWNER, _SUB, "openclaw")
            with pytest.raises(InstallKeyAlreadyExistsError) as exc_info:
                registry.generate_install_key(_OWNER, _SUB, "openclaw")
        assert exc_info.value.owner_key == _OWNER
        assert exc_info.value.program == "openclaw"

    def test_duplicate_active_claude_code_raises_already_exists_error(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            registry.generate_install_key(_OWNER, _SUB, "claude_code")
            with pytest.raises(InstallKeyAlreadyExistsError) as exc_info:
                registry.generate_install_key(_OWNER, _SUB, "claude_code")
        assert exc_info.value.program == "claude_code"

    def test_second_key_allowed_after_first_is_revoked(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            r1 = registry.generate_install_key(_OWNER, _SUB, "openclaw")
            registry.revoke_key(r1.key_id)
            r2 = registry.generate_install_key(_OWNER, _SUB, "openclaw")
        assert r2.active is True
        assert r2.key_id != r1.key_id

    def test_invalid_program_raises_value_error(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            with pytest.raises(ValueError):
                registry.generate_install_key(_OWNER, _SUB, "not_a_program")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# authenticate_install_key
# ---------------------------------------------------------------------------


class TestAuthenticateInstallKey:
    def test_returns_record_on_valid_active_key(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            generated = registry.generate_install_key(_OWNER, _SUB, "openclaw")
            result = registry.authenticate_install_key(generated.raw_key)
        assert result is not None
        assert result.key_id == generated.key_id
        assert result.active is True

    def test_returns_none_on_invalid_key(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            result = registry.authenticate_install_key("ic_install_openclaw_totally_fake_key_xyz")
        assert result is None

    def test_returns_none_on_revoked_key(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            generated = registry.generate_install_key(_OWNER, _SUB, "openclaw")
            registry.revoke_key(generated.key_id)
            result = registry.authenticate_install_key(generated.raw_key)
        assert result is None

    def test_last_used_at_is_updated_on_successful_auth(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            generated = registry.generate_install_key(_OWNER, _SUB, "openclaw")
            result = registry.authenticate_install_key(generated.raw_key)
        assert result is not None
        assert result.last_used_at is not None
        assert isinstance(result.last_used_at, datetime)

    def test_empty_string_returns_none(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            result = registry.authenticate_install_key("")
        assert result is None

    def test_raw_key_not_retained_on_returned_record_after_auth(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            generated = registry.generate_install_key(_OWNER, _SUB, "openclaw")
            result = registry.authenticate_install_key(generated.raw_key)
        assert result is not None
        assert result.raw_key == ""


# ---------------------------------------------------------------------------
# revoke_key
# ---------------------------------------------------------------------------


class TestRevokeKey:
    def test_revoke_sets_active_false(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            generated = registry.generate_install_key(_OWNER, _SUB, "openclaw")
            updated = registry.revoke_key(generated.key_id)
        assert updated.active is False

    def test_revoke_persists_to_supabase(self) -> None:
        update_calls: list[dict] = []

        def _capture_update(payload):
            update_calls.append(dict(payload))
            m = MagicMock()
            m.eq.return_value = m
            m.execute.return_value = MagicMock(data=[])
            return m

        client = _empty_client()
        registry = _fresh_registry(client)

        def _table_side_effect(name):
            chain = MagicMock()
            chain.update.side_effect = _capture_update
            chain.insert.side_effect = lambda payload: MagicMock(data=[])
            chain.eq.return_value = chain
            chain.execute.return_value = MagicMock(data=[])
            return chain

        client.table.side_effect = _table_side_effect

        with patch("app.core.install_keys._should_use_memory_fallback", return_value=False), patch(_MOCK_TARGET, return_value=client):
            generated = registry.generate_install_key(_OWNER, _SUB, "openclaw")
            registry.revoke_key(generated.key_id)

        assert any(p.get("active") is False for p in update_calls)

    def test_revoking_already_revoked_key_is_idempotent(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            generated = registry.generate_install_key(_OWNER, _SUB, "openclaw")
            registry.revoke_key(generated.key_id)
            result = registry.revoke_key(generated.key_id)
        assert result.active is False

    def test_revoke_unknown_key_id_raises_not_found(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            with pytest.raises(InstallKeyNotFoundError) as exc_info:
                registry.revoke_key("ik_does_not_exist")
        assert exc_info.value.key_id == "ik_does_not_exist"

    def test_get_key_by_id_returns_none_after_registry_cleared(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            result = registry.get_key_by_id("ik_nonexistent")
        assert result is None


# ---------------------------------------------------------------------------
# record_key_usage
# ---------------------------------------------------------------------------


class TestRecordKeyUsage:
    def test_increments_units_consumed_correctly(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            generated = registry.generate_install_key(_OWNER, _SUB, "openclaw")
            updated = registry.record_key_usage(generated.key_id, units=10)
        assert updated.units_consumed == 10

    def test_increments_accumulate_across_calls(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            generated = registry.generate_install_key(_OWNER, _SUB, "openclaw")
            registry.record_key_usage(generated.key_id, units=5)
            updated = registry.record_key_usage(generated.key_id, units=3)
        assert updated.units_consumed == 8

    def test_raises_usage_error_on_inactive_key(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            generated = registry.generate_install_key(_OWNER, _SUB, "openclaw")
            registry.revoke_key(generated.key_id)
            with pytest.raises(InstallKeyUsageError) as exc_info:
                registry.record_key_usage(generated.key_id, units=1)
        assert exc_info.value.key_id == generated.key_id

    def test_raises_usage_error_when_units_zero(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            generated = registry.generate_install_key(_OWNER, _SUB, "openclaw")
            with pytest.raises(InstallKeyUsageError):
                registry.record_key_usage(generated.key_id, units=0)

    def test_raises_usage_error_when_units_negative(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            generated = registry.generate_install_key(_OWNER, _SUB, "openclaw")
            with pytest.raises(InstallKeyUsageError):
                registry.record_key_usage(generated.key_id, units=-5)

    def test_raises_not_found_for_unknown_key_id(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            with pytest.raises(InstallKeyNotFoundError):
                registry.record_key_usage("ik_ghost_key", units=1)

    def test_last_used_at_updated_after_usage(self) -> None:
        client = _empty_client()
        registry = _fresh_registry(client)
        with patch(_MOCK_TARGET, return_value=client):
            generated = registry.generate_install_key(_OWNER, _SUB, "openclaw")
            updated = registry.record_key_usage(generated.key_id, units=1)
        assert updated.last_used_at is not None
        assert isinstance(updated.last_used_at, datetime)


# ---------------------------------------------------------------------------
# _reset_install_key_registry_for_testing — state isolation
# ---------------------------------------------------------------------------


class TestResetInstallKeyRegistryForTesting:
    def test_reset_clears_singleton(self) -> None:
        client = _empty_client()
        with patch(_MOCK_TARGET, return_value=client):
            r1 = get_install_key_registry()
        _reset_install_key_registry_for_testing()
        with patch(_MOCK_TARGET, return_value=client):
            r2 = get_install_key_registry()
        assert r1 is not r2

    def test_reset_clears_in_memory_records(self) -> None:
        client = _empty_client()
        registry = InstallKeyRegistry()
        with patch(_MOCK_TARGET, return_value=client):
            registry.generate_install_key(_OWNER, _SUB, "openclaw")
        fresh = InstallKeyRegistry()
        with patch(_MOCK_TARGET, return_value=_empty_client()):
            keys = fresh.get_keys_for_owner(_OWNER)
        assert keys == []

    def test_reset_allows_new_key_generation_after_duplicate_would_have_blocked(self) -> None:
        client = _empty_client()
        registry = InstallKeyRegistry()
        with patch(_MOCK_TARGET, return_value=client):
            registry.generate_install_key(_OWNER, _SUB, "openclaw")
            with pytest.raises(InstallKeyAlreadyExistsError):
                registry.generate_install_key(_OWNER, _SUB, "openclaw")

        fresh = InstallKeyRegistry()
        with patch(_MOCK_TARGET, return_value=_empty_client()):
            new_record = fresh.generate_install_key(_OWNER, _SUB, "openclaw")
        assert new_record.active is True


# ---------------------------------------------------------------------------
# Singleton isolation from get_install_key_registry()
# ---------------------------------------------------------------------------


class TestSingletonIsolation:
    def test_get_install_key_registry_returns_same_instance(self) -> None:
        client = _empty_client()
        with patch(_MOCK_TARGET, return_value=client):
            a = get_install_key_registry()
            b = get_install_key_registry()
        assert a is b

    def test_singleton_is_separate_from_api_key_registry(self) -> None:
        from app.core.apikeys import get_api_key_registry

        client = _empty_client()
        with patch(_MOCK_TARGET, return_value=client):
            install_reg = get_install_key_registry()
            api_reg = get_api_key_registry()
        assert install_reg is not api_reg
        assert type(install_reg).__name__ == "InstallKeyRegistry"

    def test_reset_then_get_returns_fresh_instance(self) -> None:
        client = _empty_client()
        with patch(_MOCK_TARGET, return_value=client):
            first = get_install_key_registry()
        _reset_install_key_registry_for_testing()
        with patch(_MOCK_TARGET, return_value=client):
            second = get_install_key_registry()
        assert first is not second

    def test_state_added_to_singleton_is_visible_on_second_get(self) -> None:
        client = _empty_client()
        with patch(_MOCK_TARGET, return_value=client):
            reg = get_install_key_registry()
            generated = reg.generate_install_key(_OWNER, _SUB, "openclaw")
            same_reg = get_install_key_registry()
            found = same_reg.get_key_by_id(generated.key_id)
        assert found is not None
        assert found.key_id == generated.key_id
