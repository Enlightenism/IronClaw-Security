from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from app.core.install_keys import (
    InstallKeyAlreadyExistsError,
    InstallKeyNotFoundError,
    InstallKeyRecord,
    InstallKeyRegistry,
    InstallKeyUsageError,
    _mask_key,
    _reset_install_key_registry_for_testing,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_OWNER = "user@ironclaw.test"
_SUB_ID = "sub-001"
_OPENCLAW_PREFIX = "ic_install_openclaw_"
_CLAUDE_PREFIX = "ic_install_claude_code_"


# ---------------------------------------------------------------------------
# Supabase stub factory
# ---------------------------------------------------------------------------


def _make_supabase_stub() -> MagicMock:
    """Return a MagicMock that mimics the chained Supabase fluent API."""
    stub = MagicMock()
    execute_result = MagicMock()
    execute_result.data = []
    chain = MagicMock()
    chain.execute.return_value = execute_result
    stub.table.return_value.select.return_value.execute.return_value = execute_result
    stub.table.return_value.insert.return_value.execute.return_value = execute_result
    stub.table.return_value.update.return_value.eq.return_value.execute.return_value = execute_result
    return stub


_PATCH_TARGET = "app.core.install_keys.get_supabase_service_client"


# ---------------------------------------------------------------------------
# TestMaskKey
# ---------------------------------------------------------------------------


class TestMaskKey(unittest.TestCase):
    """_mask_key — prefix and short-secret behaviour."""

    def test_openclaw_prefix_masked_shows_first_10_and_last_4(self):
        raw = _OPENCLAW_PREFIX + "abcdefghijklmnopqrstuvwxyz123456"
        masked = _mask_key(raw)
        assert masked.startswith(raw[:10])
        assert masked.endswith(raw[-4:])
        assert "..." in masked

    def test_claude_prefix_masked_shows_first_10_and_last_4(self):
        raw = _CLAUDE_PREFIX + "abcdefghijklmnopqrstuvwxyz123456"
        masked = _mask_key(raw)
        assert masked.startswith(raw[:10])
        assert masked.endswith(raw[-4:])
        assert "..." in masked

    def test_openclaw_prefix_masked_omits_middle_characters(self):
        raw = _OPENCLAW_PREFIX + "XXXXXXXSECRETXXXXXXX"
        masked = _mask_key(raw)
        assert "XXXXXXXSECRETXXXXXXX" not in masked

    def test_claude_prefix_masked_omits_middle_characters(self):
        raw = _CLAUDE_PREFIX + "XXXXXXXSECRETXXXXXXX"
        masked = _mask_key(raw)
        assert "XXXXXXXSECRETXXXXXXX" not in masked

    def test_short_key_returns_all_stars(self):
        # 12 chars or fewer → all stars
        short = "ic_short_k12"
        assert len(short) == 12
        masked = _mask_key(short)
        assert masked == "*" * len(short)

    def test_short_key_11_chars_returns_all_stars(self):
        short = "ic_short_k1"
        assert len(short) == 11
        masked = _mask_key(short)
        assert set(masked) == {"*"}

    def test_short_key_length_preserved(self):
        short = "abc"
        masked = _mask_key(short)
        assert len(masked) == len(short)

    def test_no_prefix_key_longer_than_12_shows_dots(self):
        raw = "noprefixlongkeyvalue1234"
        masked = _mask_key(raw)
        assert "..." in masked
        assert masked.startswith(raw[:10])
        assert masked.endswith(raw[-4:])


# ---------------------------------------------------------------------------
# TestInstallKeyRecordPostInit
# ---------------------------------------------------------------------------


class TestInstallKeyRecordPostInit(unittest.TestCase):
    """InstallKeyRecord.__post_init__ validation."""

    def _valid_record(self, **overrides) -> InstallKeyRecord:
        defaults = dict(
            key_id="ik_test001",
            owner_key=_OWNER,
            subscription_id=_SUB_ID,
            program="openclaw",
            raw_key=_OPENCLAW_PREFIX + "abc123",
            raw_key_hash="deadbeef" * 8,
            masked_key="ic_install...5678",
        )
        defaults.update(overrides)
        return InstallKeyRecord(**defaults)

    def test_valid_openclaw_program_does_not_raise(self):
        record = self._valid_record(program="openclaw")
        assert record.program == "openclaw"

    def test_valid_claude_code_program_does_not_raise(self):
        record = self._valid_record(program="claude_code")
        assert record.program == "claude_code"

    def test_invalid_program_raises_value_error(self):
        with self.assertRaises(ValueError):
            self._valid_record(program="gpt4")

    def test_invalid_program_message_contains_program_name(self):
        with self.assertRaises(ValueError) as ctx:
            self._valid_record(program="gpt4")
        assert "gpt4" in str(ctx.exception)

    def test_negative_units_consumed_raises_value_error(self):
        with self.assertRaises(ValueError):
            self._valid_record(units_consumed=-1)

    def test_zero_units_consumed_is_valid(self):
        record = self._valid_record(units_consumed=0)
        assert record.units_consumed == 0

    def test_positive_units_consumed_is_valid(self):
        record = self._valid_record(units_consumed=100)
        assert record.units_consumed == 100

    def test_empty_program_raises_value_error(self):
        with self.assertRaises(ValueError):
            self._valid_record(program="")

    def test_program_case_sensitive_uppercase_raises(self):
        with self.assertRaises(ValueError):
            self._valid_record(program="OpenClaw")


# ---------------------------------------------------------------------------
# TestInstallKeyRegistryGenerateInstallKey
# ---------------------------------------------------------------------------


class TestInstallKeyRegistryGenerateInstallKey(unittest.TestCase):
    def setUp(self):
        _reset_install_key_registry_for_testing()
        self._stub = _make_supabase_stub()
        self._patcher = patch(_PATCH_TARGET, return_value=self._stub)
        self._patcher.start()

    def tearDown(self):
        self._patcher.stop()
        _reset_install_key_registry_for_testing()

    def _registry(self) -> InstallKeyRegistry:
        reg = InstallKeyRegistry()
        reg._loaded = True
        return reg

    def test_openclaw_happy_path_returns_record(self):
        reg = self._registry()
        record = reg.generate_install_key(_OWNER, _SUB_ID, "openclaw")
        assert isinstance(record, InstallKeyRecord)

    def test_openclaw_happy_path_raw_key_has_correct_prefix(self):
        reg = self._registry()
        record = reg.generate_install_key(_OWNER, _SUB_ID, "openclaw")
        assert record.raw_key.startswith(_OPENCLAW_PREFIX)

    def test_openclaw_happy_path_active_true(self):
        reg = self._registry()
        record = reg.generate_install_key(_OWNER, _SUB_ID, "openclaw")
        assert record.active is True

    def test_openclaw_happy_path_units_consumed_zero(self):
        reg = self._registry()
        record = reg.generate_install_key(_OWNER, _SUB_ID, "openclaw")
        assert record.units_consumed == 0

    def test_openclaw_happy_path_program_correct(self):
        reg = self._registry()
        record = reg.generate_install_key(_OWNER, _SUB_ID, "openclaw")
        assert record.program == "openclaw"

    def test_claude_code_happy_path_raw_key_has_correct_prefix(self):
        reg = self._registry()
        record = reg.generate_install_key(_OWNER, _SUB_ID, "claude_code")
        assert record.raw_key.startswith(_CLAUDE_PREFIX)

    def test_claude_code_happy_path_program_correct(self):
        reg = self._registry()
        record = reg.generate_install_key(_OWNER, _SUB_ID, "claude_code")
        assert record.program == "claude_code"

    def test_claude_code_happy_path_returns_record(self):
        reg = self._registry()
        record = reg.generate_install_key(_OWNER, _SUB_ID, "claude_code")
        assert isinstance(record, InstallKeyRecord)

    def test_duplicate_active_key_raises_already_exists_error(self):
        reg = self._registry()
        reg.generate_install_key(_OWNER, _SUB_ID, "openclaw")
        with self.assertRaises(InstallKeyAlreadyExistsError):
            reg.generate_install_key(_OWNER, _SUB_ID, "openclaw")

    def test_duplicate_error_contains_owner_key(self):
        reg = self._registry()
        reg.generate_install_key(_OWNER, _SUB_ID, "openclaw")
        with self.assertRaises(InstallKeyAlreadyExistsError) as ctx:
            reg.generate_install_key(_OWNER, _SUB_ID, "openclaw")
        assert _OWNER in str(ctx.exception)

    def test_duplicate_error_contains_program(self):
        reg = self._registry()
        reg.generate_install_key(_OWNER, _SUB_ID, "openclaw")
        with self.assertRaises(InstallKeyAlreadyExistsError) as ctx:
            reg.generate_install_key(_OWNER, _SUB_ID, "openclaw")
        assert "openclaw" in str(ctx.exception)

    def test_different_programs_same_owner_does_not_raise(self):
        reg = self._registry()
        r1 = reg.generate_install_key(_OWNER, _SUB_ID, "openclaw")
        r2 = reg.generate_install_key(_OWNER, _SUB_ID, "claude_code")
        assert r1.program != r2.program

    def test_invalid_program_raises_value_error(self):
        reg = self._registry()
        with self.assertRaises(ValueError):
            reg.generate_install_key(_OWNER, _SUB_ID, "badprogram")  # type: ignore[arg-type]

    def test_supabase_insert_called_on_generate(self):
        reg = self._registry()
        reg.generate_install_key(_OWNER, _SUB_ID, "openclaw")
        self._stub.table.assert_called()

    def test_label_stored_on_record(self):
        reg = self._registry()
        record = reg.generate_install_key(_OWNER, _SUB_ID, "openclaw", label="prod-key")
        assert record.label == "prod-key"

    def test_metadata_stored_on_record(self):
        reg = self._registry()
        meta = {"env": "prod"}
        record = reg.generate_install_key(_OWNER, _SUB_ID, "openclaw", metadata=meta)
        assert record.metadata == meta


# ---------------------------------------------------------------------------
# TestAuthenticateInstallKey
# ---------------------------------------------------------------------------


class TestAuthenticateInstallKey(unittest.TestCase):
    def setUp(self):
        _reset_install_key_registry_for_testing()
        self._stub = _make_supabase_stub()
        self._patcher = patch(_PATCH_TARGET, return_value=self._stub)
        self._patcher.start()

    def tearDown(self):
        self._patcher.stop()
        _reset_install_key_registry_for_testing()

    def _registry_with_key(self, program="openclaw", active=True):
        reg = InstallKeyRegistry()
        reg._loaded = True
        record = reg.generate_install_key(_OWNER, _SUB_ID, program)
        raw_key = record.raw_key
        if not active:
            reg.revoke_key(record.key_id)
        return reg, raw_key

    def test_valid_active_key_returns_record(self):
        reg, raw_key = self._registry_with_key()
        result = reg.authenticate_install_key(raw_key)
        assert result is not None

    def test_valid_active_key_returns_correct_program(self):
        reg, raw_key = self._registry_with_key(program="openclaw")
        result = reg.authenticate_install_key(raw_key)
        assert result.program == "openclaw"

    def test_valid_active_key_updates_last_used_at(self):
        reg, raw_key = self._registry_with_key()
        result = reg.authenticate_install_key(raw_key)
        assert result.last_used_at is not None

    def test_inactive_key_returns_none(self):
        reg, raw_key = self._registry_with_key(active=False)
        result = reg.authenticate_install_key(raw_key)
        assert result is None

    def test_unknown_key_returns_none(self):
        reg, _ = self._registry_with_key()
        result = reg.authenticate_install_key("ic_install_openclaw_totallyfakekey12345")
        assert result is None

    def test_empty_string_key_returns_none(self):
        reg, _ = self._registry_with_key()
        result = reg.authenticate_install_key("")
        assert result is None

    def test_claude_code_active_key_returns_record(self):
        reg, raw_key = self._registry_with_key(program="claude_code")
        result = reg.authenticate_install_key(raw_key)
        assert result is not None
        assert result.program == "claude_code"

    def test_returned_record_raw_key_empty(self):
        reg, raw_key = self._registry_with_key()
        result = reg.authenticate_install_key(raw_key)
        assert result.raw_key == ""

    def test_supabase_update_called_on_auth(self):
        reg, raw_key = self._registry_with_key()
        reg.authenticate_install_key(raw_key)
        self._stub.table.assert_called()


# ---------------------------------------------------------------------------
# TestRevokeKey
# ---------------------------------------------------------------------------


class TestRevokeKey(unittest.TestCase):
    def setUp(self):
        _reset_install_key_registry_for_testing()
        self._stub = _make_supabase_stub()
        self._patcher = patch(_PATCH_TARGET, return_value=self._stub)
        self._patcher.start()

    def tearDown(self):
        self._patcher.stop()
        _reset_install_key_registry_for_testing()

    def _registry_with_key(self, program="openclaw"):
        reg = InstallKeyRegistry()
        reg._loaded = True
        record = reg.generate_install_key(_OWNER, _SUB_ID, program)
        return reg, record.key_id

    def test_active_key_revoked_returns_inactive(self):
        reg, key_id = self._registry_with_key()
        updated = reg.revoke_key(key_id)
        assert updated.active is False

    def test_active_key_revoked_persisted_in_registry(self):
        reg, key_id = self._registry_with_key()
        reg.revoke_key(key_id)
        record = reg.get_key_by_id(key_id)
        assert record.active is False

    def test_revoke_calls_supabase_update(self):
        reg, key_id = self._registry_with_key()
        reg.revoke_key(key_id)
        self._stub.table.assert_called()

    def test_idempotent_on_already_revoked(self):
        reg, key_id = self._registry_with_key()
        reg.revoke_key(key_id)
        updated = reg.revoke_key(key_id)
        assert updated.active is False

    def test_idempotent_second_revoke_returns_record(self):
        reg, key_id = self._registry_with_key()
        reg.revoke_key(key_id)
        result = reg.revoke_key(key_id)
        assert isinstance(result, InstallKeyRecord)

    def test_unknown_key_id_raises_not_found_error(self):
        reg, _ = self._registry_with_key()
        with self.assertRaises(InstallKeyNotFoundError):
            reg.revoke_key("ik_doesnotexist")

    def test_not_found_error_contains_key_id(self):
        reg, _ = self._registry_with_key()
        with self.assertRaises(InstallKeyNotFoundError) as ctx:
            reg.revoke_key("ik_doesnotexist")
        assert "ik_doesnotexist" in str(ctx.exception)

    def test_revoke_blocks_authenticate(self):
        reg = InstallKeyRegistry()
        reg._loaded = True
        record = reg.generate_install_key(_OWNER, _SUB_ID, "openclaw")
        raw_key = record.raw_key
        reg.revoke_key(record.key_id)
        assert reg.authenticate_install_key(raw_key) is None


# ---------------------------------------------------------------------------
# TestRecordKeyUsage
# ---------------------------------------------------------------------------


class TestRecordKeyUsage(unittest.TestCase):
    def setUp(self):
        _reset_install_key_registry_for_testing()
        self._stub = _make_supabase_stub()
        self._patcher = patch(_PATCH_TARGET, return_value=self._stub)
        self._patcher.start()

    def tearDown(self):
        self._patcher.stop()
        _reset_install_key_registry_for_testing()

    def _registry_with_key(self, program="openclaw", active=True):
        reg = InstallKeyRegistry()
        reg._loaded = True
        record = reg.generate_install_key(_OWNER, _SUB_ID, program)
        if not active:
            reg.revoke_key(record.key_id)
        return reg, record.key_id

    def test_increments_units_consumed_correctly(self):
        reg, key_id = self._registry_with_key()
        updated = reg.record_key_usage(key_id, units=5)
        assert updated.units_consumed == 5

    def test_multiple_increments_accumulate(self):
        reg, key_id = self._registry_with_key()
        reg.record_key_usage(key_id, units=3)
        updated = reg.record_key_usage(key_id, units=7)
        assert updated.units_consumed == 10

    def test_record_usage_updates_last_used_at(self):
        reg, key_id = self._registry_with_key()
        updated = reg.record_key_usage(key_id, units=1)
        assert updated.last_used_at is not None

    def test_supabase_update_called_on_usage(self):
        reg, key_id = self._registry_with_key()
        reg.record_key_usage(key_id, units=2)
        self._stub.table.assert_called()

    def test_inactive_key_raises_usage_error(self):
        reg, key_id = self._registry_with_key(active=False)
        with self.assertRaises(InstallKeyUsageError):
            reg.record_key_usage(key_id, units=1)

    def test_inactive_key_usage_error_contains_key_id(self):
        reg, key_id = self._registry_with_key(active=False)
        with self.assertRaises(InstallKeyUsageError) as ctx:
            reg.record_key_usage(key_id, units=1)
        assert key_id in str(ctx.exception)

    def test_zero_units_raises_usage_error(self):
        reg, key_id = self._registry_with_key()
        with self.assertRaises(InstallKeyUsageError):
            reg.record_key_usage(key_id, units=0)

    def test_negative_units_raises_usage_error(self):
        reg, key_id = self._registry_with_key()
        with self.assertRaises(InstallKeyUsageError):
            reg.record_key_usage(key_id, units=-5)

    def test_unknown_key_raises_not_found_error(self):
        reg, _ = self._registry_with_key()
        with self.assertRaises(InstallKeyNotFoundError):
            reg.record_key_usage("ik_unknown_xyz", units=1)

    def test_not_found_error_contains_key_id(self):
        reg, _ = self._registry_with_key()
        with self.assertRaises(InstallKeyNotFoundError) as ctx:
            reg.record_key_usage("ik_unknown_xyz", units=1)
        assert "ik_unknown_xyz" in str(ctx.exception)


# ---------------------------------------------------------------------------
# TestSummary
# ---------------------------------------------------------------------------


class TestSummary(unittest.TestCase):
    def setUp(self):
        _reset_install_key_registry_for_testing()
        self._stub = _make_supabase_stub()
        self._patcher = patch(_PATCH_TARGET, return_value=self._stub)
        self._patcher.start()

    def tearDown(self):
        self._patcher.stop()
        _reset_install_key_registry_for_testing()

    def _fresh_registry(self) -> InstallKeyRegistry:
        reg = InstallKeyRegistry()
        reg._loaded = True
        return reg

    def test_empty_registry_summary_all_zeros(self):
        reg = self._fresh_registry()
        s = reg.summary()
        assert s["total"] == 0
        assert s["active"] == 0
        assert s["revoked"] == 0
        assert s["openclaw_keys"] == 0
        assert s["claude_code_keys"] == 0

    def test_total_count_correct(self):
        reg = self._fresh_registry()
        reg.generate_install_key(_OWNER, _SUB_ID, "openclaw")
        reg.generate_install_key(_OWNER, _SUB_ID, "claude_code")
        s = reg.summary()
        assert s["total"] == 2

    def test_active_count_correct(self):
        reg = self._fresh_registry()
        r1 = reg.generate_install_key(_OWNER, _SUB_ID, "openclaw")
        reg.generate_install_key(_OWNER, _SUB_ID, "claude_code")
        reg.revoke_key(r1.key_id)
        s = reg.summary()
        assert s["active"] == 1

    def test_revoked_count_correct(self):
        reg = self._fresh_registry()
        r1 = reg.generate_install_key(_OWNER, _SUB_ID, "openclaw")
        reg.generate_install_key(_OWNER, _SUB_ID, "claude_code")
        reg.revoke_key(r1.key_id)
        s = reg.summary()
        assert s["revoked"] == 1

    def test_openclaw_keys_count(self):
        reg = self._fresh_registry()
        reg.generate_install_key(_OWNER, _SUB_ID, "openclaw")
        reg.generate_install_key("other@ironclaw.test", _SUB_ID, "openclaw")
        s = reg.summary()
        assert s["openclaw_keys"] == 2

    def test_claude_code_keys_count(self):
        reg = self._fresh_registry()
        reg.generate_install_key(_OWNER, _SUB_ID, "claude_code")
        s = reg.summary()
        assert s["claude_code_keys"] == 1

    def test_revoked_active_sum_equals_total(self):
        reg = self._fresh_registry()
        r1 = reg.generate_install_key(_OWNER, _SUB_ID, "openclaw")
        reg.generate_install_key(_OWNER, _SUB_ID, "claude_code")
        reg.revoke_key(r1.key_id)
        s = reg.summary()
        assert s["active"] + s["revoked"] == s["total"]

    def test_summary_keys_present(self):
        reg = self._fresh_registry()
        s = reg.summary()
        for key in ("total", "active", "revoked", "openclaw_keys", "claude_code_keys"):
            assert key in s
