from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from app.core.install_keys import (
    InstallKeyAlreadyExistsError,
    InstallKeyNotFoundError,
    InstallKeyPaymentRequiredError,
    InstallKeyRecord,
    InstallKeyRegistry,
    InstallKeyUsageError,
    _mask_key,
    _reset_install_key_registry_for_testing,
)
from app.core.unit_wallet import get_unit_wallet_registry

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


_OWNER = "user@ironclaw.test"
_SUB_ID = "sub-001"
_OPENCLAW_PREFIX = "ic_install_openclaw_"
_CLAUDE_PREFIX = "ic_install_claude_code_"
_CURSOR_PREFIX = "ic_install_cursor_"
_GOOSE_PREFIX = "ic_install_goose_"
_GEMINI_PREFIX = "ic_install_gemini_cli_"
_COPILOT_PREFIX = "ic_install_copilot_"
_HERMES_PREFIX = "ic_install_hermes_"
_SKILLS_PREFIX = "ic_install_security_guardian_"
_CHECKOUT_SESSION_ID = "cs_test_001"
_PURCHASE_REFERENCE = "sub_001"


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

    def test_runtime_family_keys_mask_middle_secret_without_exposing_full_value(self):
        raw_keys = (
            _CURSOR_PREFIX + "cursor_secret_value_123",
            _GOOSE_PREFIX + "goose_secret_value_123",
            _GEMINI_PREFIX + "gemini_secret_value_123",
            _COPILOT_PREFIX + "copilot_secret_value_123",
            _HERMES_PREFIX + "hermes_secret_value_123",
            _SKILLS_PREFIX + "security_guardian_secret_123",
        )

        for raw in raw_keys:
            prefix = next(item for item in (_CURSOR_PREFIX, _GOOSE_PREFIX, _GEMINI_PREFIX, _COPILOT_PREFIX, _HERMES_PREFIX, _SKILLS_PREFIX) if raw.startswith(item))
            secret = raw[len(prefix) :]
            masked = _mask_key(raw)
            assert masked.startswith(prefix)
            assert masked.endswith(secret[-4:])
            assert "..." in masked
            assert secret not in masked
            assert raw not in masked


# ---------------------------------------------------------------------------
# TestInstallKeyRecordPostInit
# ---------------------------------------------------------------------------


class TestInstallKeyRecordPostInit(unittest.TestCase):
    """InstallKeyRecord.__post_init__ validation."""

    def _valid_record(self, **overrides) -> InstallKeyRecord:
        program = overrides.get("program", "openclaw")
        normalized_program = program.replace(" ", "_").replace("-", "_").lower()
        if normalized_program == "open_claw":
            normalized_program = "openclaw"
        if normalized_program == "cursor_agent":
            normalized_program = "cursor"
        if normalized_program == "goose_agent":
            normalized_program = "goose"
        if normalized_program == "gemini_cli":
            normalized_program = "gemini_cli"
        if normalized_program == "github_copilot":
            normalized_program = "copilot"
        if normalized_program == "security_guardian":
            normalized_program = "security_guardian"
        if normalized_program == "hermes_agent":
            normalized_program = "hermes"

        prefix_map = {
            "openclaw": _OPENCLAW_PREFIX,
            "claude_code": _CLAUDE_PREFIX,
            "cursor": _CURSOR_PREFIX,
            "goose": _GOOSE_PREFIX,
            "gemini_cli": _GEMINI_PREFIX,
            "copilot": _COPILOT_PREFIX,
            "hermes": _HERMES_PREFIX,
            "security_guardian": _SKILLS_PREFIX,
        }

        defaults = dict(
            key_id="ik_test001",
            owner_key=_OWNER,
            subscription_id=_SUB_ID,
            program="openclaw",
            raw_key=(prefix_map.get(normalized_program, _OPENCLAW_PREFIX) + "abc123"),
            raw_key_hash="deadbeef" * 8,
            masked_key="ic_install...5678",
        )
        defaults.update(overrides)
        if "program" in overrides:
            program_value = overrides["program"]
            canonical = program_value.replace(" ", "_").replace("-", "_").lower()
            if canonical == "open_claw":
                canonical = "openclaw"
            if canonical == "cursor_agent":
                canonical = "cursor"
            if canonical == "goose_agent":
                canonical = "goose"
            if canonical == "github_copilot":
                canonical = "copilot"
            if canonical == "hermes_agent":
                canonical = "hermes"
            defaults["raw_key"] = prefix_map.get(canonical, _OPENCLAW_PREFIX) + "abc123"
        return InstallKeyRecord(**defaults)

    def test_valid_openclaw_program_does_not_raise(self):
        record = self._valid_record(program="openclaw")
        assert record.program == "openclaw"

    def test_valid_claude_code_program_does_not_raise(self):
        record = self._valid_record(program="claude_code")
        assert record.program == "claude_code"

    def test_valid_alias_programs_normalize_to_canonical_names(self):
        alias_map = {
            "cursor": "cursor",
            "cursor-agent": "cursor",
            "goose": "goose",
            "goose-agent": "goose",
            "gemini-cli": "gemini_cli",
            "github-copilot": "copilot",
            "security-guardian": "security_guardian",
            "hermes-agent": "hermes",
        }

        for alias, canonical in alias_map.items():
            record = InstallKeyRecord(**{**self._valid_record(program=alias).__dict__, "program": alias})
            assert record.program == canonical

    def test_active_record_requires_paid_payment_status(self):
        with self.assertRaises(ValueError):
            self._valid_record(active=True, payment_status="pending", entitlements_status="active", issued_after_payment=True)

    def test_active_record_requires_active_entitlement_status(self):
        with self.assertRaises(ValueError):
            self._valid_record(active=True, payment_status="paid", entitlements_status="not_active", issued_after_payment=True)

    def test_invalid_program_raises_value_error(self):
        for bad_program in ("gpt4", "not_a_supported_family", "security_guardian_cli"):
            with self.assertRaises(ValueError):
                self._valid_record(program=bad_program)

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

    def test_program_case_insensitive_aliases_normalize(self):
        record = self._valid_record(program="OpenClaw")
        assert record.program == "openclaw"
        gemini = self._valid_record(program="GEMINI-CLI")
        assert gemini.program == "gemini_cli"


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

    def _generate_paid_key(self, reg: InstallKeyRegistry, program: str) -> InstallKeyRecord:
        return reg.generate_for_paid_customer(
            owner_key=_OWNER,
            subscription_id=_SUB_ID,
            program=program,
            payment_status="paid",
            entitlements_status="active",
            issued_after_payment=True,
            checkout_session_id=_CHECKOUT_SESSION_ID,
            purchase_reference=_PURCHASE_REFERENCE,
        )

    def test_openclaw_happy_path_returns_record(self):
        reg = self._registry()
        record = self._generate_paid_key(reg, "openclaw")
        assert isinstance(record, InstallKeyRecord)

    def test_openclaw_happy_path_raw_key_has_correct_prefix(self):
        reg = self._registry()
        record = self._generate_paid_key(reg, "openclaw")
        assert record.raw_key.startswith(_OPENCLAW_PREFIX)

    def test_openclaw_happy_path_active_true(self):
        reg = self._registry()
        record = self._generate_paid_key(reg, "openclaw")
        assert record.active is True

    def test_openclaw_happy_path_units_consumed_zero(self):
        reg = self._registry()
        record = self._generate_paid_key(reg, "openclaw")
        assert record.units_consumed == 0

    def test_openclaw_happy_path_program_correct(self):
        reg = self._registry()
        record = self._generate_paid_key(reg, "openclaw")
        assert record.program == "openclaw"

    def test_claude_code_happy_path_raw_key_has_correct_prefix(self):
        reg = self._registry()
        record = self._generate_paid_key(reg, "claude_code")
        assert record.raw_key.startswith(_CLAUDE_PREFIX)

    def test_claude_code_happy_path_program_correct(self):
        reg = self._registry()
        record = self._generate_paid_key(reg, "claude_code")
        assert record.program == "claude_code"

    def test_claude_code_happy_path_returns_record(self):
        reg = self._registry()
        record = self._generate_paid_key(reg, "claude_code")
        assert isinstance(record, InstallKeyRecord)

    def test_multi_platform_aliases_generate_canonical_keys(self):
        reg = self._registry()
        for program in ("cursor", "goose", "gemini-cli", "github-copilot", "hermes"):
            record = reg.generate_for_paid_customer(
                owner_key=_OWNER,
                subscription_id=_SUB_ID,
                program=program,
                payment_status="paid",
                entitlements_status="active",
                issued_after_payment=True,
                checkout_session_id=_CHECKOUT_SESSION_ID,
                purchase_reference=_PURCHASE_REFERENCE,
            )
            assert record.program in {"cursor", "goose", "gemini_cli", "copilot", "hermes"}
            assert record.raw_key.startswith(
                (
                    _CURSOR_PREFIX,
                    _GOOSE_PREFIX,
                    _GEMINI_PREFIX,
                    _COPILOT_PREFIX,
                    _HERMES_PREFIX,
                )
            )

    def test_security_guardian_connector_is_rejected_from_runtime_key_issuance(self):
        reg = self._registry()
        for program in ("security_guardian", "security-guardian", "securityguardian", "skill"):
            with self.assertRaises(ValueError):
                reg.generate_for_paid_customer(
                    owner_key=_OWNER,
                    subscription_id=_SUB_ID,
                    program=program,
                    payment_status="paid",
                    entitlements_status="active",
                    issued_after_payment=True,
                    checkout_session_id=_CHECKOUT_SESSION_ID,
                    purchase_reference=_PURCHASE_REFERENCE,
                )

    def test_runtime_family_aliases_require_paid_entitlement_before_generation(self):
        reg = self._registry()
        for program in ("cursor", "goose", "gemini-cli", "github-copilot", "hermes"):
            with self.assertRaises(InstallKeyPaymentRequiredError):
                reg.generate_for_paid_customer(
                    owner_key=_OWNER,
                    subscription_id=_SUB_ID,
                    program=program,
                    payment_status="pending",
                    entitlements_status="active",
                    issued_after_payment=True,
                    checkout_session_id=_CHECKOUT_SESSION_ID,
                    purchase_reference=_PURCHASE_REFERENCE,
                )

    def test_legacy_generate_install_key_uses_subscription_reference_when_missing(self):
        reg = self._registry()
        record = reg.generate_install_key(
            owner_key=_OWNER,
            subscription_id=_SUB_ID,
            program="openclaw",
        )
        assert record.purchase_reference == _SUB_ID
        assert record.checkout_session_id == _SUB_ID
        assert record.payment_status == "paid"
        assert record.entitlements_status == "active"

    def test_legacy_generate_install_key_rejects_unpaid_status(self):
        reg = self._registry()
        with self.assertRaises(InstallKeyPaymentRequiredError):
            reg.generate_install_key(
                owner_key=_OWNER,
                subscription_id=_SUB_ID,
                program="openclaw",
                payment_status="pending",
                entitlements_status="active",
                issued_after_payment=True,
            )

    def test_duplicate_active_key_raises_already_exists_error(self):
        reg = self._registry()
        self._generate_paid_key(reg, "openclaw")
        with self.assertRaises(InstallKeyAlreadyExistsError):
            self._generate_paid_key(reg, "openclaw")

    def test_duplicate_paid_entitlement_record_raises_already_exists_error(self):
        reg = self._registry()
        record = reg.generate_for_paid_customer(
            owner_key="ic_org_org_42",
            subscription_id=_SUB_ID,
            program="openclaw",
            payment_status="paid",
            entitlements_status="active",
            issued_after_payment=True,
            checkout_session_id=_CHECKOUT_SESSION_ID,
            purchase_reference=_PURCHASE_REFERENCE,
            org_id="Org_42",
        )
        reg._records_by_id[record.key_id] = record
        with self.assertRaises(InstallKeyAlreadyExistsError):
            reg.generate_for_paid_customer(
                owner_key="  IC_ORG_ORG_42  ",
                subscription_id="sub-duplicate",
                program="openclaw",
                payment_status="paid",
                entitlements_status="active",
                issued_after_payment=True,
                checkout_session_id="cs_dup_001",
                purchase_reference="purchase_dup_001",
                org_id="Org_42",
            )

    def test_duplicate_error_contains_owner_key(self):
        reg = self._registry()
        self._generate_paid_key(reg, "openclaw")
        with self.assertRaises(InstallKeyAlreadyExistsError) as ctx:
            self._generate_paid_key(reg, "openclaw")
        assert _OWNER in str(ctx.exception)

    def test_duplicate_error_contains_program(self):
        reg = self._registry()
        self._generate_paid_key(reg, "openclaw")
        with self.assertRaises(InstallKeyAlreadyExistsError) as ctx:
            self._generate_paid_key(reg, "openclaw")
        assert "openclaw" in str(ctx.exception)

    def test_owner_key_is_canonicalized_for_lookup_and_storage(self):
        reg = self._registry()
        record = reg.generate_for_paid_customer(
            owner_key=" Buyer@IronClaw.Test ",
            subscription_id=_SUB_ID,
            program="openclaw",
            payment_status="paid",
            entitlements_status="active",
            issued_after_payment=True,
            checkout_session_id=_CHECKOUT_SESSION_ID,
            purchase_reference=_PURCHASE_REFERENCE,
        )
        assert record.owner_key == "buyer@ironclaw.test"
        assert len(reg.get_keys_for_owner("BUYER@IRONCLAW.TEST")) == 1

    def test_generate_for_paid_customer_rejects_generic_platform_auth_owner(self):
        reg = self._registry()
        for bad_owner in ("ghp_secret123", "ghu_secret123", "github_pat_abc123", "sk_live_abc123", "xoxb-abc123", "platform_api_key", "system_api_key"):
            with self.assertRaises(ValueError):
                reg.generate_for_paid_customer(
                    owner_key=bad_owner,
                    subscription_id=_SUB_ID,
                    program="openclaw",
                    payment_status="paid",
                    entitlements_status="active",
                    issued_after_payment=True,
                    checkout_session_id=_CHECKOUT_SESSION_ID,
                    purchase_reference=_PURCHASE_REFERENCE,
                )

    def test_raw_key_prefix_must_match_program(self):
        with self.assertRaises(ValueError):
            InstallKeyRecord(
                key_id="ik_program_prefix_mismatch",
                owner_key=_OWNER,
                subscription_id=_SUB_ID,
                program="cursor",
                raw_key=_OPENCLAW_PREFIX + "abc123",
                raw_key_hash="deadbeef" * 8,
                masked_key="ic_install...5678",
                active=True,
                payment_status="paid",
                entitlements_status="active",
                issued_after_payment=True,
            )

    def test_generate_for_paid_customer_requires_org_owner_to_match_org_id(self):
        reg = self._registry()
        with self.assertRaises(ValueError):
            reg.generate_for_paid_customer(
                owner_key="ic_org_org_42",
                subscription_id=_SUB_ID,
                program="openclaw",
                org_id="org_99",
                payment_status="paid",
                entitlements_status="active",
                issued_after_payment=True,
                checkout_session_id=_CHECKOUT_SESSION_ID,
                purchase_reference=_PURCHASE_REFERENCE,
            )

    def test_record_normalizes_owner_key_to_canonical_value(self):
        record = InstallKeyRecord(
            key_id="ik_test_owner_normalize",
            owner_key="  Buyer@IronClaw.Test  ",
            subscription_id=_SUB_ID,
            program="openclaw",
            raw_key=_OPENCLAW_PREFIX + "abc123",
            raw_key_hash="deadbeef" * 8,
            masked_key="ic_install...5678",
            active=True,
            payment_status="paid",
            entitlements_status="active",
            issued_after_payment=True,
        )
        assert record.owner_key == "buyer@ironclaw.test"

    def test_active_record_rejects_generic_platform_auth_owner(self):
        with self.assertRaises(ValueError):
            InstallKeyRecord(
                key_id="ik_generic_owner",
                owner_key="ghp_secret123",
                subscription_id=_SUB_ID,
                program="openclaw",
                raw_key=_OPENCLAW_PREFIX + "abc123",
                raw_key_hash="deadbeef" * 8,
                masked_key="ic_install...5678",
                active=True,
                payment_status="paid",
                entitlements_status="active",
                issued_after_payment=True,
            )

    def test_org_scoped_owner_matches_org_id(self):
        with self.assertRaises(ValueError):
            InstallKeyRecord(
                key_id="ik_org_mismatch",
                owner_key="ic_org_org_42",
                org_id="org_99",
                subscription_id=_SUB_ID,
                program="openclaw",
                raw_key=_OPENCLAW_PREFIX + "abc123",
                raw_key_hash="deadbeef" * 8,
                masked_key="ic_install...5678",
                active=True,
                payment_status="paid",
                entitlements_status="active",
                issued_after_payment=True,
            )

    def test_different_programs_same_owner_does_not_raise(self):
        reg = self._registry()
        r1 = self._generate_paid_key(reg, "openclaw")
        r2 = self._generate_paid_key(reg, "claude_code")
        assert r1.program != r2.program

    def test_key_locks_when_owner_wallet_balance_is_zero(self):
        reg = self._registry()
        wallet = get_unit_wallet_registry()
        wallet.get_or_create_wallet(_OWNER).balance_units = 0
        record = self._generate_paid_key(reg, "openclaw")

        assert reg.get_key_by_id(record.key_id).active is False
        assert reg.authenticate_install_key(record.raw_key) is None

    def test_invalid_program_raises_value_error(self):
        reg = self._registry()
        with self.assertRaises(ValueError):
            reg.generate_for_paid_customer(
                owner_key=_OWNER,
                subscription_id=_SUB_ID,
                program="badprogram",  # type: ignore[arg-type]
                payment_status="paid",
                entitlements_status="active",
                issued_after_payment=True,
                checkout_session_id=_CHECKOUT_SESSION_ID,
                purchase_reference=_PURCHASE_REFERENCE,
            )

    def test_supabase_insert_called_on_generate(self):
        reg = self._registry()
        self._generate_paid_key(reg, "openclaw")
        self._stub.table.assert_called()

    def test_label_stored_on_record(self):
        reg = self._registry()
        record = reg.generate_for_paid_customer(
            owner_key=_OWNER,
            subscription_id=_SUB_ID,
            program="openclaw",
            payment_status="paid",
            entitlements_status="active",
            issued_after_payment=True,
            checkout_session_id=_CHECKOUT_SESSION_ID,
            purchase_reference=_PURCHASE_REFERENCE,
            label="prod-key",
        )
        assert record.label == "prod-key"

    def test_metadata_stored_on_record(self):
        reg = self._registry()
        meta = {"env": "prod"}
        record = reg.generate_for_paid_customer(
            owner_key=_OWNER,
            subscription_id=_SUB_ID,
            program="openclaw",
            payment_status="paid",
            entitlements_status="active",
            issued_after_payment=True,
            checkout_session_id=_CHECKOUT_SESSION_ID,
            purchase_reference=_PURCHASE_REFERENCE,
            metadata=meta,
        )
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
        record = reg.generate_for_paid_customer(
            owner_key=_OWNER,
            subscription_id=_SUB_ID,
            program=program,
            payment_status="paid",
            entitlements_status="active",
            issued_after_payment=True,
            checkout_session_id=_CHECKOUT_SESSION_ID,
            purchase_reference=_PURCHASE_REFERENCE,
        )
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
        record = reg.generate_for_paid_customer(
            owner_key=_OWNER,
            subscription_id=_SUB_ID,
            program=program,
            payment_status="paid",
            entitlements_status="active",
            issued_after_payment=True,
            checkout_session_id=_CHECKOUT_SESSION_ID,
            purchase_reference=_PURCHASE_REFERENCE,
        )
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
        record = reg.generate_for_paid_customer(
            owner_key=_OWNER,
            subscription_id=_SUB_ID,
            program="openclaw",
            payment_status="paid",
            entitlements_status="active",
            issued_after_payment=True,
            checkout_session_id=_CHECKOUT_SESSION_ID,
            purchase_reference=_PURCHASE_REFERENCE,
        )
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
        record = reg.generate_for_paid_customer(
            owner_key=_OWNER,
            subscription_id=_SUB_ID,
            program=program,
            payment_status="paid",
            entitlements_status="active",
            issued_after_payment=True,
            checkout_session_id=_CHECKOUT_SESSION_ID,
            purchase_reference=_PURCHASE_REFERENCE,
        )
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

    def _generate_paid_key(self, reg: InstallKeyRegistry, owner_key: str, subscription_id: str, program: str) -> InstallKeyRecord:
        return reg.generate_for_paid_customer(
            owner_key=owner_key,
            subscription_id=subscription_id,
            program=program,
            payment_status="paid",
            entitlements_status="active",
            issued_after_payment=True,
            checkout_session_id=_CHECKOUT_SESSION_ID,
            purchase_reference=_PURCHASE_REFERENCE,
        )

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
        self._generate_paid_key(reg, _OWNER, _SUB_ID, "openclaw")
        self._generate_paid_key(reg, _OWNER, _SUB_ID, "claude_code")
        s = reg.summary()
        assert s["total"] == 2

    def test_active_count_correct(self):
        reg = self._fresh_registry()
        r1 = self._generate_paid_key(reg, _OWNER, _SUB_ID, "openclaw")
        self._generate_paid_key(reg, _OWNER, _SUB_ID, "claude_code")
        reg.revoke_key(r1.key_id)
        s = reg.summary()
        assert s["active"] == 1

    def test_revoked_count_correct(self):
        reg = self._fresh_registry()
        r1 = self._generate_paid_key(reg, _OWNER, _SUB_ID, "openclaw")
        self._generate_paid_key(reg, _OWNER, _SUB_ID, "claude_code")
        reg.revoke_key(r1.key_id)
        s = reg.summary()
        assert s["revoked"] == 1

    def test_openclaw_keys_count(self):
        reg = self._fresh_registry()
        self._generate_paid_key(reg, _OWNER, _SUB_ID, "openclaw")
        self._generate_paid_key(reg, "other@ironclaw.test", _SUB_ID, "openclaw")
        s = reg.summary()
        assert s["openclaw_keys"] == 2

    def test_claude_code_keys_count(self):
        reg = self._fresh_registry()
        self._generate_paid_key(reg, _OWNER, _SUB_ID, "claude_code")
        s = reg.summary()
        assert s["claude_code_keys"] == 1

    def test_revoked_active_sum_equals_total(self):
        reg = self._fresh_registry()
        r1 = self._generate_paid_key(reg, _OWNER, _SUB_ID, "openclaw")
        self._generate_paid_key(reg, _OWNER, _SUB_ID, "claude_code")
        reg.revoke_key(r1.key_id)
        s = reg.summary()
        assert s["active"] + s["revoked"] == s["total"]

    def test_summary_keys_present(self):
        reg = self._fresh_registry()
        s = reg.summary()
        for key in ("total", "active", "revoked", "openclaw_keys", "claude_code_keys"):
            assert key in s
