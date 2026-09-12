from __future__ import annotations

import os

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("IRONCLAW_API_KEY", "test-api-key")
os.environ.setdefault("AUTH_REQUIRED", "true")
os.environ.setdefault("IRONCLAW_RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "")
os.environ.setdefault("SUPABASE_KEY", "")
os.environ.setdefault("SUPABASE_ANON_KEY", "")

from contextlib import contextmanager

from fastapi.testclient import TestClient
import pytest

from app.core.auth import (
    AuthContext,
    get_api_key,
    get_auth_context,
    require_api_key,
    require_auth_context,
)
import app.core.install_keys as _install_keys_module
from app.core.install_keys import (
    InstallKeyAlreadyExistsError,
    InstallKeyNotFoundError,
    InstallKeyPaymentRequiredError,
    InstallKeyRecord,
    InstallKeyRegistry,
    InstallKeyUsageError,
)
import app.core.unit_wallet as _unit_wallet_module
from app.core.unit_wallet import UnitWalletRegistry
from app.main import app as _app

_MOCK_API_KEY = "test-api-key"
_AUTH_HEADERS = {"X-API-Key": _MOCK_API_KEY}
_OWNER = "buyer@ironclaw.test"
_SUB_ID = "purch_test00000000001"


def _issue_paid_key(
    registry: InstallKeyRegistry,
    *,
    owner_key: str = _OWNER,
    subscription_id: str = _SUB_ID,
    program: str = "openclaw",
    **kwargs: object,
) -> InstallKeyRecord:
    purchase_reference = str(kwargs.pop("purchase_reference", f"ref_{program}_{subscription_id[-8:]}") or f"ref_{program}_{subscription_id[-8:]}")
    checkout_session_id = str(kwargs.pop("checkout_session_id", f"cs_{program}_{subscription_id[-8:]}") or f"cs_{program}_{subscription_id[-8:]}")
    return registry.generate_install_key(
        owner_key=owner_key,
        subscription_id=subscription_id,
        program=program,
        payment_status="paid",
        entitlements_status="active",
        issued_after_payment=True,
        purchase_reference=purchase_reference,
        checkout_session_id=checkout_session_id,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Auth context factories
# ---------------------------------------------------------------------------


def _make_personal_ctx(email: str = _OWNER) -> AuthContext:
    return AuthContext(
        api_key=_MOCK_API_KEY,
        principal_type="api_key",
        principal_id=email,
        session_id=None,
        org_id=None,
        authenticated=True,
        auth_source="registry",
        auth_method="api_key",
        key_type="personal",
    )


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------


def _fresh_install_registry() -> InstallKeyRegistry:
    """Replace the module-level singleton with a blank in-memory registry."""
    fresh = InstallKeyRegistry()
    # Force the loaded flag so _ensure_loaded never hits Supabase
    fresh._loaded = True
    _install_keys_module._install_key_registry = fresh
    return fresh


def _fresh_wallet_registry() -> UnitWalletRegistry:
    fresh = UnitWalletRegistry()
    _unit_wallet_module._unit_wallet_registry = fresh
    return fresh


# ---------------------------------------------------------------------------
# Auth override context manager
# ---------------------------------------------------------------------------


@contextmanager
def _override_auth(ctx: AuthContext):
    """Override auth deps and install fresh isolated registries."""
    _fresh_install_registry()
    _fresh_wallet_registry()

    def _stub_api_key() -> str:
        return ctx.api_key or _MOCK_API_KEY

    def _stub_auth_ctx() -> AuthContext:
        return ctx

    _app.dependency_overrides[get_api_key] = _stub_api_key
    _app.dependency_overrides[get_auth_context] = _stub_auth_ctx
    _app.dependency_overrides[require_auth_context] = _stub_auth_ctx
    _app.dependency_overrides[require_api_key] = _stub_api_key
    try:
        yield TestClient(_app, raise_server_exceptions=False)
    finally:
        _app.dependency_overrides.pop(get_api_key, None)
        _app.dependency_overrides.pop(get_auth_context, None)
        _app.dependency_overrides.pop(require_auth_context, None)
        _app.dependency_overrides.pop(require_api_key, None)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_registries():
    """Guarantee clean install key and wallet registries before/after each test."""
    _fresh_install_registry()
    _fresh_wallet_registry()
    yield
    _fresh_install_registry()
    _fresh_wallet_registry()


@pytest.fixture()
def registry() -> InstallKeyRegistry:
    return _install_keys_module._install_key_registry  # type: ignore[return-value]


@pytest.fixture()
def client():
    ctx = _make_personal_ctx()

    def _stub_api_key() -> str:
        return _MOCK_API_KEY

    def _stub_auth_ctx() -> AuthContext:
        return ctx

    _app.dependency_overrides[require_api_key] = _stub_api_key
    _app.dependency_overrides[get_api_key] = _stub_api_key
    _app.dependency_overrides[get_auth_context] = _stub_auth_ctx
    _app.dependency_overrides[require_auth_context] = _stub_auth_ctx
    with TestClient(_app, raise_server_exceptions=False) as c:
        c.headers.update(_AUTH_HEADERS)
        yield c
    _app.dependency_overrides.pop(require_api_key, None)
    _app.dependency_overrides.pop(get_api_key, None)
    _app.dependency_overrides.pop(get_auth_context, None)
    _app.dependency_overrides.pop(require_auth_context, None)


# ---------------------------------------------------------------------------
# Unit tests — InstallKeyRegistry (in-process, no HTTP)
# ---------------------------------------------------------------------------


class TestInstallKeyRegistryGenerate:
    def test_generate_returns_record_with_raw_key(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")
        assert isinstance(record, InstallKeyRecord)
        assert record.raw_key.startswith("ic_install_openclaw_")
        assert record.active is True
        assert record.owner_key == _OWNER
        assert record.program == "openclaw"

    def test_generate_claude_key_has_correct_prefix(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="claude_code")
        assert record.raw_key.startswith("ic_install_claude_code_")

    def test_masked_key_does_not_expose_full_secret(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")
        assert record.masked_key != record.raw_key
        assert "..." in record.masked_key

    def test_raw_key_hash_matches_key(self, registry: InstallKeyRegistry) -> None:
        import hashlib

        record = _issue_paid_key(registry, program="openclaw")
        expected_hash = hashlib.sha256(record.raw_key.encode()).hexdigest()
        assert record.raw_key_hash == expected_hash

    def test_duplicate_active_key_raises_already_exists(self, registry: InstallKeyRegistry) -> None:
        _issue_paid_key(registry, program="openclaw")
        with pytest.raises(InstallKeyAlreadyExistsError):
            _issue_paid_key(registry, program="openclaw")

    def test_two_programs_allowed_for_same_owner(self, registry: InstallKeyRegistry) -> None:
        r1 = _issue_paid_key(registry, program="openclaw")
        r2 = _issue_paid_key(registry, program="claude_code")
        assert r1.key_id != r2.key_id
        assert r1.program == "openclaw"
        assert r2.program == "claude_code"

    def test_invalid_program_raises_value_error(self, registry: InstallKeyRegistry) -> None:
        with pytest.raises((ValueError, Exception)):
            registry.generate_install_key(
                owner_key=_OWNER,
                subscription_id=_SUB_ID,
                program="invalid_program",  # type: ignore[arg-type]
                payment_status="paid",
                entitlements_status="active",
                issued_after_payment=True,
                purchase_reference="ref_invalid_001",
                checkout_session_id="cs_invalid_001",
            )


class TestInstallKeyRegistryAuthenticate:
    def test_authenticate_valid_key_returns_record(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")
        authenticated = registry.authenticate_install_key(record.raw_key)
        assert authenticated is not None
        assert authenticated.key_id == record.key_id

    def test_authenticate_unknown_key_returns_none(self, registry: InstallKeyRegistry) -> None:
        result = registry.authenticate_install_key("ic_install_openclaw_not_a_real_key")
        assert result is None

    def test_authenticate_revoked_key_returns_none(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")
        registry.revoke_key(record.key_id)
        result = registry.authenticate_install_key(record.raw_key)
        assert result is None

    def test_authenticate_updates_last_used_at(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")
        assert record.last_used_at is None
        authenticated = registry.authenticate_install_key(record.raw_key)
        assert authenticated is not None
        assert authenticated.last_used_at is not None


class TestInstallKeyRegistryRevoke:
    def test_revoke_deactivates_key(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")
        updated = registry.revoke_key(record.key_id)
        assert updated.active is False

    def test_revoke_unknown_key_raises_not_found(self, registry: InstallKeyRegistry) -> None:
        with pytest.raises(InstallKeyNotFoundError):
            registry.revoke_key("ik_doesnotexist")

    def test_revoke_idempotent(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")
        registry.revoke_key(record.key_id)
        updated = registry.revoke_key(record.key_id)
        assert updated.active is False

    def test_revoked_key_fails_authenticate(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")
        raw = record.raw_key
        registry.revoke_key(record.key_id)
        assert registry.authenticate_install_key(raw) is None

    def test_revoked_key_fails_record_usage(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")
        registry.revoke_key(record.key_id)
        with pytest.raises(InstallKeyUsageError):
            registry.record_key_usage(record.key_id, units=1)

    def test_revoked_key_can_be_regenerated_for_same_owner(self, registry: InstallKeyRegistry) -> None:
        """After revoking the active key, a new one can be generated (no duplicate active)."""
        record = _issue_paid_key(registry, program="openclaw")
        registry.revoke_key(record.key_id)
        new_record = _issue_paid_key(registry, owner_key=_OWNER, subscription_id="purch_test00000000002", program="openclaw")
        assert new_record.active is True
        assert new_record.key_id != record.key_id


class TestInstallKeyRegistryRecordUsage:
    def test_record_usage_increments_units_consumed(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")
        assert record.units_consumed == 0
        updated = registry.record_key_usage(record.key_id, units=10)
        assert updated.units_consumed == 10

    def test_record_usage_accumulates(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")
        registry.record_key_usage(record.key_id, units=5)
        updated = registry.record_key_usage(record.key_id, units=3)
        assert updated.units_consumed == 8

    def test_record_usage_zero_units_raises_usage_error(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")
        with pytest.raises(InstallKeyUsageError):
            registry.record_key_usage(record.key_id, units=0)

    def test_record_usage_negative_units_raises_usage_error(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")
        with pytest.raises(InstallKeyUsageError):
            registry.record_key_usage(record.key_id, units=-5)

    def test_record_usage_unknown_key_raises_not_found(self, registry: InstallKeyRegistry) -> None:
        with pytest.raises(InstallKeyNotFoundError):
            registry.record_key_usage("ik_ghost00000000000", units=1)

    def test_record_usage_inactive_key_raises_usage_error(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")
        registry.revoke_key(record.key_id)
        with pytest.raises(InstallKeyUsageError):
            registry.record_key_usage(record.key_id, units=1)

    def test_record_usage_updates_last_used_at(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")
        updated = registry.record_key_usage(record.key_id, units=1)
        assert updated.last_used_at is not None


class TestInstallKeyRegistryGetKeys:
    def test_get_keys_for_owner_returns_both_programs(self, registry: InstallKeyRegistry) -> None:
        _issue_paid_key(registry, program="openclaw")
        _issue_paid_key(registry, program="claude_code")
        keys = registry.get_keys_for_owner(_OWNER)
        assert len(keys) == 2
        programs = {k.program for k in keys}
        assert programs == {"openclaw", "claude_code"}

    def test_get_keys_for_unknown_owner_returns_empty(self, registry: InstallKeyRegistry) -> None:
        keys = registry.get_keys_for_owner("nobody@ironclaw.test")
        assert keys == []

    def test_masked_keys_correct_in_owner_listing(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")
        keys = registry.get_keys_for_owner(_OWNER)
        assert len(keys) == 1
        listed = keys[0]
        assert listed.masked_key == record.masked_key
        assert listed.raw_key == "" or listed.raw_key == record.raw_key

    def test_units_per_program_tracked_separately(self, registry: InstallKeyRegistry) -> None:
        r1 = _issue_paid_key(registry, program="openclaw")
        r2 = _issue_paid_key(registry, program="claude_code")
        registry.record_key_usage(r1.key_id, units=7)
        registry.record_key_usage(r2.key_id, units=3)

        keys = {k.program: k for k in registry.get_keys_for_owner(_OWNER)}
        assert keys["openclaw"].units_consumed == 7
        assert keys["claude_code"].units_consumed == 3


# ---------------------------------------------------------------------------
# Paid-entitlement contract: install-key issuance must be gated and masked
# ---------------------------------------------------------------------------


class TestInstallKeyRegistryPaidEntitlementContract:
    def test_generate_rejects_unpaid_checkout(self, registry: InstallKeyRegistry) -> None:
        with pytest.raises(InstallKeyPaymentRequiredError):
            registry.generate_for_paid_customer(
                owner_key=_OWNER,
                subscription_id=_SUB_ID,
                program="openclaw",
                payment_status="pending",
                entitlements_status="active",
                issued_after_payment=True,
                purchase_reference="ref_123",
                checkout_session_id="cs_123",
            )

    def test_generate_rejects_inactive_entitlement(self, registry: InstallKeyRegistry) -> None:
        with pytest.raises(InstallKeyPaymentRequiredError):
            registry.generate_for_paid_customer(
                owner_key=_OWNER,
                subscription_id=_SUB_ID,
                program="claude_code",
                payment_status="paid",
                entitlements_status="inactive",
                issued_after_payment=True,
                purchase_reference="ref_456",
                checkout_session_id="cs_456",
            )

    def test_generate_rejects_before_payment_completion(self, registry: InstallKeyRegistry) -> None:
        with pytest.raises(InstallKeyPaymentRequiredError):
            registry.generate_for_paid_customer(
                owner_key=_OWNER,
                subscription_id=_SUB_ID,
                program="openclaw",
                payment_status="paid",
                entitlements_status="active",
                issued_after_payment=False,
                purchase_reference="ref_789",
                checkout_session_id="cs_789",
            )

    def test_public_dict_exposes_only_masked_key(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")

        payload = record.public_dict()
        assert payload["masked_key"] == record.masked_key
        assert "raw_key" not in payload
        assert payload["masked_key"] != record.raw_key
        assert "..." in payload["masked_key"]

    def test_authenticate_rejects_non_paid_or_revoked_key(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")
        assert registry.authenticate_install_key(record.raw_key) is not None

        registry.revoke_key(record.key_id)
        assert registry.authenticate_install_key(record.raw_key) is None

        with pytest.raises(InstallKeyPaymentRequiredError):
            registry.generate_for_paid_customer(
                owner_key="another_owner@example.com",
                subscription_id="sub_pending",
                program="openclaw",
                payment_status="pending",
                entitlements_status="active",
                issued_after_payment=True,
                purchase_reference="ref_pending",
                checkout_session_id="cs_pending",
            )


# ---------------------------------------------------------------------------
# Revoked key — activate and record-usage both blocked
# ---------------------------------------------------------------------------


class TestRevokedKeyBlocked:
    def test_revoked_key_authenticate_returns_none(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")
        registry.revoke_key(record.key_id)
        assert registry.authenticate_install_key(record.raw_key) is None

    def test_revoked_key_record_usage_raises_usage_error(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")
        registry.revoke_key(record.key_id)
        with pytest.raises(InstallKeyUsageError):
            registry.record_key_usage(record.key_id, units=1)

    def test_revoked_key_not_in_active_listing(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")
        registry.revoke_key(record.key_id)
        keys = registry.get_keys_for_owner(_OWNER)
        active_keys = [k for k in keys if k.active]
        assert all(k.key_id != record.key_id for k in active_keys)

    def test_revoked_then_new_key_is_active_and_usable(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")
        registry.revoke_key(record.key_id)
        new_record = _issue_paid_key(registry, owner_key=_OWNER, subscription_id="purch_test00000000002", program="openclaw")
        assert new_record.active is True
        updated = registry.record_key_usage(new_record.key_id, units=5)
        assert updated.units_consumed == 5


# ---------------------------------------------------------------------------
# my-keys: masked keys and units per program
# ---------------------------------------------------------------------------


class TestMyKeysMaskedAndUnits:
    def test_my_keys_returns_masked_not_raw(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="openclaw")
        keys = registry.get_keys_for_owner(_OWNER)
        assert len(keys) == 1
        listed = keys[0]
        public = listed.public_dict()
        assert "raw_key" not in public
        assert public["masked_key"] == record.masked_key

    def test_my_keys_shows_correct_units_per_program(self, registry: InstallKeyRegistry) -> None:
        r_oc = _issue_paid_key(registry, program="openclaw")
        r_cc = _issue_paid_key(registry, program="claude_code")
        registry.record_key_usage(r_oc.key_id, units=12)
        registry.record_key_usage(r_cc.key_id, units=4)

        keys = {k.program: k for k in registry.get_keys_for_owner(_OWNER)}
        assert keys["openclaw"].units_consumed == 12
        assert keys["claude_code"].units_consumed == 4

    def test_my_keys_empty_before_purchase(self, registry: InstallKeyRegistry) -> None:
        keys = registry.get_keys_for_owner("newuser@ironclaw.test")
        assert keys == []

    def test_my_keys_program_field_correct(self, registry: InstallKeyRegistry) -> None:
        _issue_paid_key(registry, program="openclaw")
        keys = registry.get_keys_for_owner(_OWNER)
        assert keys[0].program == "openclaw"

    def test_masked_key_format_preserved_in_public_dict(self, registry: InstallKeyRegistry) -> None:
        record = _issue_paid_key(registry, program="claude_code")
        public = record.public_dict()
        assert "..." in public["masked_key"]
        assert public["masked_key"].startswith("ic_install_claude_code_")

    def test_summary_counts_active_and_revoked(self, registry: InstallKeyRegistry) -> None:
        r1 = _issue_paid_key(registry, program="openclaw")
        _issue_paid_key(registry, program="claude_code")
        registry.revoke_key(r1.key_id)
        summary = registry.summary()
        assert summary["total"] == 2
        assert summary["active"] == 1
        assert summary["revoked"] == 1
        assert summary["openclaw_keys"] == 1
        assert summary["claude_code_keys"] == 1
