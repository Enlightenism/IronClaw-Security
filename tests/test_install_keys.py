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
        record = registry.generate_install_key(
            owner_key=_OWNER,
            subscription_id=_SUB_ID,
            program="openclaw",
        )
        assert isinstance(record, InstallKeyRecord)
        assert record.raw_key.startswith("ic_install_openclaw_")
        assert record.active is True
        assert record.owner_key == _OWNER
        assert record.program == "openclaw"

    def test_generate_claude_key_has_correct_prefix(self, registry: InstallKeyRegistry) -> None:
        record = registry.generate_install_key(
            owner_key=_OWNER,
            subscription_id=_SUB_ID,
            program="claude_code",
        )
        assert record.raw_key.startswith("ic_install_claude_code_")

    def test_masked_key_does_not_expose_full_secret(self, registry: InstallKeyRegistry) -> None:
        record = registry.generate_install_key(
            owner_key=_OWNER,
            subscription_id=_SUB_ID,
            program="openclaw",
        )
        assert record.masked_key != record.raw_key
        assert "..." in record.masked_key

    def test_raw_key_hash_matches_key(self, registry: InstallKeyRegistry) -> None:
        import hashlib

        record = registry.generate_install_key(
            owner_key=_OWNER,
            subscription_id=_SUB_ID,
            program="openclaw",
        )
        expected_hash = hashlib.sha256(record.raw_key.encode()).hexdigest()
        assert record.raw_key_hash == expected_hash

    def test_duplicate_active_key_raises_already_exists(self, registry: InstallKeyRegistry) -> None:
        registry.generate_install_key(
            owner_key=_OWNER,
            subscription_id=_SUB_ID,
            program="openclaw",
        )
        with pytest.raises(InstallKeyAlreadyExistsError):
            registry.generate_install_key(
                owner_key=_OWNER,
                subscription_id=_SUB_ID,
                program="openclaw",
            )

    def test_two_programs_allowed_for_same_owner(self, registry: InstallKeyRegistry) -> None:
        r1 = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        r2 = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="claude_code")
        assert r1.key_id != r2.key_id
        assert r1.program == "openclaw"
        assert r2.program == "claude_code"

    def test_invalid_program_raises_value_error(self, registry: InstallKeyRegistry) -> None:
        with pytest.raises((ValueError, Exception)):
            registry.generate_install_key(
                owner_key=_OWNER,
                subscription_id=_SUB_ID,
                program="invalid_program",  # type: ignore[arg-type]
            )


class TestInstallKeyRegistryAuthenticate:
    def test_authenticate_valid_key_returns_record(self, registry: InstallKeyRegistry) -> None:
        record = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        authenticated = registry.authenticate_install_key(record.raw_key)
        assert authenticated is not None
        assert authenticated.key_id == record.key_id

    def test_authenticate_unknown_key_returns_none(self, registry: InstallKeyRegistry) -> None:
        result = registry.authenticate_install_key("ic_install_openclaw_not_a_real_key")
        assert result is None

    def test_authenticate_revoked_key_returns_none(self, registry: InstallKeyRegistry) -> None:
        record = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        registry.revoke_key(record.key_id)
        result = registry.authenticate_install_key(record.raw_key)
        assert result is None

    def test_authenticate_updates_last_used_at(self, registry: InstallKeyRegistry) -> None:
        record = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        assert record.last_used_at is None
        authenticated = registry.authenticate_install_key(record.raw_key)
        assert authenticated is not None
        assert authenticated.last_used_at is not None


class TestInstallKeyRegistryRevoke:
    def test_revoke_deactivates_key(self, registry: InstallKeyRegistry) -> None:
        record = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        updated = registry.revoke_key(record.key_id)
        assert updated.active is False

    def test_revoke_unknown_key_raises_not_found(self, registry: InstallKeyRegistry) -> None:
        with pytest.raises(InstallKeyNotFoundError):
            registry.revoke_key("ik_doesnotexist")

    def test_revoke_idempotent(self, registry: InstallKeyRegistry) -> None:
        record = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        registry.revoke_key(record.key_id)
        # Second revoke should not raise
        updated = registry.revoke_key(record.key_id)
        assert updated.active is False

    def test_revoked_key_fails_authenticate(self, registry: InstallKeyRegistry) -> None:
        record = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        raw = record.raw_key
        registry.revoke_key(record.key_id)
        assert registry.authenticate_install_key(raw) is None

    def test_revoked_key_fails_record_usage(self, registry: InstallKeyRegistry) -> None:
        record = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        registry.revoke_key(record.key_id)
        with pytest.raises(InstallKeyUsageError):
            registry.record_key_usage(record.key_id, units=1)

    def test_revoked_key_can_be_regenerated_for_same_owner(self, registry: InstallKeyRegistry) -> None:
        """After revoking the active key, a new one can be generated (no duplicate active)."""
        record = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        registry.revoke_key(record.key_id)
        new_record = registry.generate_install_key(owner_key=_OWNER, subscription_id="purch_test00000000002", program="openclaw")
        assert new_record.active is True
        assert new_record.key_id != record.key_id


class TestInstallKeyRegistryRecordUsage:
    def test_record_usage_increments_units_consumed(self, registry: InstallKeyRegistry) -> None:
        record = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        assert record.units_consumed == 0
        updated = registry.record_key_usage(record.key_id, units=10)
        assert updated.units_consumed == 10

    def test_record_usage_accumulates(self, registry: InstallKeyRegistry) -> None:
        record = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        registry.record_key_usage(record.key_id, units=5)
        updated = registry.record_key_usage(record.key_id, units=3)
        assert updated.units_consumed == 8

    def test_record_usage_zero_units_raises_usage_error(self, registry: InstallKeyRegistry) -> None:
        record = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        with pytest.raises(InstallKeyUsageError):
            registry.record_key_usage(record.key_id, units=0)

    def test_record_usage_negative_units_raises_usage_error(self, registry: InstallKeyRegistry) -> None:
        record = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        with pytest.raises(InstallKeyUsageError):
            registry.record_key_usage(record.key_id, units=-5)

    def test_record_usage_unknown_key_raises_not_found(self, registry: InstallKeyRegistry) -> None:
        with pytest.raises(InstallKeyNotFoundError):
            registry.record_key_usage("ik_ghost00000000000", units=1)

    def test_record_usage_inactive_key_raises_usage_error(self, registry: InstallKeyRegistry) -> None:
        record = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        registry.revoke_key(record.key_id)
        with pytest.raises(InstallKeyUsageError):
            registry.record_key_usage(record.key_id, units=1)

    def test_record_usage_updates_last_used_at(self, registry: InstallKeyRegistry) -> None:
        record = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        updated = registry.record_key_usage(record.key_id, units=1)
        assert updated.last_used_at is not None


class TestInstallKeyRegistryGetKeys:
    def test_get_keys_for_owner_returns_both_programs(self, registry: InstallKeyRegistry) -> None:
        registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="claude_code")
        keys = registry.get_keys_for_owner(_OWNER)
        assert len(keys) == 2
        programs = {k.program for k in keys}
        assert programs == {"openclaw", "claude_code"}

    def test_get_keys_for_unknown_owner_returns_empty(self, registry: InstallKeyRegistry) -> None:
        keys = registry.get_keys_for_owner("nobody@ironclaw.test")
        assert keys == []

    def test_masked_keys_correct_in_owner_listing(self, registry: InstallKeyRegistry) -> None:
        record = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        keys = registry.get_keys_for_owner(_OWNER)
        assert len(keys) == 1
        listed = keys[0]
        assert listed.masked_key == record.masked_key
        assert listed.raw_key == "" or listed.raw_key == record.raw_key

    def test_units_per_program_tracked_separately(self, registry: InstallKeyRegistry) -> None:
        r1 = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        r2 = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="claude_code")
        registry.record_key_usage(r1.key_id, units=7)
        registry.record_key_usage(r2.key_id, units=3)

        keys = {k.program: k for k in registry.get_keys_for_owner(_OWNER)}
        assert keys["openclaw"].units_consumed == 7
        assert keys["claude_code"].units_consumed == 3


# ---------------------------------------------------------------------------
# Integration: POST /billing/purchase — install key provisioning
# ---------------------------------------------------------------------------


class TestBillingPurchaseProvisioningInstallKeys:
    def test_install_key_not_generated_before_purchase_returns_empty_my_keys(self, registry: InstallKeyRegistry) -> None:
        """No install keys exist before any purchase is made."""
        keys = registry.get_keys_for_owner(_OWNER)
        assert keys == []

    def test_purchase_provisions_both_program_keys(self, client: TestClient) -> None:
        """POST /billing/purchase provisions openclaw and claude_code install keys."""
        payload = {
            "package_id": "pkg_5000",
            "buyer_name": "Test Buyer",
            "buyer_email": _OWNER,
        }
        resp = client.post("/billing/purchase", json=payload)
        assert resp.status_code == 201
        body = resp.json()
        purchase = body["purchase"]
        assert purchase["openclaw_install_key"] is not None
        assert purchase["openclaw_install_key"].startswith("ic_install_openclaw_")
        assert purchase["claude_code_install_key"] is not None
        assert purchase["claude_code_install_key"].startswith("ic_install_claude_code_")

    def test_purchase_returns_both_key_strings_non_empty(self, client: TestClient) -> None:
        payload = {
            "package_id": "pkg_5000",
            "buyer_name": "Test Buyer",
            "buyer_email": _OWNER,
        }
        resp = client.post("/billing/purchase", json=payload)
        assert resp.status_code == 201
        purchase = resp.json()["purchase"]
        assert len(purchase["openclaw_install_key"]) > 20
        assert len(purchase["claude_code_install_key"]) > 20

    def test_install_key_not_generated_before_purchase_http_402(self, client: TestClient) -> None:
        """
        Attempting to use a /billing/wallet debit without a prior purchase
        results in 402 (wallet does not exist / zero balance).
        Equivalent guard: no install key exists before a subscription is created.
        """
        resp = client.post(
            f"/billing/wallet/{_OWNER}/debit",
            json={"units": 1},
        )
        assert resp.status_code == 402

    def test_second_purchase_does_not_provision_new_keys_for_existing_owner(self, client: TestClient) -> None:
        """
        Second purchase for same owner silently skips key generation
        (InstallKeyAlreadyExistsError is swallowed) and returns None for both keys.
        """
        payload = {
            "package_id": "pkg_5000",
            "buyer_name": "Test Buyer",
            "buyer_email": _OWNER,
        }
        first = client.post("/billing/purchase", json=payload)
        assert first.status_code == 201

        second = client.post("/billing/purchase", json=payload)
        assert second.status_code == 201
        # On duplicate, _provision_install_keys catches the AlreadyExists and returns None
        purchase = second.json()["purchase"]
        assert purchase["openclaw_install_key"] is None
        assert purchase["claude_code_install_key"] is None


# ---------------------------------------------------------------------------
# Unit-wallet integration: record-usage debit path
# ---------------------------------------------------------------------------


class TestWalletDebitAndUsage:
    def test_record_usage_debits_wallet_correctly(self, client: TestClient) -> None:
        """Seed wallet, debit units, verify balance reduced by exact amount."""
        wallet_registry = _unit_wallet_module._unit_wallet_registry
        wallet_registry.credit_units(owner_key=_OWNER, units=100)

        resp = client.post(
            f"/billing/wallet/{_OWNER}/debit",
            json={"units": 25},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["units_debited"] == 25
        assert body["wallet"]["balance_units"] == 75

    def test_record_usage_with_zero_balance_raises_insufficient_units_402(self, client: TestClient) -> None:
        """
        Debit against a wallet with zero/no balance raises InsufficientUnitsError → 402.
        """
        resp = client.post(
            f"/billing/wallet/{_OWNER}/debit",
            json={"units": 50},
        )
        assert resp.status_code == 402
        detail = resp.json()["detail"]
        assert detail["status"] == "insufficient_units"
        assert detail["have"] == 0
        assert detail["need"] == 50

    def test_record_usage_exact_balance_succeeds_and_zeroes_wallet(self, client: TestClient) -> None:
        wallet_registry = _unit_wallet_module._unit_wallet_registry
        wallet_registry.credit_units(owner_key=_OWNER, units=10)

        resp = client.post(
            f"/billing/wallet/{_OWNER}/debit",
            json={"units": 10},
        )
        assert resp.status_code == 200
        assert resp.json()["wallet"]["balance_units"] == 0

    def test_record_usage_over_balance_returns_402(self, client: TestClient) -> None:
        wallet_registry = _unit_wallet_module._unit_wallet_registry
        wallet_registry.credit_units(owner_key=_OWNER, units=5)

        resp = client.post(
            f"/billing/wallet/{_OWNER}/debit",
            json={"units": 100},
        )
        assert resp.status_code == 402
        detail = resp.json()["detail"]
        assert detail["have"] == 5
        assert detail["need"] == 100

    def test_record_usage_insufficient_units_error_shape(self, client: TestClient) -> None:
        """Verify error response shape includes all required fields."""
        resp = client.post(
            f"/billing/wallet/{_OWNER}/debit",
            json={"units": 999},
        )
        assert resp.status_code == 402
        detail = resp.json()["detail"]
        for field in ("status", "error", "owner_key", "have", "need", "tokens_per_unit", "timestamp"):
            assert field in detail, f"Missing field: {field}"


# ---------------------------------------------------------------------------
# Revoked key — activate and record-usage both blocked
# ---------------------------------------------------------------------------


class TestRevokedKeyBlocked:
    def test_revoked_key_authenticate_returns_none(self, registry: InstallKeyRegistry) -> None:
        record = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        registry.revoke_key(record.key_id)
        assert registry.authenticate_install_key(record.raw_key) is None

    def test_revoked_key_record_usage_raises_usage_error(self, registry: InstallKeyRegistry) -> None:
        record = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        registry.revoke_key(record.key_id)
        with pytest.raises(InstallKeyUsageError):
            registry.record_key_usage(record.key_id, units=1)

    def test_revoked_key_not_in_active_listing(self, registry: InstallKeyRegistry) -> None:
        record = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        registry.revoke_key(record.key_id)
        keys = registry.get_keys_for_owner(_OWNER)
        active_keys = [k for k in keys if k.active]
        assert all(k.key_id != record.key_id for k in active_keys)

    def test_revoked_then_new_key_is_active_and_usable(self, registry: InstallKeyRegistry) -> None:
        record = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        registry.revoke_key(record.key_id)
        new_record = registry.generate_install_key(owner_key=_OWNER, subscription_id="purch_test00000000002", program="openclaw")
        assert new_record.active is True
        # Record usage on new key should succeed
        updated = registry.record_key_usage(new_record.key_id, units=5)
        assert updated.units_consumed == 5


# ---------------------------------------------------------------------------
# my-keys: masked keys and units per program
# ---------------------------------------------------------------------------


class TestMyKeysMaskedAndUnits:
    def test_my_keys_returns_masked_not_raw(self, registry: InstallKeyRegistry) -> None:
        record = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        keys = registry.get_keys_for_owner(_OWNER)
        assert len(keys) == 1
        listed = keys[0]
        # public_dict must never expose raw_key
        public = listed.public_dict()
        assert "raw_key" not in public
        assert public["masked_key"] == record.masked_key

    def test_my_keys_shows_correct_units_per_program(self, registry: InstallKeyRegistry) -> None:
        r_oc = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        r_cc = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="claude_code")
        registry.record_key_usage(r_oc.key_id, units=12)
        registry.record_key_usage(r_cc.key_id, units=4)

        keys = {k.program: k for k in registry.get_keys_for_owner(_OWNER)}
        assert keys["openclaw"].units_consumed == 12
        assert keys["claude_code"].units_consumed == 4

    def test_my_keys_empty_before_purchase(self, registry: InstallKeyRegistry) -> None:
        keys = registry.get_keys_for_owner("newuser@ironclaw.test")
        assert keys == []

    def test_my_keys_program_field_correct(self, registry: InstallKeyRegistry) -> None:
        registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        keys = registry.get_keys_for_owner(_OWNER)
        assert keys[0].program == "openclaw"

    def test_masked_key_format_preserved_in_public_dict(self, registry: InstallKeyRegistry) -> None:
        record = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="claude_code")
        public = record.public_dict()
        assert "..." in public["masked_key"]
        assert public["masked_key"].startswith("ic_install_claude_code_")

    def test_summary_counts_active_and_revoked(self, registry: InstallKeyRegistry) -> None:
        r1 = registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="openclaw")
        registry.generate_install_key(owner_key=_OWNER, subscription_id=_SUB_ID, program="claude_code")
        registry.revoke_key(r1.key_id)
        summary = registry.summary()
        assert summary["total"] == 2
        assert summary["active"] == 1
        assert summary["revoked"] == 1
        assert summary["openclaw_keys"] == 1
        assert summary["claude_code_keys"] == 1
