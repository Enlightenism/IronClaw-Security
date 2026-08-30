from __future__ import annotations

import os

import pytest

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("IRONCLAW_API_KEY", "test-api-key")
os.environ.setdefault("AUTH_REQUIRED", "true")
os.environ.setdefault("IRONCLAW_RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "")
os.environ.setdefault("SUPABASE_KEY", "")
os.environ.setdefault("SUPABASE_ANON_KEY", "")


from app.core.unit_wallet import (
    TOKEN_CHUNK_SIZE,
    UNIT_PACKAGE_CATALOG,
    InsufficientUnitsError,
    RegistryUnitWallet,
    UnitWalletRegistry,
    units_required_for_tokens,
)

# ---------------------------------------------------------------------------
# Per-test fixture: fresh registry isolated from all other tests
# ---------------------------------------------------------------------------


@pytest.fixture()
def registry() -> UnitWalletRegistry:
    return UnitWalletRegistry()


# ---------------------------------------------------------------------------
# UNIT_PACKAGE_CATALOG integrity
# ---------------------------------------------------------------------------


_EXPECTED_CATALOG: dict[str, tuple[int, float]] = {
    "pkg_5000": (5_000, 20.00),
    "pkg_25000": (25_000, 90.00),
    "pkg_60000": (60_000, 180.00),
}


def test_catalog_contains_all_three_canonical_packages() -> None:
    for pkg_id in _EXPECTED_CATALOG:
        assert pkg_id in UNIT_PACKAGE_CATALOG, f"UNIT_PACKAGE_CATALOG missing {pkg_id!r}"


def test_catalog_unit_amounts_are_correct() -> None:
    for pkg_id, (expected_units, _) in _EXPECTED_CATALOG.items():
        entry = UNIT_PACKAGE_CATALOG[pkg_id]
        assert entry["unit_amount"] == expected_units, f"{pkg_id}: unit_amount={entry['unit_amount']} expected {expected_units}"


def test_catalog_price_usd_is_correct() -> None:
    for pkg_id, (_, expected_price) in _EXPECTED_CATALOG.items():
        entry = UNIT_PACKAGE_CATALOG[pkg_id]
        assert entry["price_usd"] == expected_price, f"{pkg_id}: price_usd={entry['price_usd']} expected {expected_price}"


def test_catalog_tokens_per_unit_equals_token_chunk_size() -> None:
    for pkg_id in _EXPECTED_CATALOG:
        entry = UNIT_PACKAGE_CATALOG[pkg_id]
        assert entry["tokens_per_unit"] == TOKEN_CHUNK_SIZE, f"{pkg_id}: tokens_per_unit={entry['tokens_per_unit']} expected {TOKEN_CHUNK_SIZE}"


def test_catalog_package_id_field_matches_key() -> None:
    for pkg_id in _EXPECTED_CATALOG:
        entry = UNIT_PACKAGE_CATALOG[pkg_id]
        assert entry["package_id"] == pkg_id


# ---------------------------------------------------------------------------
# Catalog validation guard — RuntimeError (not AssertionError)
# ---------------------------------------------------------------------------


def _run_catalog_validation(catalog: dict) -> None:
    """Mirror the exact module-level validation loop from unit_wallet.py."""
    _EXPECTED = {
        "pkg_5000": (5_000, 20.00),
        "pkg_25000": (25_000, 90.00),
        "pkg_60000": (60_000, 180.00),
    }
    for pkg_id, (expected_units, expected_price) in _EXPECTED.items():
        entry = catalog.get(pkg_id)
        if entry is None:
            raise RuntimeError(f"unit_wallet: UNIT_PACKAGE_CATALOG is missing required package {pkg_id!r}")
        if entry["unit_amount"] != expected_units:
            raise RuntimeError(f"unit_wallet: {pkg_id} unit_amount mismatch: got {entry['unit_amount']}, expected {expected_units}")
        if entry["price_usd"] != expected_price:
            raise RuntimeError(f"unit_wallet: {pkg_id} price_usd mismatch: got {entry['price_usd']}, expected {expected_price}")
        if entry["tokens_per_unit"] != TOKEN_CHUNK_SIZE:
            raise RuntimeError(f"unit_wallet: {pkg_id} tokens_per_unit mismatch: got {entry['tokens_per_unit']}, expected {TOKEN_CHUNK_SIZE}")


def _good_catalog() -> dict:
    import copy

    return copy.deepcopy(UNIT_PACKAGE_CATALOG)


# --- valid catalog passes ---------------------------------------------------


def test_catalog_validation_passes_for_valid_catalog() -> None:
    _run_catalog_validation(_good_catalog())


# --- missing package --------------------------------------------------------


def test_catalog_validation_missing_package_raises_runtime_error() -> None:
    bad = _good_catalog()
    del bad["pkg_5000"]
    with pytest.raises(RuntimeError, match="missing required package"):
        _run_catalog_validation(bad)


def test_catalog_validation_missing_package_error_is_not_assertion_error() -> None:
    bad = _good_catalog()
    del bad["pkg_25000"]
    try:
        _run_catalog_validation(bad)
    except RuntimeError:
        pass
    except AssertionError:
        pytest.fail("catalog validation raised AssertionError instead of RuntimeError")


def test_catalog_validation_missing_package_message_contains_pkg_id() -> None:
    bad = _good_catalog()
    del bad["pkg_60000"]
    with pytest.raises(RuntimeError, match="pkg_60000"):
        _run_catalog_validation(bad)


# --- wrong unit_amount ------------------------------------------------------


def test_catalog_validation_wrong_unit_amount_raises_runtime_error() -> None:
    bad = _good_catalog()
    bad["pkg_5000"]["unit_amount"] = 9999
    with pytest.raises(RuntimeError, match="unit_amount mismatch"):
        _run_catalog_validation(bad)


def test_catalog_validation_wrong_unit_amount_message_contains_pkg_id() -> None:
    bad = _good_catalog()
    bad["pkg_25000"]["unit_amount"] = 1
    with pytest.raises(RuntimeError, match="pkg_25000"):
        _run_catalog_validation(bad)


def test_catalog_validation_wrong_unit_amount_message_contains_got_value() -> None:
    bad = _good_catalog()
    bad["pkg_5000"]["unit_amount"] = 42
    with pytest.raises(RuntimeError, match="42"):
        _run_catalog_validation(bad)


def test_catalog_validation_wrong_unit_amount_is_not_assertion_error() -> None:
    bad = _good_catalog()
    bad["pkg_60000"]["unit_amount"] = 0
    try:
        _run_catalog_validation(bad)
    except RuntimeError:
        pass
    except AssertionError:
        pytest.fail("catalog validation raised AssertionError instead of RuntimeError")


# --- wrong price_usd --------------------------------------------------------


def test_catalog_validation_wrong_price_usd_raises_runtime_error() -> None:
    bad = _good_catalog()
    bad["pkg_5000"]["price_usd"] = 0.01
    with pytest.raises(RuntimeError, match="price_usd mismatch"):
        _run_catalog_validation(bad)


def test_catalog_validation_wrong_price_usd_message_contains_pkg_id() -> None:
    bad = _good_catalog()
    bad["pkg_25000"]["price_usd"] = 999.99
    with pytest.raises(RuntimeError, match="pkg_25000"):
        _run_catalog_validation(bad)


def test_catalog_validation_wrong_price_usd_message_contains_got_value() -> None:
    bad = _good_catalog()
    bad["pkg_5000"]["price_usd"] = 1.23
    with pytest.raises(RuntimeError, match="1.23"):
        _run_catalog_validation(bad)


def test_catalog_validation_wrong_price_usd_is_not_assertion_error() -> None:
    bad = _good_catalog()
    bad["pkg_60000"]["price_usd"] = 0.0
    try:
        _run_catalog_validation(bad)
    except RuntimeError:
        pass
    except AssertionError:
        pytest.fail("catalog validation raised AssertionError instead of RuntimeError")


# --- wrong tokens_per_unit --------------------------------------------------


def test_catalog_validation_wrong_tokens_per_unit_raises_runtime_error() -> None:
    bad = _good_catalog()
    bad["pkg_5000"]["tokens_per_unit"] = TOKEN_CHUNK_SIZE + 1
    with pytest.raises(RuntimeError, match="tokens_per_unit mismatch"):
        _run_catalog_validation(bad)


def test_catalog_validation_wrong_tokens_per_unit_message_contains_pkg_id() -> None:
    bad = _good_catalog()
    bad["pkg_25000"]["tokens_per_unit"] = 0
    with pytest.raises(RuntimeError, match="pkg_25000"):
        _run_catalog_validation(bad)


def test_catalog_validation_wrong_tokens_per_unit_message_contains_got_value() -> None:
    bad = _good_catalog()
    bad["pkg_5000"]["tokens_per_unit"] = 1
    with pytest.raises(RuntimeError, match="1"):
        _run_catalog_validation(bad)


def test_catalog_validation_wrong_tokens_per_unit_is_not_assertion_error() -> None:
    bad = _good_catalog()
    bad["pkg_60000"]["tokens_per_unit"] = 99999
    try:
        _run_catalog_validation(bad)
    except RuntimeError:
        pass
    except AssertionError:
        pytest.fail("catalog validation raised AssertionError instead of RuntimeError")


# ---------------------------------------------------------------------------
# units_required_for_tokens — boundary values
# ---------------------------------------------------------------------------


def test_units_required_one_token_costs_one_unit() -> None:
    assert units_required_for_tokens(1) == 1


def test_units_required_exact_chunk_boundary_costs_one_unit() -> None:
    assert units_required_for_tokens(TOKEN_CHUNK_SIZE) == 1


def test_units_required_one_over_boundary_costs_two_units() -> None:
    assert units_required_for_tokens(TOKEN_CHUNK_SIZE + 1) == 2


def test_units_required_two_full_chunks_costs_two_units() -> None:
    assert units_required_for_tokens(TOKEN_CHUNK_SIZE * 2) == 2


def test_units_required_two_chunks_plus_one_costs_three_units() -> None:
    assert units_required_for_tokens(TOKEN_CHUNK_SIZE * 2 + 1) == 3


def test_units_required_zero_returns_zero() -> None:
    assert units_required_for_tokens(0) == 0


def test_units_required_negative_returns_zero() -> None:
    assert units_required_for_tokens(-1) == 0


# ---------------------------------------------------------------------------
# credit_units — wallet creation and accumulation
# ---------------------------------------------------------------------------


def test_credit_units_creates_wallet_on_first_call(registry: UnitWalletRegistry) -> None:
    wallet = registry.credit_units("alice@ironclaw.test", 500)
    assert wallet.owner_key == "alice@ironclaw.test"
    assert wallet.balance_units == 500
    assert wallet.wallet_id.startswith("wallet_")


def test_get_wallet_ignores_invalid_cached_entry_and_fetches_real_wallet(registry: UnitWalletRegistry) -> None:
    repo_wallet = RegistryUnitWallet(
        wallet_id="wallet_live_123",
        owner_key="alice@ironclaw.test",
        balance_units=42,
    )
    registry._wallets["wallet_stale_123"] = object()
    registry._wallets_by_owner["alice@ironclaw.test"] = "wallet_stale_123"
    registry._repo = type(
        "RepoStub",
        (),
        {"fetch_wallet": lambda self, owner_key: repo_wallet},
    )()

    wallet = registry.get_wallet("alice@ironclaw.test")

    assert wallet is repo_wallet
    assert registry._wallets_by_owner["alice@ironclaw.test"] == "wallet_live_123"


def test_credit_units_sets_total_purchased_units(registry: UnitWalletRegistry) -> None:
    wallet = registry.credit_units("alice@ironclaw.test", 500)
    assert wallet.total_purchased_units == 500


def test_credit_units_accumulates_on_second_call(registry: UnitWalletRegistry) -> None:
    registry.credit_units("alice@ironclaw.test", 500)
    wallet = registry.credit_units("alice@ironclaw.test", 300)
    assert wallet.balance_units == 800
    assert wallet.total_purchased_units == 800


def test_credit_units_different_owners_are_isolated(registry: UnitWalletRegistry) -> None:
    registry.credit_units("alice@ironclaw.test", 1_000)
    wallet_b = registry.credit_units("bob@ironclaw.test", 250)
    assert wallet_b.balance_units == 250
    assert wallet_b.total_purchased_units == 250


def test_credit_units_normalizes_owner_key_to_lowercase(registry: UnitWalletRegistry) -> None:
    registry.credit_units("ALICE@IRONCLAW.TEST", 100)
    wallet = registry.get_wallet("alice@ironclaw.test")
    assert wallet is not None
    assert wallet.balance_units == 100


def test_credit_units_creates_credit_ledger_entry(registry: UnitWalletRegistry) -> None:
    registry.credit_units("alice@ironclaw.test", 500)
    entries = registry.list_ledger_entries(owner_key="alice@ironclaw.test")
    assert len(entries) >= 1
    assert entries[-1].entry_type == "credit"
    assert entries[-1].units == 500


# ---------------------------------------------------------------------------
# debit_units — happy path
# ---------------------------------------------------------------------------


def test_debit_units_reduces_balance(registry: UnitWalletRegistry) -> None:
    registry.credit_units("carol@ironclaw.test", 1_000)
    wallet = registry.debit_units("carol@ironclaw.test", 200)
    assert wallet.balance_units == 800
    assert wallet.total_consumed_units == 200


def test_debit_units_creates_debit_ledger_entry(registry: UnitWalletRegistry) -> None:
    registry.credit_units("carol@ironclaw.test", 1_000)
    registry.debit_units("carol@ironclaw.test", 200)
    entries = registry.list_ledger_entries(owner_key="carol@ironclaw.test")
    entry_types = [e.entry_type for e in entries]
    assert "debit" in entry_types


def test_debit_units_balance_after_is_correct_in_ledger(registry: UnitWalletRegistry) -> None:
    registry.credit_units("carol@ironclaw.test", 1_000)
    registry.debit_units("carol@ironclaw.test", 200)
    entries = registry.list_ledger_entries(owner_key="carol@ironclaw.test")
    debit_entry = next(e for e in entries if e.entry_type == "debit")
    assert debit_entry.balance_after == 800


def test_debit_units_exact_balance_empties_wallet(registry: UnitWalletRegistry) -> None:
    registry.credit_units("carol@ironclaw.test", 500)
    wallet = registry.debit_units("carol@ironclaw.test", 500)
    assert wallet.balance_units == 0


# ---------------------------------------------------------------------------
# debit_units — InsufficientUnitsError
# ---------------------------------------------------------------------------


def test_debit_units_raises_insufficient_units_error_when_balance_low(registry: UnitWalletRegistry) -> None:
    registry.credit_units("broke@ironclaw.test", 10)
    with pytest.raises(InsufficientUnitsError):
        registry.debit_units("broke@ironclaw.test", 100)


def test_debit_units_error_have_attribute_is_correct(registry: UnitWalletRegistry) -> None:
    registry.credit_units("broke@ironclaw.test", 10)
    with pytest.raises(InsufficientUnitsError) as exc_info:
        registry.debit_units("broke@ironclaw.test", 100)
    assert exc_info.value.have == 10


def test_debit_units_error_need_attribute_is_correct(registry: UnitWalletRegistry) -> None:
    registry.credit_units("broke@ironclaw.test", 10)
    with pytest.raises(InsufficientUnitsError) as exc_info:
        registry.debit_units("broke@ironclaw.test", 100)
    assert exc_info.value.need == 100


def test_debit_units_error_owner_key_attribute_is_correct(registry: UnitWalletRegistry) -> None:
    registry.credit_units("broke@ironclaw.test", 10)
    with pytest.raises(InsufficientUnitsError) as exc_info:
        registry.debit_units("broke@ironclaw.test", 100)
    assert exc_info.value.owner_key == "broke@ironclaw.test"


def test_debit_units_zero_wallet_raises_insufficient_units_error(registry: UnitWalletRegistry) -> None:
    with pytest.raises(InsufficientUnitsError) as exc_info:
        registry.debit_units("empty@ironclaw.test", 1)
    assert exc_info.value.have == 0
    assert exc_info.value.need == 1


def test_debit_units_error_does_not_mutate_balance(registry: UnitWalletRegistry) -> None:
    registry.credit_units("broke@ironclaw.test", 10)
    with pytest.raises(InsufficientUnitsError):
        registry.debit_units("broke@ironclaw.test", 100)
    wallet = registry.get_wallet("broke@ironclaw.test")
    assert wallet is not None
    assert wallet.balance_units == 10


# ---------------------------------------------------------------------------
# refund_units
# ---------------------------------------------------------------------------


def test_refund_units_increments_total_refunded_units(registry: UnitWalletRegistry) -> None:
    registry.credit_units("dana@ironclaw.test", 1_000)
    registry.debit_units("dana@ironclaw.test", 200)
    wallet = registry.refund_units("dana@ironclaw.test", 100)
    assert wallet.total_refunded_units == 100


def test_refund_units_restores_balance(registry: UnitWalletRegistry) -> None:
    registry.credit_units("dana@ironclaw.test", 1_000)
    registry.debit_units("dana@ironclaw.test", 200)
    wallet = registry.refund_units("dana@ironclaw.test", 100)
    assert wallet.balance_units == 900


def test_refund_units_creates_refund_entry_type_in_ledger(registry: UnitWalletRegistry) -> None:
    registry.credit_units("dana@ironclaw.test", 1_000)
    registry.debit_units("dana@ironclaw.test", 200)
    registry.refund_units("dana@ironclaw.test", 100)
    entries = registry.list_ledger_entries(owner_key="dana@ironclaw.test")
    entry_types = [e.entry_type for e in entries]
    assert "refund" in entry_types


def test_refund_units_entry_has_correct_units_and_balance_after(registry: UnitWalletRegistry) -> None:
    registry.credit_units("dana@ironclaw.test", 1_000)
    registry.debit_units("dana@ironclaw.test", 200)
    registry.refund_units("dana@ironclaw.test", 100)
    entries = registry.list_ledger_entries(owner_key="dana@ironclaw.test")
    refund_entry = next(e for e in entries if e.entry_type == "refund")
    assert refund_entry.units == 100
    assert refund_entry.balance_after == 900


def test_refund_units_does_not_affect_total_purchased_units(registry: UnitWalletRegistry) -> None:
    registry.credit_units("dana@ironclaw.test", 1_000)
    registry.debit_units("dana@ironclaw.test", 200)
    wallet = registry.refund_units("dana@ironclaw.test", 100)
    assert wallet.total_purchased_units == 1_000


# ---------------------------------------------------------------------------
# list_ledger_entries — filtering
# ---------------------------------------------------------------------------


def test_list_ledger_entries_without_owner_key_returns_all_entries(registry: UnitWalletRegistry) -> None:
    registry.credit_units("eve@ironclaw.test", 500)
    registry.credit_units("frank@ironclaw.test", 500)
    entries = registry.list_ledger_entries()
    owner_keys = {e.owner_key for e in entries}
    assert "eve@ironclaw.test" in owner_keys
    assert "frank@ironclaw.test" in owner_keys


def test_list_ledger_entries_filters_by_owner_key(registry: UnitWalletRegistry) -> None:
    registry.credit_units("eve@ironclaw.test", 500)
    registry.credit_units("frank@ironclaw.test", 500)
    entries = registry.list_ledger_entries(owner_key="eve@ironclaw.test")
    for entry in entries:
        assert entry.owner_key == "eve@ironclaw.test"


def test_list_ledger_entries_unknown_owner_returns_empty_list(registry: UnitWalletRegistry) -> None:
    entries = registry.list_ledger_entries(owner_key="ghost@ironclaw.test")
    assert entries == []


def test_list_ledger_entries_limit_is_respected(registry: UnitWalletRegistry) -> None:
    registry.credit_units("grace@ironclaw.test", 100)
    for _ in range(10):
        registry.debit_units("grace@ironclaw.test", 1)
    entries = registry.list_ledger_entries(owner_key="grace@ironclaw.test", limit=5)
    assert len(entries) <= 5


def test_list_ledger_entries_entry_fields_are_complete(registry: UnitWalletRegistry) -> None:
    registry.credit_units("henry@ironclaw.test", 200)
    entries = registry.list_ledger_entries(owner_key="henry@ironclaw.test")
    assert len(entries) >= 1
    entry = entries[0]
    assert entry.entry_id.startswith("ledger_")
    assert entry.wallet_id.startswith("wallet_")
    assert entry.owner_key == "henry@ironclaw.test"
    assert entry.entry_type == "credit"
    assert entry.units == 200
    assert entry.balance_after == 200
    assert entry.created_at is not None


# ---------------------------------------------------------------------------
# debit_units_for_tokens
# ---------------------------------------------------------------------------


def test_debit_units_for_tokens_exact_boundary_debits_one_unit(registry: UnitWalletRegistry) -> None:
    registry.credit_units("ivan@ironclaw.test", 10)
    wallet, debited = registry.debit_units_for_tokens("ivan@ironclaw.test", TOKEN_CHUNK_SIZE)
    assert debited == 1
    assert wallet.balance_units == 9


def test_debit_units_for_tokens_one_over_boundary_debits_two_units(registry: UnitWalletRegistry) -> None:
    registry.credit_units("ivan@ironclaw.test", 10)
    wallet, debited = registry.debit_units_for_tokens("ivan@ironclaw.test", TOKEN_CHUNK_SIZE + 1)
    assert debited == 2
    assert wallet.balance_units == 8


def test_debit_units_for_tokens_raises_insufficient_units_error(registry: UnitWalletRegistry) -> None:
    registry.credit_units("ivan@ironclaw.test", 1)
    with pytest.raises(InsufficientUnitsError):
        registry.debit_units_for_tokens("ivan@ironclaw.test", TOKEN_CHUNK_SIZE * 3)


def test_debit_units_for_tokens_returns_correct_units_debited(registry: UnitWalletRegistry) -> None:
    registry.credit_units("ivan@ironclaw.test", 10)
    _, debited = registry.debit_units_for_tokens("ivan@ironclaw.test", TOKEN_CHUNK_SIZE * 2)
    assert debited == 2


# ---------------------------------------------------------------------------
# debit_units_for_install_key — happy path
# ---------------------------------------------------------------------------


def test_debit_units_for_install_key_reduces_balance(registry: UnitWalletRegistry) -> None:
    registry.credit_units("key_user@ironclaw.test", 1_000)
    wallet, usage, entry = registry.debit_units_for_install_key(
        owner_key="key_user@ironclaw.test",
        key_id="key_abc123",
        program="claude",
        units=50,
    )
    assert wallet.balance_units == 950
    assert wallet.total_consumed_units == 50


def test_debit_units_for_install_key_entry_type_is_install_key_debit(registry: UnitWalletRegistry) -> None:
    registry.credit_units("key_user@ironclaw.test", 1_000)
    registry.debit_units_for_install_key(
        owner_key="key_user@ironclaw.test",
        key_id="key_abc123",
        program="claude",
        units=50,
    )
    entries = registry.list_ledger_entries(owner_key="key_user@ironclaw.test")
    debit_entry = next(e for e in entries if e.entry_type == "install_key_debit")
    assert debit_entry.entry_type == "install_key_debit"


def test_debit_units_for_install_key_metadata_contains_key_id(registry: UnitWalletRegistry) -> None:
    registry.credit_units("key_user@ironclaw.test", 1_000)
    registry.debit_units_for_install_key(
        owner_key="key_user@ironclaw.test",
        key_id="key_abc123",
        program="claude",
        units=50,
    )
    entries = registry.list_ledger_entries(owner_key="key_user@ironclaw.test")
    debit_entry = next(e for e in entries if e.entry_type == "install_key_debit")
    assert debit_entry.metadata.get("key_id") == "key_abc123"


def test_debit_units_for_install_key_metadata_contains_program(registry: UnitWalletRegistry) -> None:
    registry.credit_units("key_user@ironclaw.test", 1_000)
    registry.debit_units_for_install_key(
        owner_key="key_user@ironclaw.test",
        key_id="key_abc123",
        program="claude",
        units=50,
    )
    entries = registry.list_ledger_entries(owner_key="key_user@ironclaw.test")
    debit_entry = next(e for e in entries if e.entry_type == "install_key_debit")
    assert debit_entry.metadata.get("program") == "claude"


def test_debit_units_for_install_key_balance_after_is_correct_in_ledger(registry: UnitWalletRegistry) -> None:
    registry.credit_units("key_user@ironclaw.test", 1_000)
    registry.debit_units_for_install_key(
        owner_key="key_user@ironclaw.test",
        key_id="key_abc123",
        program="claude",
        units=50,
    )
    entries = registry.list_ledger_entries(owner_key="key_user@ironclaw.test")
    debit_entry = next(e for e in entries if e.entry_type == "install_key_debit")
    assert debit_entry.balance_after == 950


def test_debit_units_for_install_key_exact_balance_empties_wallet(registry: UnitWalletRegistry) -> None:
    registry.credit_units("key_user@ironclaw.test", 100)
    wallet, usage, entry = registry.debit_units_for_install_key(
        owner_key="key_user@ironclaw.test",
        key_id="key_exact",
        program="openai",
        units=100,
    )
    assert wallet.balance_units == 0


# ---------------------------------------------------------------------------
# debit_units_for_install_key — InsufficientUnitsError propagation
# ---------------------------------------------------------------------------


def test_debit_units_for_install_key_raises_insufficient_units_error(registry: UnitWalletRegistry) -> None:
    registry.credit_units("key_broke@ironclaw.test", 10)
    with pytest.raises(InsufficientUnitsError):
        registry.debit_units_for_install_key(
            owner_key="key_broke@ironclaw.test",
            key_id="key_over",
            program="groq",
            units=999,
        )


def test_debit_units_for_install_key_error_have_attribute_is_correct(registry: UnitWalletRegistry) -> None:
    registry.credit_units("key_broke@ironclaw.test", 10)
    with pytest.raises(InsufficientUnitsError) as exc_info:
        registry.debit_units_for_install_key(
            owner_key="key_broke@ironclaw.test",
            key_id="key_over",
            program="groq",
            units=999,
        )
    assert exc_info.value.have == 10


def test_debit_units_for_install_key_error_need_attribute_is_correct(registry: UnitWalletRegistry) -> None:
    registry.credit_units("key_broke@ironclaw.test", 10)
    with pytest.raises(InsufficientUnitsError) as exc_info:
        registry.debit_units_for_install_key(
            owner_key="key_broke@ironclaw.test",
            key_id="key_over",
            program="groq",
            units=999,
        )
    assert exc_info.value.need == 999


def test_debit_units_for_install_key_error_does_not_mutate_balance(registry: UnitWalletRegistry) -> None:
    registry.credit_units("key_broke@ironclaw.test", 10)
    with pytest.raises(InsufficientUnitsError):
        registry.debit_units_for_install_key(
            owner_key="key_broke@ironclaw.test",
            key_id="key_over",
            program="groq",
            units=999,
        )
    wallet = registry.get_wallet("key_broke@ironclaw.test")
    assert wallet is not None
    assert wallet.balance_units == 10


def test_debit_units_for_install_key_zero_wallet_raises_insufficient_units_error(registry: UnitWalletRegistry) -> None:
    with pytest.raises(InsufficientUnitsError) as exc_info:
        registry.debit_units_for_install_key(
            owner_key="key_empty@ironclaw.test",
            key_id="key_zero",
            program="claude",
            units=1,
        )
    assert exc_info.value.have == 0
    assert exc_info.value.need == 1


# ---------------------------------------------------------------------------
# get_or_create_wallet idempotency
# ---------------------------------------------------------------------------


def test_get_or_create_wallet_is_idempotent(registry: UnitWalletRegistry) -> None:
    w1 = registry.get_or_create_wallet("judy@ironclaw.test")
    w2 = registry.get_or_create_wallet("judy@ironclaw.test")
    assert w1.wallet_id == w2.wallet_id


def test_get_wallet_returns_none_for_unknown_owner(registry: UnitWalletRegistry) -> None:
    assert registry.get_wallet("nobody@ironclaw.test") is None


def test_get_or_create_wallet_ignores_stale_none_cache_entry(registry: UnitWalletRegistry) -> None:
    owner_key = "stale-cache@ironclaw.test"
    registry._wallets_by_owner[owner_key] = "stale_wallet_id"
    registry._wallets["stale_wallet_id"] = None  # type: ignore[assignment]

    wallet = registry.get_or_create_wallet(owner_key)

    assert wallet is not None
    assert wallet.owner_key == owner_key
    assert wallet.wallet_id.startswith("wallet_")


def test_get_wallet_returns_wallet_after_credit(registry: UnitWalletRegistry) -> None:
    registry.credit_units("judy@ironclaw.test", 50)
    wallet = registry.get_wallet("judy@ironclaw.test")
    assert wallet is not None
    assert wallet.balance_units == 50
