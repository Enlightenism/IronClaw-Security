# tests/core/test_landing_page_counters_migration.py
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import re

import pytest

_MIGRATION_PATH = Path(__file__).resolve().parents[2] / "supabase" / "migrations" / "011_landing_page_counters.sql"

_UINT32_MASK = 0xFFFFFFFF
_THREATS_SEED = 1736102489
_ENGINEERS_SEED = 2406839077
_ANCHOR_AT = datetime(2026, 10, 13, 6, 0, tzinfo=UTC)
_TICK_SECONDS = 600

_HASH_VECTORS: tuple[tuple[int, int, int], ...] = (
    (_THREATS_SEED, 0, 3056090455),
    (_THREATS_SEED, 1, 3622855923),
    (_THREATS_SEED, 2, 3510258675),
    (_THREATS_SEED, 3, 2279842973),
    (_THREATS_SEED, 10, 1574579506),
    (_THREATS_SEED, 2933333, 2889397415),
    (_THREATS_SEED, 2933334, 3355178022),
    (_THREATS_SEED, 4294967295, 3250598578),
    (_ENGINEERS_SEED, 0, 1995626446),
    (_ENGINEERS_SEED, 1, 650592004),
    (_ENGINEERS_SEED, 2, 2890143157),
    (_ENGINEERS_SEED, 3, 3113384485),
    (_ENGINEERS_SEED, 10, 1957474908),
    (_ENGINEERS_SEED, 2933333, 2958952686),
    (_ENGINEERS_SEED, 2933334, 4012410247),
    (_ENGINEERS_SEED, 4294967295, 9659748),
)

_VALUE_VECTORS: tuple[tuple[int, int, int], ...] = (
    (0, 732, 344),
    (600, 734, 345),
    (6000, 754, 354),
    (86400, 1084, 488),
    (86400 * 30, 11493, 4664),
    (86400 * 365, 131914, 52904),
)


def _sql() -> str:
    return _MIGRATION_PATH.read_text(encoding="utf-8")


def _normalized_sql() -> str:
    return re.sub(r"\s+", " ", _sql().lower())


def _mul32(a: int, b: int) -> int:
    return ((a * (b & 65535)) + (((a * (b >> 16)) & 65535) << 16)) & _UINT32_MASK


def _hash32(seed: int, tick: int) -> int:
    h = (_mul32(tick & _UINT32_MASK, 2654435761) + seed) & _UINT32_MASK
    h ^= h >> 16
    h = _mul32(h, 2246822507)
    h ^= h >> 13
    h = _mul32(h, 3266489909)
    h ^= h >> 16
    return h


def _step(seed: int, tick: int, step_min: int, step_max: int) -> int:
    return step_min + (_hash32(seed, tick) % (step_max - step_min + 1))


def _compute(
    anchor_value: int,
    anchor_epoch: int,
    tick_seconds: int,
    step_min: int,
    step_max: int,
    seed: int,
    at_epoch: int,
) -> int:
    first = anchor_epoch // tick_seconds + 1
    last = at_epoch // tick_seconds
    return anchor_value + sum(_step(seed, k, step_min, step_max) for k in range(first, last + 1))


def _threats(at_epoch: int, anchor_value: int = 732, anchor_epoch: int | None = None) -> int:
    epoch = int(_ANCHOR_AT.timestamp()) if anchor_epoch is None else anchor_epoch
    return _compute(anchor_value, epoch, _TICK_SECONDS, 2, 3, _THREATS_SEED, at_epoch)


def _engineers(at_epoch: int) -> int:
    return _compute(344, int(_ANCHOR_AT.timestamp()), _TICK_SECONDS, 1, 1, _ENGINEERS_SEED, at_epoch)


class TestLandingCountersMigrationDefinition:
    def test_migration_file_exists(self) -> None:
        assert _MIGRATION_PATH.is_file()

    def test_pg_cron_is_fully_removed(self) -> None:
        sql = _normalized_sql()
        assert "pg_cron" not in sql
        assert "cron.schedule" not in sql
        assert "cron.unschedule" not in sql
        assert "cron.job" not in sql

    def test_table_has_required_columns(self) -> None:
        sql = _normalized_sql()
        assert "create table if not exists public.landing_counters" in sql
        for column in (
            "counter_key text primary key",
            "anchor_value bigint not null",
            "anchor_at timestamptz not null",
            "tick_seconds integer not null",
            "step_min integer not null",
            "step_max integer not null",
            "seed bigint not null",
            "updated_at timestamptz not null default now()",
        ):
            assert column in sql

    def test_table_constraints_are_present(self) -> None:
        sql = _normalized_sql()
        for constraint in (
            "landing_counters_anchor_value_non_negative_check",
            "landing_counters_tick_seconds_positive_check",
            "landing_counters_step_min_non_negative_check",
            "landing_counters_step_range_check",
            "landing_counters_seed_range_check",
        ):
            assert constraint in sql

    def test_seed_rows_match_contract(self) -> None:
        sql = _normalized_sql()
        assert "('threats_blocked', 732, '2026-10-13 06:00:00+00', 600, 2, 3, 1736102489)" in sql
        assert "('engineers_protected', 344, '2026-10-13 06:00:00+00', 600, 1, 1, 2406839077)" in sql
        assert "on conflict (counter_key) do nothing" in sql

    def test_seed_anchor_is_fixed_and_not_now(self) -> None:
        sql = _normalized_sql()
        values_block = sql.split("insert into public.landing_counters", 1)[1].split("on conflict", 1)[0]
        assert "now()" not in values_block
        assert "do update" not in sql

    def test_seed_anchor_is_tick_aligned(self) -> None:
        assert int(_ANCHOR_AT.timestamp()) % _TICK_SECONDS == 0


class TestLandingCountersMigrationSecurity:
    def test_rls_enabled_with_read_only_public_policy(self) -> None:
        sql = _normalized_sql()
        assert "alter table public.landing_counters enable row level security" in sql
        assert "drop policy if exists landing_counters_public_read on public.landing_counters" in sql
        assert ("create policy landing_counters_public_read on public.landing_counters for select to anon, authenticated using (true)") in sql

    def test_client_roles_cannot_write_table(self) -> None:
        sql = _normalized_sql()
        assert "revoke all on table public.landing_counters from public, anon, authenticated, service_role" in sql
        assert "grant select on table public.landing_counters to anon, authenticated" in sql
        assert "grant select, update on table public.landing_counters to service_role" in sql
        assert "grant insert" not in sql
        assert "grant delete" not in sql

    def test_security_definer_functions_pin_empty_search_path(self) -> None:
        sql = _normalized_sql()
        definers = sql.count("security definer")
        assert definers == 4
        assert sql.count("set search_path = ''") == 7
        for name in (
            "landing_counter_mul32",
            "landing_counter_hash32",
            "landing_counter_compute",
            "landing_counter_value",
            "get_landing_counters",
            "upgrade_landing_counter",
            "landing_counters_enforce_monotonic",
        ):
            assert f"create or replace function public.{name}" in sql

    def test_pure_helpers_are_immutable(self) -> None:
        sql = _normalized_sql()
        for name in ("landing_counter_mul32", "landing_counter_hash32", "landing_counter_compute"):
            head = sql.split(f"create or replace function public.{name}", 1)[1].split("as $$", 1)[0]
            assert " immutable " in f" {head} "

    def test_table_reading_function_is_not_immutable(self) -> None:
        sql = _normalized_sql()
        head = sql.split("create or replace function public.landing_counter_value", 1)[1].split("as $$", 1)[0]
        assert " stable " in f" {head} "
        assert " immutable " not in f" {head} "

    def test_public_rpc_is_callable_by_anon_and_authenticated(self) -> None:
        sql = _normalized_sql()
        assert "revoke all on function public.get_landing_counters() from public, anon, authenticated" in sql
        assert "grant execute on function public.get_landing_counters() to anon, authenticated, service_role" in sql

    def test_upgrade_function_is_service_role_only(self) -> None:
        sql = _normalized_sql()
        revoke = "revoke all on function public.upgrade_landing_counter(text, bigint) from public, anon, authenticated"
        grant = "grant execute on function public.upgrade_landing_counter(text, bigint) to service_role;"
        assert revoke in sql
        assert grant in sql

    def test_internal_helpers_are_not_exposed_to_client_roles(self) -> None:
        sql = _normalized_sql()
        for name in ("landing_counter_mul32", "landing_counter_hash32", "landing_counters_enforce_monotonic"):
            assert f"grant execute on function public.{name}" not in sql

    def test_upgrade_function_only_moves_forward(self) -> None:
        sql = _normalized_sql()
        assert "greatest(p_new_value, v_current)" in sql
        assert "for update" in sql
        assert "p_new_value < 0" in sql

    def test_monotonic_trigger_rejects_decrease_and_delete(self) -> None:
        sql = _normalized_sql()
        assert "before update or delete on public.landing_counters" in sql
        assert "for each row execute function public.landing_counters_enforce_monotonic()" in sql
        assert "if v_new < v_old then" in sql
        assert "cannot decrease" in sql
        assert "cannot be deleted" in sql
        assert "new.counter_key is distinct from old.counter_key" in sql

    def test_get_landing_counters_returns_value_and_server_time(self) -> None:
        sql = _normalized_sql()
        head = sql.split("create or replace function public.get_landing_counters", 1)[1].split("as $$", 1)[0]
        for column in ("counter_key text", "value bigint", "server_time timestamptz"):
            assert column in head


class TestLandingCounterFormulaContract:
    @pytest.mark.parametrize(("seed", "tick", "expected"), _HASH_VECTORS)
    def test_hash_vectors_are_stable(self, seed: int, tick: int, expected: int) -> None:
        assert _hash32(seed, tick) == expected

    def test_mul32_matches_exact_modular_product(self) -> None:
        for a in (0, 1, 65535, 65536, 2**31, _UINT32_MASK):
            for b in (0, 1, 2654435761, 2246822507, 3266489909, _UINT32_MASK):
                assert _mul32(a, b) == (a * b) & _UINT32_MASK

    def test_sql_uses_the_same_hash_constants(self) -> None:
        sql = _normalized_sql()
        for constant in ("2654435761", "2246822507", "3266489909", "h >> 16", "h >> 13"):
            assert constant in sql

    @pytest.mark.parametrize(("offset", "threats", "engineers"), _VALUE_VECTORS)
    def test_value_vectors_from_anchor(self, offset: int, threats: int, engineers: int) -> None:
        at_epoch = int(_ANCHOR_AT.timestamp()) + offset
        assert _threats(at_epoch) == threats
        assert _engineers(at_epoch) == engineers

    def test_value_before_anchor_is_anchor_value(self) -> None:
        before = int(_ANCHOR_AT.timestamp()) - 86400 * 400
        assert _threats(before) == 732
        assert _engineers(before) == 344

    def test_threat_steps_stay_in_two_to_three_band(self) -> None:
        steps = {_step(_THREATS_SEED, k, 2, 3) for k in range(1, 20001)}
        assert steps == {2, 3}

    def test_engineer_steps_are_exactly_one(self) -> None:
        assert {_step(_ENGINEERS_SEED, k, 1, 1) for k in range(1, 20001)} == {1}

    def test_values_only_increase_over_100000_ticks(self) -> None:
        first = int(_ANCHOR_AT.timestamp()) // _TICK_SECONDS
        previous = 732
        for k in range(first + 1, first + 100001):
            current = previous + _step(_THREATS_SEED, k, 2, 3)
            assert current > previous
            previous = current

    def test_value_is_identical_for_any_reader_at_the_same_instant(self) -> None:
        at_epoch = int(_ANCHOR_AT.timestamp()) + 86400 * 3 + 123
        assert _threats(at_epoch) == _threats(at_epoch)
        assert _threats(at_epoch) == _threats(at_epoch - 123 + 599)

    def test_reanchor_to_current_value_preserves_future_values(self) -> None:
        anchor_epoch = int(_ANCHOR_AT.timestamp())
        reanchor_epoch = ((anchor_epoch + 86400 * 10 + 301) // _TICK_SECONDS) * _TICK_SECONDS
        current = _threats(reanchor_epoch)
        future = anchor_epoch + 86400 * 20 + 77
        assert _threats(future, anchor_value=current, anchor_epoch=reanchor_epoch) == _threats(future)

    def test_reanchor_to_higher_value_never_lowers_the_counter(self) -> None:
        anchor_epoch = int(_ANCHOR_AT.timestamp())
        reanchor_epoch = ((anchor_epoch + 86400 * 5) // _TICK_SECONDS) * _TICK_SECONDS
        current = _threats(reanchor_epoch)
        raised = max(current + 1000, current)
        assert _threats(reanchor_epoch, anchor_value=raised, anchor_epoch=reanchor_epoch) >= current
        for offset in (0, 599, 600, 86400):
            at_epoch = reanchor_epoch + offset
            assert _threats(at_epoch, anchor_value=raised, anchor_epoch=reanchor_epoch) >= _threats(at_epoch)

    def test_no_reset_after_more_than_24_hours(self) -> None:
        anchor_epoch = int(_ANCHOR_AT.timestamp())
        assert _threats(anchor_epoch + 86400 * 2) > 732
        assert _engineers(anchor_epoch + 86400 * 2) > 344
