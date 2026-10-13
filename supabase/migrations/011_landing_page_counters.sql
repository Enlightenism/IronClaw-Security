-- =============================================================================
-- 011_landing_page_counters.sql
-- Deterministic, globally consistent landing page counters.
-- Creates:
--   public.landing_counters             — per-counter anchor + step configuration
--   public.landing_counter_mul32        — 32-bit unsigned multiply helper
--   public.landing_counter_hash32       — integer hash (mirrored by the frontend)
--   public.landing_counter_compute      — pure counter formula (IMMUTABLE)
--   public.landing_counter_value        — counter value for a key at a time
--   public.get_landing_counters         — public read RPC (value + server time)
--   public.upgrade_landing_counter      — service_role-only forward re-anchor
--   public.landing_counters_enforce_monotonic — trigger: counters never go down
-- Formula (k = floor(epoch_seconds / tick_seconds), absolute tick index):
--   value(at) = anchor_value
--             + sum over k in (k(anchor_at), k(at)] of
--               step_min + (hash32(seed, k) mod (step_max - step_min + 1))
-- No scheduled job: every client derives the same value from time alone.
-- Safe to re-run: seed rows use ON CONFLICT DO NOTHING with a fixed anchor_at.
-- =============================================================================

-- =============================================================================
-- SECTION 1 — Table
-- =============================================================================

create table if not exists public.landing_counters (
    counter_key text primary key,
    anchor_value bigint not null,
    anchor_at timestamptz not null,
    tick_seconds integer not null,
    step_min integer not null,
    step_max integer not null,
    seed bigint not null,
    updated_at timestamptz not null default now(),
    constraint landing_counters_anchor_value_non_negative_check check (anchor_value >= 0),
    constraint landing_counters_tick_seconds_positive_check check (tick_seconds > 0),
    constraint landing_counters_step_min_non_negative_check check (step_min >= 0),
    constraint landing_counters_step_range_check check (step_max >= step_min),
    constraint landing_counters_seed_range_check check (seed between 0 and 4294967295)
);

comment on table public.landing_counters is
    'Server-authoritative anchors for the marketing landing page counters. Values are derived from time via landing_counter_compute; rows are read-only to client roles and can only move forward through upgrade_landing_counter.';

insert into public.landing_counters (
    counter_key,
    anchor_value,
    anchor_at,
    tick_seconds,
    step_min,
    step_max,
    seed
)
values
    ('threats_blocked', 732, '2026-10-13 06:00:00+00', 600, 2, 3, 1736102489),
    ('engineers_protected', 344, '2026-10-13 06:00:00+00', 600, 1, 1, 2406839077)
on conflict (counter_key) do nothing;

-- =============================================================================
-- SECTION 2 — Pure helpers (hash + formula)
-- =============================================================================

create or replace function public.landing_counter_mul32(a bigint, b bigint)
returns bigint
language sql
immutable
parallel safe
set search_path = ''
as $$
    select (
        (a * (b & 65535))
        + ((((a * (b >> 16)) & 65535)) << 16)
    ) & 4294967295
$$;

create or replace function public.landing_counter_hash32(p_seed bigint, p_tick bigint)
returns bigint
language plpgsql
immutable
parallel safe
set search_path = ''
as $$
declare
    h bigint;
begin
    h := (public.landing_counter_mul32(p_tick & 4294967295, 2654435761) + p_seed) & 4294967295;
    h := h # (h >> 16);
    h := public.landing_counter_mul32(h, 2246822507);
    h := h # (h >> 13);
    h := public.landing_counter_mul32(h, 3266489909);
    h := h # (h >> 16);
    return h;
end;
$$;

create or replace function public.landing_counter_compute(
    p_anchor_value bigint,
    p_anchor_at timestamptz,
    p_tick_seconds integer,
    p_step_min integer,
    p_step_max integer,
    p_seed bigint,
    p_at timestamptz
)
returns bigint
language sql
immutable
parallel safe
set search_path = ''
as $$
    select (
        p_anchor_value
        + coalesce(
            sum(
                p_step_min
                + (public.landing_counter_hash32(p_seed, k) % (p_step_max - p_step_min + 1))
            ),
            0
        )
    )::bigint
    from generate_series(
        floor(extract(epoch from p_anchor_at) / p_tick_seconds)::bigint + 1,
        floor(extract(epoch from p_at) / p_tick_seconds)::bigint
    ) as k
$$;

create or replace function public.landing_counter_value(p_key text, p_at timestamptz default now())
returns bigint
language sql
stable
security definer
set search_path = ''
as $$
    select public.landing_counter_compute(
        c.anchor_value,
        c.anchor_at,
        c.tick_seconds,
        c.step_min,
        c.step_max,
        c.seed,
        p_at
    )
    from public.landing_counters as c
    where c.counter_key = p_key
$$;

-- =============================================================================
-- SECTION 3 — Public read RPC
-- =============================================================================

create or replace function public.get_landing_counters()
returns table (
    counter_key text,
    value bigint,
    server_time timestamptz,
    anchor_value bigint,
    anchor_at timestamptz,
    tick_seconds integer,
    step_min integer,
    step_max integer,
    seed bigint
)
language sql
stable
security definer
set search_path = ''
as $$
    select
        c.counter_key,
        public.landing_counter_value(c.counter_key, now()),
        now(),
        c.anchor_value,
        c.anchor_at,
        c.tick_seconds,
        c.step_min,
        c.step_max,
        c.seed
    from public.landing_counters as c
    order by c.counter_key
$$;

-- =============================================================================
-- SECTION 4 — Forward-only upgrade (service_role)
-- =============================================================================

create or replace function public.upgrade_landing_counter(p_key text, p_new_value bigint)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_current bigint;
    v_new bigint;
begin
    if p_new_value is null or p_new_value < 0 then
        raise exception 'p_new_value must be a non-negative bigint'
            using errcode = '22023';
    end if;

    perform 1
    from public.landing_counters
    where counter_key = p_key
    for update;

    if not found then
        raise exception 'unknown landing counter: %', p_key
            using errcode = 'P0002';
    end if;

    v_current := public.landing_counter_value(p_key, now());
    v_new := greatest(p_new_value, v_current);

    update public.landing_counters
    set anchor_value = v_new,
        anchor_at = to_timestamp(floor(extract(epoch from now()) / tick_seconds) * tick_seconds),
        updated_at = now()
    where counter_key = p_key;

    return v_new;
end;
$$;

-- =============================================================================
-- SECTION 5 — Never-reset trigger
-- =============================================================================

create or replace function public.landing_counters_enforce_monotonic()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_old bigint;
    v_new bigint;
begin
    if tg_op = 'DELETE' then
        raise exception 'landing counter % cannot be deleted', old.counter_key
            using errcode = '23001';
    end if;

    if new.counter_key is distinct from old.counter_key then
        raise exception 'landing counter key % is immutable', old.counter_key
            using errcode = '23001';
    end if;

    v_old := public.landing_counter_compute(
        old.anchor_value, old.anchor_at, old.tick_seconds, old.step_min, old.step_max, old.seed, now()
    );
    v_new := public.landing_counter_compute(
        new.anchor_value, new.anchor_at, new.tick_seconds, new.step_min, new.step_max, new.seed, now()
    );

    if v_new < v_old then
        raise exception 'landing counter % cannot decrease (% -> %)', old.counter_key, v_old, v_new
            using errcode = '23514';
    end if;

    new.updated_at := now();
    return new;
end;
$$;

drop trigger if exists landing_counters_enforce_monotonic on public.landing_counters;
create trigger landing_counters_enforce_monotonic
    before update or delete on public.landing_counters
    for each row
    execute function public.landing_counters_enforce_monotonic();

-- =============================================================================
-- SECTION 6 — RLS and privileges
-- =============================================================================

alter table public.landing_counters enable row level security;

drop policy if exists landing_counters_public_read on public.landing_counters;
create policy landing_counters_public_read
    on public.landing_counters
    for select
    to anon, authenticated
    using (true);

revoke all on table public.landing_counters from public, anon, authenticated, service_role;
grant select on table public.landing_counters to anon, authenticated;
grant select, update on table public.landing_counters to service_role;

revoke all on function public.landing_counter_mul32(bigint, bigint) from public, anon, authenticated;
revoke all on function public.landing_counter_hash32(bigint, bigint) from public, anon, authenticated;
revoke all on function public.landing_counter_compute(
    bigint, timestamptz, integer, integer, integer, bigint, timestamptz
) from public, anon, authenticated;
revoke all on function public.landing_counter_value(text, timestamptz) from public, anon, authenticated;
revoke all on function public.landing_counters_enforce_monotonic() from public, anon, authenticated;
revoke all on function public.get_landing_counters() from public, anon, authenticated;
revoke all on function public.upgrade_landing_counter(text, bigint) from public, anon, authenticated;

grant execute on function public.get_landing_counters() to anon, authenticated, service_role;
grant execute on function public.landing_counter_value(text, timestamptz) to service_role;
grant execute on function public.upgrade_landing_counter(text, bigint) to service_role;

-- =============================================================================
-- END 011_landing_page_counters.sql
-- =============================================================================
