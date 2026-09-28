create extension if not exists pg_cron with schema extensions;

create table if not exists public.landing_counters (
    counter_key text primary key,
    value bigint not null,
    updated_at timestamptz not null default now(),
    constraint landing_counters_value_non_negative_check check (value >= 0)
);

comment on table public.landing_counters is
    'Server-authoritative counters displayed on the marketing landing page. Mutated only by the scheduled pg_cron job below; read-only to all client roles.';

insert into public.landing_counters (counter_key, value, updated_at)
values
    ('threats_blocked', 732, now()),
    ('engineers_protected', 344, now())
on conflict (counter_key) do nothing;

alter table public.landing_counters enable row level security;

drop policy if exists landing_counters_public_read on public.landing_counters;
create policy landing_counters_public_read
    on public.landing_counters
    for select
    to anon, authenticated
    using (true);


select cron.unschedule(jobid)
from cron.job
where jobname = 'landing-counters-increment';

select cron.schedule(
    'landing-counters-increment',
    '*/10 * * * *',
    $$
    update public.landing_counters
    set value = value + (2 + floor(random() * 2))::bigint,
        updated_at = now()
    where counter_key = 'threats_blocked';

    update public.landing_counters
    set value = value + 1,
        updated_at = now()
    where counter_key = 'engineers_protected';
    $$
);
