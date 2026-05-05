create table if not exists public.runtime_sessions (
    id uuid primary key default gen_random_uuid(),
    session_key text not null unique,
    mode text not null default 'monitor',
    status text not null default 'active',
    current_stage text not null default 'intake',
    risk_level text not null default 'low',
    source text not null default 'runtime',
    started_at timestamptz not null default timezone('utc', now()),
    last_heartbeat_at timestamptz not null default timezone('utc', now()),
    ended_at timestamptz,
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint runtime_sessions_mode_check
        check (mode in ('monitor', 'enforce', 'simulation')),
    constraint runtime_sessions_status_check
        check (status in ('active', 'paused', 'completed', 'failed', 'terminated')),
    constraint runtime_sessions_stage_check
        check (current_stage in ('intake', 'analysis', 'policy', 'review', 'response', 'closed')),
    constraint runtime_sessions_risk_level_check
        check (risk_level in ('low', 'medium', 'high', 'critical'))
);

create table if not exists public.runtime_state_checkpoints (
    id uuid primary key default gen_random_uuid(),
    runtime_session_id uuid not null references public.runtime_sessions(id) on delete cascade,
    checkpoint_type text not null,
    stage text not null,
    state jsonb not null default '{}'::jsonb,
    notes text not null default '',
    created_at timestamptz not null default timezone('utc', now()),
    constraint runtime_state_checkpoints_stage_check
        check (stage in ('intake', 'analysis', 'policy', 'review', 'response', 'closed'))
);

create table if not exists public.runtime_review_queue (
    id uuid primary key default gen_random_uuid(),
    runtime_session_id uuid not null references public.runtime_sessions(id) on delete cascade,
    analysis_report_id uuid references public.analysis_reports(id) on delete set null,
    quarantine_event_id uuid references public.quarantine_events(id) on delete set null,
    priority text not null default 'normal',
    status text not null default 'pending',
    assigned_to text,
    queue_reason text not null,
    payload jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    resolved_at timestamptz,
    constraint runtime_review_queue_priority_check
        check (priority in ('low', 'normal', 'high', 'urgent')),
    constraint runtime_review_queue_status_check
        check (status in ('pending', 'in_review', 'approved', 'rejected', 'resolved'))
);

create table if not exists public.runtime_incidents (
    id uuid primary key default gen_random_uuid(),
    runtime_session_id uuid not null references public.runtime_sessions(id) on delete cascade,
    review_queue_id uuid references public.runtime_review_queue(id) on delete set null,
    severity text not null,
    status text not null default 'open',
    title text not null,
    description text not null default '',
    evidence jsonb not null default '{}'::jsonb,
    opened_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    closed_at timestamptz,
    constraint runtime_incidents_severity_check
        check (severity in ('low', 'medium', 'high', 'critical')),
    constraint runtime_incidents_status_check
        check (status in ('open', 'investigating', 'contained', 'resolved', 'closed'))
);

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
    new.updated_at = timezone('utc', now());
    return new;
end;
$$;

drop trigger if exists trg_runtime_sessions_updated_at on public.runtime_sessions;
create trigger trg_runtime_sessions_updated_at
before update on public.runtime_sessions
for each row
execute function public.set_updated_at();

drop trigger if exists trg_runtime_review_queue_updated_at on public.runtime_review_queue;
create trigger trg_runtime_review_queue_updated_at
before update on public.runtime_review_queue
for each row
execute function public.set_updated_at();

drop trigger if exists trg_runtime_incidents_updated_at on public.runtime_incidents;
create trigger trg_runtime_incidents_updated_at
before update on public.runtime_incidents
for each row
execute function public.set_updated_at();

create index if not exists idx_runtime_sessions_status
    on public.runtime_sessions (status);

create index if not exists idx_runtime_sessions_risk_level
    on public.runtime_sessions (risk_level);

create index if not exists idx_runtime_sessions_started_at
    on public.runtime_sessions (started_at desc);

create index if not exists idx_runtime_state_checkpoints_runtime_session_id
    on public.runtime_state_checkpoints (runtime_session_id);

create index if not exists idx_runtime_state_checkpoints_created_at
    on public.runtime_state_checkpoints (created_at desc);

create index if not exists idx_runtime_review_queue_runtime_session_id
    on public.runtime_review_queue (runtime_session_id);

create index if not exists idx_runtime_review_queue_status
    on public.runtime_review_queue (status);

create index if not exists idx_runtime_review_queue_priority
    on public.runtime_review_queue (priority);

create index if not exists idx_runtime_review_queue_created_at
    on public.runtime_review_queue (created_at desc);

create index if not exists idx_runtime_incidents_runtime_session_id
    on public.runtime_incidents (runtime_session_id);

create index if not exists idx_runtime_incidents_status
    on public.runtime_incidents (status);

create index if not exists idx_runtime_incidents_severity
    on public.runtime_incidents (severity);

create index if not exists idx_runtime_incidents_opened_at
    on public.runtime_incidents (opened_at desc);