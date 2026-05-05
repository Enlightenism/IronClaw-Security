begin;

create table if not exists public.runtime_state_snapshots (
    id uuid primary key default gen_random_uuid(),
    snapshot_key text not null unique,
    session_key text not null,
    runtime_name text not null,
    state_kind text not null,
    status text not null default 'active',
    checkpoint_id uuid references public.runtime_checkpoints(id) on delete set null,
    backend_id uuid references public.persistence_backends(id) on delete set null,
    parent_snapshot_id uuid references public.runtime_state_snapshots(id) on delete set null,
    sequence_no bigint not null default 0,
    captured_at timestamptz not null default timezone('utc', now()),
    expires_at timestamptz,
    state_version text not null default '1',
    integrity_hash text not null default '',
    payload jsonb not null default '{}'::jsonb,
    recovery_metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint runtime_state_snapshots_state_kind_check
        check (state_kind in ('session', 'pipeline', 'queue', 'checkpoint', 'supervisor', 'execution', 'review')),
    constraint runtime_state_snapshots_status_check
        check (status in ('active', 'superseded', 'restored', 'expired', 'corrupted')),
    constraint runtime_state_snapshots_sequence_no_check
        check (sequence_no >= 0)
);

create table if not exists public.runtime_sessions (
    id uuid primary key default gen_random_uuid(),
    session_key text not null unique,
    runtime_name text not null,
    session_type text not null,
    status text not null default 'active',
    org_id text,
    actor_id text,
    started_at timestamptz not null default timezone('utc', now()),
    last_seen_at timestamptz not null default timezone('utc', now()),
    ended_at timestamptz,
    expires_at timestamptz,
    current_snapshot_id uuid references public.runtime_state_snapshots(id) on delete set null,
    current_checkpoint_id uuid references public.runtime_checkpoints(id) on delete set null,
    failover_event_id uuid references public.persistence_failover_events(id) on delete set null,
    state_version text not null default '1',
    session_metadata jsonb not null default '{}'::jsonb,
    recovery_metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint runtime_sessions_session_type_check
        check (session_type in ('guard', 'scan', 'review', 'execution', 'supervisor', 'orchestrator')),
    constraint runtime_sessions_status_check
        check (status in ('active', 'idle', 'paused', 'restoring', 'completed', 'failed', 'expired'))
);

create table if not exists public.runtime_session_events (
    id uuid primary key default gen_random_uuid(),
    event_key text not null unique,
    session_id uuid not null references public.runtime_sessions(id) on delete cascade,
    event_type text not null,
    status text not null default 'recorded',
    sequence_no bigint not null,
    occurred_at timestamptz not null default timezone('utc', now()),
    actor_id text,
    actor_type text not null default 'system',
    request_id text,
    correlation_id text,
    payload jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint runtime_session_events_status_check
        check (status in ('recorded', 'replayed', 'ignored', 'failed')),
    constraint runtime_session_events_sequence_no_check
        check (sequence_no >= 0),
    constraint runtime_session_events_session_sequence_unique
        unique (session_id, sequence_no)
);

create table if not exists public.review_state_snapshots (
    id uuid primary key default gen_random_uuid(),
    snapshot_key text not null unique,
    review_item_id uuid references public.review_queue_items(id) on delete set null,
    session_id uuid references public.runtime_sessions(id) on delete set null,
    status text not null default 'active',
    decision_state text not null default 'pending',
    version_no bigint not null default 1,
    captured_at timestamptz not null default timezone('utc', now()),
    restored_at timestamptz,
    snapshot_data jsonb not null default '{}'::jsonb,
    evidence_data jsonb not null default '{}'::jsonb,
    recovery_metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint review_state_snapshots_status_check
        check (status in ('active', 'superseded', 'restored', 'expired')),
    constraint review_state_snapshots_decision_state_check
        check (decision_state in ('pending', 'approved', 'rejected', 'escalated', 'failed')),
    constraint review_state_snapshots_version_no_check
        check (version_no > 0)
);

create table if not exists public.queue_runtime_leases (
    id uuid primary key default gen_random_uuid(),
    lease_key text not null unique,
    queue_name text not null,
    owner_id text not null,
    session_id uuid references public.runtime_sessions(id) on delete set null,
    review_item_id uuid references public.review_queue_items(id) on delete set null,
    status text not null default 'held',
    acquired_at timestamptz not null default timezone('utc', now()),
    renew_by timestamptz not null,
    released_at timestamptz,
    lease_metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint queue_runtime_leases_status_check
        check (status in ('held', 'released', 'expired', 'stolen'))
);

create table if not exists public.runtime_replay_runs (
    id uuid primary key default gen_random_uuid(),
    replay_key text not null unique,
    session_id uuid references public.runtime_sessions(id) on delete set null,
    source_snapshot_id uuid references public.runtime_state_snapshots(id) on delete set null,
    target_checkpoint_id uuid references public.runtime_checkpoints(id) on delete set null,
    status text not null default 'planned',
    replay_reason text not null,
    started_at timestamptz,
    completed_at timestamptz,
    events_replayed bigint not null default 0,
    error_message text not null default '',
    replay_metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint runtime_replay_runs_status_check
        check (status in ('planned', 'running', 'completed', 'failed', 'cancelled')),
    constraint runtime_replay_runs_events_replayed_check
        check (events_replayed >= 0)
);

create table if not exists public.supervisor_state_snapshots (
    id uuid primary key default gen_random_uuid(),
    snapshot_key text not null unique,
    supervisor_name text not null,
    status text not null default 'active',
    backend_id uuid references public.persistence_backends(id) on delete set null,
    failover_event_id uuid references public.persistence_failover_events(id) on delete set null,
    captured_at timestamptz not null default timezone('utc', now()),
    restored_at timestamptz,
    snapshot_data jsonb not null default '{}'::jsonb,
    health_data jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint supervisor_state_snapshots_status_check
        check (status in ('active', 'superseded', 'restored', 'failed'))
);

create table if not exists public.pipeline_runtime_states (
    id uuid primary key default gen_random_uuid(),
    state_key text not null unique,
    session_id uuid references public.runtime_sessions(id) on delete set null,
    pipeline_name text not null,
    stage_name text not null,
    stage_order integer not null default 0,
    status text not null default 'pending',
    entered_at timestamptz not null default timezone('utc', now()),
    exited_at timestamptz,
    checkpoint_id uuid references public.runtime_checkpoints(id) on delete set null,
    snapshot_id uuid references public.runtime_state_snapshots(id) on delete set null,
    input_data jsonb not null default '{}'::jsonb,
    output_data jsonb not null default '{}'::jsonb,
    error_data jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint pipeline_runtime_states_stage_order_check
        check (stage_order >= 0),
    constraint pipeline_runtime_states_status_check
        check (status in ('pending', 'running', 'completed', 'failed', 'skipped', 'restored'))
);

create table if not exists public.orchestration_checkpoints (
    id uuid primary key default gen_random_uuid(),
    checkpoint_key text not null unique,
    session_id uuid references public.runtime_sessions(id) on delete set null,
    orchestration_name text not null,
    status text not null default 'active',
    step_name text not null,
    step_order integer not null default 0,
    captured_at timestamptz not null default timezone('utc', now()),
    restored_at timestamptz,
    checkpoint_data jsonb not null default '{}'::jsonb,
    dependency_state jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint orchestration_checkpoints_status_check
        check (status in ('active', 'superseded', 'restored', 'failed')),
    constraint orchestration_checkpoints_step_order_check
        check (step_order >= 0)
);

create trigger set_runtime_state_snapshots_updated_at
before update on public.runtime_state_snapshots
for each row execute function public.set_updated_at();

create trigger set_runtime_sessions_updated_at
before update on public.runtime_sessions
for each row execute function public.set_updated_at();

create trigger set_runtime_session_events_updated_at
before update on public.runtime_session_events
for each row execute function public.set_updated_at();

create trigger set_review_state_snapshots_updated_at
before update on public.review_state_snapshots
for each row execute function public.set_updated_at();

create trigger set_queue_runtime_leases_updated_at
before update on public.queue_runtime_leases
for each row execute function public.set_updated_at();

create trigger set_runtime_replay_runs_updated_at
before update on public.runtime_replay_runs
for each row execute function public.set_updated_at();

create trigger set_supervisor_state_snapshots_updated_at
before update on public.supervisor_state_snapshots
for each row execute function public.set_updated_at();

create trigger set_pipeline_runtime_states_updated_at
before update on public.pipeline_runtime_states
for each row execute function public.set_updated_at();

create trigger set_orchestration_checkpoints_updated_at
before update on public.orchestration_checkpoints
for each row execute function public.set_updated_at();

insert into public.persistence_migrations (
    migration_key,
    description,
    applied_by,
    checksum,
    metadata
)
values (
    '002_runtime_state_schema',
    'Runtime session, snapshot, replay, queue lease, supervisor, pipeline, and orchestration persistence schema for IronClaw.',
    'system',
    '',
    jsonb_build_object('section', 'data_lifecycle_and_resilience')
)
on conflict (migration_key) do nothing;

commit;