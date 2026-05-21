begin;

-- ─── Runtime state snapshots ──────────────────────────────────────────────────

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

-- ─── Runtime sessions ─────────────────────────────────────────────────────────

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

-- ─── Runtime session events ───────────────────────────────────────────────────

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

-- ─── Review state snapshots ───────────────────────────────────────────────────

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

-- ─── Queue runtime leases ─────────────────────────────────────────────────────

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

-- ─── Runtime replay runs ──────────────────────────────────────────────────────

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

-- ─── Supervisor state snapshots ───────────────────────────────────────────────

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

-- ─── Pipeline runtime states ──────────────────────────────────────────────────

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

-- ─── Orchestration checkpoints ────────────────────────────────────────────────

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

-- ─── Absorbed from 002_runtime_state_schema.sql ───────────────────────────────

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

-- ─── updated_at triggers ──────────────────────────────────────────────────────

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

create trigger set_runtime_review_queue_updated_at
before update on public.runtime_review_queue
for each row execute function public.set_updated_at();

create trigger set_runtime_incidents_updated_at
before update on public.runtime_incidents
for each row execute function public.set_updated_at();

-- ─── Indexes absorbed from 002_runtime_state_schema.sql ──────────────────────

create index if not exists idx_runtime_sessions_status
    on public.runtime_sessions (status);

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

-- ─── Migration record ─────────────────────────────────────────────────────────

insert into public.persistence_migrations (
    migration_key,
    description,
    applied_by,
    checksum,
    metadata
)
values (
    '002_runtime_state_schema',
    'Runtime session, snapshot, replay, queue lease, supervisor, pipeline, and orchestration persistence schema. Absorbs runtime_state_checkpoints, runtime_review_queue, and runtime_incidents from duplicate underscore migration.',
    'system',
    '',
    jsonb_build_object('section', 'data_lifecycle_and_resilience')
)
on conflict (migration_key) do nothing;

commit;