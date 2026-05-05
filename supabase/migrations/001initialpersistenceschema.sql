begin;

create extension if not exists pgcrypto;

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
    new.updated_at = timezone('utc', now());
    return new;
end;
$$;

create table if not exists public.persistence_migrations (
    id uuid primary key default gen_random_uuid(),
    migration_key text not null unique,
    description text not null default '',
    applied_by text not null default 'system',
    applied_at timestamptz not null default timezone('utc', now()),
    checksum text not null default '',
    metadata jsonb not null default '{}'::jsonb
);

create table if not exists public.persistence_backends (
    id uuid primary key default gen_random_uuid(),
    backend_key text not null unique,
    display_name text not null,
    backend_type text not null,
    priority integer not null default 100,
    mode text not null default 'primary',
    enabled boolean not null default true,
    health_status text not null default 'unknown',
    last_heartbeat_at timestamptz,
    last_failure_at timestamptz,
    last_restore_test_at timestamptz,
    connection_metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint persistence_backends_mode_check
        check (mode in ('primary', 'replica', 'failover', 'archive')),
    constraint persistence_backends_health_status_check
        check (health_status in ('unknown', 'healthy', 'degraded', 'failing', 'offline'))
);

create table if not exists public.persistence_failover_events (
    id uuid primary key default gen_random_uuid(),
    event_key text not null unique,
    from_backend_id uuid references public.persistence_backends(id) on delete set null,
    to_backend_id uuid references public.persistence_backends(id) on delete set null,
    trigger_reason text not null,
    status text not null default 'detected',
    detected_at timestamptz not null default timezone('utc', now()),
    started_at timestamptz,
    completed_at timestamptz,
    recovery_point timestamptz,
    notes text not null default '',
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint persistence_failover_events_status_check
        check (status in ('detected', 'in_progress', 'completed', 'failed', 'rolled_back'))
);

create table if not exists public.backup_policies (
    id uuid primary key default gen_random_uuid(),
    policy_key text not null unique,
    display_name text not null,
    target_scope text not null,
    cadence text not null,
    retention_days integer not null,
    backup_type text not null default 'full',
    encryption_required boolean not null default true,
    verification_required boolean not null default true,
    enabled boolean not null default true,
    backup_backend_id uuid references public.persistence_backends(id) on delete set null,
    config jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint backup_policies_retention_days_check
        check (retention_days > 0),
    constraint backup_policies_backup_type_check
        check (backup_type in ('full', 'incremental', 'snapshot', 'logical')),
    constraint backup_policies_target_scope_check
        check (target_scope in ('platform', 'audit', 'review', 'quarantine', 'incidents', 'billing', 'runtime', 'telemetry'))
);

create table if not exists public.backup_runs (
    id uuid primary key default gen_random_uuid(),
    run_key text not null unique,
    policy_id uuid not null references public.backup_policies(id) on delete cascade,
    backend_id uuid references public.persistence_backends(id) on delete set null,
    status text not null default 'scheduled',
    backup_type text not null,
    started_at timestamptz,
    completed_at timestamptz,
    expires_at timestamptz,
    storage_uri text not null default '',
    checksum text not null default '',
    bytes_stored bigint not null default 0,
    records_captured bigint not null default 0,
    verification_status text not null default 'pending',
    error_message text not null default '',
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint backup_runs_status_check
        check (status in ('scheduled', 'running', 'completed', 'failed', 'expired', 'deleted')),
    constraint backup_runs_backup_type_check
        check (backup_type in ('full', 'incremental', 'snapshot', 'logical')),
    constraint backup_runs_verification_status_check
        check (verification_status in ('pending', 'verified', 'failed', 'skipped')),
    constraint backup_runs_bytes_stored_check
        check (bytes_stored >= 0),
    constraint backup_runs_records_captured_check
        check (records_captured >= 0)
);

create table if not exists public.restore_runs (
    id uuid primary key default gen_random_uuid(),
    restore_key text not null unique,
    source_backup_run_id uuid references public.backup_runs(id) on delete set null,
    target_backend_id uuid references public.persistence_backends(id) on delete set null,
    initiated_by text not null default 'system',
    restore_scope text not null,
    status text not null default 'planned',
    dry_run boolean not null default false,
    started_at timestamptz,
    completed_at timestamptz,
    validated_at timestamptz,
    rollback_ready boolean not null default true,
    records_restored bigint not null default 0,
    error_message text not null default '',
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint restore_runs_restore_scope_check
        check (restore_scope in ('platform', 'audit', 'review', 'quarantine', 'incidents', 'billing', 'runtime', 'telemetry')),
    constraint restore_runs_status_check
        check (status in ('planned', 'validating', 'running', 'completed', 'failed', 'rolled_back')),
    constraint restore_runs_records_restored_check
        check (records_restored >= 0)
);

create table if not exists public.retention_policies (
    id uuid primary key default gen_random_uuid(),
    policy_key text not null unique,
    target_table text not null,
    target_scope text not null,
    retention_days integer not null,
    archive_before_delete boolean not null default true,
    legal_hold_supported boolean not null default true,
    enabled boolean not null default true,
    policy_metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint retention_policies_retention_days_check
        check (retention_days > 0),
    constraint retention_policies_target_scope_check
        check (target_scope in ('platform', 'audit', 'review', 'quarantine', 'incidents', 'billing', 'runtime', 'telemetry'))
);

create table if not exists public.retention_runs (
    id uuid primary key default gen_random_uuid(),
    run_key text not null unique,
    policy_id uuid not null references public.retention_policies(id) on delete cascade,
    status text not null default 'scheduled',
    scanned_records bigint not null default 0,
    archived_records bigint not null default 0,
    deleted_records bigint not null default 0,
    held_records bigint not null default 0,
    started_at timestamptz,
    completed_at timestamptz,
    error_message text not null default '',
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint retention_runs_status_check
        check (status in ('scheduled', 'running', 'completed', 'failed', 'cancelled')),
    constraint retention_runs_scanned_records_check
        check (scanned_records >= 0),
    constraint retention_runs_archived_records_check
        check (archived_records >= 0),
    constraint retention_runs_deleted_records_check
        check (deleted_records >= 0),
    constraint retention_runs_held_records_check
        check (held_records >= 0)
);

create table if not exists public.legal_holds (
    id uuid primary key default gen_random_uuid(),
    hold_key text not null unique,
    target_scope text not null,
    target_ref text not null,
    reason text not null,
    active boolean not null default true,
    created_by text not null default 'system',
    released_by text,
    released_at timestamptz,
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint legal_holds_target_scope_check
        check (target_scope in ('platform', 'audit', 'review', 'quarantine', 'incidents', 'billing', 'runtime', 'telemetry'))
);

create table if not exists public.audit_events (
    id uuid primary key default gen_random_uuid(),
    event_key text not null unique,
    event_type text not null,
    severity text not null default 'info',
    actor_id text,
    actor_type text not null default 'system',
    org_id text,
    resource_type text not null,
    resource_id text not null,
    action text not null,
    outcome text not null,
    occurred_at timestamptz not null default timezone('utc', now()),
    correlation_id text,
    request_id text,
    ip_address inet,
    user_agent text not null default '',
    summary text not null default '',
    details jsonb not null default '{}'::jsonb,
    retention_until timestamptz,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint audit_events_severity_check
        check (severity in ('debug', 'info', 'warning', 'error', 'critical')),
    constraint audit_events_outcome_check
        check (outcome in ('allowed', 'blocked', 'completed', 'failed', 'queued', 'restored'))
);

create table if not exists public.review_queue_items (
    id uuid primary key default gen_random_uuid(),
    item_key text not null unique,
    review_type text not null,
    status text not null default 'pending',
    priority text not null default 'normal',
    org_id text,
    actor_id text,
    subject_ref text not null,
    risk_score numeric(6,2) not null default 0,
    queued_at timestamptz not null default timezone('utc', now()),
    claimed_at timestamptz,
    completed_at timestamptz,
    assigned_to text,
    resolution text not null default '',
    evidence jsonb not null default '{}'::jsonb,
    metadata jsonb not null default '{}'::jsonb,
    retention_until timestamptz,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint review_queue_items_status_check
        check (status in ('pending', 'claimed', 'approved', 'rejected', 'expired', 'failed')),
    constraint review_queue_items_priority_check
        check (priority in ('low', 'normal', 'high', 'critical')),
    constraint review_queue_items_risk_score_check
        check (risk_score >= 0 and risk_score <= 1000)
);

create table if not exists public.quarantine_items (
    id uuid primary key default gen_random_uuid(),
    item_key text not null unique,
    artifact_type text not null,
    status text not null default 'active',
    reason text not null,
    severity text not null default 'high',
    org_id text,
    source_ref text not null,
    sha256 text,
    storage_uri text not null default '',
    detected_at timestamptz not null default timezone('utc', now()),
    expires_at timestamptz,
    released_at timestamptz,
    released_by text,
    disposition text not null default '',
    metadata jsonb not null default '{}'::jsonb,
    retention_until timestamptz,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint quarantine_items_status_check
        check (status in ('active', 'released', 'destroyed', 'expired')),
    constraint quarantine_items_severity_check
        check (severity in ('low', 'medium', 'high', 'critical'))
);

create table if not exists public.incidents (
    id uuid primary key default gen_random_uuid(),
    incident_key text not null unique,
    title text not null,
    status text not null default 'open',
    severity text not null default 'high',
    category text not null default 'security',
    org_id text,
    opened_at timestamptz not null default timezone('utc', now()),
    acknowledged_at timestamptz,
    resolved_at timestamptz,
    owner_id text,
    summary text not null default '',
    details jsonb not null default '{}'::jsonb,
    recovery_metadata jsonb not null default '{}'::jsonb,
    retention_until timestamptz,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint incidents_status_check
        check (status in ('open', 'triaged', 'contained', 'resolved', 'closed')),
    constraint incidents_severity_check
        check (severity in ('low', 'medium', 'high', 'critical'))
);

create table if not exists public.history_events (
    id uuid primary key default gen_random_uuid(),
    event_key text not null unique,
    stream_key text not null,
    sequence_no bigint not null,
    event_type text not null,
    subject_ref text not null,
    org_id text,
    actor_id text,
    payload jsonb not null default '{}'::jsonb,
    occurred_at timestamptz not null default timezone('utc', now()),
    retention_until timestamptz,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint history_events_sequence_no_check
        check (sequence_no >= 0),
    constraint history_events_stream_sequence_unique
        unique (stream_key, sequence_no)
);

create table if not exists public.telemetry_events (
    id uuid primary key default gen_random_uuid(),
    event_key text not null unique,
    metric_name text not null,
    metric_type text not null,
    source text not null,
    org_id text,
    value_numeric numeric(20,6),
    value_text text,
    unit text not null default '',
    dimensions jsonb not null default '{}'::jsonb,
    captured_at timestamptz not null default timezone('utc', now()),
    retention_until timestamptz,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint telemetry_events_metric_type_check
        check (metric_type in ('counter', 'gauge', 'histogram', 'event', 'status'))
);

create table if not exists public.runtime_checkpoints (
    id uuid primary key default gen_random_uuid(),
    checkpoint_key text not null unique,
    runtime_name text not null,
    runtime_state text not null,
    status text not null default 'active',
    backend_id uuid references public.persistence_backends(id) on delete set null,
    captured_at timestamptz not null default timezone('utc', now()),
    expires_at timestamptz,
    sequence_no bigint not null default 0,
    checkpoint_data jsonb not null default '{}'::jsonb,
    recovery_metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint runtime_checkpoints_status_check
        check (status in ('active', 'superseded', 'restored', 'expired')),
    constraint runtime_checkpoints_sequence_no_check
        check (sequence_no >= 0)
);

create table if not exists public.persistence_validation_runs (
    id uuid primary key default gen_random_uuid(),
    validation_key text not null unique,
    validation_type text not null,
    status text not null default 'scheduled',
    backend_id uuid references public.persistence_backends(id) on delete set null,
    started_at timestamptz,
    completed_at timestamptz,
    findings jsonb not null default '[]'::jsonb,
    error_message text not null default '',
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint persistence_validation_runs_validation_type_check
        check (validation_type in ('backup', 'restore', 'migration', 'failover', 'retention', 'checkpoint')),
    constraint persistence_validation_runs_status_check
        check (status in ('scheduled', 'running', 'passed', 'failed', 'cancelled'))
);

create trigger set_persistence_backends_updated_at
before update on public.persistence_backends
for each row execute function public.set_updated_at();

create trigger set_persistence_failover_events_updated_at
before update on public.persistence_failover_events
for each row execute function public.set_updated_at();

create trigger set_backup_policies_updated_at
before update on public.backup_policies
for each row execute function public.set_updated_at();

create trigger set_backup_runs_updated_at
before update on public.backup_runs
for each row execute function public.set_updated_at();

create trigger set_restore_runs_updated_at
before update on public.restore_runs
for each row execute function public.set_updated_at();

create trigger set_retention_policies_updated_at
before update on public.retention_policies
for each row execute function public.set_updated_at();

create trigger set_retention_runs_updated_at
before update on public.retention_runs
for each row execute function public.set_updated_at();

create trigger set_legal_holds_updated_at
before update on public.legal_holds
for each row execute function public.set_updated_at();

create trigger set_audit_events_updated_at
before update on public.audit_events
for each row execute function public.set_updated_at();

create trigger set_review_queue_items_updated_at
before update on public.review_queue_items
for each row execute function public.set_updated_at();

create trigger set_quarantine_items_updated_at
before update on public.quarantine_items
for each row execute function public.set_updated_at();

create trigger set_incidents_updated_at
before update on public.incidents
for each row execute function public.set_updated_at();

create trigger set_history_events_updated_at
before update on public.history_events
for each row execute function public.set_updated_at();

create trigger set_telemetry_events_updated_at
before update on public.telemetry_events
for each row execute function public.set_updated_at();

create trigger set_runtime_checkpoints_updated_at
before update on public.runtime_checkpoints
for each row execute function public.set_updated_at();

create trigger set_persistence_validation_runs_updated_at
before update on public.persistence_validation_runs
for each row execute function public.set_updated_at();

insert into public.persistence_migrations (
    migration_key,
    description,
    applied_by,
    checksum,
    metadata
)
values (
    '001_initial_persistence_schema',
    'Initial IronClaw persistence, backup, restore, retention, audit, queue, quarantine, incident, history, telemetry, and checkpoint schema.',
    'system',
    '',
    jsonb_build_object('section', 'data_lifecycle_and_resilience')
)
on conflict (migration_key) do nothing;

commit;