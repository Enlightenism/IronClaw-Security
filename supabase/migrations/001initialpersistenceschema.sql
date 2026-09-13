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

-- ─── Migration tracking ────────────────────────────────────────────────────────

create table if not exists public.persistence_migrations (
    id uuid primary key default gen_random_uuid(),
    migration_key text not null unique,
    description text not null default '',
    applied_by text not null default 'system',
    applied_at timestamptz not null default timezone('utc', now()),
    checksum text not null default '',
    metadata jsonb not null default '{}'::jsonb
);

-- ─── Persistence infrastructure ───────────────────────────────────────────────

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

-- ─── Billing / install-key durable state ──────────────────────────────────────

create table if not exists public.billing_purchases (
    id uuid primary key default gen_random_uuid(),
    purchase_id text not null unique,
    owner_key text not null,
    customer_id text,
    buyer_name text not null default '',
    buyer_email text,
    package_id text not null default '',
    package_name text not null default '',
    checkout_session_id text,
    stripe_payment_intent_id text,
    price_usd numeric(12,2) not null default 0,
    amount_total numeric(12,2) not null default 0,
    currency text not null default 'usd',
    payment_status text not null default 'pending',
    fulfillment_status text not null default 'pending',
    granted_units integer not null default 0,
    token_coverage integer not null default 0,
    tokens_per_unit integer not null default 25000,
    units_credited boolean not null default false,
    install_keys_provisioned boolean not null default false,
    openclaw_install_key text,
    claude_code_install_key text,
    raw_metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    fulfilled_at timestamptz,
    expires_at timestamptz,
    constraint billing_purchases_payment_status_check
        check (payment_status in ('pending', 'paid', 'failed', 'refunded', 'cancelled')),
    constraint billing_purchases_fulfillment_status_check
        check (fulfillment_status in ('pending', 'fulfilled', 'failed', 'retrying')),
    constraint billing_purchases_amount_total_check
        check (amount_total >= 0),
    constraint billing_purchases_price_usd_check
        check (price_usd >= 0),
    constraint billing_purchases_granted_units_check
        check (granted_units >= 0),
    constraint billing_purchases_owner_key_not_empty_check
        check (char_length(trim(owner_key)) > 0),
    constraint billing_purchases_checkout_session_id_not_empty_check
        check (checkout_session_id is null or char_length(trim(checkout_session_id)) > 0),
    constraint billing_purchases_currency_check
        check (char_length(trim(currency)) > 0)
);

create table if not exists public.install_key_records (
    id uuid primary key default gen_random_uuid(),
    key_id text not null unique,
    purchase_id text references public.billing_purchases(purchase_id) on delete set null,
    purchase_reference text,
    subscription_id text not null default '',
    owner_key text not null,
    org_id text,
    customer_id text,
    program text not null,
    checkout_session_id text,
    raw_key_hash text not null default '',
    masked_key text not null default '',
    label text not null default '',
    active boolean not null default false,
    payment_status text not null default 'unpaid',
    entitlements_status text not null default 'not_active',
    issued_after_payment boolean not null default false,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    last_used_at timestamptz,
    revoked_at timestamptz,
    metadata jsonb not null default '{}'::jsonb,
    constraint install_key_records_payment_status_check
        check (payment_status in ('unpaid', 'paid', 'failed', 'refunded', 'cancelled')),
    constraint install_key_records_entitlements_status_check
        check (entitlements_status in ('not_active', 'active', 'revoked', 'expired')),
    constraint install_key_records_owner_key_not_empty_check
        check (char_length(trim(owner_key)) > 0),
    constraint install_key_records_program_not_empty_check
        check (char_length(trim(program)) > 0),
    constraint install_key_records_key_hash_not_empty_check
        check (raw_key_hash = '' or char_length(trim(raw_key_hash)) > 0),
    constraint install_key_records_subscription_id_not_empty_check
        check (char_length(trim(subscription_id)) > 0 or subscription_id = '')
);

create table if not exists public.install_key_issuance_history (
    id uuid primary key default gen_random_uuid(),
    history_id text not null unique default gen_random_uuid()::text,
    key_id text not null references public.install_key_records(key_id) on delete cascade,
    purchase_id text references public.billing_purchases(purchase_id) on delete set null,
    owner_key text not null,
    customer_id text,
    program text not null,
    event_type text not null default 'issued',
    status text not null default 'issued',
    actor_type text not null default 'system',
    reason text not null default '',
    issued_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    metadata jsonb not null default '{}'::jsonb,
    constraint install_key_issuance_history_event_type_check
        check (event_type in ('issued', 'reissued', 'revoked', 'replaced', 'expired')),
    constraint install_key_issuance_history_status_check
        check (status in ('issued', 'active', 'revoked', 'failed')),
    constraint install_key_issuance_history_owner_key_not_empty_check
        check (char_length(trim(owner_key)) > 0),
    constraint install_key_issuance_history_program_not_empty_check
        check (char_length(trim(program)) > 0)
);

create table if not exists public.event_idempotency_ledger (
    id uuid primary key default gen_random_uuid(),
    event_id text not null unique,
    source text not null default 'stripe',
    event_type text not null default '',
    purchase_id text,
    checkout_session_id text,
    owner_key text,
    customer_id text,
    payload_hash text not null default '',
    processed_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    metadata jsonb not null default '{}'::jsonb,
    constraint event_idempotency_ledger_source_check
        check (source in ('stripe', 'internal', 'webhook')),
    constraint event_idempotency_ledger_event_type_not_empty_check
        check (char_length(trim(event_type)) > 0),
    constraint event_idempotency_ledger_processed_at_not_null_check
        check (processed_at is not null)
);

create trigger set_billing_purchases_updated_at
    before update on public.billing_purchases
    for each row execute function public.set_updated_at();

create trigger set_install_key_records_updated_at
    before update on public.install_key_records
    for each row execute function public.set_updated_at();

create trigger set_install_key_issuance_history_updated_at
    before update on public.install_key_issuance_history
    for each row execute function public.set_updated_at();

create trigger set_event_idempotency_ledger_updated_at
    before update on public.event_idempotency_ledger
    for each row execute function public.set_updated_at();

create index if not exists idx_billing_purchases_owner_created_at
    on public.billing_purchases (owner_key, created_at desc);

create index if not exists idx_billing_purchases_checkout_session_lookup
    on public.billing_purchases (checkout_session_id)
    where checkout_session_id is not null;

create unique index if not exists idx_billing_purchases_paid_checkout_session_unique
    on public.billing_purchases (checkout_session_id)
    where checkout_session_id is not null and payment_status = 'paid';

create index if not exists idx_billing_purchases_payment_status_created_at
    on public.billing_purchases (payment_status, created_at desc);

create index if not exists idx_install_key_records_owner_program
    on public.install_key_records (owner_key, program, created_at desc);

create index if not exists idx_install_key_records_checkout_session
    on public.install_key_records (checkout_session_id)
    where checkout_session_id is not null;

create unique index if not exists idx_install_key_records_active_owner_program_unique
    on public.install_key_records (owner_key, program)
    where active = true;

create unique index if not exists idx_install_key_records_raw_key_hash_unique
    on public.install_key_records (raw_key_hash)
    where raw_key_hash is not null and raw_key_hash <> '';

create index if not exists idx_install_key_issuance_history_purchase_issued_at
    on public.install_key_issuance_history (purchase_id, issued_at desc);

create index if not exists idx_install_key_issuance_history_key_id
    on public.install_key_issuance_history (key_id, issued_at desc);

create index if not exists idx_event_idempotency_ledger_checkout_session
    on public.event_idempotency_ledger (checkout_session_id)
    where checkout_session_id is not null;

create index if not exists idx_event_idempotency_ledger_purchase_id
    on public.event_idempotency_ledger (purchase_id)
    where purchase_id is not null;

-- ─── Backup / restore ─────────────────────────────────────────────────────────

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

-- ─── Retention ────────────────────────────────────────────────────────────────

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

-- ─── Security events / analysis ───────────────────────────────────────────────

create table if not exists public.analysis_reports (
    id uuid primary key default gen_random_uuid(),
    sha256 text not null unique,
    source_filename text not null,
    verdict text not null,
    risk_score integer not null default 0,
    summary text not null default '',
    indicators jsonb not null default '[]'::jsonb,
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),
    constraint analysis_reports_verdict_check
        check (verdict in ('clean', 'suspicious', 'malicious', 'unknown')),
    constraint analysis_reports_risk_score_check
        check (risk_score >= 0 and risk_score <= 100)
);

create table if not exists public.quarantine_events (
    id uuid primary key default gen_random_uuid(),
    analysis_report_id uuid not null references public.analysis_reports(id) on delete cascade,
    sha256 text not null,
    original_filename text not null,
    original_path text,
    quarantine_path text not null,
    reason text not null,
    status text not null default 'quarantined',
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    released_at timestamptz,
    constraint quarantine_events_status_check
        check (status in ('quarantined', 'released', 'deleted'))
);

create table if not exists public.release_policy_decisions (
    id uuid primary key default gen_random_uuid(),
    quarantine_event_id uuid not null references public.quarantine_events(id) on delete cascade,
    action text not null,
    approved boolean not null default false,
    reason text not null default '',
    decided_by text,
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default timezone('utc', now()),
    constraint release_policy_decisions_action_check
        check (action in ('keep_quarantined', 'release', 'delete', 'escalate'))
);

-- ─── Audit / review / quarantine / incidents ──────────────────────────────────

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

-- ─── History / telemetry / runtime ────────────────────────────────────────────

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

-- ─── updated_at triggers ──────────────────────────────────────────────────────

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

create trigger set_analysis_reports_updated_at
before update on public.analysis_reports
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

-- ─── Indexes absorbed from 001_initial_persistence_schema.sql ────────────────

create index if not exists idx_analysis_reports_verdict
    on public.analysis_reports (verdict);

create index if not exists idx_analysis_reports_created_at
    on public.analysis_reports (created_at desc);

create index if not exists idx_quarantine_events_analysis_report_id
    on public.quarantine_events (analysis_report_id);

create index if not exists idx_quarantine_events_sha256
    on public.quarantine_events (sha256);

create index if not exists idx_quarantine_events_status
    on public.quarantine_events (status);

create index if not exists idx_quarantine_events_created_at
    on public.quarantine_events (created_at desc);

create index if not exists idx_release_policy_decisions_quarantine_event_id
    on public.release_policy_decisions (quarantine_event_id);

create index if not exists idx_release_policy_decisions_action
    on public.release_policy_decisions (action);

create index if not exists idx_release_policy_decisions_created_at
    on public.release_policy_decisions (created_at desc);

-- ─── Migration record ─────────────────────────────────────────────────────────

insert into public.persistence_migrations (
    migration_key,
    description,
    applied_by,
    checksum,
    metadata
)
values (
    '001_initial_persistence_schema',
    'Initial IronClaw persistence, backup, restore, retention, audit, queue, quarantine, incident, history, telemetry, and checkpoint schema. Absorbs analysis_reports, quarantine_events, and release_policy_decisions from duplicate underscore migration.',
    'system',
    '',
    jsonb_build_object('section', 'data_lifecycle_and_resilience')
)
on conflict (migration_key) do nothing;

commit;
