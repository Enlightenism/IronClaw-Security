begin;

-- ─── audit_events ─────────────────────────────────────────────────────────────

create index if not exists idx_audit_events_org_created_at
    on public.audit_events (org_id, created_at desc);

create index if not exists idx_audit_events_actor_created_at
    on public.audit_events (actor_id, created_at desc);

create index if not exists idx_audit_events_request_id
    on public.audit_events (request_id);

create index if not exists idx_audit_events_event_type_created_at
    on public.audit_events (event_type, created_at desc);

-- ─── incidents (was: security_incidents) ─────────────────────────────────────

create index if not exists idx_incidents_org_status_detected_at
    on public.incidents (org_id, status, detected_at desc);

create index if not exists idx_incidents_severity_detected_at
    on public.incidents (severity, detected_at desc);

create index if not exists idx_incidents_verdict_detected_at
    on public.incidents (verdict, detected_at desc);

-- ─── review_queue_items ───────────────────────────────────────────────────────

create index if not exists idx_review_queue_items_status_priority_created_at
    on public.review_queue_items (status, priority, created_at asc);

create index if not exists idx_review_queue_items_org_status_created_at
    on public.review_queue_items (org_id, status, created_at desc);

create index if not exists idx_review_queue_items_incident_id
    on public.review_queue_items (incident_id);

create unique index if not exists idx_review_queue_items_open_incident_unique
    on public.review_queue_items (incident_id)
    where incident_id is not null and status in ('pending', 'assigned', 'escalated');

-- ─── quarantine_items (was: quarantine_records) ───────────────────────────────

create index if not exists idx_quarantine_items_org_status_created_at
    on public.quarantine_items (org_id, status, created_at desc);

create index if not exists idx_quarantine_items_sha256
    on public.quarantine_items (artifact_sha256);

create index if not exists idx_quarantine_items_incident_id
    on public.quarantine_items (incident_id);

-- ─── telemetry_events ────────────────────────────────────────────────────────

create index if not exists idx_telemetry_events_category_recorded_at
    on public.telemetry_events (category, recorded_at desc);

create index if not exists idx_telemetry_events_severity_recorded_at
    on public.telemetry_events (severity, recorded_at desc);

create index if not exists idx_telemetry_events_incident_id
    on public.telemetry_events (incident_id);

-- ─── runtime_checkpoints ─────────────────────────────────────────────────────

create index if not exists idx_runtime_checkpoints_runtime_name_captured_at
    on public.runtime_checkpoints (runtime_name, captured_at desc);

create index if not exists idx_runtime_checkpoints_session_key_captured_at
    on public.runtime_checkpoints (session_key, captured_at desc);

create index if not exists idx_runtime_checkpoints_status_captured_at
    on public.runtime_checkpoints (status, captured_at desc);

-- ─── runtime_state_snapshots ─────────────────────────────────────────────────

create index if not exists idx_runtime_state_snapshots_session_key_captured_at
    on public.runtime_state_snapshots (session_key, captured_at desc);

create index if not exists idx_runtime_state_snapshots_runtime_kind_captured_at
    on public.runtime_state_snapshots (runtime_name, state_kind, captured_at desc);

create index if not exists idx_runtime_state_snapshots_status_captured_at
    on public.runtime_state_snapshots (status, captured_at desc);

create index if not exists idx_runtime_state_snapshots_checkpoint_id
    on public.runtime_state_snapshots (checkpoint_id);

-- ─── runtime_sessions ────────────────────────────────────────────────────────

create index if not exists idx_runtime_sessions_runtime_status_last_seen_at
    on public.runtime_sessions (runtime_name, status, last_seen_at desc);

create index if not exists idx_runtime_sessions_actor_status_last_seen_at
    on public.runtime_sessions (actor_id, status, last_seen_at desc);

create index if not exists idx_runtime_sessions_org_status_last_seen_at
    on public.runtime_sessions (org_id, status, last_seen_at desc);

-- absorbed from underscore: references last_heartbeat_at (column present in underscore runtime_sessions)
-- SKIPPED — nospaces runtime_sessions uses last_seen_at, not last_heartbeat_at; covered above

-- ─── runtime_session_events ──────────────────────────────────────────────────

create index if not exists idx_runtime_session_events_session_sequence_no
    on public.runtime_session_events (session_id, sequence_no asc);

create index if not exists idx_runtime_session_events_event_type_occurred_at
    on public.runtime_session_events (event_type, occurred_at desc);

create index if not exists idx_runtime_session_events_correlation_id
    on public.runtime_session_events (correlation_id);

-- ─── review_state_snapshots ───────────────────────────────────────────────────

create index if not exists idx_review_state_snapshots_review_item_version_no
    on public.review_state_snapshots (review_item_id, version_no desc);

create index if not exists idx_review_state_snapshots_session_captured_at
    on public.review_state_snapshots (session_id, captured_at desc);

create index if not exists idx_review_state_snapshots_status_captured_at
    on public.review_state_snapshots (status, captured_at desc);

-- ─── queue_runtime_leases ────────────────────────────────────────────────────

create index if not exists idx_queue_runtime_leases_queue_status_renew_by
    on public.queue_runtime_leases (queue_name, status, renew_by asc);

create index if not exists idx_queue_runtime_leases_session_id
    on public.queue_runtime_leases (session_id);

create index if not exists idx_queue_runtime_leases_review_item_id
    on public.queue_runtime_leases (review_item_id);

create unique index if not exists idx_queue_runtime_leases_active_review_item_unique
    on public.queue_runtime_leases (review_item_id)
    where review_item_id is not null and status = 'held';

-- ─── runtime_replay_runs ─────────────────────────────────────────────────────

create index if not exists idx_runtime_replay_runs_session_status_created_at
    on public.runtime_replay_runs (session_id, status, created_at desc);

create index if not exists idx_runtime_replay_runs_source_snapshot_id
    on public.runtime_replay_runs (source_snapshot_id);

-- ─── supervisor_state_snapshots ───────────────────────────────────────────────

create index if not exists idx_supervisor_state_snapshots_supervisor_captured_at
    on public.supervisor_state_snapshots (supervisor_name, captured_at desc);

create index if not exists idx_supervisor_state_snapshots_status_captured_at
    on public.supervisor_state_snapshots (status, captured_at desc);

-- ─── pipeline_runtime_states ─────────────────────────────────────────────────

create index if not exists idx_pipeline_runtime_states_session_stage_order
    on public.pipeline_runtime_states (session_id, stage_order asc);

create index if not exists idx_pipeline_runtime_states_pipeline_status_entered_at
    on public.pipeline_runtime_states (pipeline_name, status, entered_at desc);

create index if not exists idx_pipeline_runtime_states_checkpoint_id
    on public.pipeline_runtime_states (checkpoint_id);

-- ─── orchestration_checkpoints ───────────────────────────────────────────────

create index if not exists idx_orchestration_checkpoints_session_step_order
    on public.orchestration_checkpoints (session_id, step_order asc);

create index if not exists idx_orchestration_checkpoints_orchestration_status_captured_at
    on public.orchestration_checkpoints (orchestration_name, status, captured_at desc);

-- ─── analysis_reports (absorbed from underscore) ─────────────────────────────

create index if not exists idx_analysis_reports_created_verdict
    on public.analysis_reports (created_at desc, verdict);

create index if not exists idx_analysis_reports_malicious_created
    on public.analysis_reports (created_at desc)
    where verdict in ('suspicious', 'malicious');

-- ─── quarantine_events (absorbed from underscore) ────────────────────────────

create index if not exists idx_quarantine_events_active_created
    on public.quarantine_events (created_at desc)
    where status = 'quarantined';

-- ─── release_policy_decisions (absorbed from underscore) ─────────────────────

create index if not exists idx_release_policy_decisions_created_action
    on public.release_policy_decisions (created_at desc, action);

-- ─── runtime_review_queue (absorbed from underscore) ─────────────────────────

create index if not exists idx_runtime_review_queue_pending_priority
    on public.runtime_review_queue (priority, created_at desc)
    where status in ('pending', 'in_review');

-- ─── runtime_incidents (absorbed from underscore) ────────────────────────────

create index if not exists idx_runtime_incidents_open_severity
    on public.runtime_incidents (severity, opened_at desc)
    where status in ('open', 'investigating', 'contained');

-- ─── Billing / install-key reconciliation ─────────────────────────────────────

create unique index if not exists idx_billing_purchases_purchase_id_reconciliation_unique
    on public.billing_purchases (purchase_id);

create unique index if not exists idx_billing_purchases_checkout_session_reconciliation_unique
    on public.billing_purchases (checkout_session_id)
    where checkout_session_id is not null and payment_status = 'paid';

create unique index if not exists idx_billing_purchases_owner_package_reconciliation_unique
    on public.billing_purchases (owner_key, package_id)
    where owner_key is not null and package_id is not null and payment_status = 'paid';

create index if not exists idx_billing_purchases_payment_status_created_at
    on public.billing_purchases (payment_status, created_at desc);

create index if not exists idx_billing_purchases_fulfillment_status_created_at
    on public.billing_purchases (fulfillment_status, created_at desc);

create index if not exists idx_billing_purchases_owner_key_created_at
    on public.billing_purchases (owner_key, created_at desc);

create index if not exists idx_billing_purchases_package_created_at
    on public.billing_purchases (package_id, created_at desc);

create unique index if not exists idx_install_key_records_key_id_reconciliation_unique
    on public.install_key_records (key_id);

create unique index if not exists idx_install_key_records_active_owner_program_reconciliation_unique
    on public.install_key_records (owner_key, program)
    where active = true and owner_key is not null and program is not null;

create index if not exists idx_install_key_records_payment_status_created_at
    on public.install_key_records (payment_status, created_at desc);

create index if not exists idx_install_key_records_entitlements_status_created_at
    on public.install_key_records (entitlements_status, created_at desc);

create index if not exists idx_install_key_records_owner_program_created_at
    on public.install_key_records (owner_key, program, created_at desc);

create index if not exists idx_install_key_issuance_history_purchase_created_at
    on public.install_key_issuance_history (purchase_id, issued_at desc);

create index if not exists idx_install_key_issuance_history_owner_program_status
    on public.install_key_issuance_history (owner_key, program, status, issued_at desc);

create unique index if not exists idx_event_idempotency_ledger_event_id_reconciliation_unique
    on public.event_idempotency_ledger (event_id);

create unique index if not exists idx_event_idempotency_ledger_event_fingerprint_unique
    on public.event_idempotency_ledger (source, event_type, payload_hash)
    where payload_hash is not null and payload_hash <> '';

create index if not exists idx_event_idempotency_ledger_processed_at
    on public.event_idempotency_ledger (processed_at desc);

-- ─── Constraints ─────────────────────────────────────────────────────────────

alter table public.review_queue_items
    add constraint review_queue_items_assigned_requires_reviewer_check
    check (
        status <> 'assigned'
        or assigned_reviewer is not null
    );

alter table public.review_queue_items
    add constraint review_queue_items_resolved_requires_time_check
    check (
        status not in ('resolved', 'rejected')
        or resolved_at is not null
    );

alter table public.incidents
    add constraint incidents_resolved_requires_time_check
    check (
        status <> 'resolved'
        or resolved_at is not null
    );

alter table public.quarantine_items
    add constraint quarantine_items_released_requires_time_check
    check (
        status <> 'released'
        or released_at is not null
    );

alter table public.runtime_sessions
    add constraint runtime_sessions_end_after_start_check
    check (
        ended_at is null
        or ended_at >= started_at
    );

alter table public.runtime_sessions
    add constraint runtime_sessions_expiry_after_start_check
    check (
        expires_at is null
        or expires_at >= started_at
    );

alter table public.runtime_state_snapshots
    add constraint runtime_state_snapshots_expiry_after_capture_check
    check (
        expires_at is null
        or expires_at >= captured_at
    );

alter table public.queue_runtime_leases
    add constraint queue_runtime_leases_release_after_acquire_check
    check (
        released_at is null
        or released_at >= acquired_at
    );

alter table public.queue_runtime_leases
    add constraint queue_runtime_leases_renew_after_acquire_check
    check (renew_by >= acquired_at);

alter table public.runtime_replay_runs
    add constraint runtime_replay_runs_completed_after_started_check
    check (
        completed_at is null
        or started_at is null
        or completed_at >= started_at
    );

alter table public.review_state_snapshots
    add constraint review_state_snapshots_restored_after_capture_check
    check (
        restored_at is null
        or restored_at >= captured_at
    );

alter table public.supervisor_state_snapshots
    add constraint supervisor_state_snapshots_restored_after_capture_check
    check (
        restored_at is null
        or restored_at >= captured_at
    );

alter table public.pipeline_runtime_states
    add constraint pipeline_runtime_states_exit_after_enter_check
    check (
        exited_at is null
        or exited_at >= entered_at
    );

alter table public.orchestration_checkpoints
    add constraint orchestration_checkpoints_restored_after_capture_check
    check (
        restored_at is null
        or restored_at >= captured_at
    );

-- absorbed from underscore

alter table public.quarantine_events
    add constraint quarantine_events_sha256_matches_report_check
    check (
        analysis_report_id is null
        or sha256 is not null
    );

alter table public.release_policy_decisions
    add constraint release_policy_decisions_reason_nonempty_check
    check (length(btrim(reason)) > 0);

alter table public.runtime_review_queue
    add constraint runtime_review_queue_resolution_check
    check (
        (status in ('approved', 'rejected', 'resolved') and resolved_at is not null)
        or (status in ('pending', 'in_review') and resolved_at is null)
    );

alter table public.runtime_incidents
    add constraint runtime_incidents_closed_at_check
    check (
        (status = 'closed' and closed_at is not null)
        or (status <> 'closed')
    );

alter table public.runtime_sessions
    add constraint runtime_sessions_ended_at_check
    check (
        (status in ('completed', 'failed', 'terminated') and ended_at is not null)
        or (status in ('active', 'paused') and ended_at is null)
    );

-- ─── Migration record ────────────────────────────────────────────────────────

insert into public.persistence_migrations (
    migration_key,
    description,
    applied_by,
    checksum,
    metadata
)
values (
    '003_indexes_and_constraints',
    'Performance indexes and lifecycle integrity constraints for IronClaw persistence and runtime state tables.',
    'system',
    '',
    jsonb_build_object('section', 'performance_and_integrity')
)
on conflict (migration_key) do nothing;

commit;
