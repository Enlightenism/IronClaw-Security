begin;

create index if not exists idx_audit_events_org_created_at
    on public.audit_events (org_id, created_at desc);

create index if not exists idx_audit_events_actor_created_at
    on public.audit_events (actor_id, created_at desc);

create index if not exists idx_audit_events_request_id
    on public.audit_events (request_id);

create index if not exists idx_audit_events_event_type_created_at
    on public.audit_events (event_type, created_at desc);

create index if not exists idx_security_incidents_org_status_detected_at
    on public.security_incidents (org_id, status, detected_at desc);

create index if not exists idx_security_incidents_severity_detected_at
    on public.security_incidents (severity, detected_at desc);

create index if not exists idx_security_incidents_verdict_detected_at
    on public.security_incidents (verdict, detected_at desc);

create index if not exists idx_review_queue_items_status_priority_created_at
    on public.review_queue_items (status, priority, created_at asc);

create index if not exists idx_review_queue_items_org_status_created_at
    on public.review_queue_items (org_id, status, created_at desc);

create index if not exists idx_review_queue_items_incident_id
    on public.review_queue_items (incident_id);

create unique index if not exists idx_review_queue_items_open_incident_unique
    on public.review_queue_items (incident_id)
    where incident_id is not null and status in ('pending', 'assigned', 'escalated');

create index if not exists idx_quarantine_records_org_status_created_at
    on public.quarantine_records (org_id, status, created_at desc);

create index if not exists idx_quarantine_records_sha256
    on public.quarantine_records (artifact_sha256);

create index if not exists idx_quarantine_records_incident_id
    on public.quarantine_records (incident_id);

create index if not exists idx_usage_events_org_occurred_at
    on public.usage_events (org_id, occurred_at desc);

create index if not exists idx_usage_events_event_type_occurred_at
    on public.usage_events (event_type, occurred_at desc);

create index if not exists idx_usage_events_request_id
    on public.usage_events (request_id);

create index if not exists idx_telemetry_events_category_recorded_at
    on public.telemetry_events (category, recorded_at desc);

create index if not exists idx_telemetry_events_severity_recorded_at
    on public.telemetry_events (severity, recorded_at desc);

create index if not exists idx_telemetry_events_incident_id
    on public.telemetry_events (incident_id);

create index if not exists idx_runtime_checkpoints_runtime_name_captured_at
    on public.runtime_checkpoints (runtime_name, captured_at desc);

create index if not exists idx_runtime_checkpoints_session_key_captured_at
    on public.runtime_checkpoints (session_key, captured_at desc);

create index if not exists idx_runtime_checkpoints_status_captured_at
    on public.runtime_checkpoints (status, captured_at desc);

create index if not exists idx_runtime_state_snapshots_session_key_captured_at
    on public.runtime_state_snapshots (session_key, captured_at desc);

create index if not exists idx_runtime_state_snapshots_runtime_kind_captured_at
    on public.runtime_state_snapshots (runtime_name, state_kind, captured_at desc);

create index if not exists idx_runtime_state_snapshots_status_captured_at
    on public.runtime_state_snapshots (status, captured_at desc);

create index if not exists idx_runtime_state_snapshots_checkpoint_id
    on public.runtime_state_snapshots (checkpoint_id);

create index if not exists idx_runtime_sessions_runtime_status_last_seen_at
    on public.runtime_sessions (runtime_name, status, last_seen_at desc);

create index if not exists idx_runtime_sessions_actor_status_last_seen_at
    on public.runtime_sessions (actor_id, status, last_seen_at desc);

create index if not exists idx_runtime_sessions_org_status_last_seen_at
    on public.runtime_sessions (org_id, status, last_seen_at desc);

create index if not exists idx_runtime_session_events_session_sequence_no
    on public.runtime_session_events (session_id, sequence_no asc);

create index if not exists idx_runtime_session_events_event_type_occurred_at
    on public.runtime_session_events (event_type, occurred_at desc);

create index if not exists idx_runtime_session_events_correlation_id
    on public.runtime_session_events (correlation_id);

create index if not exists idx_review_state_snapshots_review_item_version_no
    on public.review_state_snapshots (review_item_id, version_no desc);

create index if not exists idx_review_state_snapshots_session_captured_at
    on public.review_state_snapshots (session_id, captured_at desc);

create index if not exists idx_review_state_snapshots_status_captured_at
    on public.review_state_snapshots (status, captured_at desc);

create index if not exists idx_queue_runtime_leases_queue_status_renew_by
    on public.queue_runtime_leases (queue_name, status, renew_by asc);

create index if not exists idx_queue_runtime_leases_session_id
    on public.queue_runtime_leases (session_id);

create index if not exists idx_queue_runtime_leases_review_item_id
    on public.queue_runtime_leases (review_item_id);

create unique index if not exists idx_queue_runtime_leases_active_review_item_unique
    on public.queue_runtime_leases (review_item_id)
    where review_item_id is not null and status = 'held';

create index if not exists idx_runtime_replay_runs_session_status_created_at
    on public.runtime_replay_runs (session_id, status, created_at desc);

create index if not exists idx_runtime_replay_runs_source_snapshot_id
    on public.runtime_replay_runs (source_snapshot_id);

create index if not exists idx_supervisor_state_snapshots_supervisor_captured_at
    on public.supervisor_state_snapshots (supervisor_name, captured_at desc);

create index if not exists idx_supervisor_state_snapshots_status_captured_at
    on public.supervisor_state_snapshots (status, captured_at desc);

create index if not exists idx_pipeline_runtime_states_session_stage_order
    on public.pipeline_runtime_states (session_id, stage_order asc);

create index if not exists idx_pipeline_runtime_states_pipeline_status_entered_at
    on public.pipeline_runtime_states (pipeline_name, status, entered_at desc);

create index if not exists idx_pipeline_runtime_states_checkpoint_id
    on public.pipeline_runtime_states (checkpoint_id);

create index if not exists idx_orchestration_checkpoints_session_step_order
    on public.orchestration_checkpoints (session_id, step_order asc);

create index if not exists idx_orchestration_checkpoints_orchestration_status_captured_at
    on public.orchestration_checkpoints (orchestration_name, status, captured_at desc);

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

alter table public.security_incidents
    add constraint security_incidents_resolved_requires_time_check
    check (
        status <> 'resolved'
        or resolved_at is not null
    );

alter table public.quarantine_records
    add constraint quarantine_records_released_requires_time_check
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