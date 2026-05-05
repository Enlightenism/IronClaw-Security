create index if not exists idx_analysis_reports_created_verdict
    on public.analysis_reports (created_at desc, verdict);

create index if not exists idx_analysis_reports_malicious_created
    on public.analysis_reports (created_at desc)
    where verdict in ('suspicious', 'malicious');

create index if not exists idx_quarantine_events_active_created
    on public.quarantine_events (created_at desc)
    where status = 'quarantined';

create index if not exists idx_release_policy_decisions_created_action
    on public.release_policy_decisions (created_at desc, action);

create index if not exists idx_runtime_sessions_active_heartbeat
    on public.runtime_sessions (last_heartbeat_at desc)
    where status = 'active';

create index if not exists idx_runtime_review_queue_pending_priority
    on public.runtime_review_queue (priority, created_at desc)
    where status in ('pending', 'in_review');

create index if not exists idx_runtime_incidents_open_severity
    on public.runtime_incidents (severity, opened_at desc)
    where status in ('open', 'investigating', 'contained');

do $$
begin
    if not exists (
        select 1
        from pg_constraint
        where conrelid = 'public.quarantine_events'::regclass
          and conname = 'quarantine_events_sha256_matches_report_check'
    ) then
        alter table public.quarantine_events
        add constraint quarantine_events_sha256_matches_report_check
        check (
            analysis_report_id is null
            or sha256 is not null
        );
    end if;
end
$$;

do $$
begin
    if not exists (
        select 1
        from pg_constraint
        where conrelid = 'public.release_policy_decisions'::regclass
          and conname = 'release_policy_decisions_reason_nonempty_check'
    ) then
        alter table public.release_policy_decisions
        add constraint release_policy_decisions_reason_nonempty_check
        check (length(btrim(reason)) > 0);
    end if;
end
$$;

do $$
begin
    if not exists (
        select 1
        from pg_constraint
        where conrelid = 'public.runtime_review_queue'::regclass
          and conname = 'runtime_review_queue_resolution_check'
    ) then
        alter table public.runtime_review_queue
        add constraint runtime_review_queue_resolution_check
        check (
            (status in ('approved', 'rejected', 'resolved') and resolved_at is not null)
            or (status in ('pending', 'in_review') and resolved_at is null)
        );
    end if;
end
$$;

do $$
begin
    if not exists (
        select 1
        from pg_constraint
        where conrelid = 'public.runtime_incidents'::regclass
          and conname = 'runtime_incidents_closed_at_check'
    ) then
        alter table public.runtime_incidents
        add constraint runtime_incidents_closed_at_check
        check (
            (status = 'closed' and closed_at is not null)
            or (status <> 'closed')
        );
    end if;
end
$$;

do $$
begin
    if not exists (
        select 1
        from pg_constraint
        where conrelid = 'public.runtime_sessions'::regclass
          and conname = 'runtime_sessions_ended_at_check'
    ) then
        alter table public.runtime_sessions
        add constraint runtime_sessions_ended_at_check
        check (
            (status in ('completed', 'failed', 'terminated') and ended_at is not null)
            or (status in ('active', 'paused') and ended_at is null)
        );
    end if;
end
$$;