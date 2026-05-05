create extension if not exists pgcrypto;

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

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
    new.updated_at = timezone('utc', now());
    return new;
end;
$$;

drop trigger if exists trg_analysis_reports_updated_at on public.analysis_reports;

create trigger trg_analysis_reports_updated_at
before update on public.analysis_reports
for each row
execute function public.set_updated_at();

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