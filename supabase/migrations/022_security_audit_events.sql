-- 022_security_audit_events.sql
-- Durable block-verdict audit events for the security runtime.
-- Written write-through by SecurityAuditEventStore so attack counts survive restarts and multiple workers.
-- Stores verdict metadata only; no raw agent content is stored.

CREATE TABLE IF NOT EXISTS public.security_audit_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    verdict TEXT,
    summary TEXT NOT NULL DEFAULT '',
    actor_id TEXT,
    session_id TEXT,
    request_id TEXT,
    trace_id TEXT,
    integration_id TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_security_audit_events_created_at
    ON public.security_audit_events (created_at DESC);

ALTER TABLE public.security_audit_events ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.security_audit_events FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT ON TABLE public.security_audit_events TO service_role;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public' AND tablename = 'security_audit_events' AND policyname = 'security_audit_events_service_role_select'
    ) THEN
        CREATE POLICY security_audit_events_service_role_select ON public.security_audit_events
            AS PERMISSIVE FOR SELECT TO service_role USING (TRUE);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public' AND tablename = 'security_audit_events' AND policyname = 'security_audit_events_service_role_insert'
    ) THEN
        CREATE POLICY security_audit_events_service_role_insert ON public.security_audit_events
            AS PERMISSIVE FOR INSERT TO service_role WITH CHECK (TRUE);
    END IF;
END
$$;
