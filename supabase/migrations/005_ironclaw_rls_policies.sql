-- ---------------------------------------------------------------------------
-- private.install_key_secrets — service_role only
-- ---------------------------------------------------------------------------

ALTER TABLE private.install_key_secrets ENABLE ROW LEVEL SECURITY;


DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'private' AND tablename = 'install_key_secrets' AND policyname = 'private_install_key_secrets_service_role_all') THEN
    CREATE POLICY private_install_key_secrets_service_role_all ON private.install_key_secrets AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;


-- ---------------------------------------------------------------------------
-- Idempotent column additions for legacy table shapes
-- Ensures all columns referenced by RLS policies exist before policies are created
-- ---------------------------------------------------------------------------

ALTER TABLE public.audit_events ADD COLUMN IF NOT EXISTS org_id TEXT;
ALTER TABLE public.audit_events ADD COLUMN IF NOT EXISTS actor_id TEXT;

ALTER TABLE public.telemetry_events ADD COLUMN IF NOT EXISTS org_id TEXT;

ALTER TABLE public.quarantine_items ADD COLUMN IF NOT EXISTS org_id TEXT;

ALTER TABLE public.review_queue_items ADD COLUMN IF NOT EXISTS org_id TEXT;
ALTER TABLE public.review_queue_items ADD COLUMN IF NOT EXISTS actor_id TEXT;

ALTER TABLE public.incidents ADD COLUMN IF NOT EXISTS org_id TEXT;
ALTER TABLE public.incidents ADD COLUMN IF NOT EXISTS owner_id TEXT;

ALTER TABLE public.history_events ADD COLUMN IF NOT EXISTS org_id TEXT;
ALTER TABLE public.history_events ADD COLUMN IF NOT EXISTS actor_id TEXT;

ALTER TABLE public.runtime_sessions ADD COLUMN IF NOT EXISTS org_id TEXT;
ALTER TABLE public.runtime_sessions ADD COLUMN IF NOT EXISTS actor_id TEXT;

ALTER TABLE public.api_keys ADD COLUMN IF NOT EXISTS created_by TEXT;

ALTER TABLE public.webhook_subscriptions ADD COLUMN IF NOT EXISTS tenant_id TEXT;

ALTER TABLE public.webhook_delivery_log ADD COLUMN IF NOT EXISTS subscription_id UUID;
ALTER TABLE public.webhook_delivery_log ADD COLUMN IF NOT EXISTS tenant_id TEXT;

ALTER TABLE public.policy_rules ADD COLUMN IF NOT EXISTS is_builtin BOOLEAN DEFAULT FALSE;

ALTER TABLE public.policy_sets ADD COLUMN IF NOT EXISTS is_builtin BOOLEAN DEFAULT FALSE;

ALTER TABLE public.policy_set_memberships ADD COLUMN IF NOT EXISTS policy_set_id UUID;


-- ===========================================================================
-- SECTION 1 — ironclaw behavioral tables (004)
-- ===========================================================================

ALTER TABLE ironclaw_agent_observations ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'ironclaw_agent_observations' AND policyname = 'obs_service_role_all') THEN
    CREATE POLICY obs_service_role_all ON ironclaw_agent_observations AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'ironclaw_agent_observations' AND policyname = 'obs_select_own_client') THEN
    CREATE POLICY obs_select_own_client ON ironclaw_agent_observations FOR SELECT TO authenticated USING (client_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'ironclaw_agent_observations' AND policyname = 'obs_insert_own_client') THEN
    CREATE POLICY obs_insert_own_client ON ironclaw_agent_observations FOR INSERT TO authenticated WITH CHECK (client_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE ironclaw_agent_baselines ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'ironclaw_agent_baselines' AND policyname = 'baselines_service_role_all') THEN
    CREATE POLICY baselines_service_role_all ON ironclaw_agent_baselines AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'ironclaw_agent_baselines' AND policyname = 'baselines_select_own_client') THEN
    CREATE POLICY baselines_select_own_client ON ironclaw_agent_baselines FOR SELECT TO authenticated USING (client_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'ironclaw_agent_baselines' AND policyname = 'baselines_insert_own_client') THEN
    CREATE POLICY baselines_insert_own_client ON ironclaw_agent_baselines FOR INSERT TO authenticated WITH CHECK (client_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'ironclaw_agent_baselines' AND policyname = 'baselines_update_own_client') THEN
    CREATE POLICY baselines_update_own_client ON ironclaw_agent_baselines FOR UPDATE TO authenticated USING (client_id = (SELECT auth.uid()::TEXT)) WITH CHECK (client_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE ironclaw_drift_reports ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'ironclaw_drift_reports' AND policyname = 'drift_service_role_all') THEN
    CREATE POLICY drift_service_role_all ON ironclaw_drift_reports AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'ironclaw_drift_reports' AND policyname = 'drift_select_own_client') THEN
    CREATE POLICY drift_select_own_client ON ironclaw_drift_reports FOR SELECT TO authenticated USING (client_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'ironclaw_drift_reports' AND policyname = 'drift_insert_own_client') THEN
    CREATE POLICY drift_insert_own_client ON ironclaw_drift_reports FOR INSERT TO authenticated WITH CHECK (client_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE ironclaw_alerts ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'ironclaw_alerts' AND policyname = 'alerts_service_role_all') THEN
    CREATE POLICY alerts_service_role_all ON ironclaw_alerts AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'ironclaw_alerts' AND policyname = 'alerts_select_own_client') THEN
    CREATE POLICY alerts_select_own_client ON ironclaw_alerts FOR SELECT TO authenticated USING (client_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'ironclaw_alerts' AND policyname = 'alerts_insert_own_client') THEN
    CREATE POLICY alerts_insert_own_client ON ironclaw_alerts FOR INSERT TO authenticated WITH CHECK (client_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'ironclaw_alerts' AND policyname = 'alerts_update_own_client') THEN
    CREATE POLICY alerts_update_own_client ON ironclaw_alerts FOR UPDATE TO authenticated USING (client_id = (SELECT auth.uid()::TEXT)) WITH CHECK (client_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- ironclaw_audit_logs — append-only

ALTER TABLE ironclaw_audit_logs ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'ironclaw_audit_logs' AND policyname = 'audit_service_role_all') THEN
    CREATE POLICY audit_service_role_all ON ironclaw_audit_logs AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'ironclaw_audit_logs' AND policyname = 'audit_select_own_client') THEN
    CREATE POLICY audit_select_own_client ON ironclaw_audit_logs FOR SELECT TO authenticated USING (client_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'ironclaw_audit_logs' AND policyname = 'audit_insert_own_client') THEN
    CREATE POLICY audit_insert_own_client ON ironclaw_audit_logs FOR INSERT TO authenticated WITH CHECK (client_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

-- ===========================================================================
-- SECTION 2 — public schema tables (001)
-- ===========================================================================

ALTER TABLE public.audit_events ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'audit_events' AND policyname = 'audit_events_service_role_all') THEN
    CREATE POLICY audit_events_service_role_all ON public.audit_events AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'audit_events' AND policyname = 'audit_events_select_own_org') THEN
    CREATE POLICY audit_events_select_own_org ON public.audit_events FOR SELECT TO authenticated USING (org_id = (SELECT auth.uid()::TEXT) OR actor_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'audit_events' AND policyname = 'audit_events_insert_own_org') THEN
    CREATE POLICY audit_events_insert_own_org ON public.audit_events FOR INSERT TO authenticated WITH CHECK (actor_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.telemetry_events ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'telemetry_events' AND policyname = 'telemetry_events_service_role_all') THEN
    CREATE POLICY telemetry_events_service_role_all ON public.telemetry_events AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'telemetry_events' AND policyname = 'telemetry_events_select_own_org') THEN
    CREATE POLICY telemetry_events_select_own_org ON public.telemetry_events FOR SELECT TO authenticated USING (org_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'telemetry_events' AND policyname = 'telemetry_events_insert_own_org') THEN
    CREATE POLICY telemetry_events_insert_own_org ON public.telemetry_events FOR INSERT TO authenticated WITH CHECK (org_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.quarantine_items ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'quarantine_items' AND policyname = 'quarantine_items_service_role_all') THEN
    CREATE POLICY quarantine_items_service_role_all ON public.quarantine_items AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'quarantine_items' AND policyname = 'quarantine_items_select_own_org') THEN
    CREATE POLICY quarantine_items_select_own_org ON public.quarantine_items FOR SELECT TO authenticated USING (org_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'quarantine_items' AND policyname = 'quarantine_items_insert_own_org') THEN
    CREATE POLICY quarantine_items_insert_own_org ON public.quarantine_items FOR INSERT TO authenticated WITH CHECK (org_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'quarantine_items' AND policyname = 'quarantine_items_update_own_org') THEN
    CREATE POLICY quarantine_items_update_own_org ON public.quarantine_items FOR UPDATE TO authenticated USING (org_id = (SELECT auth.uid()::TEXT)) WITH CHECK (org_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.review_queue_items ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'review_queue_items' AND policyname = 'review_queue_items_service_role_all') THEN
    CREATE POLICY review_queue_items_service_role_all ON public.review_queue_items AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'review_queue_items' AND policyname = 'review_queue_items_select_own_org') THEN
    CREATE POLICY review_queue_items_select_own_org ON public.review_queue_items FOR SELECT TO authenticated USING (org_id = (SELECT auth.uid()::TEXT) OR actor_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'review_queue_items' AND policyname = 'review_queue_items_insert_own_org') THEN
    CREATE POLICY review_queue_items_insert_own_org ON public.review_queue_items FOR INSERT TO authenticated WITH CHECK (actor_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'review_queue_items' AND policyname = 'review_queue_items_update_own_org') THEN
    CREATE POLICY review_queue_items_update_own_org ON public.review_queue_items FOR UPDATE TO authenticated USING (actor_id = (SELECT auth.uid()::TEXT)) WITH CHECK (actor_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.incidents ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'incidents' AND policyname = 'incidents_service_role_all') THEN
    CREATE POLICY incidents_service_role_all ON public.incidents AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'incidents' AND policyname = 'incidents_select_own_org') THEN
    CREATE POLICY incidents_select_own_org ON public.incidents FOR SELECT TO authenticated USING (org_id = (SELECT auth.uid()::TEXT) OR owner_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'incidents' AND policyname = 'incidents_insert_own_org') THEN
    CREATE POLICY incidents_insert_own_org ON public.incidents FOR INSERT TO authenticated WITH CHECK (org_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'incidents' AND policyname = 'incidents_update_own_org') THEN
    CREATE POLICY incidents_update_own_org ON public.incidents FOR UPDATE TO authenticated USING (owner_id = (SELECT auth.uid()::TEXT)) WITH CHECK (owner_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- history_events — append-only

ALTER TABLE public.history_events ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'history_events' AND policyname = 'history_events_service_role_all') THEN
    CREATE POLICY history_events_service_role_all ON public.history_events AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'history_events' AND policyname = 'history_events_select_own_org') THEN
    CREATE POLICY history_events_select_own_org ON public.history_events FOR SELECT TO authenticated USING (org_id = (SELECT auth.uid()::TEXT) OR actor_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'history_events' AND policyname = 'history_events_insert_own_org') THEN
    CREATE POLICY history_events_insert_own_org ON public.history_events FOR INSERT TO authenticated WITH CHECK (actor_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.analysis_reports ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'analysis_reports' AND policyname = 'analysis_reports_service_role_all') THEN
    CREATE POLICY analysis_reports_service_role_all ON public.analysis_reports AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'analysis_reports' AND policyname = 'analysis_reports_select_authenticated') THEN
    CREATE POLICY analysis_reports_select_authenticated ON public.analysis_reports FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.quarantine_events ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'quarantine_events' AND policyname = 'quarantine_events_service_role_all') THEN
    CREATE POLICY quarantine_events_service_role_all ON public.quarantine_events AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'quarantine_events' AND policyname = 'quarantine_events_select_authenticated') THEN
    CREATE POLICY quarantine_events_select_authenticated ON public.quarantine_events FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.release_policy_decisions ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'release_policy_decisions' AND policyname = 'release_policy_decisions_service_role_all') THEN
    CREATE POLICY release_policy_decisions_service_role_all ON public.release_policy_decisions AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'release_policy_decisions' AND policyname = 'release_policy_decisions_select_authenticated') THEN
    CREATE POLICY release_policy_decisions_select_authenticated ON public.release_policy_decisions FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.persistence_backends ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'persistence_backends' AND policyname = 'persistence_backends_service_role_all') THEN
    CREATE POLICY persistence_backends_service_role_all ON public.persistence_backends AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'persistence_backends' AND policyname = 'persistence_backends_select_authenticated') THEN
    CREATE POLICY persistence_backends_select_authenticated ON public.persistence_backends FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.backup_policies ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'backup_policies' AND policyname = 'backup_policies_service_role_all') THEN
    CREATE POLICY backup_policies_service_role_all ON public.backup_policies AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'backup_policies' AND policyname = 'backup_policies_select_authenticated') THEN
    CREATE POLICY backup_policies_select_authenticated ON public.backup_policies FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.backup_runs ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'backup_runs' AND policyname = 'backup_runs_service_role_all') THEN
    CREATE POLICY backup_runs_service_role_all ON public.backup_runs AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'backup_runs' AND policyname = 'backup_runs_select_authenticated') THEN
    CREATE POLICY backup_runs_select_authenticated ON public.backup_runs FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.restore_runs ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'restore_runs' AND policyname = 'restore_runs_service_role_all') THEN
    CREATE POLICY restore_runs_service_role_all ON public.restore_runs AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'restore_runs' AND policyname = 'restore_runs_select_authenticated') THEN
    CREATE POLICY restore_runs_select_authenticated ON public.restore_runs FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.retention_policies ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'retention_policies' AND policyname = 'retention_policies_service_role_all') THEN
    CREATE POLICY retention_policies_service_role_all ON public.retention_policies AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'retention_policies' AND policyname = 'retention_policies_select_authenticated') THEN
    CREATE POLICY retention_policies_select_authenticated ON public.retention_policies FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.retention_runs ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'retention_runs' AND policyname = 'retention_runs_service_role_all') THEN
    CREATE POLICY retention_runs_service_role_all ON public.retention_runs AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'retention_runs' AND policyname = 'retention_runs_select_authenticated') THEN
    CREATE POLICY retention_runs_select_authenticated ON public.retention_runs FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.legal_holds ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'legal_holds' AND policyname = 'legal_holds_service_role_all') THEN
    CREATE POLICY legal_holds_service_role_all ON public.legal_holds AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'legal_holds' AND policyname = 'legal_holds_select_authenticated') THEN
    CREATE POLICY legal_holds_select_authenticated ON public.legal_holds FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.persistence_failover_events ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'persistence_failover_events' AND policyname = 'persistence_failover_events_service_role_all') THEN
    CREATE POLICY persistence_failover_events_service_role_all ON public.persistence_failover_events AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'persistence_failover_events' AND policyname = 'persistence_failover_events_select_authenticated') THEN
    CREATE POLICY persistence_failover_events_select_authenticated ON public.persistence_failover_events FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.persistence_validation_runs ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'persistence_validation_runs' AND policyname = 'persistence_validation_runs_service_role_all') THEN
    CREATE POLICY persistence_validation_runs_service_role_all ON public.persistence_validation_runs AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'persistence_validation_runs' AND policyname = 'persistence_validation_runs_select_authenticated') THEN
    CREATE POLICY persistence_validation_runs_select_authenticated ON public.persistence_validation_runs FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

-- ===========================================================================
-- SECTION 3 — runtime state tables (002)
-- ===========================================================================

ALTER TABLE public.runtime_sessions ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'runtime_sessions' AND policyname = 'runtime_sessions_service_role_all') THEN
    CREATE POLICY runtime_sessions_service_role_all ON public.runtime_sessions AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'runtime_sessions' AND policyname = 'runtime_sessions_select_own_org') THEN
    CREATE POLICY runtime_sessions_select_own_org ON public.runtime_sessions FOR SELECT TO authenticated USING (org_id = (SELECT auth.uid()::TEXT) OR actor_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'runtime_sessions' AND policyname = 'runtime_sessions_insert_own_org') THEN
    CREATE POLICY runtime_sessions_insert_own_org ON public.runtime_sessions FOR INSERT TO authenticated WITH CHECK (actor_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.runtime_state_snapshots ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'runtime_state_snapshots' AND policyname = 'runtime_state_snapshots_service_role_all') THEN
    CREATE POLICY runtime_state_snapshots_service_role_all ON public.runtime_state_snapshots AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'runtime_state_snapshots' AND policyname = 'runtime_state_snapshots_select_authenticated') THEN
    CREATE POLICY runtime_state_snapshots_select_authenticated ON public.runtime_state_snapshots FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- runtime_session_events — append-only

ALTER TABLE public.runtime_session_events ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'runtime_session_events' AND policyname = 'runtime_session_events_service_role_all') THEN
    CREATE POLICY runtime_session_events_service_role_all ON public.runtime_session_events AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'runtime_session_events' AND policyname = 'runtime_session_events_select_authenticated') THEN
    CREATE POLICY runtime_session_events_select_authenticated ON public.runtime_session_events FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.review_state_snapshots ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'review_state_snapshots' AND policyname = 'review_state_snapshots_service_role_all') THEN
    CREATE POLICY review_state_snapshots_service_role_all ON public.review_state_snapshots AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'review_state_snapshots' AND policyname = 'review_state_snapshots_select_authenticated') THEN
    CREATE POLICY review_state_snapshots_select_authenticated ON public.review_state_snapshots FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- queue_runtime_leases — service_role only

ALTER TABLE public.queue_runtime_leases ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'queue_runtime_leases' AND policyname = 'queue_runtime_leases_service_role_all') THEN
    CREATE POLICY queue_runtime_leases_service_role_all ON public.queue_runtime_leases AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.runtime_replay_runs ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'runtime_replay_runs' AND policyname = 'runtime_replay_runs_service_role_all') THEN
    CREATE POLICY runtime_replay_runs_service_role_all ON public.runtime_replay_runs AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'runtime_replay_runs' AND policyname = 'runtime_replay_runs_select_authenticated') THEN
    CREATE POLICY runtime_replay_runs_select_authenticated ON public.runtime_replay_runs FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- supervisor_state_snapshots — service_role only

ALTER TABLE public.supervisor_state_snapshots ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'supervisor_state_snapshots' AND policyname = 'supervisor_state_snapshots_service_role_all') THEN
    CREATE POLICY supervisor_state_snapshots_service_role_all ON public.supervisor_state_snapshots AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.pipeline_runtime_states ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'pipeline_runtime_states' AND policyname = 'pipeline_runtime_states_service_role_all') THEN
    CREATE POLICY pipeline_runtime_states_service_role_all ON public.pipeline_runtime_states AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'pipeline_runtime_states' AND policyname = 'pipeline_runtime_states_select_authenticated') THEN
    CREATE POLICY pipeline_runtime_states_select_authenticated ON public.pipeline_runtime_states FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- orchestration_checkpoints — service_role only

ALTER TABLE public.orchestration_checkpoints ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'orchestration_checkpoints' AND policyname = 'orchestration_checkpoints_service_role_all') THEN
    CREATE POLICY orchestration_checkpoints_service_role_all ON public.orchestration_checkpoints AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- runtime_state_checkpoints — service_role only

ALTER TABLE public.runtime_state_checkpoints ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'runtime_state_checkpoints' AND policyname = 'runtime_state_checkpoints_service_role_all') THEN
    CREATE POLICY runtime_state_checkpoints_service_role_all ON public.runtime_state_checkpoints AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.runtime_review_queue ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'runtime_review_queue' AND policyname = 'runtime_review_queue_service_role_all') THEN
    CREATE POLICY runtime_review_queue_service_role_all ON public.runtime_review_queue AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'runtime_review_queue' AND policyname = 'runtime_review_queue_select_authenticated') THEN
    CREATE POLICY runtime_review_queue_select_authenticated ON public.runtime_review_queue FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.runtime_incidents ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'runtime_incidents' AND policyname = 'runtime_incidents_service_role_all') THEN
    CREATE POLICY runtime_incidents_service_role_all ON public.runtime_incidents AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'runtime_incidents' AND policyname = 'runtime_incidents_select_authenticated') THEN
    CREATE POLICY runtime_incidents_select_authenticated ON public.runtime_incidents FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

-- ===========================================================================
-- SECTION 4 — policy engine tables (006, 007)
-- ===========================================================================

ALTER TABLE public.policy_rules ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'policy_rules' AND policyname = 'policy_rules_service_role_all') THEN
    CREATE POLICY policy_rules_service_role_all ON public.policy_rules AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'policy_rules' AND policyname = 'policy_rules_select_authenticated') THEN
    CREATE POLICY policy_rules_select_authenticated ON public.policy_rules FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'policy_rules' AND policyname = 'policy_rules_insert_non_builtin') THEN
    CREATE POLICY policy_rules_insert_non_builtin ON public.policy_rules FOR INSERT TO authenticated WITH CHECK (is_builtin = FALSE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'policy_rules' AND policyname = 'policy_rules_update_non_builtin') THEN
    CREATE POLICY policy_rules_update_non_builtin ON public.policy_rules FOR UPDATE TO authenticated USING (is_builtin = FALSE) WITH CHECK (is_builtin = FALSE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.policy_sets ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'policy_sets' AND policyname = 'policy_sets_service_role_all') THEN
    CREATE POLICY policy_sets_service_role_all ON public.policy_sets AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'policy_sets' AND policyname = 'policy_sets_select_authenticated') THEN
    CREATE POLICY policy_sets_select_authenticated ON public.policy_sets FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'policy_sets' AND policyname = 'policy_sets_insert_non_builtin') THEN
    CREATE POLICY policy_sets_insert_non_builtin ON public.policy_sets FOR INSERT TO authenticated WITH CHECK (is_builtin = FALSE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'policy_sets' AND policyname = 'policy_sets_update_non_builtin') THEN
    CREATE POLICY policy_sets_update_non_builtin ON public.policy_sets FOR UPDATE TO authenticated USING (is_builtin = FALSE) WITH CHECK (is_builtin = FALSE);
  END IF;
END $$;

-- ---------------------------------------------------------------------------

ALTER TABLE public.policy_set_memberships ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'policy_set_memberships' AND policyname = 'policy_set_memberships_service_role_all') THEN
    CREATE POLICY policy_set_memberships_service_role_all ON public.policy_set_memberships AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'policy_set_memberships' AND policyname = 'policy_set_memberships_select_authenticated') THEN
    CREATE POLICY policy_set_memberships_select_authenticated ON public.policy_set_memberships FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'policy_set_memberships' AND policyname = 'policy_set_memberships_insert_non_builtin') THEN
    CREATE POLICY policy_set_memberships_insert_non_builtin ON public.policy_set_memberships FOR INSERT TO authenticated WITH CHECK (
      policy_set_id IN (SELECT id FROM public.policy_sets WHERE is_builtin = FALSE)
    );
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- ioc_patterns — service_role only; authenticated read-only

DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'ioc_patterns') THEN
    ALTER TABLE public.ioc_patterns ENABLE ROW LEVEL SECURITY;
  END IF;
END $$;

DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'ioc_patterns')
     AND NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'ioc_patterns' AND policyname = 'ioc_patterns_service_role_all') THEN
    CREATE POLICY ioc_patterns_service_role_all ON public.ioc_patterns AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'ioc_patterns')
     AND NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'ioc_patterns' AND policyname = 'ioc_patterns_select_authenticated') THEN
    CREATE POLICY ioc_patterns_select_authenticated ON public.ioc_patterns FOR SELECT TO authenticated USING (TRUE);
  END IF;
END $$;

-- ===========================================================================
-- SECTION 5 — API keys and auth (008)
-- ===========================================================================

ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'api_keys' AND policyname = 'api_keys_service_role_all') THEN
    CREATE POLICY api_keys_service_role_all ON public.api_keys AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'api_keys' AND policyname = 'api_keys_select_own') THEN
    CREATE POLICY api_keys_select_own ON public.api_keys FOR SELECT TO authenticated USING (created_by = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'api_keys' AND policyname = 'api_keys_insert_own') THEN
    CREATE POLICY api_keys_insert_own ON public.api_keys FOR INSERT TO authenticated WITH CHECK (created_by = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'api_keys' AND policyname = 'api_keys_update_own') THEN
    CREATE POLICY api_keys_update_own ON public.api_keys FOR UPDATE TO authenticated USING (created_by = (SELECT auth.uid()::TEXT)) WITH CHECK (created_by = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

-- ===========================================================================
-- SECTION 6 — Webhooks (009)
-- ===========================================================================

ALTER TABLE public.webhook_subscriptions ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'webhook_subscriptions' AND policyname = 'webhook_subscriptions_service_role_all') THEN
    CREATE POLICY webhook_subscriptions_service_role_all ON public.webhook_subscriptions AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'webhook_subscriptions' AND policyname = 'webhook_subscriptions_select_own') THEN
    CREATE POLICY webhook_subscriptions_select_own ON public.webhook_subscriptions FOR SELECT TO authenticated USING (tenant_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'webhook_subscriptions' AND policyname = 'webhook_subscriptions_insert_own') THEN
    CREATE POLICY webhook_subscriptions_insert_own ON public.webhook_subscriptions FOR INSERT TO authenticated WITH CHECK (tenant_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'webhook_subscriptions' AND policyname = 'webhook_subscriptions_update_own') THEN
    CREATE POLICY webhook_subscriptions_update_own ON public.webhook_subscriptions FOR UPDATE TO authenticated USING (tenant_id = (SELECT auth.uid()::TEXT)) WITH CHECK (tenant_id = (SELECT auth.uid()::TEXT));
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- webhook_delivery_log — append-only

ALTER TABLE public.webhook_delivery_log ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'webhook_delivery_log' AND policyname = 'webhook_delivery_log_service_role_all') THEN
    CREATE POLICY webhook_delivery_log_service_role_all ON public.webhook_delivery_log AS PERMISSIVE FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'webhook_delivery_log' AND policyname = 'webhook_delivery_log_select_own') THEN
    CREATE POLICY webhook_delivery_log_select_own ON public.webhook_delivery_log FOR SELECT TO authenticated USING (
      subscription_id IN (
        SELECT id FROM public.webhook_subscriptions WHERE tenant_id = (SELECT auth.uid()::TEXT)
      )
    );
  END IF;
END $$;

-- ===========================================================================
-- SECTION 7 — Future tables (guarded by IF EXISTS checks)
-- ===========================================================================

DO $$
DECLARE
    tbl TEXT;
    future_tables TEXT[] := ARRAY[
        'scan_history',
        'users',
        'agent_trust_profiles',
        'trust_events',
        'sandbox_sessions',
        'sandbox_executions',
        'tool_call_logs',
        'scan_patterns',
        'pattern_versions',
        'rate_limit_state',
        'memory_entries',
        'hook_definitions',
        'hook_executions',
        'orchestrator_sessions',
        'orchestrator_steps',
        'rule_evaluations',
        'verdict_overrides',
        'review_decisions',
        'escalations',
        'agent_sessions',
        'agent_events',
        'repositories',
        'deploy_targets',
        'integration_configs',
        'credentials_vault',
        'threat_detections',
        'security_events'
    ];
BEGIN
    FOREACH tbl IN ARRAY future_tables LOOP
        IF EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = tbl
        ) THEN
            EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', tbl);
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies
                WHERE schemaname = 'public'
                  AND tablename = tbl
                  AND policyname = tbl || '_service_role_all'
            ) THEN
                EXECUTE format($p$
                    CREATE POLICY %I
                        ON public.%I
                        AS PERMISSIVE
                        FOR ALL
                        TO service_role
                        USING (TRUE)
                        WITH CHECK (TRUE)
                $p$, tbl || '_service_role_all', tbl);
            END IF;
        END IF;
    END LOOP;
END $$;

-- credentials_vault: when created, service_role-only enforced; no authenticated policy
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'credentials_vault'
    ) THEN
        RAISE NOTICE 'credentials_vault exists: RLS enabled, service_role-only enforced.';
    END IF;
END $$;
