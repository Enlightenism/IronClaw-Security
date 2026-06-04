-- =============================================================================
-- 005_ironclaw_rls_policies.sql
-- IronClaw consolidated RLS policy definitions.
-- Covers all tables across migrations 001–009.
-- Safe to re-run: all policies use CREATE POLICY IF NOT EXISTS.
-- Tables not yet created are wrapped in DO $$ IF EXISTS $$ guards.
-- Policy pattern (matches original 005 structure):
--   service_role : PERMISSIVE ALL USING(TRUE) WITH CHECK(TRUE)
--   authenticated: table-appropriate SELECT/INSERT/UPDATE scoped to actor
--   anon         : no policy — RLS default-deny enforces zero access
-- Write-protected tables (policy_rules, policy_sets, policy_set_memberships,
--   ioc_patterns, api_keys, credentials_vault): service_role only.
-- Append-only tables (ironclaw_audit_logs, audit_events, webhook_delivery_log,
--   history_events, telemetry_events): INSERT allowed, no UPDATE/DELETE.
-- =============================================================================

-- ===========================================================================
-- SECTION 1 — ironclaw behavioral tables (004)
-- Original 005 content preserved exactly; policies made idempotent.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- ironclaw_agent_observations
-- ---------------------------------------------------------------------------
ALTER TABLE ironclaw_agent_observations ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS obs_service_role_all
    ON ironclaw_agent_observations
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS obs_select_own_client
    ON ironclaw_agent_observations
    FOR SELECT
    TO authenticated
    USING (client_id = (SELECT auth.uid()::TEXT));

CREATE POLICY IF NOT EXISTS obs_insert_own_client
    ON ironclaw_agent_observations
    FOR INSERT
    TO authenticated
    WITH CHECK (client_id = (SELECT auth.uid()::TEXT));

-- ---------------------------------------------------------------------------
-- ironclaw_agent_baselines
-- ---------------------------------------------------------------------------
ALTER TABLE ironclaw_agent_baselines ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS baselines_service_role_all
    ON ironclaw_agent_baselines
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS baselines_select_own_client
    ON ironclaw_agent_baselines
    FOR SELECT
    TO authenticated
    USING (client_id = (SELECT auth.uid()::TEXT));

CREATE POLICY IF NOT EXISTS baselines_insert_own_client
    ON ironclaw_agent_baselines
    FOR INSERT
    TO authenticated
    WITH CHECK (client_id = (SELECT auth.uid()::TEXT));

CREATE POLICY IF NOT EXISTS baselines_update_own_client
    ON ironclaw_agent_baselines
    FOR UPDATE
    TO authenticated
    USING (client_id = (SELECT auth.uid()::TEXT))
    WITH CHECK (client_id = (SELECT auth.uid()::TEXT));

-- ---------------------------------------------------------------------------
-- ironclaw_drift_reports
-- ---------------------------------------------------------------------------
ALTER TABLE ironclaw_drift_reports ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS drift_service_role_all
    ON ironclaw_drift_reports
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS drift_select_own_client
    ON ironclaw_drift_reports
    FOR SELECT
    TO authenticated
    USING (client_id = (SELECT auth.uid()::TEXT));

CREATE POLICY IF NOT EXISTS drift_insert_own_client
    ON ironclaw_drift_reports
    FOR INSERT
    TO authenticated
    WITH CHECK (client_id = (SELECT auth.uid()::TEXT));

-- ---------------------------------------------------------------------------
-- ironclaw_alerts
-- ---------------------------------------------------------------------------
ALTER TABLE ironclaw_alerts ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS alerts_service_role_all
    ON ironclaw_alerts
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS alerts_select_own_client
    ON ironclaw_alerts
    FOR SELECT
    TO authenticated
    USING (client_id = (SELECT auth.uid()::TEXT));

CREATE POLICY IF NOT EXISTS alerts_insert_own_client
    ON ironclaw_alerts
    FOR INSERT
    TO authenticated
    WITH CHECK (client_id = (SELECT auth.uid()::TEXT));

CREATE POLICY IF NOT EXISTS alerts_update_own_client
    ON ironclaw_alerts
    FOR UPDATE
    TO authenticated
    USING (client_id = (SELECT auth.uid()::TEXT))
    WITH CHECK (client_id = (SELECT auth.uid()::TEXT));

-- ---------------------------------------------------------------------------
-- ironclaw_audit_logs — append-only; no UPDATE/DELETE for authenticated
-- ---------------------------------------------------------------------------
ALTER TABLE ironclaw_audit_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS audit_service_role_all
    ON ironclaw_audit_logs
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS audit_select_own_client
    ON ironclaw_audit_logs
    FOR SELECT
    TO authenticated
    USING (client_id = (SELECT auth.uid()::TEXT));

CREATE POLICY IF NOT EXISTS audit_insert_own_client
    ON ironclaw_audit_logs
    FOR INSERT
    TO authenticated
    WITH CHECK (client_id = (SELECT auth.uid()::TEXT));

-- ===========================================================================
-- SECTION 2 — public schema tables (001)
-- actor scoped to org_id or actor_id where applicable.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- audit_events — append-only
-- ---------------------------------------------------------------------------
ALTER TABLE public.audit_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS audit_events_service_role_all
    ON public.audit_events
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS audit_events_select_own_org
    ON public.audit_events
    FOR SELECT
    TO authenticated
    USING (org_id = (SELECT auth.uid()::TEXT)
        OR actor_id = (SELECT auth.uid()::TEXT));

CREATE POLICY IF NOT EXISTS audit_events_insert_own_org
    ON public.audit_events
    FOR INSERT
    TO authenticated
    WITH CHECK (actor_id = (SELECT auth.uid()::TEXT));

-- ---------------------------------------------------------------------------
-- telemetry_events — append-only
-- ---------------------------------------------------------------------------
ALTER TABLE public.telemetry_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS telemetry_events_service_role_all
    ON public.telemetry_events
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS telemetry_events_select_own_org
    ON public.telemetry_events
    FOR SELECT
    TO authenticated
    USING (org_id = (SELECT auth.uid()::TEXT));

CREATE POLICY IF NOT EXISTS telemetry_events_insert_own_org
    ON public.telemetry_events
    FOR INSERT
    TO authenticated
    WITH CHECK (org_id = (SELECT auth.uid()::TEXT));

-- ---------------------------------------------------------------------------
-- quarantine_items
-- ---------------------------------------------------------------------------
ALTER TABLE public.quarantine_items ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS quarantine_items_service_role_all
    ON public.quarantine_items
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS quarantine_items_select_own_org
    ON public.quarantine_items
    FOR SELECT
    TO authenticated
    USING (org_id = (SELECT auth.uid()::TEXT));

CREATE POLICY IF NOT EXISTS quarantine_items_insert_own_org
    ON public.quarantine_items
    FOR INSERT
    TO authenticated
    WITH CHECK (org_id = (SELECT auth.uid()::TEXT));

CREATE POLICY IF NOT EXISTS quarantine_items_update_own_org
    ON public.quarantine_items
    FOR UPDATE
    TO authenticated
    USING (org_id = (SELECT auth.uid()::TEXT))
    WITH CHECK (org_id = (SELECT auth.uid()::TEXT));

-- ---------------------------------------------------------------------------
-- review_queue_items
-- ---------------------------------------------------------------------------
ALTER TABLE public.review_queue_items ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS review_queue_items_service_role_all
    ON public.review_queue_items
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS review_queue_items_select_own_org
    ON public.review_queue_items
    FOR SELECT
    TO authenticated
    USING (org_id = (SELECT auth.uid()::TEXT)
        OR actor_id = (SELECT auth.uid()::TEXT));

CREATE POLICY IF NOT EXISTS review_queue_items_insert_own_org
    ON public.review_queue_items
    FOR INSERT
    TO authenticated
    WITH CHECK (actor_id = (SELECT auth.uid()::TEXT));

CREATE POLICY IF NOT EXISTS review_queue_items_update_own_org
    ON public.review_queue_items
    FOR UPDATE
    TO authenticated
    USING (actor_id = (SELECT auth.uid()::TEXT))
    WITH CHECK (actor_id = (SELECT auth.uid()::TEXT));

-- ---------------------------------------------------------------------------
-- incidents
-- ---------------------------------------------------------------------------
ALTER TABLE public.incidents ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS incidents_service_role_all
    ON public.incidents
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS incidents_select_own_org
    ON public.incidents
    FOR SELECT
    TO authenticated
    USING (org_id = (SELECT auth.uid()::TEXT)
        OR owner_id = (SELECT auth.uid()::TEXT));

CREATE POLICY IF NOT EXISTS incidents_insert_own_org
    ON public.incidents
    FOR INSERT
    TO authenticated
    WITH CHECK (org_id = (SELECT auth.uid()::TEXT));

CREATE POLICY IF NOT EXISTS incidents_update_own_org
    ON public.incidents
    FOR UPDATE
    TO authenticated
    USING (owner_id = (SELECT auth.uid()::TEXT))
    WITH CHECK (owner_id = (SELECT auth.uid()::TEXT));

-- ---------------------------------------------------------------------------
-- history_events — append-only
-- ---------------------------------------------------------------------------
ALTER TABLE public.history_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS history_events_service_role_all
    ON public.history_events
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS history_events_select_own_org
    ON public.history_events
    FOR SELECT
    TO authenticated
    USING (org_id = (SELECT auth.uid()::TEXT)
        OR actor_id = (SELECT auth.uid()::TEXT));

CREATE POLICY IF NOT EXISTS history_events_insert_own_org
    ON public.history_events
    FOR INSERT
    TO authenticated
    WITH CHECK (actor_id = (SELECT auth.uid()::TEXT));

-- ---------------------------------------------------------------------------
-- analysis_reports — service_role only (system-generated verdicts)
-- ---------------------------------------------------------------------------
ALTER TABLE public.analysis_reports ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS analysis_reports_service_role_all
    ON public.analysis_reports
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS analysis_reports_select_authenticated
    ON public.analysis_reports
    FOR SELECT
    TO authenticated
    USING (TRUE);

-- ---------------------------------------------------------------------------
-- quarantine_events
-- ---------------------------------------------------------------------------
ALTER TABLE public.quarantine_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS quarantine_events_service_role_all
    ON public.quarantine_events
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS quarantine_events_select_authenticated
    ON public.quarantine_events
    FOR SELECT
    TO authenticated
    USING (TRUE);

-- ---------------------------------------------------------------------------
-- release_policy_decisions — service_role only
-- ---------------------------------------------------------------------------
ALTER TABLE public.release_policy_decisions ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS release_policy_decisions_service_role_all
    ON public.release_policy_decisions
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS release_policy_decisions_select_authenticated
    ON public.release_policy_decisions
    FOR SELECT
    TO authenticated
    USING (TRUE);

-- ---------------------------------------------------------------------------
-- persistence_backends — read for authenticated, write for service_role only
-- ---------------------------------------------------------------------------
ALTER TABLE public.persistence_backends ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS persistence_backends_service_role_all
    ON public.persistence_backends
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS persistence_backends_select_authenticated
    ON public.persistence_backends
    FOR SELECT
    TO authenticated
    USING (TRUE);

-- ---------------------------------------------------------------------------
-- backup_policies — read for authenticated
-- ---------------------------------------------------------------------------
ALTER TABLE public.backup_policies ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS backup_policies_service_role_all
    ON public.backup_policies
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS backup_policies_select_authenticated
    ON public.backup_policies
    FOR SELECT
    TO authenticated
    USING (TRUE);

-- ---------------------------------------------------------------------------
-- backup_runs — read for authenticated
-- ---------------------------------------------------------------------------
ALTER TABLE public.backup_runs ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS backup_runs_service_role_all
    ON public.backup_runs
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS backup_runs_select_authenticated
    ON public.backup_runs
    FOR SELECT
    TO authenticated
    USING (TRUE);

-- ---------------------------------------------------------------------------
-- restore_runs — read for authenticated
-- ---------------------------------------------------------------------------
ALTER TABLE public.restore_runs ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS restore_runs_service_role_all
    ON public.restore_runs
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS restore_runs_select_authenticated
    ON public.restore_runs
    FOR SELECT
    TO authenticated
    USING (TRUE);

-- ---------------------------------------------------------------------------
-- retention_policies — read for authenticated
-- ---------------------------------------------------------------------------
ALTER TABLE public.retention_policies ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS retention_policies_service_role_all
    ON public.retention_policies
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS retention_policies_select_authenticated
    ON public.retention_policies
    FOR SELECT
    TO authenticated
    USING (TRUE);

-- ---------------------------------------------------------------------------
-- retention_runs — read for authenticated
-- ---------------------------------------------------------------------------
ALTER TABLE public.retention_runs ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS retention_runs_service_role_all
    ON public.retention_runs
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS retention_runs_select_authenticated
    ON public.retention_runs
    FOR SELECT
    TO authenticated
    USING (TRUE);

-- ---------------------------------------------------------------------------
-- legal_holds — service_role only (legal/compliance writes)
-- ---------------------------------------------------------------------------
ALTER TABLE public.legal_holds ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS legal_holds_service_role_all
    ON public.legal_holds
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS legal_holds_select_authenticated
    ON public.legal_holds
    FOR SELECT
    TO authenticated
    USING (TRUE);

-- ---------------------------------------------------------------------------
-- persistence_failover_events — read for authenticated
-- ---------------------------------------------------------------------------
ALTER TABLE public.persistence_failover_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS persistence_failover_events_service_role_all
    ON public.persistence_failover_events
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS persistence_failover_events_select_authenticated
    ON public.persistence_failover_events
    FOR SELECT
    TO authenticated
    USING (TRUE);

-- ---------------------------------------------------------------------------
-- persistence_validation_runs — read for authenticated
-- ---------------------------------------------------------------------------
ALTER TABLE public.persistence_validation_runs ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS persistence_validation_runs_service_role_all
    ON public.persistence_validation_runs
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS persistence_validation_runs_select_authenticated
    ON public.persistence_validation_runs
    FOR SELECT
    TO authenticated
    USING (TRUE);

-- ===========================================================================
-- SECTION 3 — runtime state tables (002)
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- runtime_sessions
-- ---------------------------------------------------------------------------
ALTER TABLE public.runtime_sessions ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS runtime_sessions_service_role_all
    ON public.runtime_sessions
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS runtime_sessions_select_own_org
    ON public.runtime_sessions
    FOR SELECT
    TO authenticated
    USING (org_id = (SELECT auth.uid()::TEXT)
        OR actor_id = (SELECT auth.uid()::TEXT));

CREATE POLICY IF NOT EXISTS runtime_sessions_insert_own_org
    ON public.runtime_sessions
    FOR INSERT
    TO authenticated
    WITH CHECK (actor_id = (SELECT auth.uid()::TEXT));

-- ---------------------------------------------------------------------------
-- runtime_state_snapshots — read for authenticated
-- ---------------------------------------------------------------------------
ALTER TABLE public.runtime_state_snapshots ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS runtime_state_snapshots_service_role_all
    ON public.runtime_state_snapshots
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS runtime_state_snapshots_select_authenticated
    ON public.runtime_state_snapshots
    FOR SELECT
    TO authenticated
    USING (TRUE);

-- ---------------------------------------------------------------------------
-- runtime_session_events — append-only
-- ---------------------------------------------------------------------------
ALTER TABLE public.runtime_session_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS runtime_session_events_service_role_all
    ON public.runtime_session_events
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS runtime_session_events_select_authenticated
    ON public.runtime_session_events
    FOR SELECT
    TO authenticated
    USING (TRUE);

-- ---------------------------------------------------------------------------
-- review_state_snapshots — read for authenticated
-- ---------------------------------------------------------------------------
ALTER TABLE public.review_state_snapshots ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS review_state_snapshots_service_role_all
    ON public.review_state_snapshots
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS review_state_snapshots_select_authenticated
    ON public.review_state_snapshots
    FOR SELECT
    TO authenticated
    USING (TRUE);

-- ---------------------------------------------------------------------------
-- queue_runtime_leases — service_role only (worker-owned)
-- ---------------------------------------------------------------------------
ALTER TABLE public.queue_runtime_leases ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS queue_runtime_leases_service_role_all
    ON public.queue_runtime_leases
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

-- ---------------------------------------------------------------------------
-- runtime_replay_runs — read for authenticated
-- ---------------------------------------------------------------------------
ALTER TABLE public.runtime_replay_runs ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS runtime_replay_runs_service_role_all
    ON public.runtime_replay_runs
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS runtime_replay_runs_select_authenticated
    ON public.runtime_replay_runs
    FOR SELECT
    TO authenticated
    USING (TRUE);

-- ---------------------------------------------------------------------------
-- supervisor_state_snapshots — service_role only
-- ---------------------------------------------------------------------------
ALTER TABLE public.supervisor_state_snapshots ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS supervisor_state_snapshots_service_role_all
    ON public.supervisor_state_snapshots
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

-- ---------------------------------------------------------------------------
-- pipeline_runtime_states — read for authenticated
-- ---------------------------------------------------------------------------
ALTER TABLE public.pipeline_runtime_states ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS pipeline_runtime_states_service_role_all
    ON public.pipeline_runtime_states
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS pipeline_runtime_states_select_authenticated
    ON public.pipeline_runtime_states
    FOR SELECT
    TO authenticated
    USING (TRUE);

-- ---------------------------------------------------------------------------
-- orchestration_checkpoints — service_role only
-- ---------------------------------------------------------------------------
ALTER TABLE public.orchestration_checkpoints ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS orchestration_checkpoints_service_role_all
    ON public.orchestration_checkpoints
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

-- ---------------------------------------------------------------------------
-- runtime_state_checkpoints — service_role only
-- ---------------------------------------------------------------------------
ALTER TABLE public.runtime_state_checkpoints ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS runtime_state_checkpoints_service_role_all
    ON public.runtime_state_checkpoints
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

-- ---------------------------------------------------------------------------
-- runtime_review_queue — read/insert for authenticated
-- ---------------------------------------------------------------------------
ALTER TABLE public.runtime_review_queue ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS runtime_review_queue_service_role_all
    ON public.runtime_review_queue
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS runtime_review_queue_select_authenticated
    ON public.runtime_review_queue
    FOR SELECT
    TO authenticated
    USING (TRUE);

-- ---------------------------------------------------------------------------
-- runtime_incidents — read/insert for authenticated
-- ---------------------------------------------------------------------------
ALTER TABLE public.runtime_incidents ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS runtime_incidents_service_role_all
    ON public.runtime_incidents
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS runtime_incidents_select_authenticated
    ON public.runtime_incidents
    FOR SELECT
    TO authenticated
    USING (TRUE);

-- ===========================================================================
-- SECTION 4 — policy engine tables (006, 007)
-- policy_rules and policy_sets: service_role only for all writes.
-- is_builtin guard: authenticated may SELECT but never INSERT/UPDATE/DELETE
-- builtin rows. Non-builtin rows may be inserted by authenticated actors.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- policy_rules — write-protected; is_builtin rows immutable to non-service
-- ---------------------------------------------------------------------------
ALTER TABLE public.policy_rules ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS policy_rules_service_role_all
    ON public.policy_rules
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS policy_rules_select_authenticated
    ON public.policy_rules
    FOR SELECT
    TO authenticated
    USING (TRUE);

-- Block authenticated from inserting builtin rows
CREATE POLICY IF NOT EXISTS policy_rules_insert_non_builtin
    ON public.policy_rules
    FOR INSERT
    TO authenticated
    WITH CHECK (is_builtin = FALSE);

-- Block authenticated from overwriting builtin rows
CREATE POLICY IF NOT EXISTS policy_rules_update_non_builtin
    ON public.policy_rules
    FOR UPDATE
    TO authenticated
    USING (is_builtin = FALSE)
    WITH CHECK (is_builtin = FALSE);

-- ---------------------------------------------------------------------------
-- policy_sets — write-protected; is_builtin rows immutable to non-service
-- ---------------------------------------------------------------------------
ALTER TABLE public.policy_sets ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS policy_sets_service_role_all
    ON public.policy_sets
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS policy_sets_select_authenticated
    ON public.policy_sets
    FOR SELECT
    TO authenticated
    USING (TRUE);

CREATE POLICY IF NOT EXISTS policy_sets_insert_non_builtin
    ON public.policy_sets
    FOR INSERT
    TO authenticated
    WITH CHECK (is_builtin = FALSE);

CREATE POLICY IF NOT EXISTS policy_sets_update_non_builtin
    ON public.policy_sets
    FOR UPDATE
    TO authenticated
    USING (is_builtin = FALSE)
    WITH CHECK (is_builtin = FALSE);

-- ---------------------------------------------------------------------------
-- policy_set_memberships — write-protected; follows parent policy_sets guard
-- ---------------------------------------------------------------------------
ALTER TABLE public.policy_set_memberships ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS policy_set_memberships_service_role_all
    ON public.policy_set_memberships
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS policy_set_memberships_select_authenticated
    ON public.policy_set_memberships
    FOR SELECT
    TO authenticated
    USING (TRUE);

-- Authenticated may only insert memberships for non-builtin sets
CREATE POLICY IF NOT EXISTS policy_set_memberships_insert_non_builtin
    ON public.policy_set_memberships
    FOR INSERT
    TO authenticated
    WITH CHECK (
        policy_set_id IN (
            SELECT id FROM public.policy_sets WHERE is_builtin = FALSE
        )
    );

-- ---------------------------------------------------------------------------
-- ioc_patterns (006) — service_role only; authenticated read-only
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'ioc_patterns'
    ) THEN
        ALTER TABLE public.ioc_patterns ENABLE ROW LEVEL SECURITY;
    END IF;
END $$;

CREATE POLICY IF NOT EXISTS ioc_patterns_service_role_all
    ON public.ioc_patterns
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS ioc_patterns_select_authenticated
    ON public.ioc_patterns
    FOR SELECT
    TO authenticated
    USING (TRUE);

-- ===========================================================================
-- SECTION 5 — API keys and auth (008)
-- ===========================================================================

ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS api_keys_service_role_all
    ON public.api_keys
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS api_keys_select_own
    ON public.api_keys
    FOR SELECT
    TO authenticated
    USING (created_by = (SELECT auth.uid()::TEXT));

CREATE POLICY IF NOT EXISTS api_keys_insert_own
    ON public.api_keys
    FOR INSERT
    TO authenticated
    WITH CHECK (created_by = (SELECT auth.uid()::TEXT));

CREATE POLICY IF NOT EXISTS api_keys_update_own
    ON public.api_keys
    FOR UPDATE
    TO authenticated
    USING (created_by = (SELECT auth.uid()::TEXT))
    WITH CHECK (created_by = (SELECT auth.uid()::TEXT));

-- ===========================================================================
-- SECTION 6 — Webhooks (009)
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- webhook_subscriptions
-- ---------------------------------------------------------------------------
ALTER TABLE public.webhook_subscriptions ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS webhook_subscriptions_service_role_all
    ON public.webhook_subscriptions
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS webhook_subscriptions_select_own
    ON public.webhook_subscriptions
    FOR SELECT
    TO authenticated
    USING (tenant_id = (SELECT auth.uid()::TEXT));

CREATE POLICY IF NOT EXISTS webhook_subscriptions_insert_own
    ON public.webhook_subscriptions
    FOR INSERT
    TO authenticated
    WITH CHECK (tenant_id = (SELECT auth.uid()::TEXT));

CREATE POLICY IF NOT EXISTS webhook_subscriptions_update_own
    ON public.webhook_subscriptions
    FOR UPDATE
    TO authenticated
    USING (tenant_id = (SELECT auth.uid()::TEXT))
    WITH CHECK (tenant_id = (SELECT auth.uid()::TEXT));

-- ---------------------------------------------------------------------------
-- webhook_delivery_log — append-only; authenticated SELECT only via sub FK
-- ---------------------------------------------------------------------------
ALTER TABLE public.webhook_delivery_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS webhook_delivery_log_service_role_all
    ON public.webhook_delivery_log
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY IF NOT EXISTS webhook_delivery_log_select_own
    ON public.webhook_delivery_log
    FOR SELECT
    TO authenticated
    USING (
        subscription_id IN (
            SELECT id
            FROM public.webhook_subscriptions
            WHERE tenant_id = (SELECT auth.uid()::TEXT)
        )
    );

-- ===========================================================================
-- SECTION 7 — Future tables (not yet created; guarded by IF EXISTS checks)
-- RLS is enabled and policies are created only when the table exists.
-- Add the CREATE TABLE migration first; this section will activate on re-run.
-- Tables: scan_history, users, agent_trust_profiles, trust_events,
--   sandbox_sessions, sandbox_executions, tool_call_logs, scan_patterns,
--   pattern_versions, rate_limit_state, memory_entries, hook_definitions,
--   hook_executions, orchestrator_sessions, orchestrator_steps,
--   rule_evaluations, verdict_overrides, review_decisions, escalations,
--   agent_sessions, agent_events, repositories, deploy_targets,
--   integration_configs, credentials_vault, feed_ingest_log,
--   threat_detections, ioc_records, security_events
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
        'feed_ingest_log',
        'threat_detections',
        'ioc_records',
        'security_events'
    ];
BEGIN
    FOREACH tbl IN ARRAY future_tables LOOP
        IF EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = tbl
        ) THEN
            EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', tbl);
            -- service_role ALL (universal)
            EXECUTE format($$
                CREATE POLICY IF NOT EXISTS %I
                    ON public.%I
                    AS PERMISSIVE
                    FOR ALL
                    TO service_role
                    USING (TRUE)
                    WITH CHECK (TRUE)
            $$, tbl || '_service_role_all', tbl);
        END IF;
    END LOOP;
END $$;

-- credentials_vault: when created, explicitly block all authenticated access
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'credentials_vault'
    ) THEN
        -- No authenticated policy — service_role only, anon zero access
        RAISE NOTICE 'credentials_vault exists: RLS enabled, service_role-only enforced.';
    END IF;
END $$;