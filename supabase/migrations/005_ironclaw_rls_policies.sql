ALTER TABLE ironclaw_agent_observations ENABLE ROW LEVEL SECURITY;

CREATE POLICY obs_select_own_client
    ON ironclaw_agent_observations
    FOR SELECT
    USING (client_id = (SELECT auth.uid()::TEXT));

CREATE POLICY obs_insert_own_client
    ON ironclaw_agent_observations
    FOR INSERT
    WITH CHECK (client_id = (SELECT auth.uid()::TEXT));

CREATE POLICY obs_service_role_all
    ON ironclaw_agent_observations
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

-- ---------------------------------------------------------------------------
-- ironclaw_agent_baselines
-- ---------------------------------------------------------------------------
ALTER TABLE ironclaw_agent_baselines ENABLE ROW LEVEL SECURITY;

CREATE POLICY baselines_select_own_client
    ON ironclaw_agent_baselines
    FOR SELECT
    USING (client_id = (SELECT auth.uid()::TEXT));

CREATE POLICY baselines_insert_own_client
    ON ironclaw_agent_baselines
    FOR INSERT
    WITH CHECK (client_id = (SELECT auth.uid()::TEXT));

CREATE POLICY baselines_update_own_client
    ON ironclaw_agent_baselines
    FOR UPDATE
    USING (client_id = (SELECT auth.uid()::TEXT))
    WITH CHECK (client_id = (SELECT auth.uid()::TEXT));

CREATE POLICY baselines_service_role_all
    ON ironclaw_agent_baselines
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

-- ---------------------------------------------------------------------------
-- ironclaw_drift_reports
-- ---------------------------------------------------------------------------
ALTER TABLE ironclaw_drift_reports ENABLE ROW LEVEL SECURITY;

CREATE POLICY drift_select_own_client
    ON ironclaw_drift_reports
    FOR SELECT
    USING (client_id = (SELECT auth.uid()::TEXT));

CREATE POLICY drift_insert_own_client
    ON ironclaw_drift_reports
    FOR INSERT
    WITH CHECK (client_id = (SELECT auth.uid()::TEXT));

CREATE POLICY drift_service_role_all
    ON ironclaw_drift_reports
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

-- ---------------------------------------------------------------------------
-- ironclaw_alerts
-- ---------------------------------------------------------------------------
ALTER TABLE ironclaw_alerts ENABLE ROW LEVEL SECURITY;

CREATE POLICY alerts_select_own_client
    ON ironclaw_alerts
    FOR SELECT
    USING (client_id = (SELECT auth.uid()::TEXT));

CREATE POLICY alerts_insert_own_client
    ON ironclaw_alerts
    FOR INSERT
    WITH CHECK (client_id = (SELECT auth.uid()::TEXT));

CREATE POLICY alerts_update_own_client
    ON ironclaw_alerts
    FOR UPDATE
    USING (client_id = (SELECT auth.uid()::TEXT))
    WITH CHECK (client_id = (SELECT auth.uid()::TEXT));

CREATE POLICY alerts_service_role_all
    ON ironclaw_alerts
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

-- ---------------------------------------------------------------------------
-- ironclaw_audit_logs
-- Insert-only for authenticated clients; no UPDATE/DELETE by design.
-- ---------------------------------------------------------------------------
ALTER TABLE ironclaw_audit_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY audit_select_own_client
    ON ironclaw_audit_logs
    FOR SELECT
    USING (client_id = (SELECT auth.uid()::TEXT));

CREATE POLICY audit_insert_own_client
    ON ironclaw_audit_logs
    FOR INSERT
    WITH CHECK (client_id = (SELECT auth.uid()::TEXT));

CREATE POLICY audit_service_role_all
    ON ironclaw_audit_logs
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);