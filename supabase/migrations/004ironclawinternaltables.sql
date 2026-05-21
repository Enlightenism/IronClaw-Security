-- =============================================================================
-- 004_ironclaw_behavioral_tables.sql
-- IronClaw behavioral/observability tables
-- Columns derived from verified to_dict() shapes in app/supabaseclient.py
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Shared trigger function for updated_at maintenance
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ironclaw_set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

-- ---------------------------------------------------------------------------
-- ironclaw_agent_observations
-- Insert-only; upsert conflict target: observation_id
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ironclaw_agent_observations (
    observation_id   TEXT        PRIMARY KEY,
    agent_id         TEXT        NOT NULL,
    session_id       TEXT,
    client_id        TEXT        NOT NULL,
    timestamp        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    action_type      TEXT        NOT NULL,
    target           TEXT,
    risk_score       NUMERIC(5,4),
    matched_patterns JSONB       NOT NULL DEFAULT '[]'::jsonb,
    metadata         JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_obs_agent_id   ON ironclaw_agent_observations (agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_obs_client_id  ON ironclaw_agent_observations (client_id);
CREATE INDEX IF NOT EXISTS idx_agent_obs_session_id ON ironclaw_agent_observations (session_id);
CREATE INDEX IF NOT EXISTS idx_agent_obs_timestamp  ON ironclaw_agent_observations (timestamp DESC);

-- ---------------------------------------------------------------------------
-- ironclaw_agent_baselines
-- Upsert conflict target: agent_id (one active baseline per agent)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ironclaw_agent_baselines (
    baseline_id                    TEXT        PRIMARY KEY,
    agent_id                       TEXT        NOT NULL UNIQUE,
    client_id                      TEXT        NOT NULL,
    status                         TEXT        NOT NULL DEFAULT 'building',
    schema_version                 TEXT        NOT NULL DEFAULT '1.0',
    sample_count                   INTEGER     NOT NULL DEFAULT 0,
    mean_action_rate               NUMERIC(10,6),
    stdev_action_rate              NUMERIC(10,6),
    action_type_distribution       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    mean_risk_score                NUMERIC(5,4),
    stdev_risk_score               NUMERIC(5,4),
    mean_target_breadth            NUMERIC(10,6),
    stdev_target_breadth           NUMERIC(10,6),
    mean_tool_call_rate            NUMERIC(10,6),
    stdev_tool_call_rate           NUMERIC(10,6),
    frozen_action_type_distribution JSONB      NOT NULL DEFAULT '{}'::jsonb,
    baseline_obs_count             INTEGER     NOT NULL DEFAULT 0,
    metadata                       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at                     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_baselines_agent_id  ON ironclaw_agent_baselines (agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_baselines_client_id ON ironclaw_agent_baselines (client_id);

CREATE TRIGGER trg_agent_baselines_updated_at
    BEFORE UPDATE ON ironclaw_agent_baselines
    FOR EACH ROW EXECUTE FUNCTION ironclaw_set_updated_at();

-- ---------------------------------------------------------------------------
-- ironclaw_drift_reports
-- Upsert conflict target: report_id
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ironclaw_drift_reports (
    report_id              TEXT        PRIMARY KEY,
    agent_id               TEXT        NOT NULL,
    client_id              TEXT        NOT NULL,
    session_id             TEXT,
    timestamp              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    window_seconds         INTEGER     NOT NULL DEFAULT 0,
    observation_count      INTEGER     NOT NULL DEFAULT 0,
    baseline_sample_count  INTEGER     NOT NULL DEFAULT 0,
    baseline_status        TEXT,
    overall_drift_score    NUMERIC(5,4),
    overall_severity       TEXT,
    signals                JSONB       NOT NULL DEFAULT '[]'::jsonb,
    recommendations        JSONB       NOT NULL DEFAULT '[]'::jsonb,
    should_alert           BOOLEAN     NOT NULL DEFAULT FALSE,
    should_suspend         BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_drift_reports_agent_id   ON ironclaw_drift_reports (agent_id);
CREATE INDEX IF NOT EXISTS idx_drift_reports_client_id  ON ironclaw_drift_reports (client_id);
CREATE INDEX IF NOT EXISTS idx_drift_reports_session_id ON ironclaw_drift_reports (session_id);
CREATE INDEX IF NOT EXISTS idx_drift_reports_timestamp  ON ironclaw_drift_reports (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_drift_reports_severity   ON ironclaw_drift_reports (overall_severity);

-- ---------------------------------------------------------------------------
-- ironclaw_alerts
-- Upsert conflict target: alert_id
-- fetch_alerts() filters on: status, severity, created_at, client_id
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ironclaw_alerts (
    alert_id   TEXT        PRIMARY KEY,
    client_id  TEXT        NOT NULL,
    status     TEXT        NOT NULL DEFAULT 'open',
    severity   TEXT        NOT NULL DEFAULT 'medium',
    metadata   JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_client_id  ON ironclaw_alerts (client_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status     ON ironclaw_alerts (status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON ironclaw_alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON ironclaw_alerts (created_at DESC);

CREATE TRIGGER trg_alerts_updated_at
    BEFORE UPDATE ON ironclaw_alerts
    FOR EACH ROW EXECUTE FUNCTION ironclaw_set_updated_at();

-- ---------------------------------------------------------------------------
-- ironclaw_audit_logs
-- Insert-only (persist_audit_log); no upsert, no updated_at
-- Shape from SecurityAuditEvent dataclass in app/orchestrator/security_audit_log.py
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ironclaw_audit_logs (
    event_id   TEXT        PRIMARY KEY,
    event_type TEXT        NOT NULL,
    actor_id   TEXT,
    action_type TEXT,
    target     TEXT,
    verdict    TEXT,
    risk_score NUMERIC(5,4),
    reason     TEXT,
    session_id TEXT,
    file_path  TEXT,
    trace_id   TEXT,
    request_id TEXT,
    agent_id   TEXT,
    client_id  TEXT        NOT NULL,
    metadata   JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_client_id   ON ironclaw_audit_logs (client_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_agent_id    ON ironclaw_audit_logs (agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_session_id  ON ironclaw_audit_logs (session_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type  ON ironclaw_audit_logs (event_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_verdict     ON ironclaw_audit_logs (verdict);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at  ON ironclaw_audit_logs (created_at DESC);