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

-- ---------------------------------------------------------------------------
-- Billing + install-key lifecycle state
-- Pattern mirrors the internal tables above: stable PKs, explicit FKs, and
-- updated_at triggers for durable reconciliation after restarts.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ironclaw_billing_purchases (
    purchase_id          TEXT        PRIMARY KEY,
    owner_key            TEXT        NOT NULL,
    package_id           TEXT        NOT NULL,
    checkout_session_id   TEXT,
    customer_id          TEXT,
    buyer_email          TEXT,
    payment_status       TEXT        NOT NULL DEFAULT 'pending',
    fulfillment_status   TEXT        NOT NULL DEFAULT 'pending',
    amount_total         NUMERIC(12,2) NOT NULL DEFAULT 0,
    currency             TEXT        NOT NULL DEFAULT 'usd',
    granted_units        INTEGER     NOT NULL DEFAULT 0,
    units_credited       BOOLEAN     NOT NULL DEFAULT FALSE,
    install_keys_ready   BOOLEAN     NOT NULL DEFAULT FALSE,
    metadata             JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    fulfilled_at         TIMESTAMPTZ,
    CONSTRAINT ironclaw_billing_purchases_payment_status_check
        CHECK (payment_status IN ('pending', 'paid', 'failed', 'refunded', 'cancelled')),
    CONSTRAINT ironclaw_billing_purchases_fulfillment_status_check
        CHECK (fulfillment_status IN ('pending', 'fulfilled', 'failed', 'retrying')),
    CONSTRAINT ironclaw_billing_purchases_owner_key_not_empty_check
        CHECK (char_length(trim(owner_key)) > 0),
    CONSTRAINT ironclaw_billing_purchases_package_id_not_empty_check
        CHECK (char_length(trim(package_id)) > 0),
    CONSTRAINT ironclaw_billing_purchases_amount_total_check
        CHECK (amount_total >= 0),
    CONSTRAINT ironclaw_billing_purchases_granted_units_check
        CHECK (granted_units >= 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ironclaw_billing_purchases_checkout_session
    ON ironclaw_billing_purchases (checkout_session_id)
    WHERE checkout_session_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_ironclaw_billing_purchases_owner_status
    ON ironclaw_billing_purchases (owner_key, payment_status, fulfillment_status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ironclaw_billing_purchases_package_status
    ON ironclaw_billing_purchases (package_id, payment_status, fulfillment_status, created_at DESC);

CREATE TRIGGER trg_ironclaw_billing_purchases_updated_at
    BEFORE UPDATE ON ironclaw_billing_purchases
    FOR EACH ROW EXECUTE FUNCTION ironclaw_set_updated_at();

CREATE TABLE IF NOT EXISTS ironclaw_install_key_state (
    key_id                TEXT        PRIMARY KEY,
    purchase_id           TEXT        NOT NULL REFERENCES ironclaw_billing_purchases(purchase_id) ON DELETE RESTRICT,
    owner_key             TEXT        NOT NULL,
    customer_id           TEXT,
    program               TEXT        NOT NULL,
    checkout_session_id    TEXT,
    raw_key_hash          TEXT        NOT NULL,
    masked_key            TEXT        NOT NULL,
    status                TEXT        NOT NULL DEFAULT 'issued',
    active                BOOLEAN     NOT NULL DEFAULT TRUE,
    issued_after_payment  BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at            TIMESTAMPTZ,
    metadata              JSONB       NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT ironclaw_install_key_state_status_check
        CHECK (status IN ('issued', 'active', 'revoked', 'expired')),
    CONSTRAINT ironclaw_install_key_state_owner_key_not_empty_check
        CHECK (char_length(trim(owner_key)) > 0),
    CONSTRAINT ironclaw_install_key_state_program_not_empty_check
        CHECK (char_length(trim(program)) > 0),
    CONSTRAINT ironclaw_install_key_state_raw_key_hash_not_empty_check
        CHECK (char_length(trim(raw_key_hash)) > 0),
    CONSTRAINT ironclaw_install_key_state_masked_key_not_empty_check
        CHECK (char_length(trim(masked_key)) > 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ironclaw_install_key_state_active_owner_program
    ON ironclaw_install_key_state (owner_key, program)
    WHERE active = TRUE;

CREATE INDEX IF NOT EXISTS idx_ironclaw_install_key_state_purchase_status
    ON ironclaw_install_key_state (purchase_id, status, active, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ironclaw_install_key_state_owner_program
    ON ironclaw_install_key_state (owner_key, program, status, created_at DESC);

CREATE TRIGGER trg_ironclaw_install_key_state_updated_at
    BEFORE UPDATE ON ironclaw_install_key_state
    FOR EACH ROW EXECUTE FUNCTION ironclaw_set_updated_at();

CREATE TABLE IF NOT EXISTS ironclaw_install_key_history (
    history_id            TEXT        PRIMARY KEY,
    key_id                TEXT        NOT NULL REFERENCES ironclaw_install_key_state(key_id) ON DELETE CASCADE,
    purchase_id           TEXT        REFERENCES ironclaw_billing_purchases(purchase_id) ON DELETE SET NULL,
    event_type            TEXT        NOT NULL,
    status                TEXT        NOT NULL DEFAULT 'issued',
    actor_type            TEXT        NOT NULL DEFAULT 'system',
    reason                TEXT        NOT NULL DEFAULT '',
    metadata              JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ironclaw_install_key_history_event_type_check
        CHECK (event_type IN ('issued', 'activated', 'revoked', 'replaced', 'expired')),
    CONSTRAINT ironclaw_install_key_history_status_check
        CHECK (status IN ('issued', 'active', 'revoked', 'expired'))
);

CREATE INDEX IF NOT EXISTS idx_ironclaw_install_key_history_key_event
    ON ironclaw_install_key_history (key_id, event_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ironclaw_install_key_history_purchase
    ON ironclaw_install_key_history (purchase_id, created_at DESC);

CREATE TRIGGER trg_ironclaw_install_key_history_updated_at
    BEFORE UPDATE ON ironclaw_install_key_history
    FOR EACH ROW EXECUTE FUNCTION ironclaw_set_updated_at();

CREATE TABLE IF NOT EXISTS ironclaw_event_idempotency (
    event_id              TEXT        PRIMARY KEY,
    source                TEXT        NOT NULL DEFAULT 'stripe',
    event_type            TEXT        NOT NULL,
    purchase_id           TEXT        REFERENCES ironclaw_billing_purchases(purchase_id) ON DELETE SET NULL,
    checkout_session_id    TEXT,
    owner_key             TEXT,
    customer_id           TEXT,
    payload_hash          TEXT        NOT NULL,
    processed_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata              JSONB       NOT NULL DEFAULT '{}'::jsonb,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ironclaw_event_idempotency_source_check
        CHECK (source IN ('stripe', 'internal', 'webhook')),
    CONSTRAINT ironclaw_event_idempotency_event_type_not_empty
        CHECK (char_length(trim(event_type)) > 0),
    CONSTRAINT ironclaw_event_idempotency_payload_hash_not_empty
        CHECK (char_length(trim(payload_hash)) > 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ironclaw_event_idempotency_fingerprint
    ON ironclaw_event_idempotency (source, event_type, payload_hash);

CREATE INDEX IF NOT EXISTS idx_ironclaw_event_idempotency_checkout_session
    ON ironclaw_event_idempotency (checkout_session_id, processed_at DESC);

CREATE INDEX IF NOT EXISTS idx_ironclaw_event_idempotency_purchase
    ON ironclaw_event_idempotency (purchase_id, processed_at DESC);

CREATE TRIGGER trg_ironclaw_event_idempotency_updated_at
    BEFORE UPDATE ON ironclaw_event_idempotency
    FOR EACH ROW EXECUTE FUNCTION ironclaw_set_updated_at();
