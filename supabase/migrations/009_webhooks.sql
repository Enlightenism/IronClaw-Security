-- =============================================================================
-- 009_webhooks.sql
-- IronClaw webhook subscription registry and delivery log.
-- Depends on: 001initialpersistenceschema.sql (set_updated_at, pgcrypto,
--                                              persistence_migrations)
--             004ironclawinternaltables.sql    (ironclaw_set_updated_at)
--             005_ironclaw_rls_policies.sql    (RLS pattern reference)
-- tenant_id is TEXT (matches client_id pattern established in 004/005).
-- secret_hash stores HMAC signing secret as SHA-256 hex; never raw secret.
-- webhook_delivery_log is append-only; no UPDATE policy for authenticated.
-- RLS: service_role = full access; authenticated = own tenant rows;
--      anon = zero access.
-- =============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- webhook_subscriptions
-- One row per registered webhook endpoint per tenant.
-- events JSONB array declares which IronClaw event types trigger delivery,
-- e.g. ["verdict.block", "verdict.review", "trust_collapse", "alert.critical"]
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.webhook_subscriptions (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     TEXT        NOT NULL,
    url           TEXT        NOT NULL,
    events        JSONB       NOT NULL DEFAULT '[]'::JSONB,
    secret_hash   TEXT        NOT NULL DEFAULT '',
    enabled       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', NOW()),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', NOW()),
    CONSTRAINT webhook_subscriptions_url_not_empty_check
        CHECK (char_length(trim(url)) > 0),
    CONSTRAINT webhook_subscriptions_url_scheme_check
        CHECK (url ~ '^https?://'),
    CONSTRAINT webhook_subscriptions_events_is_array_check
        CHECK (jsonb_typeof(events) = 'array'),
    CONSTRAINT webhook_subscriptions_secret_hash_format_check
        CHECK (
            secret_hash = ''
            OR secret_hash ~ '^[a-f0-9]{64}$'
        ),
    CONSTRAINT webhook_subscriptions_tenant_id_not_empty_check
        CHECK (char_length(trim(tenant_id)) > 0)
);

-- ---------------------------------------------------------------------------
-- webhook_delivery_log
-- Append-only record of every delivery attempt for a subscription.
-- status tracks the lifecycle of a single dispatch attempt.
-- attempts is the cumulative retry count across all attempts for this event.
-- response_code is the HTTP status code returned by the endpoint (NULL if
-- network-level failure before a response was received).
-- delivered_at is set when status transitions to 'delivered'.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.webhook_delivery_log (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id UUID        NOT NULL
                        REFERENCES public.webhook_subscriptions(id)
                        ON DELETE CASCADE,
    event_type      TEXT        NOT NULL,
    payload         JSONB       NOT NULL DEFAULT '{}'::JSONB,
    status          TEXT        NOT NULL DEFAULT 'pending',
    response_code   INTEGER,
    attempts        INTEGER     NOT NULL DEFAULT 0,
    delivered_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', NOW()),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', NOW()),
    CONSTRAINT webhook_delivery_log_status_check
        CHECK (status IN (
            'pending',
            'delivering',
            'delivered',
            'failed',
            'retrying',
            'abandoned'
        )),
    CONSTRAINT webhook_delivery_log_attempts_check
        CHECK (attempts >= 0),
    CONSTRAINT webhook_delivery_log_response_code_check
        CHECK (response_code IS NULL OR (response_code >= 100 AND response_code <= 599)),
    CONSTRAINT webhook_delivery_log_event_type_not_empty_check
        CHECK (char_length(trim(event_type)) > 0),
    CONSTRAINT webhook_delivery_log_delivered_at_consistency_check
        CHECK (
            (status = 'delivered' AND delivered_at IS NOT NULL)
            OR status != 'delivered'
        )
);

-- ---------------------------------------------------------------------------
-- Indexes — webhook_subscriptions
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_webhook_subscriptions_tenant_id
    ON public.webhook_subscriptions (tenant_id);

CREATE INDEX IF NOT EXISTS idx_webhook_subscriptions_enabled
    ON public.webhook_subscriptions (enabled)
    WHERE enabled = TRUE;

CREATE INDEX IF NOT EXISTS idx_webhook_subscriptions_created_at
    ON public.webhook_subscriptions (created_at DESC);

-- GIN index on events array for fast event-type fan-out queries:
-- WHERE events @> '["verdict.block"]'
CREATE INDEX IF NOT EXISTS idx_webhook_subscriptions_events_gin
    ON public.webhook_subscriptions USING gin (events);

-- ---------------------------------------------------------------------------
-- Indexes — webhook_delivery_log
-- ---------------------------------------------------------------------------

-- Required by spec: subscription_id lookup
CREATE INDEX IF NOT EXISTS idx_webhook_delivery_log_subscription_id
    ON public.webhook_delivery_log (subscription_id);

-- Required by spec: event_type lookup (fan-out queries, replay by type)
CREATE INDEX IF NOT EXISTS idx_webhook_delivery_log_event_type
    ON public.webhook_delivery_log (event_type);

-- Retry queue: find pending/retrying deliveries efficiently
CREATE INDEX IF NOT EXISTS idx_webhook_delivery_log_status
    ON public.webhook_delivery_log (status)
    WHERE status IN ('pending', 'retrying', 'delivering');

-- Composite for per-subscription status queries (dashboard, ops tooling)
CREATE INDEX IF NOT EXISTS idx_webhook_delivery_log_sub_status
    ON public.webhook_delivery_log (subscription_id, status);

CREATE INDEX IF NOT EXISTS idx_webhook_delivery_log_created_at
    ON public.webhook_delivery_log (created_at DESC);

-- ---------------------------------------------------------------------------
-- updated_at triggers
-- Uses public.set_updated_at() from 001 as canonical function.
-- ---------------------------------------------------------------------------

CREATE TRIGGER set_webhook_subscriptions_updated_at
    BEFORE UPDATE ON public.webhook_subscriptions
    FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TRIGGER set_webhook_delivery_log_updated_at
    BEFORE UPDATE ON public.webhook_delivery_log
    FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- ---------------------------------------------------------------------------
-- Row Level Security — webhook_subscriptions
-- service_role : full access (matches 005 pattern)
-- authenticated: SELECT / INSERT / UPDATE own tenant rows
--               (tenant_id = auth.uid()::TEXT)
-- anon         : no policy defined — RLS default-deny, zero access
-- ---------------------------------------------------------------------------

ALTER TABLE public.webhook_subscriptions ENABLE ROW LEVEL SECURITY;

CREATE POLICY webhook_subscriptions_service_role_all
    ON public.webhook_subscriptions
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY webhook_subscriptions_select_own
    ON public.webhook_subscriptions
    FOR SELECT
    TO authenticated
    USING (tenant_id = (SELECT auth.uid()::TEXT));

CREATE POLICY webhook_subscriptions_insert_own
    ON public.webhook_subscriptions
    FOR INSERT
    TO authenticated
    WITH CHECK (tenant_id = (SELECT auth.uid()::TEXT));

CREATE POLICY webhook_subscriptions_update_own
    ON public.webhook_subscriptions
    FOR UPDATE
    TO authenticated
    USING (tenant_id = (SELECT auth.uid()::TEXT))
    WITH CHECK (tenant_id = (SELECT auth.uid()::TEXT));

-- ---------------------------------------------------------------------------
-- Row Level Security — webhook_delivery_log
-- Append-only for authenticated: SELECT own deliveries; no INSERT/UPDATE/DELETE.
-- All writes go through service_role (the IronClaw dispatch worker).
-- ---------------------------------------------------------------------------

ALTER TABLE public.webhook_delivery_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY webhook_delivery_log_service_role_all
    ON public.webhook_delivery_log
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY webhook_delivery_log_select_own
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

-- ---------------------------------------------------------------------------
-- Migration record
-- ---------------------------------------------------------------------------

INSERT INTO public.persistence_migrations (
    migration_key,
    description,
    applied_by,
    checksum,
    metadata
)
VALUES (
    '009_webhooks',
    'Creates webhook_subscriptions (tenant_id, url, events JSONB, secret_hash, enabled) '
    'and webhook_delivery_log (subscription_id FK, event_type, payload, status, '
    'response_code, attempts, delivered_at). Adds required indexes on subscription_id '
    'and event_type plus GIN index on events array for fan-out queries. '
    'RLS: service_role full access, authenticated own-tenant rows, anon zero access. '
    'webhook_delivery_log is write-restricted to service_role; authenticated may only SELECT.',
    'system',
    '',
    jsonb_build_object(
        'section',        'webhooks_and_egress',
        'depends_on',     jsonb_build_array(
                              '001_initial_persistence_schema',
                              '004_ironclaw_internal_tables',
                              '005_ironclaw_rls_policies'
                          ),
        'rls_roles',      jsonb_build_array('service_role', 'authenticated'),
        'anon_access',    FALSE,
        'append_only_tables', jsonb_build_array('webhook_delivery_log')
    )
)
ON CONFLICT (migration_key) DO NOTHING;

COMMIT;
