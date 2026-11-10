-- =============================================================================
-- 009_webhooks.sql
-- IronClaw webhook subscription registry and delivery log.
-- Depends on: 001initialpersistenceschema.sql (set_updated_at, pgcrypto,
--                                              persistence_migrations)
--             004ironclawinternaltables.sql    (ironclaw_set_updated_at)
--             005_ironclaw_rls_policies.sql    (RLS for webhook_subscriptions
--                                              and webhook_delivery_log owned
--                                              exclusively by 005)
-- tenant_id is TEXT (matches client_id pattern established in 004/005).
-- secret_hash stores HMAC signing secret as SHA-256 hex; never raw secret.
-- webhook_delivery_log is append-only; writes restricted to service_role.
-- NOTE: RLS for webhook_subscriptions and webhook_delivery_log is owned
-- exclusively by 005_ironclaw_rls_policies.sql.
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
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id    UUID        NOT NULL
                         REFERENCES public.webhook_subscriptions(id)
                         ON DELETE CASCADE,
    stripe_event_id    TEXT,
    purchase_id        TEXT,
    checkout_session_id TEXT,
    event_type         TEXT        NOT NULL,
    payload            JSONB       NOT NULL DEFAULT '{}'::JSONB,
    payload_hash       TEXT        NOT NULL DEFAULT '',
    status             TEXT        NOT NULL DEFAULT 'pending',
    response_code      INTEGER,
    attempts           INTEGER     NOT NULL DEFAULT 0,
    delivered_at       TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', NOW()),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', NOW()),
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
    CONSTRAINT webhook_delivery_log_payload_hash_not_empty_check
        CHECK (char_length(trim(payload_hash)) > 0),
    CONSTRAINT webhook_delivery_log_delivered_at_consistency_check
        CHECK (
            (status = 'delivered' AND delivered_at IS NOT NULL)
            OR status != 'delivered'
        ),
    CONSTRAINT webhook_delivery_log_checkout_session_not_empty_check
        CHECK (checkout_session_id IS NULL OR char_length(trim(checkout_session_id)) > 0),
    CONSTRAINT webhook_delivery_log_purchase_id_not_empty_check
        CHECK (purchase_id IS NULL OR char_length(trim(purchase_id)) > 0),
    CONSTRAINT webhook_delivery_log_stripe_event_id_not_empty_check
        CHECK (stripe_event_id IS NULL OR char_length(trim(stripe_event_id)) > 0)
);

-- ---------------------------------------------------------------------------
-- Stripe event ledger for durable idempotency and replay protection.
-- This table is deliberately narrow: it captures the event_id, payload hash,
-- and reconciliation keys needed to stop a duplicate Stripe delivery from
-- re-triggering fulfillment logic after a restart or replay.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.stripe_webhook_events (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    stripe_event_id    TEXT        NOT NULL UNIQUE,
    event_type         TEXT        NOT NULL,
    provider           TEXT        NOT NULL DEFAULT 'stripe',
    checkout_session_id TEXT,
    purchase_id        TEXT,
    customer_id        TEXT,
    owner_key          TEXT,
    payload_hash       TEXT        NOT NULL,
    payload            JSONB       NOT NULL DEFAULT '{}'::JSONB,
    status             TEXT        NOT NULL DEFAULT 'received',
    processed_at       TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', NOW()),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', NOW()),
    metadata           JSONB       NOT NULL DEFAULT '{}'::JSONB,
    CONSTRAINT stripe_webhook_events_event_type_not_empty_check
        CHECK (char_length(trim(event_type)) > 0),
    CONSTRAINT stripe_webhook_events_provider_check
        CHECK (provider = 'stripe'),
    CONSTRAINT stripe_webhook_events_status_check
        CHECK (status IN ('received', 'accepted', 'processed', 'duplicate', 'failed', 'rejected')),
    CONSTRAINT stripe_webhook_events_payload_hash_not_empty_check
        CHECK (char_length(trim(payload_hash)) > 0),
    CONSTRAINT stripe_webhook_events_checkout_session_not_empty_check
        CHECK (checkout_session_id IS NULL OR char_length(trim(checkout_session_id)) > 0),
    CONSTRAINT stripe_webhook_events_purchase_id_not_empty_check
        CHECK (purchase_id IS NULL OR char_length(trim(purchase_id)) > 0),
    CONSTRAINT stripe_webhook_events_customer_id_not_empty_check
        CHECK (customer_id IS NULL OR char_length(trim(customer_id)) > 0),
    CONSTRAINT stripe_webhook_events_owner_key_not_empty_check
        CHECK (owner_key IS NULL OR char_length(trim(owner_key)) > 0)
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

CREATE UNIQUE INDEX IF NOT EXISTS idx_webhook_delivery_log_stripe_event_unique
    ON public.webhook_delivery_log (stripe_event_id)
    WHERE stripe_event_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_webhook_delivery_log_reconciliation_unique
    ON public.webhook_delivery_log (subscription_id, stripe_event_id, event_type)
    WHERE stripe_event_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_webhook_delivery_log_checkout_session
    ON public.webhook_delivery_log (checkout_session_id, event_type, status, created_at DESC)
    WHERE checkout_session_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_webhook_delivery_log_purchase_state
    ON public.webhook_delivery_log (purchase_id, event_type, status, created_at DESC)
    WHERE purchase_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_stripe_webhook_events_checkout_session_completed_unique
    ON public.stripe_webhook_events (checkout_session_id)
    WHERE event_type = 'checkout.session.completed' AND checkout_session_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_stripe_webhook_events_purchase_state_unique
    ON public.stripe_webhook_events (purchase_id)
    WHERE purchase_id IS NOT NULL AND event_type IN ('checkout.session.completed', 'purchase.fulfilled');

CREATE INDEX IF NOT EXISTS idx_stripe_webhook_events_event_type_status
    ON public.stripe_webhook_events (event_type, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_stripe_webhook_events_checkout_session
    ON public.stripe_webhook_events (checkout_session_id, event_type, created_at DESC)
    WHERE checkout_session_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- updated_at triggers
-- Uses public.set_updated_at() from 001 as canonical function.
-- ---------------------------------------------------------------------------

create or replace trigger set_webhook_subscriptions_updated_at
    BEFORE UPDATE ON public.webhook_subscriptions
    FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

create or replace trigger set_webhook_delivery_log_updated_at
    BEFORE UPDATE ON public.webhook_delivery_log
    FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

create or replace trigger set_stripe_webhook_events_updated_at
    BEFORE UPDATE ON public.stripe_webhook_events
    FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- ---------------------------------------------------------------------------
-- Append-only protections: never allow silent overwrite or replay mutation.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.prevent_webhook_append_only_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'append-only webhook record mutation is forbidden for table %', TG_TABLE_NAME;
END;
$$;

create or replace trigger prevent_webhook_delivery_log_mutation
    BEFORE UPDATE OR DELETE ON public.webhook_delivery_log
    FOR EACH ROW EXECUTE FUNCTION public.prevent_webhook_append_only_mutation();

create or replace trigger prevent_stripe_webhook_events_mutation
    BEFORE UPDATE OR DELETE ON public.stripe_webhook_events
    FOR EACH ROW EXECUTE FUNCTION public.prevent_webhook_append_only_mutation();

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
    'RLS for both tables is owned exclusively by 005_ironclaw_rls_policies.sql. '
    'webhook_delivery_log is append-only; writes restricted to service_role.',
    'system',
    '',
    jsonb_build_object(
        'section',            'webhooks_and_egress',
        'depends_on',         jsonb_build_array(
                                  '001_initial_persistence_schema',
                                  '004_ironclaw_internal_tables',
                                  '005_ironclaw_rls_policies'
                              ),
        'anon_access',        FALSE,
        'append_only_tables', jsonb_build_array('webhook_delivery_log')
    )
)
ON CONFLICT (migration_key) DO NOTHING;

COMMIT;
